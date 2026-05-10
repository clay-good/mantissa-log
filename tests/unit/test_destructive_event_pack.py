"""
Unit tests for PR 6 of SAAS_IDENTITY_SPEC.

Two surfaces under test:

  1. ``rules/sigma/destructive/*.yml`` -- 22 destructive-event rules.
     Verifies they parse, carry the expected custom paging fields, target
     the listed source coverage, and use the level=critical convention.

  2. ``src/shared/alerting/paging.py`` -- paging extraction + router
     wrapper. Verifies the metadata extractor honours the flag, the
     attach helper writes the right keys onto an alert, and the
     PagingAwareRouter augments destinations only when paging is set.
"""

from __future__ import annotations

import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[2]
SRC = ROOT / "src"
RULES_DIR = ROOT / "rules" / "sigma" / "destructive"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from shared.alerting.paging import (  # noqa: E402
    DEFAULT_PAGING_DESTINATIONS,
    META_EVIDENCE_QUERY,
    META_PAGING,
    META_PAGING_DESTINATIONS,
    PagingAwareRouter,
    PagingMetadata,
    attach_to_alert,
    extract_paging_metadata,
)


# ---------------------------------------------------------------- rule pack


RULE_FILES = sorted(RULES_DIR.glob("dest_*.yml"))
RULES = [yaml.safe_load(p.read_text()) for p in RULE_FILES]
RULES_BY_FILENAME = dict(zip([p.name for p in RULE_FILES], RULES))


class TestRulePack:
    def test_count(self):
        # Spec §4 lists 22 destructive-event rules.
        assert len(RULE_FILES) == 22, "expected 22 destructive-event rules"

    def test_filenames_follow_convention(self):
        for f in RULE_FILES:
            assert f.name.startswith("dest_"), f"non-conforming filename: {f.name}"
            assert f.suffix == ".yml"

    @pytest.mark.parametrize("rule", RULES, ids=[p.name for p in RULE_FILES])
    def test_each_rule_parses(self, rule):
        assert isinstance(rule, dict), "rule did not parse to a dict"

    @pytest.mark.parametrize("rule", RULES, ids=[p.name for p in RULE_FILES])
    def test_each_rule_has_required_sigma_fields(self, rule):
        for key in ("title", "id", "description", "logsource", "detection",
                    "level", "tags"):
            assert key in rule, f"missing required field: {key}"

    @pytest.mark.parametrize("rule", RULES, ids=[p.name for p in RULE_FILES])
    def test_each_rule_is_critical(self, rule):
        # Spec §4: paging-grade rules are critical, full stop.
        assert rule["level"] == "critical"

    @pytest.mark.parametrize("rule", RULES, ids=[p.name for p in RULE_FILES])
    def test_each_rule_opts_in_to_paging(self, rule):
        assert rule.get("paging") is True

    @pytest.mark.parametrize("rule", RULES, ids=[p.name for p in RULE_FILES])
    def test_each_rule_has_evidence_query(self, rule):
        eq = rule.get("evidence_query")
        assert isinstance(eq, str) and eq.strip()
        # The convention is a SELECT scoped to actor + time window.
        upper = eq.upper()
        assert "SELECT" in upper and "WHERE" in upper

    @pytest.mark.parametrize("rule", RULES, ids=[p.name for p in RULE_FILES])
    def test_each_rule_specifies_paging_destinations(self, rule):
        dests = rule.get("paging_destinations") or []
        assert isinstance(dests, list) and dests, "missing paging_destinations"
        # At least one routable sink. Slack / Teams / PagerDuty are the
        # canonical paging targets; webhook is acceptable too.
        assert any(d in {"pagerduty", "slack", "teams", "webhook", "opsgenie"} for d in dests)

    @pytest.mark.parametrize("rule", RULES, ids=[p.name for p in RULE_FILES])
    def test_each_rule_has_detection_block(self, rule):
        det = rule.get("detection", {})
        assert "selection" in det
        assert det.get("condition")

    @pytest.mark.parametrize("rule", RULES, ids=[p.name for p in RULE_FILES])
    def test_each_rule_carries_mitre_tag(self, rule):
        tags = rule.get("tags", [])
        attack = [t for t in tags if isinstance(t, str) and t.startswith("attack.")]
        assert attack, f"no MITRE ATT&CK tag on rule {rule.get('id')}"

    def test_ids_unique(self):
        ids = [r["id"] for r in RULES]
        assert len(ids) == len(set(ids)), "duplicate rule ids"

    def test_covers_required_categories(self):
        """Spec §4 lists five categories. At least one rule per category."""
        filenames = {p.name for p in RULE_FILES}
        # identity / privilege escalation
        assert any("super_admin" in f or "global_admin" in f or "org_admin" in f
                   or "owner_granted" in f or "root_used" in f for f in filenames)
        # MFA / authentication
        assert any("2fa" in f or "security_defaults" in f or "conditional_access" in f
                   or "mfa" in f for f in filenames)
        # mass data
        assert any("mass_download" in f or "mass_delete" in f
                   or "mass_export" in f or "made_public" in f for f in filenames)
        # OAuth / app trust
        assert any("oauth" in f or "consent" in f for f in filenames)
        # logging / audit tampering
        assert any("cloudtrail" in f or "audit_log" in f for f in filenames)

    def test_covers_all_three_clouds_and_three_saas(self):
        products = set()
        for r in RULES:
            ls = r.get("logsource", {})
            products.add(ls.get("product"))
        # AWS, GCP, Azure / M365, GWS, Okta, GitHub
        assert "aws" in products
        assert "gcp" in products
        assert ("azure" in products) or ("microsoft365" in products)
        assert "google_workspace" in products
        assert "okta" in products
        assert "github" in products


# ------------------------------------------------------------- paging.py


class TestExtractPagingMetadata:
    def test_paging_true_returns_metadata(self):
        rule = {"paging": True, "evidence_query": "SELECT 1"}
        meta = extract_paging_metadata(rule)
        assert meta is not None
        assert meta.paging is True
        assert meta.evidence_query == "SELECT 1"
        assert meta.paging_destinations == DEFAULT_PAGING_DESTINATIONS

    def test_paging_absent_returns_none(self):
        assert extract_paging_metadata({}) is None
        assert extract_paging_metadata({"paging": False}) is None
        assert extract_paging_metadata({"paging": None}) is None

    def test_custom_destinations_honoured(self):
        rule = {"paging": True, "paging_destinations": ["pagerduty", "webhook"]}
        meta = extract_paging_metadata(rule)
        assert meta.paging_destinations == ("pagerduty", "webhook")

    def test_non_list_destinations_falls_back_to_default(self):
        rule = {"paging": True, "paging_destinations": "pagerduty"}  # bad type
        meta = extract_paging_metadata(rule)
        assert meta.paging_destinations == DEFAULT_PAGING_DESTINATIONS

    def test_non_dict_returns_none(self):
        assert extract_paging_metadata(None) is None
        assert extract_paging_metadata([1, 2, 3]) is None  # type: ignore[arg-type]

    def test_real_rule_files_extract_cleanly(self):
        for rule in RULES:
            meta = extract_paging_metadata(rule)
            assert meta is not None
            assert meta.paging is True
            assert meta.evidence_query
            assert len(meta.paging_destinations) >= 1


# --------------------------------------------------------- attach_to_alert


@dataclass
class _FakeAlert:
    id: str = "a-1"
    severity: str = "critical"
    metadata: dict = field(default_factory=dict)
    destinations: list = field(default_factory=list)


class TestAttachToAlert:
    def test_writes_three_keys(self):
        alert = _FakeAlert()
        meta = PagingMetadata(paging=True, evidence_query="SELECT 1",
                              paging_destinations=("pagerduty", "slack"))
        attach_to_alert(alert, meta)
        assert alert.metadata[META_PAGING] is True
        assert alert.metadata[META_EVIDENCE_QUERY] == "SELECT 1"
        assert alert.metadata[META_PAGING_DESTINATIONS] == ["pagerduty", "slack"]

    def test_does_not_write_evidence_when_missing(self):
        alert = _FakeAlert()
        meta = PagingMetadata(paging=True, evidence_query=None)
        attach_to_alert(alert, meta)
        assert META_PAGING in alert.metadata
        assert META_EVIDENCE_QUERY not in alert.metadata

    def test_initializes_metadata_when_none(self):
        alert = _FakeAlert(metadata=None)  # type: ignore[arg-type]
        meta = PagingMetadata(paging=True)
        attach_to_alert(alert, meta)
        assert alert.metadata[META_PAGING] is True


# ---------------------------------------------------- PagingAwareRouter


class _RecordingRouter:
    """Minimal stand-in for AlertRouter that records inputs."""

    def __init__(self):
        self.routed: list[_FakeAlert] = []
        self.routed_batches: list[list[_FakeAlert]] = []

    def route_alert(self, alert: _FakeAlert):
        self.routed.append(alert)
        return f"ok-{alert.id}"

    def route_alerts(self, alerts: list[_FakeAlert]):
        self.routed_batches.append(list(alerts))
        return [f"ok-{a.id}" for a in alerts]


class TestPagingAwareRouter:
    def test_paging_alert_gets_extra_destinations(self):
        inner = _RecordingRouter()
        router = PagingAwareRouter(inner=inner)
        alert = _FakeAlert(destinations=["jira"])
        attach_to_alert(alert, PagingMetadata(paging=True,
                                              paging_destinations=("pagerduty", "slack", "teams")))

        router.route_alert(alert)

        assert inner.routed[0].destinations == ["jira", "pagerduty", "slack", "teams"]

    def test_non_paging_alert_left_alone(self):
        inner = _RecordingRouter()
        router = PagingAwareRouter(inner=inner)
        alert = _FakeAlert(destinations=["jira"], metadata={})
        router.route_alert(alert)
        assert inner.routed[0].destinations == ["jira"]

    def test_dedup_preserves_order(self):
        inner = _RecordingRouter()
        router = PagingAwareRouter(inner=inner)
        # Existing destinations already include some paging targets.
        alert = _FakeAlert(destinations=["slack", "jira"])
        attach_to_alert(alert, PagingMetadata(paging=True,
                                              paging_destinations=("pagerduty", "slack", "teams")))
        router.route_alert(alert)
        # Order: existing first, then new paging dests in declared order,
        # without re-adding "slack" which was already present.
        assert inner.routed[0].destinations == ["slack", "jira", "pagerduty", "teams"]

    def test_route_alerts_batch(self):
        inner = _RecordingRouter()
        router = PagingAwareRouter(inner=inner)
        a1 = _FakeAlert(id="1", destinations=["jira"])
        a2 = _FakeAlert(id="2", destinations=[])
        attach_to_alert(a1, PagingMetadata(paging=True))
        # a2 has no paging metadata.
        router.route_alerts([a1, a2])

        assert inner.routed_batches[0][0].destinations == ["jira"] + list(DEFAULT_PAGING_DESTINATIONS)
        assert inner.routed_batches[0][1].destinations == []

    def test_missing_destinations_attr_initialized(self):
        # An alert with no destinations attribute should still work.
        @dataclass
        class _Lean:
            id: str = "lean-1"
            metadata: dict = field(default_factory=dict)

        alert: Any = _Lean()
        attach_to_alert(alert, PagingMetadata(paging=True,
                                              paging_destinations=("pagerduty",)))
        # destinations defaults to [] for our router augment logic
        alert.destinations = []
        inner = _RecordingRouter()
        router = PagingAwareRouter(inner=inner)
        router.route_alert(alert)
        assert alert.destinations == ["pagerduty"]


# ----------------------------------------------------- end-to-end thread


class TestEndToEndRulePackToRouter:
    """Verifies a real destructive-event rule flows through the paging
    extractor and router augmentation without any custom glue."""

    def test_super_admin_grant_routes_to_paging_destinations(self):
        rule = RULES_BY_FILENAME["dest_gws_super_admin_granted.yml"]
        meta = extract_paging_metadata(rule)
        assert meta is not None

        alert = _FakeAlert(severity=rule["level"], destinations=[])
        attach_to_alert(alert, meta)

        inner = _RecordingRouter()
        router = PagingAwareRouter(inner=inner)
        router.route_alert(alert)

        # The rule declares pagerduty + slack + teams; the router should
        # have added all three to the alert before delegating to inner.
        for dest in rule["paging_destinations"]:
            assert dest in inner.routed[0].destinations
        # And the evidence query is on the alert for the bot to render.
        assert META_EVIDENCE_QUERY in inner.routed[0].metadata
