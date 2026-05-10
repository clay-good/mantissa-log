"""
Unit tests for PR 14 of SAAS_IDENTITY_SPEC: SaaS sign-in IP threat-intel
enrichment.

Three surfaces under test:

  1. Path registry: completeness against the collectors actually shipped
     in PRs 2-13, dotted-path resolution, None-means-skip semantics.
  2. IP routability filter: public vs private/reserved/link-local/etc.
  3. SaaSSigninEnricher: bridges to a duck-typed threat-intel service,
     handles missing IP, non-routable IP, service-raises, service-None,
     idempotency, and a representative sweep across every collector
     family shipped so far.

The threat-intel service is duck-typed everywhere so we never import
the production VirusTotal / AbuseIPDB clients.
"""

from __future__ import annotations

import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

import pytest

ROOT = Path(__file__).resolve().parents[2]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from shared.enrichment.saas_signin import (  # noqa: E402
    ENRICHMENT_KEY,
    SAAS_FEED_IP_PATHS,
    SaaSSigninEnricher,
    get_ip_field_path,
    get_path,
    is_routable_ip,
)


# ============================================================ registry


class TestRegistry:
    def test_all_gws_pr2_pr3_feeds_present(self):
        # Every feed in GoogleWorkspaceCollector.ALL_FEEDS must be in the
        # registry. This is the load-bearing invariant: when PR 3 added
        # 17 feeds we did not break the enrichment surface.
        from shared.collectors.google_workspace_collector import (
            GoogleWorkspaceCollector,
        )
        for feed in GoogleWorkspaceCollector.ALL_FEEDS:
            assert ("gws", feed) in SAAS_FEED_IP_PATHS, f"missing gws/{feed}"

    def test_all_m365_management_activity_feeds_present(self):
        from shared.collectors.microsoft365_collector import Microsoft365Collector
        for feed in Microsoft365Collector.ALL_FEEDS:
            assert ("m365", feed) in SAAS_FEED_IP_PATHS, f"missing m365/{feed}"

    def test_all_m365_graph_feeds_present(self):
        from shared.collectors.microsoft_graph_collector import (
            MicrosoftGraphCollector,
        )
        for feed in MicrosoftGraphCollector.ALL_FEEDS:
            assert ("m365", feed) in SAAS_FEED_IP_PATHS, f"missing m365/{feed} (graph)"

    def test_okta_github_slack_salesforce_present(self):
        for key in [
            ("okta", "system"),
            ("github", "audit"),
            ("slack", "audit"),
            ("salesforce", "events"),
        ]:
            assert key in SAAS_FEED_IP_PATHS

    def test_directory_audits_explicitly_no_ip(self):
        # directory_audits has no IP. Must be registered as None so callers
        # can distinguish "unknown feed" from "known feed, no IP".
        assert get_ip_field_path("m365", "directory_audits") is None

    def test_unknown_feed_returns_none(self):
        assert get_ip_field_path("nope", "nada") is None

    def test_no_registry_duplicates(self):
        # Sanity. Dict keys are unique by construction but this guards
        # against future refactors that switch to a list.
        seen = set()
        for key in SAAS_FEED_IP_PATHS:
            assert key not in seen
            seen.add(key)


# ============================================================ path resolver


class TestGetPath:
    def test_top_level(self):
        assert get_path({"ipAddress": "1.2.3.4"}, "ipAddress") == "1.2.3.4"

    def test_nested(self):
        evt = {"client": {"ipAddress": "5.6.7.8"}}
        assert get_path(evt, "client.ipAddress") == "5.6.7.8"

    def test_deeply_nested(self):
        evt = {"a": {"b": {"c": "value"}}}
        assert get_path(evt, "a.b.c") == "value"

    def test_missing_top_level(self):
        assert get_path({"foo": "bar"}, "ipAddress") is None

    def test_intermediate_non_dict_returns_none(self):
        assert get_path({"client": "not-a-dict"}, "client.ipAddress") is None

    def test_non_string_value_returns_none(self):
        # The threat intel service only wants strings; numeric or list
        # values at the IP path are treated as missing.
        assert get_path({"ip": 12345}, "ip") is None
        assert get_path({"ip": ["1.2.3.4"]}, "ip") is None


# ============================================================ routability


class TestIsRoutableIP:
    @pytest.mark.parametrize("ip", [
        "8.8.8.8",                  # Google DNS
        "1.1.1.1",                  # Cloudflare DNS
        "199.232.0.1",              # GitHub-style routable
        "2001:4860:4860::8888",     # Google IPv6 DNS
    ])
    def test_public_ip_routable(self, ip):
        assert is_routable_ip(ip) is True

    @pytest.mark.parametrize("ip", [
        "203.0.113.5",              # TEST-NET-3 (RFC 5737 docs range)
        "198.51.100.1",             # TEST-NET-2 (RFC 5737 docs range)
        "2001:db8::1234",           # IPv6 docs range (RFC 3849)
    ])
    def test_documentation_ranges_not_routable(self, ip):
        # ipaddress.is_reserved returns True for these; correct behaviour
        # because no real traffic uses these addresses and looking them
        # up wastes cache slots and API quota.
        assert is_routable_ip(ip) is False

    @pytest.mark.parametrize("ip", [
        "10.0.0.1", "192.168.1.1", "172.16.0.5",  # RFC 1918
        "127.0.0.1",                                # loopback
        "169.254.1.1",                              # link-local
        "224.0.0.1",                                # multicast
        "0.0.0.0",                                  # unspecified
        "::1",                                      # ipv6 loopback
        "fe80::1",                                  # ipv6 link-local
    ])
    def test_private_or_reserved_not_routable(self, ip):
        assert is_routable_ip(ip) is False

    @pytest.mark.parametrize("v", ["", None, "not-an-ip", "1.2.3.999"])
    def test_invalid_inputs_not_routable(self, v):
        assert is_routable_ip(v) is False

    def test_strips_whitespace(self):
        assert is_routable_ip("  8.8.8.8  ") is True


# ============================================================ enricher


@dataclass
class _FakeResult:
    indicator: str = "8.8.8.8"
    indicator_type: str = "ip"
    reputation_score: Optional[float] = 75.0
    is_malicious: bool = True
    confidence: float = 0.85
    categories: list = field(default_factory=lambda: ["scanner", "brute_force"])
    abuse_score: Optional[int] = 80
    total_reports: int = 12
    is_tor_exit: bool = False
    is_vpn: bool = True
    is_proxy: bool = False
    sources: list = field(default_factory=lambda: ["abuseipdb"])
    cached: bool = False


class _FakeTI:
    def __init__(self, result: Optional[_FakeResult] = None,
                  raises: Optional[Exception] = None):
        self.result = result
        self.raises = raises
        self.lookups: list[str] = []

    def lookup_ip_reputation(self, ip: str):
        self.lookups.append(ip)
        if self.raises is not None:
            raise self.raises
        return self.result


class TestEnricherHappyPath:
    def test_gws_login_enriched_with_top_level_ip(self):
        svc = _FakeTI(result=_FakeResult())
        enricher = SaaSSigninEnricher(service=svc)
        event = {"ipAddress": "8.8.8.8", "actor": {"email": "u@a.com"}}
        out = enricher.enrich(event, source="gws", feed="login")
        assert out is event  # mutates in place
        ti = event[ENRICHMENT_KEY]
        assert ti["ip"] == "8.8.8.8"
        assert ti["is_malicious"] is True
        assert ti["reputation_score"] == 75.0
        assert ti["categories"] == ["scanner", "brute_force"]
        assert ti["is_vpn"] is True
        assert svc.lookups == ["8.8.8.8"]

    def test_okta_nested_path_enriched(self):
        svc = _FakeTI(result=_FakeResult(indicator="5.6.7.8"))
        enricher = SaaSSigninEnricher(service=svc)
        event = {"client": {"ipAddress": "5.6.7.8"}, "eventType": "user.session.start"}
        enricher.enrich(event, source="okta", feed="system")
        assert event[ENRICHMENT_KEY]["ip"] == "5.6.7.8"
        assert svc.lookups == ["5.6.7.8"]

    def test_slack_double_nested_path(self):
        svc = _FakeTI(result=_FakeResult())
        enricher = SaaSSigninEnricher(service=svc)
        event = {"context": {"ip_address": "1.1.1.1"}, "action": "user_login"}
        enricher.enrich(event, source="slack", feed="audit")
        assert ENRICHMENT_KEY in event
        assert svc.lookups == ["1.1.1.1"]


class TestEnricherSkipPaths:
    def test_unknown_feed_returns_unchanged(self):
        svc = _FakeTI(result=_FakeResult())
        enricher = SaaSSigninEnricher(service=svc)
        event = {"ipAddress": "8.8.8.8"}
        enricher.enrich(event, source="bogus", feed="nope")
        assert ENRICHMENT_KEY not in event
        assert svc.lookups == []

    def test_feed_registered_as_none_skipped(self):
        # m365 directory_audits is registered with None to mean "no IP".
        svc = _FakeTI(result=_FakeResult())
        enricher = SaaSSigninEnricher(service=svc)
        event = {"ipAddress": "8.8.8.8"}
        enricher.enrich(event, source="m365", feed="directory_audits")
        assert ENRICHMENT_KEY not in event
        assert svc.lookups == []

    def test_missing_ip_field_skipped(self):
        svc = _FakeTI(result=_FakeResult())
        enricher = SaaSSigninEnricher(service=svc)
        event = {"actor": {"email": "u@a.com"}}
        enricher.enrich(event, source="gws", feed="login")
        assert ENRICHMENT_KEY not in event
        assert svc.lookups == []

    def test_private_ip_skipped(self):
        svc = _FakeTI(result=_FakeResult())
        enricher = SaaSSigninEnricher(service=svc)
        event = {"ipAddress": "10.0.0.5"}
        enricher.enrich(event, source="gws", feed="login")
        assert ENRICHMENT_KEY not in event
        assert svc.lookups == []

    def test_loopback_skipped(self):
        svc = _FakeTI(result=_FakeResult())
        enricher = SaaSSigninEnricher(service=svc)
        event = {"ipAddress": "127.0.0.1"}
        enricher.enrich(event, source="gws", feed="login")
        assert ENRICHMENT_KEY not in event
        assert svc.lookups == []

    def test_invalid_ip_skipped(self):
        svc = _FakeTI(result=_FakeResult())
        enricher = SaaSSigninEnricher(service=svc)
        event = {"ipAddress": "not-an-ip"}
        enricher.enrich(event, source="gws", feed="login")
        assert ENRICHMENT_KEY not in event
        assert svc.lookups == []


class TestEnricherErrorHandling:
    def test_service_raises_does_not_crash_pipeline(self):
        # Enrichment failures must never poison the lake write. The
        # event flows through unchanged.
        svc = _FakeTI(raises=RuntimeError("provider down"))
        enricher = SaaSSigninEnricher(service=svc)
        event = {"ipAddress": "8.8.8.8"}
        out = enricher.enrich(event, source="gws", feed="login")
        assert out is event
        assert ENRICHMENT_KEY not in event

    def test_service_returns_none(self):
        # No matching threat intel record is the common case for benign
        # IPs. The event flows through without an enrichment block.
        svc = _FakeTI(result=None)
        enricher = SaaSSigninEnricher(service=svc)
        event = {"ipAddress": "8.8.8.8"}
        enricher.enrich(event, source="gws", feed="login")
        assert ENRICHMENT_KEY not in event


class TestEnricherIdempotency:
    def test_existing_threat_intel_not_overwritten(self):
        svc = _FakeTI(result=_FakeResult(reputation_score=99.0))
        enricher = SaaSSigninEnricher(service=svc)
        event = {
            "ipAddress": "8.8.8.8",
            ENRICHMENT_KEY: {"ip": "8.8.8.8", "reputation_score": 10.0, "sources": ["prior"]},
        }
        enricher.enrich(event, source="gws", feed="login")
        # Existing enrichment preserved; service never called.
        assert event[ENRICHMENT_KEY]["reputation_score"] == 10.0
        assert svc.lookups == []

    def test_double_enrich_calls_service_once(self):
        svc = _FakeTI(result=_FakeResult())
        enricher = SaaSSigninEnricher(service=svc)
        event = {"ipAddress": "8.8.8.8"}
        enricher.enrich(event, source="gws", feed="login")
        enricher.enrich(event, source="gws", feed="login")
        assert svc.lookups == ["8.8.8.8"]


class TestRepresentativeSweep:
    """One event per source + feed, exercising every distinct path shape.

    If a future change moves an IP field, the test that uses that
    source/feed breaks immediately rather than silently regressing
    enrichment coverage.
    """

    @pytest.mark.parametrize("source,feed,event,expected_ip", [
        ("gws", "login", {"ipAddress": "8.8.8.8"}, "8.8.8.8"),
        ("gws", "drive", {"ipAddress": "8.8.4.4"}, "8.8.4.4"),
        ("gws", "token", {"ipAddress": "1.1.1.1"}, "1.1.1.1"),
        ("m365", "aad", {"ClientIP": "9.9.9.9"}, "9.9.9.9"),
        ("m365", "exchange", {"ClientIP": "9.9.9.10"}, "9.9.9.10"),
        ("m365", "sharepoint", {"ClientIP": "9.9.9.11"}, "9.9.9.11"),
        ("m365", "signins", {"ipAddress": "13.107.6.152"}, "13.107.6.152"),
        ("m365", "risk_detections", {"ipAddress": "13.107.6.153"}, "13.107.6.153"),
        ("okta", "system", {"client": {"ipAddress": "5.6.7.8"}}, "5.6.7.8"),
        ("slack", "audit", {"context": {"ip_address": "4.4.4.4"}}, "4.4.4.4"),
        ("github", "audit", {"actor_ip": "199.232.0.1"}, "199.232.0.1"),
        ("salesforce", "events", {"CLIENT_IP": "208.67.222.222"}, "208.67.222.222"),
    ])
    def test_each_source_feed_hits_correct_path(self, source, feed, event, expected_ip):
        svc = _FakeTI(result=_FakeResult())
        SaaSSigninEnricher(service=svc).enrich(dict(event), source=source, feed=feed)
        assert svc.lookups == [expected_ip], f"{source}/{feed} resolved wrong IP"


class TestResultDictShape:
    """The enrichment dict written to the event has stable, documented keys.

    Downstream Sigma rules and NL queries depend on these names. Adding
    a new key is fine; renaming or dropping one breaks queries. The
    test enumerates the contract.
    """

    EXPECTED_KEYS = {
        "ip", "reputation_score", "is_malicious", "confidence",
        "categories", "abuse_score", "total_reports",
        "is_tor_exit", "is_vpn", "is_proxy", "sources", "cached",
    }

    def test_result_dict_has_documented_keys(self):
        svc = _FakeTI(result=_FakeResult())
        enricher = SaaSSigninEnricher(service=svc)
        event = {"ipAddress": "8.8.8.8"}
        enricher.enrich(event, source="gws", feed="login")
        assert set(event[ENRICHMENT_KEY].keys()) == self.EXPECTED_KEYS

    def test_result_dict_handles_missing_attributes(self):
        # An exotic TI provider that does not expose every attribute
        # should still produce a valid dict with defaults rather than
        # crashing on getattr().
        class _Sparse:
            indicator = "8.8.8.8"
            is_malicious = True
            # everything else absent

        svc = _FakeTI(result=_Sparse())
        enricher = SaaSSigninEnricher(service=svc)
        event = {"ipAddress": "8.8.8.8"}
        enricher.enrich(event, source="gws", feed="login")
        ti = event[ENRICHMENT_KEY]
        assert ti["is_malicious"] is True
        assert ti["reputation_score"] is None
        assert ti["categories"] == []
        assert ti["confidence"] == 0.0
