"""
Unit tests for MicrosoftGraphCollector (PR 5 of SAAS_IDENTITY_SPEC).

The collector treats its HTTP client as an injectable dependency with a
single method: ``get(url, params=None) -> dict``. Tests pass a fake client
that records calls and returns canned response dicts so we never need a
real Graph SDK in the test environment.
"""

from __future__ import annotations

import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional
from urllib.parse import quote

import pytest

ROOT = Path(__file__).resolve().parents[2]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from shared.collectors.microsoft_graph_collector import (  # noqa: E402
    FEED_CONFIG,
    GRAPH_BASE,
    GraphHTTPError,
    MicrosoftGraphCollector,
    _format_graph_iso,
    _parse_iso,
)
from shared.collectors.saas_lake import LocalFileRawLakeWriter  # noqa: E402
from shared.collectors.saas_retry import RetryPolicy, TransientError  # noqa: E402
from shared.collectors.saas_secrets import LocalFileSecretStore  # noqa: E402
from shared.collectors.saas_state import LocalFileWatermarkStore, Watermark  # noqa: E402


# ----------------------------------------------------------- Fake Graph client


class _FakeGraphClient:
    """Returns canned responses keyed by URL prefix.

    Pass ``responses_by_endpoint`` as a dict mapping the endpoint path
    fragment (e.g. ``"/auditLogs/signIns"``) to a *list* of page dicts.
    The first call to the matching endpoint returns the first element,
    successive calls walk @odata.nextLink which is encoded in each page.
    """

    def __init__(
        self,
        responses_by_endpoint: Optional[dict[str, list[dict]]] = None,
        raises: Optional[Exception] = None,
        raises_once: bool = True,
    ):
        self.responses_by_endpoint = responses_by_endpoint or {}
        self.raises = raises
        self.raises_once = raises_once
        self.get_calls: list[dict] = []

    def get(self, url: str, params: Optional[dict] = None) -> dict:
        self.get_calls.append({"url": url, "params": dict(params) if params else None})
        if self.raises is not None:
            exc = self.raises
            if self.raises_once:
                self.raises = None
            raise exc
        # Find the matching endpoint by suffix match
        for fragment, pages in self.responses_by_endpoint.items():
            if fragment in url:
                if not pages:
                    return {"value": []}
                # Pop the first remaining page for this endpoint so successive
                # calls walk forward.
                return pages.pop(0)
        return {"value": []}


def _signin(id_: str, when: str, **extra) -> dict:
    return {"id": id_, "createdDateTime": when, "userPrincipalName": "u@c.com", **extra}


def _diraudit(id_: str, when: str, **extra) -> dict:
    return {"id": id_, "activityDateTime": when, "category": "RoleManagement", **extra}


def _risk(id_: str, when: str, **extra) -> dict:
    return {"id": id_, "detectedDateTime": when, "riskLevel": "high", **extra}


def _alert(id_: str, when: str, **extra) -> dict:
    return {"id": id_, "createdDateTime": when, "severity": "high", **extra}


def _make(tmp_path, client, feeds=("signins", "directory_audits", "risk_detections", "defender_alerts"),
          retry_policy=None, secrets_seed=None, page_size=200):
    secrets = LocalFileSecretStore(tmp_path / "secrets.json")
    if secrets_seed:
        for k, v in secrets_seed.items():
            secrets.put(k, v)
    return MicrosoftGraphCollector(
        tenant_id="contoso.onmicrosoft.com",
        watermark_store=LocalFileWatermarkStore(tmp_path / "state"),
        secret_store=secrets,
        lake_writer=LocalFileRawLakeWriter(tmp_path / "lake"),
        retry_policy=retry_policy or RetryPolicy(max_attempts=3, base_delay_seconds=0.0, jitter=0.0),
        feeds=feeds,
        client_factory=lambda _t: client,
        page_size=page_size,
    )


# -------------------------------------------------------------------- tests


class TestHelpers:
    def test_iso_round_trip(self):
        d = _parse_iso("2026-05-09T14:23:11Z")
        # Graph filter format uses millisecond resolution with Z.
        assert _format_graph_iso(d) == "2026-05-09T14:23:11.000Z"

    def test_feed_config_complete(self):
        expected = {"signins", "directory_audits", "risk_detections", "defender_alerts"}
        assert set(FEED_CONFIG) == expected
        # Each config has the three required fields.
        for cfg in FEED_CONFIG.values():
            assert cfg.endpoint.startswith("/v1.0/")
            assert "{since}" in cfg.filter_template and "{until}" in cfg.filter_template
            assert cfg.time_field

    def test_shares_source_name_with_management_activity(self):
        # All M365 events land under source=m365 regardless of which Graph
        # or Management Activity API surface produced them.
        from shared.collectors.microsoft365_collector import Microsoft365Collector
        assert MicrosoftGraphCollector.source_name == Microsoft365Collector.source_name == "m365"


class TestFeedSelection:
    def test_default_feeds(self, tmp_path):
        coll = _make(tmp_path, _FakeGraphClient())
        assert coll.list_feeds() == list(MicrosoftGraphCollector.DEFAULT_FEEDS)

    def test_subset(self, tmp_path):
        coll = _make(tmp_path, _FakeGraphClient(), feeds=("signins",))
        assert coll.list_feeds() == ["signins"]

    def test_unknown_feed_rejected(self, tmp_path):
        with pytest.raises(ValueError):
            _make(tmp_path, _FakeGraphClient(), feeds=("signins", "bogus"))


class TestSinglePage:
    def test_signins_happy_path(self, tmp_path):
        events = [_signin("e1", "2026-05-09T11:00:00Z"),
                  _signin("e2", "2026-05-09T11:30:00Z")]
        client = _FakeGraphClient({"/auditLogs/signIns": [{"value": events}]})
        coll = _make(tmp_path, client, feeds=("signins",))
        until = datetime(2026, 5, 9, 12, 0, tzinfo=timezone.utc)
        result = coll.run(until=until)
        assert result.total_events == 2
        wm = coll.watermarks.get("m365", "contoso.onmicrosoft.com", "signins")
        assert wm.last_event_time == datetime(2026, 5, 9, 11, 30, tzinfo=timezone.utc)
        files = list((tmp_path / "lake").rglob("*.jsonl.gz"))
        assert len(files) == 1 and "feed=signins" in files[0].as_posix()

    def test_filter_carries_correct_time_field(self, tmp_path):
        # Each Graph endpoint uses a different time field name in its $filter.
        cases = [
            ("signins", "/auditLogs/signIns", "createdDateTime"),
            ("directory_audits", "/auditLogs/directoryAudits", "activityDateTime"),
            ("risk_detections", "/identityProtection/riskDetections", "detectedDateTime"),
            ("defender_alerts", "/security/alerts_v2", "createdDateTime"),
        ]
        for feed, fragment, field in cases:
            client = _FakeGraphClient({fragment: [{"value": []}]})
            coll = _make(tmp_path / feed, client, feeds=(feed,))
            until = datetime(2026, 5, 9, 12, 0, tzinfo=timezone.utc)
            coll.run(until=until)
            call = client.get_calls[0]
            assert fragment in call["url"]
            assert call["params"] is not None
            assert field in call["params"]["$filter"]
            assert call["params"]["$top"] == "200"

    def test_first_run_backfill_window(self, tmp_path):
        client = _FakeGraphClient({"/auditLogs/signIns": [{"value": []}]})
        coll = _make(tmp_path, client, feeds=("signins",))
        until = datetime(2026, 5, 9, 12, 0, tzinfo=timezone.utc)
        coll.run(until=until)
        f = client.get_calls[0]["params"]["$filter"]
        # since = until - 7d default backfill
        assert "2026-05-02T12:00:00.000Z" in f
        assert "2026-05-09T12:00:00.000Z" in f


class TestPagination:
    def test_two_pages_via_nextlink(self, tmp_path):
        next_url = "https://graph.microsoft.com/v1.0/auditLogs/signIns?$skiptoken=ABC"
        page1 = {"value": [_signin("e1", "2026-05-09T11:00:00Z")],
                 "@odata.nextLink": next_url}
        page2 = {"value": [_signin("e2", "2026-05-09T11:30:00Z")]}
        client = _FakeGraphClient({"/auditLogs/signIns": [page1, page2]})
        coll = _make(tmp_path, client, feeds=("signins",))
        until = datetime(2026, 5, 9, 12, 0, tzinfo=timezone.utc)
        result = coll.run(until=until)
        assert result.total_events == 2
        assert len(client.get_calls) == 2
        # Second call uses the @odata.nextLink URL verbatim, no params overlay.
        assert client.get_calls[1]["url"] == next_url
        assert client.get_calls[1]["params"] is None


class TestBoundaryFiltering:
    def test_event_at_since_boundary_excluded(self, tmp_path):
        wm = LocalFileWatermarkStore(tmp_path / "state")
        wm.put("m365", "contoso.onmicrosoft.com", "signins",
               Watermark(last_event_time=datetime(2026, 5, 9, 11, 0, tzinfo=timezone.utc)))
        events = [
            _signin("boundary", "2026-05-09T11:00:00Z"),  # must skip
            _signin("after", "2026-05-09T11:30:00Z"),
        ]
        client = _FakeGraphClient({"/auditLogs/signIns": [{"value": events}]})
        coll = MicrosoftGraphCollector(
            tenant_id="contoso.onmicrosoft.com",
            watermark_store=wm,
            secret_store=LocalFileSecretStore(tmp_path / "s.json"),
            lake_writer=LocalFileRawLakeWriter(tmp_path / "lake"),
            retry_policy=RetryPolicy(max_attempts=2, base_delay_seconds=0.0, jitter=0.0),
            feeds=("signins",),
            client_factory=lambda _t: client,
        )
        until = datetime(2026, 5, 9, 12, 0, tzinfo=timezone.utc)
        result = coll.run(until=until)
        assert result.total_events == 1

    def test_event_at_until_boundary_excluded(self, tmp_path):
        client = _FakeGraphClient({"/auditLogs/signIns": [
            {"value": [_signin("end", "2026-05-09T12:00:00Z")]}
        ]})
        coll = _make(tmp_path, client, feeds=("signins",))
        until = datetime(2026, 5, 9, 12, 0, tzinfo=timezone.utc)
        result = coll.run(until=until)
        assert result.total_events == 0

    def test_event_missing_time_field_dropped(self, tmp_path):
        client = _FakeGraphClient({"/auditLogs/signIns": [{"value": [
            {"id": "no-time", "userPrincipalName": "u@c.com"},  # missing createdDateTime
            _signin("ok", "2026-05-09T11:00:00Z"),
        ]}]})
        coll = _make(tmp_path, client, feeds=("signins",))
        until = datetime(2026, 5, 9, 12, 0, tzinfo=timezone.utc)
        result = coll.run(until=until)
        assert result.total_events == 1


class TestTransientRetry:
    def test_429_retried(self, tmp_path):
        client = _FakeGraphClient(
            {"/auditLogs/signIns": [{"value": [_signin("e1", "2026-05-09T11:00:00Z")]}]},
            raises=GraphHTTPError("rate limited", status_code=429, retry_after=0.0),
        )
        coll = _make(tmp_path, client, feeds=("signins",))
        until = datetime(2026, 5, 9, 12, 0, tzinfo=timezone.utc)
        result = coll.run(until=until)
        assert result.total_events == 1
        assert len(client.get_calls) == 2

    def test_503_retried(self, tmp_path):
        client = _FakeGraphClient(
            {"/auditLogs/signIns": [{"value": []}]},
            raises=GraphHTTPError("server", status_code=503),
        )
        coll = _make(tmp_path, client, feeds=("signins",))
        until = datetime(2026, 5, 9, 12, 0, tzinfo=timezone.utc)
        result = coll.run(until=until)
        feed = next(f for f in result.feeds if f.feed == "signins")
        assert feed.error is None
        assert len(client.get_calls) == 2

    def test_403_not_retried(self, tmp_path):
        # 403 commonly means missing Graph scope. Should surface immediately
        # so the operator knows to fix the app registration permissions.
        client = _FakeGraphClient(
            {},
            raises=GraphHTTPError("forbidden", status_code=403),
        )
        coll = _make(tmp_path, client, feeds=("signins",),
                     retry_policy=RetryPolicy(max_attempts=4, base_delay_seconds=0.0, jitter=0.0))
        until = datetime(2026, 5, 9, 12, 0, tzinfo=timezone.utc)
        result = coll.run(until=until)
        feed = next(f for f in result.feeds if f.feed == "signins")
        assert feed.error is not None and "403" in feed.error
        assert len(client.get_calls) == 1


class TestEventEnrichment:
    def test_event_time_and_id_injected(self, tmp_path):
        client = _FakeGraphClient({"/auditLogs/signIns": [
            {"value": [_signin("graph-id-1", "2026-05-09T11:00:00Z")]}
        ]})
        coll = _make(tmp_path, client, feeds=("signins",))
        until = datetime(2026, 5, 9, 12, 0, tzinfo=timezone.utc)
        coll.run(until=until)
        import gzip, json
        files = list((tmp_path / "lake").rglob("*.jsonl.gz"))
        with gzip.open(files[0], "rb") as f:
            record = json.loads(f.read().splitlines()[0])
        assert record["event_time"] == "2026-05-09T11:00:00Z"
        assert record["event_id"] == "graph-id-1"
        # Original fields preserved
        assert record["userPrincipalName"] == "u@c.com"


class TestMultiFeed:
    def test_all_four_feeds_run_independently(self, tmp_path):
        client = _FakeGraphClient({
            "/auditLogs/signIns": [{"value": [_signin("s1", "2026-05-09T11:01:00Z")]}],
            "/auditLogs/directoryAudits": [{"value": [_diraudit("d1", "2026-05-09T11:02:00Z")]}],
            "/identityProtection/riskDetections": [{"value": [_risk("r1", "2026-05-09T11:03:00Z")]}],
            "/security/alerts_v2": [{"value": [_alert("a1", "2026-05-09T11:04:00Z")]}],
        })
        coll = _make(tmp_path, client)
        until = datetime(2026, 5, 9, 12, 0, tzinfo=timezone.utc)
        result = coll.run(until=until)
        assert result.total_events == 4
        # One watermark per feed
        for feed in ("signins", "directory_audits", "risk_detections", "defender_alerts"):
            wm = coll.watermarks.get("m365", "contoso.onmicrosoft.com", feed)
            assert wm is not None, f"missing watermark for {feed}"
        # One lake partition per feed
        partitions = {p.parent.name for p in (tmp_path / "lake").rglob("*.jsonl.gz")}
        assert partitions == {
            "feed=signins", "feed=directory_audits",
            "feed=risk_detections", "feed=defender_alerts",
        }


class TestSourceUnification:
    """All M365 events (Management Activity + Graph) share source=m365 so
    cross-feed queries work without UNIONing different partition trees."""

    def test_graph_writes_under_same_source_partition_as_management_activity(self, tmp_path):
        from shared.collectors.microsoft365_collector import Microsoft365Collector

        # Run a Graph collector and check the partition tag matches what
        # the Management Activity collector would produce.
        client = _FakeGraphClient({"/auditLogs/signIns": [
            {"value": [_signin("e1", "2026-05-09T11:00:00Z")]}
        ]})
        coll = _make(tmp_path, client, feeds=("signins",))
        coll.run(until=datetime(2026, 5, 9, 12, 0, tzinfo=timezone.utc))
        files = list((tmp_path / "lake").rglob("*.jsonl.gz"))
        # source=m365 (not source=graph) so Athena/BigQuery queries union
        # naturally across all M365 surfaces.
        assert any("source=m365" in p.as_posix() for p in files)
        assert Microsoft365Collector.source_name == coll.source_name


class TestSecretsPathError:
    def test_missing_secrets_when_no_factory(self, tmp_path):
        coll = MicrosoftGraphCollector(
            tenant_id="contoso.onmicrosoft.com",
            watermark_store=LocalFileWatermarkStore(tmp_path / "state"),
            secret_store=LocalFileSecretStore(tmp_path / "secrets.json"),
            lake_writer=LocalFileRawLakeWriter(tmp_path / "lake"),
            retry_policy=RetryPolicy(max_attempts=1, base_delay_seconds=0.0, jitter=0.0),
            feeds=("signins",),
        )
        result = coll.run(until=datetime(2026, 5, 9, 12, 0, tzinfo=timezone.utc))
        feed = next(f for f in result.feeds if f.feed == "signins")
        assert feed.error is not None and "secret" in feed.error.lower()
