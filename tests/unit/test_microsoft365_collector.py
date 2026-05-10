"""
Unit tests for Microsoft365Collector (PR 4 of SAAS_IDENTITY_SPEC).

We never import the production HTTP client. Tests inject a fake client
exposing the three methods the collector relies on:

    start_subscription(content_type)
    list_content(content_type, start_time, end_time) -> list[dict]
    fetch_blob(content_uri) -> list[dict]

The fake records call arguments so tests can assert on the API contract.
"""

from __future__ import annotations

import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Optional

import pytest

ROOT = Path(__file__).resolve().parents[2]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from shared.collectors.microsoft365_collector import (  # noqa: E402
    DEFAULT_LOOKBACK_HOURS,
    FEED_TO_CONTENT_TYPE,
    MAX_WINDOW_HOURS,
    ManagementActivityHTTPError,
    Microsoft365Collector,
    _format_iso,
    _parse_iso,
)
from shared.collectors.saas_lake import LocalFileRawLakeWriter  # noqa: E402
from shared.collectors.saas_retry import RetryPolicy, TransientError  # noqa: E402
from shared.collectors.saas_secrets import LocalFileSecretStore  # noqa: E402
from shared.collectors.saas_state import LocalFileWatermarkStore, Watermark  # noqa: E402


# -------------------------------------------------------- Fake API client


class _FakeM365Client:
    def __init__(
        self,
        blobs_by_ct: Optional[dict[str, list[dict]]] = None,
        events_by_uri: Optional[dict[str, list[dict]]] = None,
        list_raises: Optional[Exception] = None,
        fetch_raises: Optional[dict[str, Exception]] = None,
        subscribe_raises: Optional[Exception] = None,
    ):
        self.blobs_by_ct = blobs_by_ct or {}
        self.events_by_uri = events_by_uri or {}
        self.list_raises = list_raises
        self.fetch_raises = fetch_raises or {}
        self.subscribe_raises = subscribe_raises

        self.subscribe_calls: list[str] = []
        self.list_calls: list[dict] = []
        self.fetch_calls: list[str] = []

    def start_subscription(self, content_type):
        self.subscribe_calls.append(content_type)
        if self.subscribe_raises is not None:
            raise self.subscribe_raises

    def list_content(self, content_type, start_time, end_time):
        self.list_calls.append(
            {"content_type": content_type, "start_time": start_time, "end_time": end_time}
        )
        if self.list_raises is not None:
            exc = self.list_raises
            # Only raise once so retries can succeed.
            self.list_raises = None
            raise exc
        return list(self.blobs_by_ct.get(content_type, []))

    def fetch_blob(self, content_uri):
        self.fetch_calls.append(content_uri)
        if content_uri in self.fetch_raises:
            raise self.fetch_raises.pop(content_uri)
        return list(self.events_by_uri.get(content_uri, []))


def _blob(uri: str, created: str) -> dict:
    return {"contentUri": uri, "contentId": uri.rsplit("/", 1)[-1], "contentCreated": created,
            "contentType": "x", "contentExpiration": created}


def _event(id_: str, creation_time: str, **extra) -> dict:
    return {"Id": id_, "CreationTime": creation_time, "Operation": "Test", **extra}


def _make(tmp_path, client, feeds=("aad", "exchange", "sharepoint", "general", "dlp"),
          retry_policy=None, lookback_hours=DEFAULT_LOOKBACK_HOURS, secrets_seed=None):
    secrets = LocalFileSecretStore(tmp_path / "secrets.json")
    if secrets_seed:
        for k, v in secrets_seed.items():
            secrets.put(k, v)
    return Microsoft365Collector(
        tenant_id="contoso.onmicrosoft.com",
        watermark_store=LocalFileWatermarkStore(tmp_path / "state"),
        secret_store=secrets,
        lake_writer=LocalFileRawLakeWriter(tmp_path / "lake"),
        retry_policy=retry_policy or RetryPolicy(max_attempts=3, base_delay_seconds=0.0, jitter=0.0),
        feeds=feeds,
        client_factory=lambda _t: client,
        lookback_hours=lookback_hours,
    )


# -------------------------------------------------------------------- tests


class TestHelpers:
    def test_iso_round_trip(self):
        d = _parse_iso("2026-05-09T14:23:11Z")
        # Management Activity API uses no trailing Z on outbound.
        assert _format_iso(d) == "2026-05-09T14:23:11"

    def test_feed_map_covers_all_five_content_types(self):
        assert set(FEED_TO_CONTENT_TYPE) == {"aad", "exchange", "sharepoint", "general", "dlp"}
        for v in FEED_TO_CONTENT_TYPE.values():
            assert v.startswith("Audit.") or v == "DLP.All"


class TestFeedSelection:
    def test_default_feeds(self, tmp_path):
        coll = _make(tmp_path, _FakeM365Client())
        assert coll.list_feeds() == list(Microsoft365Collector.DEFAULT_FEEDS)

    def test_subset(self, tmp_path):
        coll = _make(tmp_path, _FakeM365Client(), feeds=("aad",))
        assert coll.list_feeds() == ["aad"]

    def test_unknown_feed_rejected(self, tmp_path):
        with pytest.raises(ValueError):
            _make(tmp_path, _FakeM365Client(), feeds=("aad", "bogus"))


class TestSubscription:
    def test_subscribe_called_once_per_feed(self, tmp_path):
        client = _FakeM365Client()
        coll = _make(tmp_path, client)
        coll.run(until=datetime(2026, 5, 9, 12, 0, tzinfo=timezone.utc))
        assert sorted(client.subscribe_calls) == sorted([
            "Audit.AzureActiveDirectory", "Audit.Exchange", "Audit.SharePoint",
            "Audit.General", "DLP.All",
        ])

    def test_subscribe_not_called_twice_for_same_content_type(self, tmp_path):
        client = _FakeM365Client()
        coll = _make(tmp_path, client, feeds=("aad",))
        coll.run(until=datetime(2026, 5, 9, 12, 0, tzinfo=timezone.utc))
        coll.run(until=datetime(2026, 5, 9, 13, 0, tzinfo=timezone.utc))
        assert client.subscribe_calls == ["Audit.AzureActiveDirectory"]


class TestSingleBlobSingleEvent:
    def test_event_written_and_watermark_advanced(self, tmp_path):
        client = _FakeM365Client(
            blobs_by_ct={"Audit.AzureActiveDirectory": [_blob("https://u/1", "2026-05-09T11:00:00Z")]},
            events_by_uri={"https://u/1": [_event("E1", "2026-05-09T11:00:00Z", UserId="u@c.com")]},
        )
        coll = _make(tmp_path, client, feeds=("aad",))
        until = datetime(2026, 5, 9, 12, 0, tzinfo=timezone.utc)
        result = coll.run(until=until)

        assert result.total_events == 1
        wm = coll.watermarks.get("m365", "contoso.onmicrosoft.com", "aad")
        assert wm.last_event_time == datetime(2026, 5, 9, 11, 0, tzinfo=timezone.utc)
        # One lake partition for the feed
        files = list((tmp_path / "lake").rglob("*.jsonl.gz"))
        assert len(files) == 1
        assert "feed=aad" in files[0].as_posix()


class TestLookbackWindow:
    def test_api_start_widened_by_lookback(self, tmp_path):
        client = _FakeM365Client()
        coll = _make(tmp_path, client, feeds=("aad",), lookback_hours=24)
        until = datetime(2026, 5, 9, 12, 0, tzinfo=timezone.utc)
        coll.run(until=until)
        # First call's start_time should be (until - 7d backfill) - 24h lookback
        first = client.list_calls[0]
        expected_start = until - timedelta(days=7) - timedelta(hours=24)
        assert first["start_time"] == _format_iso(expected_start)

    def test_zero_lookback(self, tmp_path):
        client = _FakeM365Client()
        coll = _make(tmp_path, client, feeds=("aad",), lookback_hours=0)
        until = datetime(2026, 5, 9, 12, 0, tzinfo=timezone.utc)
        coll.run(until=until)
        first = client.list_calls[0]
        expected_start = until - timedelta(days=7)
        assert first["start_time"] == _format_iso(expected_start)


class TestWindowChunking:
    def test_long_backfill_chunked_to_seven_days(self, tmp_path):
        client = _FakeM365Client()
        coll = _make(tmp_path, client, feeds=("aad",), lookback_hours=0)
        # Force a long backfill window by setting the watermark explicitly.
        # Pre-set a watermark 14 days before until.
        until = datetime(2026, 5, 9, 12, 0, tzinfo=timezone.utc)
        coll.watermarks.put("m365", "contoso.onmicrosoft.com", "aad",
                            Watermark(last_event_time=until - timedelta(days=14)))
        coll.run(until=until)
        # 14d window chunked at 7d cap -> two list calls
        assert len(client.list_calls) == 2

    def test_short_window_single_call(self, tmp_path):
        client = _FakeM365Client()
        coll = _make(tmp_path, client, feeds=("aad",), lookback_hours=0)
        until = datetime(2026, 5, 9, 12, 0, tzinfo=timezone.utc)
        coll.watermarks.put("m365", "contoso.onmicrosoft.com", "aad",
                            Watermark(last_event_time=until - timedelta(hours=2)))
        coll.run(until=until)
        assert len(client.list_calls) == 1


class TestMultipleBlobs:
    def test_each_blob_fetched_in_order(self, tmp_path):
        blobs = [
            _blob("https://u/A", "2026-05-09T10:30:00Z"),
            _blob("https://u/B", "2026-05-09T11:00:00Z"),
            _blob("https://u/C", "2026-05-09T11:30:00Z"),
        ]
        events_by_uri = {
            "https://u/A": [_event("a1", "2026-05-09T10:25:00Z")],
            "https://u/B": [_event("b1", "2026-05-09T10:55:00Z"),
                            _event("b2", "2026-05-09T10:58:00Z")],
            "https://u/C": [_event("c1", "2026-05-09T11:25:00Z")],
        }
        client = _FakeM365Client(
            blobs_by_ct={"Audit.AzureActiveDirectory": blobs},
            events_by_uri=events_by_uri,
        )
        coll = _make(tmp_path, client, feeds=("aad",))
        until = datetime(2026, 5, 9, 12, 0, tzinfo=timezone.utc)
        result = coll.run(until=until)

        assert result.total_events == 4
        # All three blobs fetched, in returned order
        assert client.fetch_calls == ["https://u/A", "https://u/B", "https://u/C"]
        # Watermark advanced to latest event time
        wm = coll.watermarks.get("m365", "contoso.onmicrosoft.com", "aad")
        assert wm.last_event_time == datetime(2026, 5, 9, 11, 25, tzinfo=timezone.utc)


class TestBoundaryFiltering:
    def test_event_at_since_boundary_excluded(self, tmp_path):
        # Existing watermark at 11:00. Lookback-widened API window will
        # return events at or below 11:00, but they must be filtered out.
        client = _FakeM365Client(
            blobs_by_ct={"Audit.AzureActiveDirectory": [_blob("https://u/1", "2026-05-09T11:30:00Z")]},
            events_by_uri={"https://u/1": [
                _event("at-boundary", "2026-05-09T11:00:00Z"),  # must skip
                _event("after", "2026-05-09T11:15:00Z"),
            ]},
        )
        coll = _make(tmp_path, client, feeds=("aad",))
        coll.watermarks.put("m365", "contoso.onmicrosoft.com", "aad",
                            Watermark(last_event_time=datetime(2026, 5, 9, 11, 0, tzinfo=timezone.utc)))
        until = datetime(2026, 5, 9, 12, 0, tzinfo=timezone.utc)
        result = coll.run(until=until)
        assert result.total_events == 1

    def test_event_at_until_boundary_excluded(self, tmp_path):
        until = datetime(2026, 5, 9, 12, 0, tzinfo=timezone.utc)
        client = _FakeM365Client(
            blobs_by_ct={"Audit.AzureActiveDirectory": [_blob("https://u/1", "2026-05-09T11:30:00Z")]},
            events_by_uri={"https://u/1": [_event("at-end", "2026-05-09T12:00:00Z")]},
        )
        coll = _make(tmp_path, client, feeds=("aad",))
        result = coll.run(until=until)
        assert result.total_events == 0

    def test_blob_without_uri_skipped(self, tmp_path):
        bad_blob = {"contentId": "x", "contentCreated": "2026-05-09T11:00:00Z"}
        client = _FakeM365Client(blobs_by_ct={"Audit.AzureActiveDirectory": [bad_blob]})
        coll = _make(tmp_path, client, feeds=("aad",))
        until = datetime(2026, 5, 9, 12, 0, tzinfo=timezone.utc)
        result = coll.run(until=until)
        assert result.total_events == 0
        assert client.fetch_calls == []

    def test_event_missing_creation_time_dropped(self, tmp_path):
        client = _FakeM365Client(
            blobs_by_ct={"Audit.AzureActiveDirectory": [_blob("https://u/1", "2026-05-09T11:00:00Z")]},
            events_by_uri={"https://u/1": [
                {"Id": "bad", "Operation": "X"},  # no CreationTime
                _event("ok", "2026-05-09T11:05:00Z"),
            ]},
        )
        coll = _make(tmp_path, client, feeds=("aad",))
        until = datetime(2026, 5, 9, 12, 0, tzinfo=timezone.utc)
        result = coll.run(until=until)
        assert result.total_events == 1


class TestTransientRetry:
    """Each test pre-sets a recent watermark and uses ``lookback_hours=0`` so
    the API window is a single chunk. This keeps call-count assertions exact
    without re-testing the window-chunking logic (covered separately)."""

    def _single_chunk_collector(self, tmp_path, client, **kw):
        coll = _make(tmp_path, client, feeds=("aad",), lookback_hours=0, **kw)
        coll.watermarks.put("m365", "contoso.onmicrosoft.com", "aad",
                            Watermark(last_event_time=datetime(2026, 5, 9, 10, 0, tzinfo=timezone.utc)))
        return coll

    def test_429_on_list_retried(self, tmp_path):
        client = _FakeM365Client(
            blobs_by_ct={"Audit.AzureActiveDirectory": [_blob("https://u/1", "2026-05-09T11:00:00Z")]},
            events_by_uri={"https://u/1": [_event("e1", "2026-05-09T11:00:00Z")]},
            list_raises=ManagementActivityHTTPError("rate limited", status_code=429, retry_after=0.0),
        )
        coll = self._single_chunk_collector(tmp_path, client)
        until = datetime(2026, 5, 9, 12, 0, tzinfo=timezone.utc)
        result = coll.run(until=until)
        assert result.total_events == 1
        assert len(client.list_calls) == 2  # one 429, one success

    def test_500_on_list_retried(self, tmp_path):
        client = _FakeM365Client(
            list_raises=ManagementActivityHTTPError("server", status_code=503),
        )
        coll = self._single_chunk_collector(tmp_path, client)
        until = datetime(2026, 5, 9, 12, 0, tzinfo=timezone.utc)
        result = coll.run(until=until)
        feed = next(f for f in result.feeds if f.feed == "aad")
        assert feed.error is None  # retried then succeeded with no blobs
        assert len(client.list_calls) == 2

    def test_404_on_list_not_retried(self, tmp_path):
        client = _FakeM365Client(
            list_raises=ManagementActivityHTTPError("not found", status_code=404),
        )
        coll = self._single_chunk_collector(
            tmp_path, client,
            retry_policy=RetryPolicy(max_attempts=4, base_delay_seconds=0.0, jitter=0.0),
        )
        until = datetime(2026, 5, 9, 12, 0, tzinfo=timezone.utc)
        result = coll.run(until=until)
        feed = next(f for f in result.feeds if f.feed == "aad")
        assert feed.error is not None and "404" in feed.error
        assert len(client.list_calls) == 1

    def test_blob_fetch_error_surfaces_as_feed_error(self, tmp_path):
        # Per contract, errors during streaming are NOT retried by base class
        # but they DO surface as feed-level error so the operator sees the
        # failed blob in run output. Base class catches the exception.
        client = _FakeM365Client(
            blobs_by_ct={"Audit.AzureActiveDirectory": [
                _blob("https://u/A", "2026-05-09T11:00:00Z"),
                _blob("https://u/B", "2026-05-09T11:30:00Z"),
            ]},
            events_by_uri={"https://u/A": [_event("a1", "2026-05-09T10:55:00Z")]},
            fetch_raises={"https://u/B": ManagementActivityHTTPError("gone", status_code=410)},
        )
        coll = self._single_chunk_collector(tmp_path, client)
        until = datetime(2026, 5, 9, 12, 0, tzinfo=timezone.utc)
        result = coll.run(until=until)
        feed = next(f for f in result.feeds if f.feed == "aad")
        assert feed.error is not None and "410" in feed.error


class TestEventEnrichment:
    def test_event_time_and_id_injected(self, tmp_path):
        client = _FakeM365Client(
            blobs_by_ct={"Audit.AzureActiveDirectory": [_blob("https://u/1", "2026-05-09T11:00:00Z")]},
            events_by_uri={"https://u/1": [_event("Eid123", "2026-05-09T11:00:00Z")]},
        )
        coll = _make(tmp_path, client, feeds=("aad",))
        until = datetime(2026, 5, 9, 12, 0, tzinfo=timezone.utc)
        coll.run(until=until)

        import gzip, json as _json
        files = list((tmp_path / "lake").rglob("*.jsonl.gz"))
        with gzip.open(files[0], "rb") as f:
            record = _json.loads(f.read().splitlines()[0])
        assert record["event_time"] == "2026-05-09T11:00:00Z"
        assert record["event_id"] == "Eid123"
        # Original Microsoft fields preserved
        assert record["Id"] == "Eid123"
        assert record["Operation"] == "Test"


class TestMultiFeed:
    def test_each_feed_gets_independent_watermark_and_partition(self, tmp_path):
        # One blob and one event per content type. Verify the cross-feed
        # plumbing works: subscribe, list, fetch, watermark, lake partition.
        blobs = {}
        events = {}
        feed_event_times = {
            "aad": "2026-05-09T11:01:00Z",
            "exchange": "2026-05-09T11:02:00Z",
            "sharepoint": "2026-05-09T11:03:00Z",
            "general": "2026-05-09T11:04:00Z",
            "dlp": "2026-05-09T11:05:00Z",
        }
        for feed, t in feed_event_times.items():
            ct = FEED_TO_CONTENT_TYPE[feed]
            uri = f"https://u/{feed}"
            blobs[ct] = [_blob(uri, t)]
            events[uri] = [_event(f"e-{feed}", t)]

        client = _FakeM365Client(blobs_by_ct=blobs, events_by_uri=events)
        coll = _make(tmp_path, client)
        until = datetime(2026, 5, 9, 12, 0, tzinfo=timezone.utc)
        result = coll.run(until=until)

        assert result.total_events == 5
        for feed in feed_event_times:
            wm = coll.watermarks.get("m365", "contoso.onmicrosoft.com", feed)
            assert wm is not None, f"missing watermark for {feed}"
        partitions = {p.parent.name for p in (tmp_path / "lake").rglob("*.jsonl.gz")}
        assert partitions == {f"feed={f}" for f in feed_event_times}


class TestSecretsPathError:
    def test_missing_secrets_when_no_factory(self, tmp_path):
        coll = Microsoft365Collector(
            tenant_id="contoso.onmicrosoft.com",
            watermark_store=LocalFileWatermarkStore(tmp_path / "state"),
            secret_store=LocalFileSecretStore(tmp_path / "secrets.json"),
            lake_writer=LocalFileRawLakeWriter(tmp_path / "lake"),
            retry_policy=RetryPolicy(max_attempts=1, base_delay_seconds=0.0, jitter=0.0),
            feeds=("aad",),
        )
        result = coll.run(until=datetime(2026, 5, 9, 12, 0, tzinfo=timezone.utc))
        feed = next(f for f in result.feeds if f.feed == "aad")
        assert feed.error is not None and "secret" in feed.error.lower()
