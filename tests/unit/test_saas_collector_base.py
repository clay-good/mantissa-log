"""
Unit tests for the SaaS collector primitives (PR 1 of SAAS_IDENTITY_SPEC).

Covers:
- saas_retry: parse_retry_after, compute_delay, retry_call, TransientError
- saas_secrets: EnvSecretStore, LocalFileSecretStore
- saas_state: Watermark, LocalFileWatermarkStore, S3WatermarkStore (moto)
- saas_lake: raw_partition_key, LocalFileRawLakeWriter, S3RawLakeWriter (moto)
- base_saas_collector: full run loop with stubbed source

Standalone: does not import the rest of the mantissa-log package, so it
runs even when other modules have unrelated dependency issues.
"""

from __future__ import annotations

import gzip
import io
import json
import os
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Iterator

import boto3
import pytest
from moto import mock_aws

# Make src importable without depending on src/__init__.py
ROOT = Path(__file__).resolve().parents[2]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from shared.collectors.base_saas_collector import (  # noqa: E402
    BaseSaaSCollector,
    CollectorRunResult,
)
from shared.collectors.saas_lake import (  # noqa: E402
    LocalFileRawLakeWriter,
    S3RawLakeWriter,
    raw_partition_key,
)
from shared.collectors.saas_retry import (  # noqa: E402
    RetryPolicy,
    TransientError,
    compute_delay,
    parse_retry_after,
    retry_call,
)
from shared.collectors.saas_secrets import (  # noqa: E402
    EnvSecretStore,
    LocalFileSecretStore,
)
from shared.collectors.saas_state import (  # noqa: E402
    LocalFileWatermarkStore,
    S3WatermarkStore,
    Watermark,
    watermark_key,
)


# --------------------------------------------------------------------- retry


class TestRetry:
    def test_parse_retry_after_seconds(self):
        assert parse_retry_after("30") == 30.0
        assert parse_retry_after("0") == 0.0
        assert parse_retry_after("  12.5  ") == 12.5

    def test_parse_retry_after_http_date(self):
        # An HTTP-date in the future returns a positive delta
        future = "Wed, 21 Oct 2099 07:28:00 GMT"
        result = parse_retry_after(future)
        assert result is not None and result > 0

    def test_parse_retry_after_invalid(self):
        assert parse_retry_after(None) is None
        assert parse_retry_after("") is None
        assert parse_retry_after("nonsense") is None

    def test_compute_delay_grows_then_caps(self):
        policy = RetryPolicy(base_delay_seconds=1.0, max_delay_seconds=4.0, jitter=0.0)
        assert compute_delay(1, policy) == 1.0
        assert compute_delay(2, policy) == 2.0
        assert compute_delay(3, policy) == 4.0
        assert compute_delay(8, policy) == 4.0  # capped

    def test_compute_delay_honours_server_hint(self):
        policy = RetryPolicy(base_delay_seconds=1.0, jitter=0.0)
        assert compute_delay(1, policy, server_hint=10.0) == 10.0

    def test_retry_call_succeeds_after_transient(self):
        attempts = {"n": 0}
        sleeps: list[float] = []

        def fn():
            attempts["n"] += 1
            if attempts["n"] < 3:
                raise TransientError("boom", retry_after=0.001)
            return "ok"

        result = retry_call(fn, RetryPolicy(max_attempts=5, base_delay_seconds=0.0, jitter=0.0),
                            sleep=sleeps.append)
        assert result == "ok"
        assert attempts["n"] == 3
        assert len(sleeps) == 2  # two retries -> two sleeps

    def test_retry_call_exhausts(self):
        def fn():
            raise TransientError("never")

        with pytest.raises(TransientError):
            retry_call(fn, RetryPolicy(max_attempts=2, base_delay_seconds=0.0, jitter=0.0),
                       sleep=lambda _: None)


# -------------------------------------------------------------------- secrets


class TestEnvSecretStore:
    def test_envify_round_trip(self, monkeypatch):
        store = EnvSecretStore()
        monkeypatch.setenv("MANTISSA_SECRET_GWS_ACME_COM_REFRESH_TOKEN", "v1")
        assert store.get("gws/acme.com/refresh_token") == "v1"

    def test_missing_returns_none(self):
        assert EnvSecretStore().get("nope/key") is None

    def test_require_raises(self):
        with pytest.raises(KeyError):
            EnvSecretStore().require("missing")


class TestLocalFileSecretStore:
    def test_put_and_get(self, tmp_path):
        store = LocalFileSecretStore(tmp_path / "secrets.json")
        store.put("gws/t1/refresh_token", "abc")
        store.put("m365/t1/client_secret", "xyz")
        assert store.get("gws/t1/refresh_token") == "abc"
        assert store.get("m365/t1/client_secret") == "xyz"
        assert store.get("missing") is None

    def test_persists_across_instances(self, tmp_path):
        path = tmp_path / "secrets.json"
        LocalFileSecretStore(path).put("k", "v")
        assert LocalFileSecretStore(path).get("k") == "v"

    def test_file_mode_is_user_only(self, tmp_path):
        path = tmp_path / "secrets.json"
        LocalFileSecretStore(path).put("k", "v")
        mode = os.stat(path).st_mode & 0o777
        assert mode == 0o600


# ---------------------------------------------------------------- watermarks


class TestWatermark:
    def test_round_trip(self):
        wm = Watermark(
            last_event_time=datetime(2026, 5, 9, 14, 23, 11, tzinfo=timezone.utc),
            last_event_id="abc",
            updated_at=datetime(2026, 5, 9, 14, 24, tzinfo=timezone.utc),
        )
        d = wm.to_dict()
        wm2 = Watermark.from_dict(d)
        assert wm2.last_event_time == wm.last_event_time
        assert wm2.last_event_id == "abc"
        assert wm2.updated_at == wm.updated_at

    def test_key_format(self):
        key = watermark_key("gws", "acme.com", "login")
        assert key == "_state/collectors/gws/acme.com/login/watermark.json"

    def test_key_sanitizes_tenant(self):
        key = watermark_key("gws", "weird/tenant", "login")
        assert "/weird_tenant/" in key


class TestLocalFileWatermarkStore:
    def test_missing_returns_none(self, tmp_path):
        store = LocalFileWatermarkStore(tmp_path)
        assert store.get("gws", "t", "login") is None

    def test_put_then_get(self, tmp_path):
        store = LocalFileWatermarkStore(tmp_path)
        wm = Watermark(last_event_time=datetime(2026, 1, 1, tzinfo=timezone.utc))
        store.put("gws", "t", "login", wm)
        got = store.get("gws", "t", "login")
        assert got is not None and got.last_event_time == wm.last_event_time
        # updated_at filled in by store on write
        assert got.updated_at is not None

    def test_atomic_overwrite(self, tmp_path):
        store = LocalFileWatermarkStore(tmp_path)
        wm1 = Watermark(last_event_time=datetime(2026, 1, 1, tzinfo=timezone.utc))
        wm2 = Watermark(last_event_time=datetime(2026, 2, 1, tzinfo=timezone.utc))
        store.put("gws", "t", "login", wm1)
        store.put("gws", "t", "login", wm2)
        got = store.get("gws", "t", "login")
        assert got.last_event_time == wm2.last_event_time


@mock_aws
class TestS3WatermarkStore:
    def setup_method(self, method):
        self.s3 = boto3.client("s3", region_name="us-east-1")
        self.s3.create_bucket(Bucket="lake")

    def test_missing_returns_none(self):
        store = S3WatermarkStore("lake", "ml/", s3_client=self.s3)
        assert store.get("gws", "t", "login") is None

    def test_round_trip(self):
        store = S3WatermarkStore("lake", "ml/", s3_client=self.s3)
        wm = Watermark(last_event_time=datetime(2026, 1, 1, 12, tzinfo=timezone.utc))
        store.put("gws", "t", "login", wm)
        got = store.get("gws", "t", "login")
        assert got.last_event_time == wm.last_event_time

    def test_uses_prefix(self):
        store = S3WatermarkStore("lake", "ml/", s3_client=self.s3)
        store.put("gws", "t", "login",
                  Watermark(last_event_time=datetime(2026, 1, 1, tzinfo=timezone.utc)))
        keys = [o["Key"] for o in self.s3.list_objects_v2(Bucket="lake")["Contents"]]
        assert any(k.startswith("ml/_state/collectors/gws/t/login/") for k in keys)


# --------------------------------------------------------------------- lake


class TestRawPartitionKey:
    def test_format(self):
        when = datetime(2026, 5, 9, 14, 0, tzinfo=timezone.utc)
        key = raw_partition_key("gws", "acme.com", "login", when, batch_id="abc123")
        assert key == "raw/source=gws/dt=2026-05-09/hh=14/tenant=acme.com/feed=login/abc123.jsonl.gz"

    def test_naive_datetime_treated_as_utc(self):
        when = datetime(2026, 5, 9, 14, 0)  # no tz
        key = raw_partition_key("gws", "t", "login", when, batch_id="x")
        assert "dt=2026-05-09" in key and "hh=14" in key


class TestLocalFileRawLakeWriter:
    def test_writes_gzipped_jsonl(self, tmp_path):
        writer = LocalFileRawLakeWriter(tmp_path)
        events = [{"event_id": "1", "event_time": "2026-05-09T14:00:00Z", "x": 1},
                  {"event_id": "2", "event_time": "2026-05-09T14:00:01Z", "x": 2}]
        when = datetime(2026, 5, 9, 14, 0, tzinfo=timezone.utc)
        key = writer.write_batch("gws", "t", "login", events, when=when, batch_id="b")
        path = tmp_path / key
        assert path.exists()
        with gzip.open(path, "rb") as f:
            lines = [json.loads(line) for line in f.read().splitlines()]
        assert lines == events


@mock_aws
class TestS3RawLakeWriter:
    def setup_method(self, method):
        self.s3 = boto3.client("s3", region_name="us-east-1")
        self.s3.create_bucket(Bucket="lake")

    def test_writes_with_gzip_encoding(self):
        writer = S3RawLakeWriter("lake", "ml/", s3_client=self.s3)
        events = [{"event_id": "1", "event_time": "2026-05-09T14:00:00Z", "y": "z"}]
        when = datetime(2026, 5, 9, 14, 0, tzinfo=timezone.utc)
        key = writer.write_batch("gws", "t", "login", events, when=when, batch_id="b")
        assert key.startswith("ml/raw/source=gws/dt=2026-05-09/hh=14/tenant=t/feed=login/")
        obj = self.s3.get_object(Bucket="lake", Key=key)
        assert obj["ContentEncoding"] == "gzip"
        body = gzip.GzipFile(fileobj=io.BytesIO(obj["Body"].read())).read()
        assert json.loads(body.splitlines()[0]) == events[0]


# ------------------------------------------------------------------- base run


class _StubCollector(BaseSaaSCollector):
    """Test double: emits a fixed list of events regardless of since/until,
    but filters to events strictly after ``since`` to mimic real behaviour."""

    source_name = "stub"
    default_backfill_days = 1

    def __init__(self, *args, events_by_feed=None, raise_first=False, **kwargs):
        super().__init__(*args, **kwargs)
        self.events_by_feed = events_by_feed or {}
        self.raise_first = raise_first
        self._raised = False
        self.fetch_calls: list[tuple[str, datetime, datetime]] = []

    def list_feeds(self) -> list[str]:
        return list(self.events_by_feed.keys())

    def fetch_feed(self, feed, since, until) -> Iterator[dict]:
        # Call site (non-generator) records the call and raises eagerly so
        # retry_call sees the failure. This mirrors the real-world pattern
        # where API clients do auth + first request before yielding pages.
        self.fetch_calls.append((feed, since, until))
        if self.raise_first and not self._raised:
            self._raised = True
            raise TransientError("nope", retry_after=0.001)
        return self._iter_events(feed, since, until)

    def _iter_events(self, feed, since, until) -> Iterator[dict]:
        for event in self.events_by_feed.get(feed, []):
            t = datetime.fromisoformat(event["event_time"].replace("Z", "+00:00"))
            if t > since and t < until:
                yield event


def _events(*times: str, feed_prefix: str = "e") -> list[dict]:
    return [{"event_id": f"{feed_prefix}{i}", "event_time": t, "payload": i}
            for i, t in enumerate(times)]


class TestBaseSaaSCollectorRun:
    def _make(self, tmp_path, events_by_feed, **kw):
        wm = LocalFileWatermarkStore(tmp_path / "state")
        secrets = LocalFileSecretStore(tmp_path / "secrets.json")
        lake = LocalFileRawLakeWriter(tmp_path / "lake")
        return _StubCollector(
            tenant_id="t1",
            watermark_store=wm,
            secret_store=secrets,
            lake_writer=lake,
            events_by_feed=events_by_feed,
            retry_policy=RetryPolicy(max_attempts=3, base_delay_seconds=0.0, jitter=0.0),
            **kw,
        ), wm, lake

    def test_first_run_backfills_from_default_window(self, tmp_path):
        evs = _events("2026-05-09T10:00:00Z", "2026-05-09T11:00:00Z")
        coll, wm, lake = self._make(tmp_path, {"login": evs})
        until = datetime(2026, 5, 9, 12, 0, tzinfo=timezone.utc)
        result = coll.run(until=until)
        assert result.total_events == 2
        # Watermark advanced to latest event time
        stored = wm.get("stub", "t1", "login")
        assert stored.last_event_time == datetime(2026, 5, 9, 11, 0, tzinfo=timezone.utc)
        assert stored.last_event_id == "e1"
        # Files in lake
        files = list((tmp_path / "lake").rglob("*.jsonl.gz"))
        assert len(files) == 1

    def test_second_run_uses_watermark(self, tmp_path):
        evs = [
            {"event_id": "a", "event_time": "2026-05-09T10:00:00Z"},
            {"event_id": "b", "event_time": "2026-05-09T11:00:00Z"},
            {"event_id": "c", "event_time": "2026-05-09T12:00:00Z"},
        ]
        coll, wm, _ = self._make(tmp_path, {"login": evs})
        # First run cuts off at 11:00 -> only event "a" gets through (since the
        # default backfill window in the stub is 1 day from until)
        until1 = datetime(2026, 5, 9, 11, 0, tzinfo=timezone.utc)
        r1 = coll.run(until=until1)
        assert r1.total_events == 1
        # Second run advances until to 12:30, picks up "b" and "c"
        until2 = datetime(2026, 5, 9, 12, 30, tzinfo=timezone.utc)
        r2 = coll.run(until=until2)
        assert r2.total_events == 2
        assert wm.get("stub", "t1", "login").last_event_id == "c"

    def test_no_new_events_no_lake_write(self, tmp_path):
        coll, _, _ = self._make(tmp_path, {"login": []})
        until = datetime(2026, 5, 9, 12, 0, tzinfo=timezone.utc)
        result = coll.run(until=until)
        assert result.total_events == 0
        files = list((tmp_path / "lake").rglob("*.jsonl.gz"))
        assert files == []

    def test_multiple_feeds(self, tmp_path):
        coll, wm, _ = self._make(tmp_path, {
            "login": _events("2026-05-09T11:00:00Z", feed_prefix="L"),
            "admin": _events("2026-05-09T11:30:00Z", feed_prefix="A"),
        })
        until = datetime(2026, 5, 9, 12, 0, tzinfo=timezone.utc)
        result = coll.run(until=until)
        assert {f.feed for f in result.feeds} == {"login", "admin"}
        assert result.total_events == 2

    def test_batches_respect_batch_size(self, tmp_path):
        events = [{"event_id": f"x{i}", "event_time": f"2026-05-09T11:{i:02d}:00Z"}
                  for i in range(7)]
        coll, _, _ = self._make(tmp_path, {"login": events})
        coll.batch_size = 3
        until = datetime(2026, 5, 9, 12, 0, tzinfo=timezone.utc)
        result = coll.run(until=until)
        login = next(f for f in result.feeds if f.feed == "login")
        assert login.events_written == 7
        assert login.batches_written == 3  # 3 + 3 + 1

    def test_transient_failure_retried(self, tmp_path):
        coll, wm, _ = self._make(
            tmp_path,
            {"login": _events("2026-05-09T11:00:00Z")},
            raise_first=True,
        )
        until = datetime(2026, 5, 9, 12, 0, tzinfo=timezone.utc)
        result = coll.run(until=until)
        assert result.total_events == 1
        # First call raised, second succeeded
        assert len(coll.fetch_calls) == 2

    def test_subselect_feeds(self, tmp_path):
        coll, _, _ = self._make(tmp_path, {
            "login": _events("2026-05-09T11:00:00Z"),
            "admin": _events("2026-05-09T11:30:00Z"),
        })
        until = datetime(2026, 5, 9, 12, 0, tzinfo=timezone.utc)
        result = coll.run(until=until, feeds=["admin"])
        assert [f.feed for f in result.feeds] == ["admin"]
        assert result.total_events == 1

    def test_source_name_required(self, tmp_path):
        class NoName(BaseSaaSCollector):
            source_name = ""

            def list_feeds(self):
                return []

            def fetch_feed(self, feed, since, until):
                return iter([])

        with pytest.raises(ValueError):
            NoName(
                tenant_id="t",
                watermark_store=LocalFileWatermarkStore(tmp_path),
                secret_store=LocalFileSecretStore(tmp_path / "s.json"),
                lake_writer=LocalFileRawLakeWriter(tmp_path / "l"),
            )
