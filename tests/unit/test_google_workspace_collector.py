"""
Unit tests for GoogleWorkspaceCollector (PR 2 of SAAS_IDENTITY_SPEC).

Strategy. We never import google-api-python-client. Instead, we inject a
fake service factory that returns an object exposing the same call chain:

    service.activities().list(...).execute() -> dict

The fake records calls and returns canned page dicts so tests can assert
on pagination, watermark advance, retry-on-transient, and per-feed
filtering without standing up real auth.
"""

from __future__ import annotations

import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

import pytest

ROOT = Path(__file__).resolve().parents[2]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from shared.collectors.base_saas_collector import BaseSaaSCollector  # noqa: E402,F401
from shared.collectors.google_workspace_collector import (  # noqa: E402
    FEED_TO_APPLICATION_NAME,
    GoogleWorkspaceCollector,
    _make_event_id,
    _format_iso,
    _parse_iso,
)
from shared.collectors.saas_lake import LocalFileRawLakeWriter  # noqa: E402
from shared.collectors.saas_retry import RetryPolicy, TransientError  # noqa: E402
from shared.collectors.saas_secrets import LocalFileSecretStore  # noqa: E402
from shared.collectors.saas_state import LocalFileWatermarkStore, Watermark  # noqa: E402


# ----------------------------------------------------------- Fake Reports API


class _FakeRequest:
    def __init__(self, response: Any):
        self._response = response

    def execute(self):
        if isinstance(self._response, Exception):
            raise self._response
        return self._response


class _FakeActivities:
    def __init__(self, parent: "_FakeReportsService"):
        self._parent = parent

    def list(self, **kwargs):
        self._parent.list_calls.append(kwargs)
        app = kwargs["applicationName"]
        token = kwargs.get("pageToken")
        responses = self._parent.responses_by_app.get(app, [])
        if not responses:
            return _FakeRequest({"items": []})
        # Use list as a queue indexed by page token. None == first call.
        lookup = {r.get("_token"): r for r in responses}
        page = lookup.get(token)
        if page is None:
            # Allow tests to deliberately set a response keyed by token.
            page = responses[0] if token is None else {"items": []}
        if isinstance(page, Exception):
            return _FakeRequest(page)
        return _FakeRequest(page)


class _FakeReportsService:
    def __init__(self, responses_by_app: dict[str, list[Any]]):
        self.responses_by_app = responses_by_app
        self.list_calls: list[dict] = []

    def activities(self):
        return _FakeActivities(self)


def _activity(time_iso: str, qual: str, app: str, name: str = "x", actor: str = "u@a.com"):
    return {
        "kind": "admin#reports#activity",
        "id": {"time": time_iso, "uniqueQualifier": qual, "applicationName": app, "customerId": "C"},
        "actor": {"email": actor, "profileId": "1"},
        "ipAddress": "1.2.3.4",
        "events": [{"name": name, "type": "auth"}],
    }


# ------------------------------------------------------------------ helpers


def _make_collector(tmp_path, service, feeds=("login", "admin", "drive", "token"),
                    retry_policy=None, secrets_seed=None):
    secrets = LocalFileSecretStore(tmp_path / "secrets.json")
    if secrets_seed:
        for k, v in secrets_seed.items():
            secrets.put(k, v)
    return GoogleWorkspaceCollector(
        tenant_id="acme.com",
        watermark_store=LocalFileWatermarkStore(tmp_path / "state"),
        secret_store=secrets,
        lake_writer=LocalFileRawLakeWriter(tmp_path / "lake"),
        retry_policy=retry_policy or RetryPolicy(max_attempts=3, base_delay_seconds=0.0, jitter=0.0),
        feeds=feeds,
        service_factory=lambda *_a, **_k: service,
    )


# -------------------------------------------------------------------- tests


class TestHelpers:
    def test_iso_round_trip(self):
        s = "2026-05-09T14:23:11Z"
        d = _parse_iso(s)
        assert d.tzinfo is not None
        assert _format_iso(d) == s

    def test_event_id_stable(self):
        item = _activity("2026-05-09T14:00:00Z", "Q1", "login")
        e1 = _make_event_id(item)
        e2 = _make_event_id(dict(item))
        assert e1 == e2
        assert "Q1" in e1 and "login" in e1

    def test_feed_map_complete(self):
        # Every PR 2 feed must map to a Reports applicationName.
        for f in ("login", "admin", "drive", "token"):
            assert f in FEED_TO_APPLICATION_NAME

    def test_pr3_feeds_present(self):
        pr3_feeds = (
            "calendar", "groups", "groups_enterprise", "gmail", "mobile",
            "chrome", "meet", "chat", "user_accounts", "access_transparency",
            "saml", "context_aware_access", "data_studio", "gcp",
            "keep", "jamboard", "rules",
        )
        for f in pr3_feeds:
            assert f in FEED_TO_APPLICATION_NAME, f"missing PR 3 feed: {f}"

    def test_all_feeds_constant_matches_map(self):
        from shared.collectors.google_workspace_collector import GoogleWorkspaceCollector
        # Every member of ALL_FEEDS resolves in the application-name map.
        for f in GoogleWorkspaceCollector.ALL_FEEDS:
            assert f in FEED_TO_APPLICATION_NAME
        # And the constants do not silently drop a real Reports feed.
        assert set(GoogleWorkspaceCollector.ALL_FEEDS) == set(FEED_TO_APPLICATION_NAME)

    def test_default_feeds_is_subset_of_all(self):
        from shared.collectors.google_workspace_collector import GoogleWorkspaceCollector
        assert set(GoogleWorkspaceCollector.DEFAULT_FEEDS).issubset(
            set(GoogleWorkspaceCollector.ALL_FEEDS)
        )


class TestFeedSelection:
    def test_default_feeds(self, tmp_path):
        coll = _make_collector(tmp_path, _FakeReportsService({}))
        assert coll.list_feeds() == ["login", "admin", "drive", "token"]

    def test_subset(self, tmp_path):
        coll = _make_collector(tmp_path, _FakeReportsService({}), feeds=("login",))
        assert coll.list_feeds() == ["login"]

    def test_unknown_feed_rejected(self, tmp_path):
        with pytest.raises(ValueError):
            _make_collector(tmp_path, _FakeReportsService({}), feeds=("login", "bogus"))


class TestSinglePage:
    def test_writes_events_advances_watermark(self, tmp_path):
        events = [
            _activity("2026-05-09T11:00:00Z", "q1", "login"),
            _activity("2026-05-09T11:30:00Z", "q2", "login"),
        ]
        service = _FakeReportsService({"login": [{"items": events}]})
        coll = _make_collector(tmp_path, service, feeds=("login",))

        until = datetime(2026, 5, 9, 12, 0, tzinfo=timezone.utc)
        result = coll.run(until=until)

        assert result.total_events == 2
        wm = coll.watermarks.get("gws", "acme.com", "login")
        assert wm is not None
        assert wm.last_event_time == datetime(2026, 5, 9, 11, 30, tzinfo=timezone.utc)
        # Lake file written
        files = list((tmp_path / "lake").rglob("*.jsonl.gz"))
        assert len(files) == 1
        assert "feed=login" in files[0].as_posix()

    def test_first_run_uses_default_backfill(self, tmp_path):
        service = _FakeReportsService({"login": [{"items": []}]})
        coll = _make_collector(tmp_path, service, feeds=("login",))
        until = datetime(2026, 5, 9, 12, 0, tzinfo=timezone.utc)
        coll.run(until=until)
        # Inspect the start time the collector passed to the API on first run
        call = service.list_calls[0]
        # Default backfill is 7 days; startTime should be 7 days before until
        assert call["startTime"] == "2026-05-02T12:00:00Z"
        assert call["endTime"] == "2026-05-09T12:00:00Z"


class TestPagination:
    def test_two_pages(self, tmp_path):
        page1 = {"items": [_activity("2026-05-09T10:00:00Z", "q1", "admin")],
                 "nextPageToken": "TOK1"}
        # token-keyed second page
        page2 = {"_token": "TOK1",
                 "items": [_activity("2026-05-09T11:00:00Z", "q2", "admin")]}
        service = _FakeReportsService({"admin": [page1, page2]})
        coll = _make_collector(tmp_path, service, feeds=("admin",))

        until = datetime(2026, 5, 9, 12, 0, tzinfo=timezone.utc)
        result = coll.run(until=until)

        assert result.total_events == 2
        assert len(service.list_calls) == 2
        assert service.list_calls[1]["pageToken"] == "TOK1"
        wm = coll.watermarks.get("gws", "acme.com", "admin")
        assert wm.last_event_time == datetime(2026, 5, 9, 11, 0, tzinfo=timezone.utc)


class TestBoundaryFiltering:
    def test_excludes_event_at_since_boundary(self, tmp_path):
        # Watermark already at 11:00. Reports API returns events including
        # the one at exactly 11:00 because startTime is inclusive. We must
        # not re-emit that event.
        wm = LocalFileWatermarkStore(tmp_path / "state")
        wm.put("gws", "acme.com", "login",
               Watermark(last_event_time=datetime(2026, 5, 9, 11, 0, tzinfo=timezone.utc),
                         last_event_id="prior"))
        events = [
            _activity("2026-05-09T11:00:00Z", "boundary", "login"),  # must skip
            _activity("2026-05-09T11:30:00Z", "after", "login"),
        ]
        service = _FakeReportsService({"login": [{"items": events}]})
        coll = GoogleWorkspaceCollector(
            tenant_id="acme.com",
            watermark_store=wm,
            secret_store=LocalFileSecretStore(tmp_path / "s.json"),
            lake_writer=LocalFileRawLakeWriter(tmp_path / "lake"),
            retry_policy=RetryPolicy(max_attempts=2, base_delay_seconds=0.0, jitter=0.0),
            feeds=("login",),
            service_factory=lambda *_a, **_k: service,
        )
        until = datetime(2026, 5, 9, 12, 0, tzinfo=timezone.utc)
        result = coll.run(until=until)
        assert result.total_events == 1

    def test_excludes_event_at_until_boundary(self, tmp_path):
        events = [_activity("2026-05-09T12:00:00Z", "edge", "login")]
        service = _FakeReportsService({"login": [{"items": events}]})
        coll = _make_collector(tmp_path, service, feeds=("login",))
        until = datetime(2026, 5, 9, 12, 0, tzinfo=timezone.utc)
        result = coll.run(until=until)
        assert result.total_events == 0

    def test_drops_event_with_missing_time(self, tmp_path):
        bad = {"id": {"uniqueQualifier": "x", "applicationName": "login"},
               "actor": {"email": "u@a.com"}, "events": []}
        good = _activity("2026-05-09T11:00:00Z", "ok", "login")
        service = _FakeReportsService({"login": [{"items": [bad, good]}]})
        coll = _make_collector(tmp_path, service, feeds=("login",))
        until = datetime(2026, 5, 9, 12, 0, tzinfo=timezone.utc)
        result = coll.run(until=until)
        assert result.total_events == 1


class TestTransientRetry:
    def _http_error(self, status: int, retry_after: Optional[str] = None) -> Exception:
        class _Headers(dict):
            pass

        class _Resp:
            def __init__(self, s, h):
                self.status = s
                self._headers = h

        class _HttpErr(Exception):
            def __init__(self, status, headers):
                super().__init__(f"http {status}")
                self.resp = _Resp(status, headers)

        h = _Headers()
        if retry_after is not None:
            h["Retry-After"] = retry_after
        return _HttpErr(status, h)

    def test_429_retried(self, tmp_path):
        good = [_activity("2026-05-09T11:00:00Z", "q1", "login")]
        # Use a mutable response list that returns the 429 then the success
        responses = [self._http_error(429, retry_after="0"), {"items": good}]

        service = _FakeReportsService({"login": []})
        # Override list to consume the responses queue
        original_list = service.activities

        def fake_activities():
            class A:
                def list(self_inner, **kwargs):
                    service.list_calls.append(kwargs)
                    if not responses:
                        return _FakeRequest({"items": []})
                    nxt = responses.pop(0)
                    return _FakeRequest(nxt)
            return A()
        service.activities = fake_activities  # type: ignore[assignment]

        coll = _make_collector(tmp_path, service, feeds=("login",))
        until = datetime(2026, 5, 9, 12, 0, tzinfo=timezone.utc)
        result = coll.run(until=until)
        assert result.total_events == 1
        assert len(service.list_calls) == 2  # 429, then success

    def test_404_not_retried(self, tmp_path):
        responses = [self._http_error(404)]
        service = _FakeReportsService({"login": []})

        def fake_activities():
            class A:
                def list(self_inner, **kwargs):
                    service.list_calls.append(kwargs)
                    return _FakeRequest(responses[0])
            return A()
        service.activities = fake_activities  # type: ignore[assignment]

        coll = _make_collector(tmp_path, service, feeds=("login",),
                               retry_policy=RetryPolicy(max_attempts=4, base_delay_seconds=0.0, jitter=0.0))
        until = datetime(2026, 5, 9, 12, 0, tzinfo=timezone.utc)
        result = coll.run(until=until)
        # 404 is not transient -> single attempt, surfaces as feed-level error
        feed = next(f for f in result.feeds if f.feed == "login")
        assert feed.error is not None and "404" in feed.error
        assert len(service.list_calls) == 1


class TestMultiFeed:
    def test_each_feed_gets_independent_watermark(self, tmp_path):
        service = _FakeReportsService({
            "login": [{"items": [_activity("2026-05-09T11:00:00Z", "L", "login")]}],
            "admin": [{"items": [_activity("2026-05-09T11:30:00Z", "A", "admin")]}],
            "drive": [{"items": [_activity("2026-05-09T11:45:00Z", "D", "drive")]}],
            "token": [{"items": [_activity("2026-05-09T11:55:00Z", "T", "token")]}],
        })
        coll = _make_collector(tmp_path, service)
        until = datetime(2026, 5, 9, 12, 0, tzinfo=timezone.utc)
        result = coll.run(until=until)
        assert result.total_events == 4
        for feed in ("login", "admin", "drive", "token"):
            wm = coll.watermarks.get("gws", "acme.com", feed)
            assert wm is not None, f"missing watermark for {feed}"
        # Each feed got exactly one list call (no pagination)
        per_app = {}
        for c in service.list_calls:
            per_app[c["applicationName"]] = per_app.get(c["applicationName"], 0) + 1
        assert per_app == {"login": 1, "admin": 1, "drive": 1, "token": 1}


class TestEventEnrichment:
    def test_event_time_and_id_injected(self, tmp_path):
        events = [_activity("2026-05-09T11:00:00Z", "Q", "login")]
        service = _FakeReportsService({"login": [{"items": events}]})
        coll = _make_collector(tmp_path, service, feeds=("login",))
        until = datetime(2026, 5, 9, 12, 0, tzinfo=timezone.utc)
        coll.run(until=until)

        # Read the lake file back and confirm injection happened
        import gzip, json
        files = list((tmp_path / "lake").rglob("*.jsonl.gz"))
        assert len(files) == 1
        with gzip.open(files[0], "rb") as f:
            line = f.read().splitlines()[0]
        record = json.loads(line)
        assert record["event_time"] == "2026-05-09T11:00:00Z"
        assert record["event_id"].startswith("2026-05-09T11:00:00Z:Q:")
        # Original Google fields preserved
        assert record["id"]["uniqueQualifier"] == "Q"
        assert record["actor"]["email"] == "u@a.com"


class TestPR3Feeds:
    """End-to-end fan-out check: an operator opting into ALL_FEEDS gets one
    independent watermark, one lake partition, and one API call per feed."""

    def test_all_feeds_run_independently(self, tmp_path):
        from shared.collectors.google_workspace_collector import GoogleWorkspaceCollector
        feeds = GoogleWorkspaceCollector.ALL_FEEDS
        # One event per feed, one second apart, all inside the run window.
        responses = {}
        for i, feed in enumerate(feeds):
            t = f"2026-05-09T11:00:{i:02d}Z"
            responses[feed] = [{"items": [_activity(t, f"q-{feed}", feed)]}]
        service = _FakeReportsService(responses)
        coll = _make_collector(tmp_path, service, feeds=feeds)
        until = datetime(2026, 5, 9, 12, 0, tzinfo=timezone.utc)

        result = coll.run(until=until)

        assert result.total_events == len(feeds)
        # One list call per feed.
        per_app = {}
        for c in service.list_calls:
            per_app[c["applicationName"]] = per_app.get(c["applicationName"], 0) + 1
        assert per_app == {f: 1 for f in feeds}
        # One watermark per feed.
        for feed in feeds:
            wm = coll.watermarks.get("gws", "acme.com", feed)
            assert wm is not None, f"missing watermark for {feed}"
        # One lake partition per feed.
        files = list((tmp_path / "lake").rglob("*.jsonl.gz"))
        partitions = {p.parent.name for p in files}  # e.g. "feed=calendar"
        assert partitions == {f"feed={f}" for f in feeds}

    @pytest.mark.parametrize("feed", [
        "calendar", "groups", "groups_enterprise", "gmail", "mobile",
        "chrome", "meet", "chat", "user_accounts", "access_transparency",
        "saml", "context_aware_access", "data_studio", "gcp",
        "keep", "jamboard", "rules",
    ])
    def test_each_pr3_feed_passes_correct_application_name(self, tmp_path, feed):
        service = _FakeReportsService({feed: [{"items": []}]})
        coll = _make_collector(tmp_path, service, feeds=(feed,))
        until = datetime(2026, 5, 9, 12, 0, tzinfo=timezone.utc)
        coll.run(until=until)
        # The API call carried the exact applicationName we expect.
        assert service.list_calls[0]["applicationName"] == FEED_TO_APPLICATION_NAME[feed]


class TestServiceConstructionFromSecrets:
    def test_uses_factory_when_provided(self, tmp_path):
        # Already proven indirectly. This documents the explicit path.
        service = _FakeReportsService({"login": [{"items": []}]})
        coll = _make_collector(tmp_path, service, feeds=("login",))
        coll.run(until=datetime(2026, 5, 9, 12, 0, tzinfo=timezone.utc))
        assert coll._service is service

    def test_missing_secrets_when_no_factory(self, tmp_path):
        # No service_factory and no secrets seeded -> require() raises KeyError
        coll = GoogleWorkspaceCollector(
            tenant_id="acme.com",
            watermark_store=LocalFileWatermarkStore(tmp_path / "state"),
            secret_store=LocalFileSecretStore(tmp_path / "secrets.json"),
            lake_writer=LocalFileRawLakeWriter(tmp_path / "lake"),
            retry_policy=RetryPolicy(max_attempts=1, base_delay_seconds=0.0, jitter=0.0),
            feeds=("login",),
        )
        result = coll.run(until=datetime(2026, 5, 9, 12, 0, tzinfo=timezone.utc))
        feed = next(f for f in result.feeds if f.feed == "login")
        assert feed.error is not None and "secret" in feed.error.lower()
