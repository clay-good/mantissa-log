"""
Unit tests for OktaCollector and OktaSystemLogClient
(PR 10 of SAAS_IDENTITY_SPEC, §10 follow-on pack).

Strategy mirrors PRs 2, 4, 5, 9. The collector takes an injectable
client; tests pass a fake. The production HTTP client takes an
injectable transport; tests pass a fake. A short integration test
wires both together.
"""

from __future__ import annotations

import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

import pytest

ROOT = Path(__file__).resolve().parents[2]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from shared.collectors.okta_collector import (  # noqa: E402
    OktaCollector,
    OktaHTTPError,
    _format_okta_iso,
    _parse_iso,
)
from shared.collectors.okta_http_client import (  # noqa: E402
    OktaSystemLogClient,
    _extract_next_url,
    _parse_retry_after,
)
from shared.collectors.saas_lake import LocalFileRawLakeWriter  # noqa: E402
from shared.collectors.saas_retry import RetryPolicy  # noqa: E402
from shared.collectors.saas_secrets import LocalFileSecretStore  # noqa: E402
from shared.collectors.saas_state import LocalFileWatermarkStore, Watermark  # noqa: E402


# ============================================================ helpers


class _FakeOktaClient:
    """In-memory fake of the Okta System Log client.

    ``pages`` is a list of page dicts the collector will walk in order
    of ``list_logs`` then ``list_next``. The fake threads pages by
    looking at ``next_url`` and returning the matching follow-up.
    """

    def __init__(self, pages: Optional[list[dict]] = None, raises: Optional[Exception] = None,
                 raises_on: str = "list_logs"):
        self.pages = list(pages or [])
        self.raises = raises
        self.raises_on = raises_on
        self.list_logs_calls: list[dict] = []
        self.list_next_calls: list[str] = []

    def list_logs(self, since: str, until: str, limit: int) -> dict:
        self.list_logs_calls.append({"since": since, "until": until, "limit": limit})
        if self.raises is not None and self.raises_on == "list_logs":
            exc = self.raises
            self.raises = None
            raise exc
        return self.pages.pop(0) if self.pages else {"items": [], "next_url": None}

    def list_next(self, url: str) -> dict:
        self.list_next_calls.append(url)
        if self.raises is not None and self.raises_on == "list_next":
            exc = self.raises
            self.raises = None
            raise exc
        return self.pages.pop(0) if self.pages else {"items": [], "next_url": None}


def _event(uuid: str, when: str, event_type: str = "user.session.start",
           actor: str = "alice@acme.com") -> dict:
    return {
        "uuid": uuid,
        "published": when,
        "eventType": event_type,
        "actor": {"alternateId": actor, "type": "User"},
        "client": {"ipAddress": "1.2.3.4"},
        "outcome": {"result": "SUCCESS"},
    }


def _make(tmp_path, client, feeds=("system",), retry_policy=None, secrets_seed=None):
    secrets = LocalFileSecretStore(tmp_path / "secrets.json")
    if secrets_seed:
        for k, v in secrets_seed.items():
            secrets.put(k, v)
    return OktaCollector(
        tenant_id="acme.okta.com",
        watermark_store=LocalFileWatermarkStore(tmp_path / "state"),
        secret_store=secrets,
        lake_writer=LocalFileRawLakeWriter(tmp_path / "lake"),
        retry_policy=retry_policy or RetryPolicy(max_attempts=3, base_delay_seconds=0.0, jitter=0.0),
        feeds=feeds,
        client_factory=lambda _t: client,
    )


# ============================================================ helpers


class TestHelpers:
    def test_iso_round_trip(self):
        d = _parse_iso("2026-05-09T14:23:11Z")
        assert _format_okta_iso(d) == "2026-05-09T14:23:11.000Z"

    def test_default_feed_set(self):
        assert OktaCollector.DEFAULT_FEEDS == ("system",)
        assert OktaCollector.ALL_FEEDS == ("system",)


class TestFeedSelection:
    def test_default(self, tmp_path):
        coll = _make(tmp_path, _FakeOktaClient())
        assert coll.list_feeds() == ["system"]

    def test_unknown_rejected(self, tmp_path):
        with pytest.raises(ValueError):
            _make(tmp_path, _FakeOktaClient(), feeds=("system", "bogus"))


# ============================================================ happy path


class TestSinglePage:
    def test_happy(self, tmp_path):
        client = _FakeOktaClient([{
            "items": [_event("u1", "2026-05-09T11:00:00.000Z"),
                      _event("u2", "2026-05-09T11:30:00.000Z")],
            "next_url": None,
        }])
        coll = _make(tmp_path, client)
        until = datetime(2026, 5, 9, 12, 0, tzinfo=timezone.utc)
        result = coll.run(until=until)
        assert result.total_events == 2
        wm = coll.watermarks.get("okta", "acme.okta.com", "system")
        assert wm.last_event_time == datetime(2026, 5, 9, 11, 30, tzinfo=timezone.utc)
        assert wm.last_event_id == "u2"

    def test_first_call_carries_since_until_limit(self, tmp_path):
        client = _FakeOktaClient([{"items": [], "next_url": None}])
        coll = _make(tmp_path, client)
        until = datetime(2026, 5, 9, 12, 0, tzinfo=timezone.utc)
        coll.run(until=until)
        call = client.list_logs_calls[0]
        # Default 7-day backfill
        assert call["since"] == "2026-05-02T12:00:00.000Z"
        assert call["until"] == "2026-05-09T12:00:00.000Z"
        assert call["limit"] == 1000


class TestPagination:
    def test_two_pages_via_next_url(self, tmp_path):
        client = _FakeOktaClient([
            {"items": [_event("u1", "2026-05-09T11:00:00.000Z")],
             "next_url": "https://acme.okta.com/api/v1/logs?after=ABC"},
            {"items": [_event("u2", "2026-05-09T11:30:00.000Z")],
             "next_url": None},
        ])
        coll = _make(tmp_path, client)
        until = datetime(2026, 5, 9, 12, 0, tzinfo=timezone.utc)
        result = coll.run(until=until)
        assert result.total_events == 2
        # list_logs once, list_next once
        assert len(client.list_logs_calls) == 1
        assert client.list_next_calls == ["https://acme.okta.com/api/v1/logs?after=ABC"]


class TestBoundaryFiltering:
    def test_event_at_since_boundary_excluded(self, tmp_path):
        wm = LocalFileWatermarkStore(tmp_path / "state")
        wm.put("okta", "acme.okta.com", "system",
               Watermark(last_event_time=datetime(2026, 5, 9, 11, 0, tzinfo=timezone.utc)))
        client = _FakeOktaClient([{
            "items": [_event("boundary", "2026-05-09T11:00:00.000Z"),
                      _event("after", "2026-05-09T11:30:00.000Z")],
            "next_url": None,
        }])
        coll = OktaCollector(
            tenant_id="acme.okta.com",
            watermark_store=wm,
            secret_store=LocalFileSecretStore(tmp_path / "s.json"),
            lake_writer=LocalFileRawLakeWriter(tmp_path / "lake"),
            retry_policy=RetryPolicy(max_attempts=2, base_delay_seconds=0.0, jitter=0.0),
            client_factory=lambda _t: client,
        )
        until = datetime(2026, 5, 9, 12, 0, tzinfo=timezone.utc)
        result = coll.run(until=until)
        assert result.total_events == 1

    def test_event_at_until_boundary_excluded(self, tmp_path):
        client = _FakeOktaClient([{
            "items": [_event("end", "2026-05-09T12:00:00.000Z")],
            "next_url": None,
        }])
        coll = _make(tmp_path, client)
        until = datetime(2026, 5, 9, 12, 0, tzinfo=timezone.utc)
        result = coll.run(until=until)
        assert result.total_events == 0

    def test_event_missing_published_dropped(self, tmp_path):
        bad = {"uuid": "bad", "eventType": "x", "actor": {"alternateId": "a@b.com"}}
        client = _FakeOktaClient([{
            "items": [bad, _event("ok", "2026-05-09T11:00:00.000Z")],
            "next_url": None,
        }])
        coll = _make(tmp_path, client)
        until = datetime(2026, 5, 9, 12, 0, tzinfo=timezone.utc)
        result = coll.run(until=until)
        assert result.total_events == 1


class TestEventEnrichment:
    def test_event_time_and_id_injected(self, tmp_path):
        client = _FakeOktaClient([{
            "items": [_event("uuid-1", "2026-05-09T11:00:00.000Z")],
            "next_url": None,
        }])
        coll = _make(tmp_path, client)
        until = datetime(2026, 5, 9, 12, 0, tzinfo=timezone.utc)
        coll.run(until=until)
        import gzip, json
        files = list((tmp_path / "lake").rglob("*.jsonl.gz"))
        with gzip.open(files[0], "rb") as f:
            record = json.loads(f.read().splitlines()[0])
        assert record["event_time"] == "2026-05-09T11:00:00.000Z"
        assert record["event_id"] == "uuid-1"
        # Original Okta fields preserved
        assert record["eventType"] == "user.session.start"
        assert record["actor"]["alternateId"] == "alice@acme.com"


class TestTransientRetry:
    def test_429_retried(self, tmp_path):
        client = _FakeOktaClient(
            pages=[{"items": [_event("u1", "2026-05-09T11:00:00.000Z")], "next_url": None}],
            raises=OktaHTTPError("rate limited", status_code=429, retry_after=0.0),
        )
        coll = _make(tmp_path, client)
        until = datetime(2026, 5, 9, 12, 0, tzinfo=timezone.utc)
        result = coll.run(until=until)
        assert result.total_events == 1
        # First call raised, second succeeded
        assert len(client.list_logs_calls) == 2

    def test_403_not_retried(self, tmp_path):
        # 403 typically means the API token is missing System Log scope.
        # Should surface immediately so operator fixes the permission grant.
        client = _FakeOktaClient(
            raises=OktaHTTPError("forbidden", status_code=403),
        )
        coll = _make(tmp_path, client,
                     retry_policy=RetryPolicy(max_attempts=4, base_delay_seconds=0.0, jitter=0.0))
        until = datetime(2026, 5, 9, 12, 0, tzinfo=timezone.utc)
        result = coll.run(until=until)
        feed = next(f for f in result.feeds if f.feed == "system")
        assert feed.error is not None and "403" in feed.error
        assert len(client.list_logs_calls) == 1

    def test_streaming_page_error_surfaces_as_feed_error(self, tmp_path):
        client = _FakeOktaClient(
            pages=[
                {"items": [_event("u1", "2026-05-09T11:00:00.000Z")],
                 "next_url": "https://acme.okta.com/api/v1/logs?after=ABC"},
            ],
            raises=OktaHTTPError("page gone", status_code=410),
            raises_on="list_next",
        )
        coll = _make(tmp_path, client)
        until = datetime(2026, 5, 9, 12, 0, tzinfo=timezone.utc)
        result = coll.run(until=until)
        feed = next(f for f in result.feeds if f.feed == "system")
        assert feed.error is not None and "410" in feed.error


class TestSecretsPath:
    def test_missing_secrets_when_no_factory(self, tmp_path):
        coll = OktaCollector(
            tenant_id="acme.okta.com",
            watermark_store=LocalFileWatermarkStore(tmp_path / "state"),
            secret_store=LocalFileSecretStore(tmp_path / "secrets.json"),
            lake_writer=LocalFileRawLakeWriter(tmp_path / "lake"),
            retry_policy=RetryPolicy(max_attempts=1, base_delay_seconds=0.0, jitter=0.0),
        )
        result = coll.run(until=datetime(2026, 5, 9, 12, 0, tzinfo=timezone.utc))
        feed = next(f for f in result.feeds if f.feed == "system")
        assert feed.error is not None and "secret" in feed.error.lower()


# =================================================== HTTP client tests


@dataclass
class _Resp:
    status_code: int = 200
    body_json: Any = None
    body_text: str = ""
    headers: dict = field(default_factory=dict)

    def json(self):
        return self.body_json

    @property
    def text(self):
        return self.body_text


@dataclass
class _Call:
    method: str
    url: str
    params: Optional[dict]
    headers: Optional[dict]


class _FakeTransport:
    def __init__(self, responses: list):
        self.responses = list(responses)
        self.calls: list[_Call] = []

    def get(self, url, params=None, headers=None, timeout=None):
        self.calls.append(_Call("GET", url, params, headers))
        return self.responses.pop(0) if self.responses else _Resp()


class TestExtractNextUrl:
    def test_present(self):
        link = ('<https://acme.okta.com/api/v1/logs?after=ABC>; rel="next", '
                '<https://acme.okta.com/api/v1/logs>; rel="self"')
        assert _extract_next_url(link) == "https://acme.okta.com/api/v1/logs?after=ABC"

    def test_only_self(self):
        link = '<https://acme.okta.com/api/v1/logs>; rel="self"'
        assert _extract_next_url(link) is None

    def test_blank(self):
        assert _extract_next_url(None) is None
        assert _extract_next_url("") is None


class TestParseRetryAfter:
    def test_seconds(self):
        assert _parse_retry_after("60") == 60.0

    def test_invalid(self):
        assert _parse_retry_after("nope") is None
        assert _parse_retry_after(None) is None


class TestOktaHTTPClient:
    def test_list_logs_bearer_and_params(self):
        transport = _FakeTransport([
            _Resp(status_code=200, body_json=[{"uuid": "u1", "published": "2026-05-09T11:00:00.000Z"}]),
        ])
        client = OktaSystemLogClient("acme.okta.com", api_token="t0k", transport=transport)
        page = client.list_logs(since="2026-05-09T00:00:00.000Z",
                                 until="2026-05-09T12:00:00.000Z",
                                 limit=500)
        assert page["items"][0]["uuid"] == "u1"
        assert page["next_url"] is None
        call = transport.calls[0]
        assert call.method == "GET"
        assert call.url == "https://acme.okta.com/api/v1/logs"
        assert call.headers["Authorization"] == "SSWS t0k"
        assert call.headers["Accept"] == "application/json"
        assert call.params["since"] == "2026-05-09T00:00:00.000Z"
        assert call.params["limit"] == 500

    def test_list_logs_extracts_next_url_from_link(self):
        next_url = "https://acme.okta.com/api/v1/logs?after=ABC"
        link_value = f'<{next_url}>; rel="next", <https://acme.okta.com/api/v1/logs>; rel="self"'
        transport = _FakeTransport([
            _Resp(status_code=200, body_json=[], headers={"Link": link_value}),
        ])
        client = OktaSystemLogClient("acme.okta.com", api_token="t0k", transport=transport)
        page = client.list_logs(since="s", until="u", limit=10)
        assert page["next_url"] == next_url

    def test_list_next_carries_no_extra_params(self):
        transport = _FakeTransport([
            _Resp(status_code=200, body_json=[{"uuid": "u2", "published": "2026-05-09T11:30:00.000Z"}]),
        ])
        client = OktaSystemLogClient("acme.okta.com", api_token="t0k", transport=transport)
        client.list_next("https://acme.okta.com/api/v1/logs?after=ABC")
        assert transport.calls[0].params is None

    def test_429_wrapped_with_retry_after(self):
        transport = _FakeTransport([
            _Resp(status_code=429, headers={"Retry-After": "12"}, body_text="rate limited"),
        ])
        client = OktaSystemLogClient("acme.okta.com", api_token="t0k", transport=transport)
        with pytest.raises(OktaHTTPError) as exc:
            client.list_logs(since="s", until="u", limit=10)
        assert exc.value.status_code == 429
        assert exc.value.retry_after == 12.0

    def test_403_wrapped(self):
        transport = _FakeTransport([
            _Resp(status_code=403, body_text="forbidden"),
        ])
        client = OktaSystemLogClient("acme.okta.com", api_token="t0k", transport=transport)
        with pytest.raises(OktaHTTPError) as exc:
            client.list_logs(since="s", until="u", limit=10)
        assert exc.value.status_code == 403

    def test_accepts_already_qualified_url(self):
        transport = _FakeTransport([_Resp(status_code=200, body_json=[])])
        # When operators pass a full URL (preview tenants, custom domains)
        # the client must not double-prefix https://.
        client = OktaSystemLogClient("https://acme.oktapreview.com",
                                     api_token="t0k", transport=transport)
        client.list_logs(since="s", until="u", limit=10)
        assert transport.calls[0].url == "https://acme.oktapreview.com/api/v1/logs"

    def test_non_list_body_becomes_empty_items(self):
        transport = _FakeTransport([_Resp(status_code=200, body_json={"oops": "wrong shape"})])
        client = OktaSystemLogClient("acme.okta.com", api_token="t0k", transport=transport)
        page = client.list_logs(since="s", until="u", limit=10)
        assert page["items"] == []
