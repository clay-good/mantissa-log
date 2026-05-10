"""
Unit tests for SlackAuditCollector and SlackAuditClient
(PR 12 of SAAS_IDENTITY_SPEC, §10 follow-on pack continued).
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

from shared.collectors.slack_collector import (  # noqa: E402
    SlackAuditCollector,
    SlackHTTPError,
    _from_epoch_seconds,
    _to_epoch_seconds,
)
from shared.collectors.slack_http_client import (  # noqa: E402
    AUDIT_LOGS_ENDPOINT,
    SlackAuditClient,
    _parse_retry_after,
)
from shared.collectors.saas_lake import LocalFileRawLakeWriter  # noqa: E402
from shared.collectors.saas_retry import RetryPolicy  # noqa: E402
from shared.collectors.saas_secrets import LocalFileSecretStore  # noqa: E402
from shared.collectors.saas_state import LocalFileWatermarkStore, Watermark  # noqa: E402


# ============================================================ helpers


def _ts(year=2026, month=5, day=9, hour=11, minute=0, second=0) -> int:
    return int(datetime(year, month, day, hour, minute, second, tzinfo=timezone.utc).timestamp())


def _event(id_: str, when_sec: int, action: str = "user_login",
           actor: str = "alice@acme.com") -> dict:
    return {
        "id": id_,
        "date_create": when_sec,
        "action": action,
        "actor": {"type": "user", "user": {"email": actor}},
        "entity": {"type": "user", "user": {"email": actor}},
    }


class _FakeSlackClient:
    def __init__(self, pages: Optional[list[dict]] = None,
                 raises: Optional[Exception] = None,
                 raises_on: str = "list_logs"):
        self.pages = list(pages or [])
        self.raises = raises
        self.raises_on = raises_on
        self.list_logs_calls: list[dict] = []
        self.list_next_calls: list[str] = []

    def list_logs(self, oldest, latest, limit):
        self.list_logs_calls.append({"oldest": oldest, "latest": latest, "limit": limit})
        if self.raises is not None and self.raises_on == "list_logs":
            exc = self.raises
            self.raises = None
            raise exc
        return self.pages.pop(0) if self.pages else {"items": [], "next_cursor": None}

    def list_next(self, cursor):
        self.list_next_calls.append(cursor)
        if self.raises is not None and self.raises_on == "list_next":
            exc = self.raises
            self.raises = None
            raise exc
        return self.pages.pop(0) if self.pages else {"items": [], "next_cursor": None}


def _make(tmp_path, client, retry_policy=None):
    return SlackAuditCollector(
        tenant_id="acme",
        watermark_store=LocalFileWatermarkStore(tmp_path / "state"),
        secret_store=LocalFileSecretStore(tmp_path / "secrets.json"),
        lake_writer=LocalFileRawLakeWriter(tmp_path / "lake"),
        retry_policy=retry_policy or RetryPolicy(max_attempts=3, base_delay_seconds=0.0, jitter=0.0),
        feeds=("audit",),
        client_factory=lambda _t: client,
    )


# ============================================================ helpers


class TestHelpers:
    def test_to_epoch_round_trip(self):
        d = datetime(2026, 5, 9, 11, 0, tzinfo=timezone.utc)
        secs = _to_epoch_seconds(d)
        assert _from_epoch_seconds(secs) == d

    def test_from_epoch_handles_none_and_garbage(self):
        assert _from_epoch_seconds(None) is None
        assert _from_epoch_seconds("not-a-number") is None

    def test_default_feeds(self):
        assert SlackAuditCollector.DEFAULT_FEEDS == ("audit",)
        assert SlackAuditCollector.ALL_FEEDS == ("audit",)


class TestFeedSelection:
    def test_default(self, tmp_path):
        coll = _make(tmp_path, _FakeSlackClient())
        assert coll.list_feeds() == ["audit"]

    def test_unknown_rejected(self, tmp_path):
        with pytest.raises(ValueError):
            SlackAuditCollector(
                tenant_id="acme",
                watermark_store=LocalFileWatermarkStore(tmp_path / "state"),
                secret_store=LocalFileSecretStore(tmp_path / "s.json"),
                lake_writer=LocalFileRawLakeWriter(tmp_path / "lake"),
                feeds=("audit", "bogus"),
                client_factory=lambda _t: _FakeSlackClient(),
            )


# ============================================================ happy path


class TestSinglePage:
    def test_writes_and_advances_watermark(self, tmp_path):
        client = _FakeSlackClient([{
            "items": [
                _event("e1", _ts(2026, 5, 9, 11, 0)),
                _event("e2", _ts(2026, 5, 9, 11, 30)),
            ],
            "next_cursor": None,
        }])
        coll = _make(tmp_path, client)
        until = datetime(2026, 5, 9, 12, 0, tzinfo=timezone.utc)
        result = coll.run(until=until)
        assert result.total_events == 2
        wm = coll.watermarks.get("slack", "acme", "audit")
        assert wm.last_event_time == datetime(2026, 5, 9, 11, 30, tzinfo=timezone.utc)
        assert wm.last_event_id == "e2"

    def test_oldest_latest_carry_correct_epoch_seconds(self, tmp_path):
        client = _FakeSlackClient([{"items": [], "next_cursor": None}])
        coll = _make(tmp_path, client)
        until = datetime(2026, 5, 9, 12, 0, tzinfo=timezone.utc)
        coll.run(until=until)
        call = client.list_logs_calls[0]
        # Default 7-day backfill
        assert call["oldest"] == _ts(2026, 5, 2, 12, 0)
        assert call["latest"] == _ts(2026, 5, 9, 12, 0)
        assert call["limit"] == 1000


class TestPagination:
    def test_two_pages_via_cursor(self, tmp_path):
        client = _FakeSlackClient([
            {"items": [_event("e1", _ts(2026, 5, 9, 11, 0))],
             "next_cursor": "cursor-ABC"},
            {"items": [_event("e2", _ts(2026, 5, 9, 11, 30))],
             "next_cursor": None},
        ])
        coll = _make(tmp_path, client)
        until = datetime(2026, 5, 9, 12, 0, tzinfo=timezone.utc)
        result = coll.run(until=until)
        assert result.total_events == 2
        assert client.list_next_calls == ["cursor-ABC"]


class TestBoundary:
    def test_event_at_since_excluded(self, tmp_path):
        wm = LocalFileWatermarkStore(tmp_path / "state")
        wm.put("slack", "acme", "audit",
               Watermark(last_event_time=datetime(2026, 5, 9, 11, 0, tzinfo=timezone.utc)))
        client = _FakeSlackClient([{
            "items": [
                _event("boundary", _ts(2026, 5, 9, 11, 0)),
                _event("after", _ts(2026, 5, 9, 11, 30)),
            ],
            "next_cursor": None,
        }])
        coll = SlackAuditCollector(
            tenant_id="acme",
            watermark_store=wm,
            secret_store=LocalFileSecretStore(tmp_path / "s.json"),
            lake_writer=LocalFileRawLakeWriter(tmp_path / "lake"),
            retry_policy=RetryPolicy(max_attempts=2, base_delay_seconds=0.0, jitter=0.0),
            client_factory=lambda _t: client,
        )
        until = datetime(2026, 5, 9, 12, 0, tzinfo=timezone.utc)
        result = coll.run(until=until)
        assert result.total_events == 1

    def test_event_at_until_excluded(self, tmp_path):
        client = _FakeSlackClient([{
            "items": [_event("end", _ts(2026, 5, 9, 12, 0))],
            "next_cursor": None,
        }])
        coll = _make(tmp_path, client)
        until = datetime(2026, 5, 9, 12, 0, tzinfo=timezone.utc)
        assert coll.run(until=until).total_events == 0

    def test_missing_date_create_dropped(self, tmp_path):
        bad = {"id": "bad", "action": "x"}
        client = _FakeSlackClient([{
            "items": [bad, _event("good", _ts(2026, 5, 9, 11, 0))],
            "next_cursor": None,
        }])
        coll = _make(tmp_path, client)
        until = datetime(2026, 5, 9, 12, 0, tzinfo=timezone.utc)
        assert coll.run(until=until).total_events == 1


class TestEnrichment:
    def test_event_time_and_id_injected(self, tmp_path):
        client = _FakeSlackClient([{
            "items": [_event("slack-id-1", _ts(2026, 5, 9, 11, 0))],
            "next_cursor": None,
        }])
        coll = _make(tmp_path, client)
        until = datetime(2026, 5, 9, 12, 0, tzinfo=timezone.utc)
        coll.run(until=until)
        import gzip, json
        files = list((tmp_path / "lake").rglob("*.jsonl.gz"))
        with gzip.open(files[0], "rb") as f:
            rec = json.loads(f.read().splitlines()[0])
        assert rec["event_time"] == "2026-05-09T11:00:00Z"
        assert rec["event_id"] == "slack-id-1"
        # Original fields preserved
        assert rec["action"] == "user_login"
        assert rec["date_create"] == _ts(2026, 5, 9, 11, 0)


class TestRetry:
    def test_429_retried(self, tmp_path):
        client = _FakeSlackClient(
            pages=[{"items": [_event("e1", _ts(2026, 5, 9, 11, 0))], "next_cursor": None}],
            raises=SlackHTTPError("rate", status_code=429, retry_after=0.0),
        )
        coll = _make(tmp_path, client)
        result = coll.run(until=datetime(2026, 5, 9, 12, 0, tzinfo=timezone.utc))
        assert result.total_events == 1
        assert len(client.list_logs_calls) == 2

    def test_403_not_retried(self, tmp_path):
        # 403 commonly means the token lacks ``auditlogs:read``.
        client = _FakeSlackClient(raises=SlackHTTPError("forbidden", status_code=403))
        coll = _make(tmp_path, client,
                     retry_policy=RetryPolicy(max_attempts=4, base_delay_seconds=0.0, jitter=0.0))
        result = coll.run(until=datetime(2026, 5, 9, 12, 0, tzinfo=timezone.utc))
        feed = next(f for f in result.feeds if f.feed == "audit")
        assert feed.error is not None and "403" in feed.error
        assert len(client.list_logs_calls) == 1

    def test_streaming_cursor_error_surfaces(self, tmp_path):
        client = _FakeSlackClient(
            pages=[{"items": [_event("e1", _ts(2026, 5, 9, 11, 0))],
                    "next_cursor": "cursor-ABC"}],
            raises=SlackHTTPError("server", status_code=502),
            raises_on="list_next",
        )
        coll = _make(tmp_path, client)
        result = coll.run(until=datetime(2026, 5, 9, 12, 0, tzinfo=timezone.utc))
        feed = next(f for f in result.feeds if f.feed == "audit")
        assert feed.error is not None and "502" in feed.error


class TestSecretsPath:
    def test_missing_secrets_when_no_factory(self, tmp_path):
        coll = SlackAuditCollector(
            tenant_id="acme",
            watermark_store=LocalFileWatermarkStore(tmp_path / "state"),
            secret_store=LocalFileSecretStore(tmp_path / "s.json"),
            lake_writer=LocalFileRawLakeWriter(tmp_path / "lake"),
            retry_policy=RetryPolicy(max_attempts=1, base_delay_seconds=0.0, jitter=0.0),
        )
        result = coll.run(until=datetime(2026, 5, 9, 12, 0, tzinfo=timezone.utc))
        feed = next(f for f in result.feeds if f.feed == "audit")
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


class TestParseRetryAfter:
    def test_seconds(self):
        assert _parse_retry_after("45") == 45.0

    def test_blank(self):
        assert _parse_retry_after(None) is None
        assert _parse_retry_after("") is None


class TestSlackClientHTTP:
    def _ok_body(self, entries: list, next_cursor: Optional[str] = None) -> dict:
        meta = {"response_metadata": {"next_cursor": next_cursor or ""}}
        return {"ok": True, "entries": entries, **meta}

    def test_list_logs_carries_bearer_and_params(self):
        transport = _FakeTransport([
            _Resp(status_code=200, body_json=self._ok_body(entries=[])),
        ])
        client = SlackAuditClient(token="xoxs-secret", transport=transport)
        client.list_logs(oldest=1700000000, latest=1700003600, limit=500)
        call = transport.calls[0]
        assert call.url == AUDIT_LOGS_ENDPOINT
        assert call.headers["Authorization"] == "Bearer xoxs-secret"
        assert call.headers["Accept"] == "application/json"
        assert call.params == {"oldest": 1700000000, "latest": 1700003600, "limit": 500}

    def test_list_logs_extracts_entries_and_next_cursor(self):
        body = self._ok_body(
            entries=[{"id": "e1", "date_create": 1700000000, "action": "x"}],
            next_cursor="cursor-1",
        )
        transport = _FakeTransport([_Resp(status_code=200, body_json=body)])
        client = SlackAuditClient(token="t", transport=transport)
        page = client.list_logs(oldest=0, latest=1, limit=10)
        assert page["items"] == body["entries"]
        assert page["next_cursor"] == "cursor-1"

    def test_empty_next_cursor_becomes_none(self):
        body = self._ok_body(entries=[], next_cursor="")
        transport = _FakeTransport([_Resp(status_code=200, body_json=body)])
        client = SlackAuditClient(token="t", transport=transport)
        page = client.list_logs(oldest=0, latest=1, limit=10)
        assert page["next_cursor"] is None

    def test_list_next_carries_cursor_param(self):
        body = self._ok_body(entries=[])
        transport = _FakeTransport([_Resp(status_code=200, body_json=body)])
        client = SlackAuditClient(token="t", transport=transport)
        client.list_next("cursor-ABC")
        assert transport.calls[0].params == {"cursor": "cursor-ABC"}

    def test_429_with_retry_after_wrapped(self):
        transport = _FakeTransport([
            _Resp(status_code=429, headers={"Retry-After": "20"}, body_text="slow"),
        ])
        client = SlackAuditClient(token="t", transport=transport)
        with pytest.raises(SlackHTTPError) as exc:
            client.list_logs(oldest=0, latest=1, limit=10)
        assert exc.value.status_code == 429
        assert exc.value.retry_after == 20.0

    def test_403_wrapped(self):
        transport = _FakeTransport([_Resp(status_code=403, body_text="missing_scope")])
        client = SlackAuditClient(token="t", transport=transport)
        with pytest.raises(SlackHTTPError) as exc:
            client.list_logs(oldest=0, latest=1, limit=10)
        assert exc.value.status_code == 403

    def test_application_ok_false_synthesized_as_400(self):
        body = {"ok": False, "error": "invalid_auth"}
        transport = _FakeTransport([_Resp(status_code=200, body_json=body)])
        client = SlackAuditClient(token="t", transport=transport)
        with pytest.raises(SlackHTTPError) as exc:
            client.list_logs(oldest=0, latest=1, limit=10)
        assert exc.value.status_code == 400
        assert "invalid_auth" in str(exc.value)

    def test_application_ratelimited_synthesized_as_429(self):
        body = {"ok": False, "error": "ratelimited"}
        transport = _FakeTransport([
            _Resp(status_code=200, body_json=body, headers={"Retry-After": "30"}),
        ])
        client = SlackAuditClient(token="t", transport=transport)
        with pytest.raises(SlackHTTPError) as exc:
            client.list_logs(oldest=0, latest=1, limit=10)
        # The ``ratelimited`` app-error path is what makes Slack retries work
        # at all; default transport-level 200 would otherwise be terminal.
        assert exc.value.status_code == 429
        assert exc.value.retry_after == 30.0

    def test_non_dict_body_returns_empty_page(self):
        transport = _FakeTransport([_Resp(status_code=200, body_json=[1, 2, 3])])
        client = SlackAuditClient(token="t", transport=transport)
        page = client.list_logs(oldest=0, latest=1, limit=10)
        assert page == {"items": [], "next_cursor": None}

    def test_missing_entries_returns_empty(self):
        transport = _FakeTransport([
            _Resp(status_code=200, body_json={"ok": True}),
        ])
        client = SlackAuditClient(token="t", transport=transport)
        page = client.list_logs(oldest=0, latest=1, limit=10)
        assert page["items"] == []
