"""
Unit tests for SalesforceCollector and SalesforceEventClient
(PR 13 of SAAS_IDENTITY_SPEC, §10 follow-on pack — final entry).
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

from shared.collectors.salesforce_collector import (  # noqa: E402
    SalesforceCollector,
    SalesforceHTTPError,
    _event_id,
    _event_time,
    _format_soql_iso,
    _parse_sf_compact,
    _parse_sf_iso,
)
import shared.collectors.salesforce_http_client as sf_http  # noqa: E402
from shared.collectors.salesforce_http_client import (  # noqa: E402
    DEFAULT_API_VERSION,
    LOGIN_TOKEN_PATH,
    SalesforceEventClient,
    SalesforceTokenError,
    _parse_retry_after,
)
from shared.collectors.saas_lake import LocalFileRawLakeWriter  # noqa: E402
from shared.collectors.saas_retry import RetryPolicy  # noqa: E402
from shared.collectors.saas_secrets import LocalFileSecretStore  # noqa: E402
from shared.collectors.saas_state import LocalFileWatermarkStore, Watermark  # noqa: E402


# ============================================================ helpers


def _file_record(
    rec_id: str,
    event_type: str = "Login",
    log_date: str = "2026-05-09T10:00:00.000+0000",
    log_file: Optional[str] = None,
) -> dict:
    return {
        "Id": rec_id,
        "EventType": event_type,
        "LogDate": log_date,
        "LogFileLength": 1234,
        "LogFile": log_file or f"/services/data/v59.0/sobjects/EventLogFile/{rec_id}/LogFile",
    }


def _event(timestamp_iso: str, event_type: str = "Login",
           user_id: str = "005XX0000000abc",
           request_id: str = "REQ-1", uuid: Optional[str] = None) -> dict:
    evt = {
        "TIMESTAMP_DERIVED": timestamp_iso,
        "EVENT_TYPE": event_type,
        "USER_ID": user_id,
        "REQUEST_ID": request_id,
    }
    if uuid:
        evt["EVENT_UUID"] = uuid
    return evt


class _FakeSalesforceClient:
    def __init__(self, log_files: Optional[list[dict]] = None,
                 events_by_url: Optional[dict[str, list[dict]]] = None,
                 list_raises: Optional[Exception] = None,
                 fetch_raises: Optional[dict[str, Exception]] = None):
        self.log_files = list(log_files or [])
        self.events_by_url = events_by_url or {}
        self.list_raises = list_raises
        self.fetch_raises = fetch_raises or {}
        self.list_calls: list[dict] = []
        self.fetch_calls: list[str] = []

    def list_log_files(self, since: str, until: str) -> list[dict]:
        self.list_calls.append({"since": since, "until": until})
        if self.list_raises is not None:
            exc = self.list_raises
            self.list_raises = None
            raise exc
        return list(self.log_files)

    def fetch_log_file(self, url: str) -> list[dict]:
        self.fetch_calls.append(url)
        if url in self.fetch_raises:
            raise self.fetch_raises.pop(url)
        return list(self.events_by_url.get(url, []))


def _make(tmp_path, client, retry_policy=None):
    return SalesforceCollector(
        tenant_id="acme.my.salesforce.com",
        watermark_store=LocalFileWatermarkStore(tmp_path / "state"),
        secret_store=LocalFileSecretStore(tmp_path / "secrets.json"),
        lake_writer=LocalFileRawLakeWriter(tmp_path / "lake"),
        retry_policy=retry_policy or RetryPolicy(max_attempts=3, base_delay_seconds=0.0, jitter=0.0),
        feeds=("events",),
        client_factory=lambda _t: client,
    )


# ============================================================ helpers


class TestTimestampParsers:
    def test_iso_with_plus_zero_offset(self):
        assert _parse_sf_iso("2026-05-09T11:00:00.000+0000") == \
               datetime(2026, 5, 9, 11, 0, tzinfo=timezone.utc)

    def test_iso_with_colon_offset(self):
        assert _parse_sf_iso("2026-05-09T11:00:00+00:00") == \
               datetime(2026, 5, 9, 11, 0, tzinfo=timezone.utc)

    def test_iso_with_z(self):
        assert _parse_sf_iso("2026-05-09T11:00:00Z") == \
               datetime(2026, 5, 9, 11, 0, tzinfo=timezone.utc)

    def test_iso_invalid_returns_none(self):
        assert _parse_sf_iso("not-a-date") is None
        assert _parse_sf_iso("") is None

    def test_compact_format(self):
        # YYYYMMDDHHMMSS.mmm legacy format
        assert _parse_sf_compact("20260509110000.123") == \
               datetime(2026, 5, 9, 11, 0, tzinfo=timezone.utc)

    def test_compact_invalid(self):
        assert _parse_sf_compact("") is None
        assert _parse_sf_compact("oops") is None
        assert _parse_sf_compact("20261313000000.000") is None  # bad month/day

    def test_event_time_prefers_derived_then_compact(self):
        # Both present -> derived wins
        evt = {"TIMESTAMP_DERIVED": "2026-05-09T11:00:00.000+0000",
               "TIMESTAMP": "20260509120000.000"}
        assert _event_time(evt) == datetime(2026, 5, 9, 11, 0, tzinfo=timezone.utc)
        # Only compact
        assert _event_time({"TIMESTAMP": "20260509110000.000"}) == \
               datetime(2026, 5, 9, 11, 0, tzinfo=timezone.utc)
        # Neither
        assert _event_time({}) is None


class TestEventId:
    def test_prefers_uuid(self):
        assert _event_id({"EVENT_UUID": "u-1", "REQUEST_ID": "r-1"}) == "u-1"

    def test_falls_back_to_request_id(self):
        assert _event_id({"REQUEST_ID": "r-1"}) == "r-1"

    def test_empty_when_neither(self):
        assert _event_id({"USER_ID": "x"}) == ""


class TestFormatSoqlIso:
    def test_outputs_z_seconds_resolution(self):
        d = datetime(2026, 5, 9, 11, 0, tzinfo=timezone.utc)
        assert _format_soql_iso(d) == "2026-05-09T11:00:00Z"


class TestFeedSelection:
    def test_default(self, tmp_path):
        coll = _make(tmp_path, _FakeSalesforceClient())
        assert coll.list_feeds() == ["events"]

    def test_unknown_rejected(self, tmp_path):
        with pytest.raises(ValueError):
            SalesforceCollector(
                tenant_id="acme.my.salesforce.com",
                watermark_store=LocalFileWatermarkStore(tmp_path / "state"),
                secret_store=LocalFileSecretStore(tmp_path / "s.json"),
                lake_writer=LocalFileRawLakeWriter(tmp_path / "lake"),
                feeds=("events", "bogus"),
                client_factory=lambda _t: _FakeSalesforceClient(),
            )


# ============================================================ happy path


class TestSingleFileSingleEvent:
    def test_writes_and_advances_watermark(self, tmp_path):
        url = "/services/data/v59.0/sobjects/EventLogFile/0AT1/LogFile"
        client = _FakeSalesforceClient(
            log_files=[_file_record("0AT1", log_file=url)],
            events_by_url={url: [_event("2026-05-09T11:00:00.000+0000", uuid="u1")]},
        )
        coll = _make(tmp_path, client)
        until = datetime(2026, 5, 9, 12, 0, tzinfo=timezone.utc)
        result = coll.run(until=until)
        assert result.total_events == 1
        wm = coll.watermarks.get("salesforce", "acme.my.salesforce.com", "events")
        assert wm.last_event_time == datetime(2026, 5, 9, 11, 0, tzinfo=timezone.utc)
        assert wm.last_event_id == "u1"

    def test_list_call_carries_iso_window(self, tmp_path):
        client = _FakeSalesforceClient()
        coll = _make(tmp_path, client)
        until = datetime(2026, 5, 9, 12, 0, tzinfo=timezone.utc)
        coll.run(until=until)
        call = client.list_calls[0]
        # Default 7-day backfill
        assert call["since"] == "2026-05-02T12:00:00Z"
        assert call["until"] == "2026-05-09T12:00:00Z"


class TestMultipleFilesFlatten:
    def test_each_log_file_fetched_and_events_concatenated(self, tmp_path):
        urls = ["url-A", "url-B"]
        client = _FakeSalesforceClient(
            log_files=[
                _file_record("0AT-A", log_file="url-A"),
                _file_record("0AT-B", event_type="ApiCall", log_file="url-B"),
            ],
            events_by_url={
                "url-A": [_event("2026-05-09T10:30:00.000+0000", uuid="A1"),
                          _event("2026-05-09T10:35:00.000+0000", uuid="A2")],
                "url-B": [_event("2026-05-09T11:00:00.000+0000", "ApiCall", uuid="B1")],
            },
        )
        coll = _make(tmp_path, client)
        until = datetime(2026, 5, 9, 12, 0, tzinfo=timezone.utc)
        result = coll.run(until=until)
        assert result.total_events == 3
        assert client.fetch_calls == ["url-A", "url-B"]


class TestEventTypeAnnotation:
    def test_event_type_filled_from_log_file_when_absent_on_row(self, tmp_path):
        url = "url-1"
        # Event row WITHOUT an EVENT_TYPE key
        row_without_type = {
            "TIMESTAMP_DERIVED": "2026-05-09T11:00:00.000+0000",
            "USER_ID": "u",
            "REQUEST_ID": "r",
        }
        client = _FakeSalesforceClient(
            log_files=[_file_record("X", event_type="LightningError", log_file=url)],
            events_by_url={url: [row_without_type]},
        )
        coll = _make(tmp_path, client)
        coll.run(until=datetime(2026, 5, 9, 12, 0, tzinfo=timezone.utc))
        import gzip, json
        files = list((tmp_path / "lake").rglob("*.jsonl.gz"))
        with gzip.open(files[0], "rb") as f:
            rec = json.loads(f.read().splitlines()[0])
        assert rec["EVENT_TYPE"] == "LightningError"

    def test_existing_event_type_not_overwritten(self, tmp_path):
        url = "url-1"
        row_with_type = _event("2026-05-09T11:00:00.000+0000", event_type="ApiCall", uuid="u1")
        client = _FakeSalesforceClient(
            log_files=[_file_record("X", event_type="Login", log_file=url)],
            events_by_url={url: [row_with_type]},
        )
        coll = _make(tmp_path, client)
        coll.run(until=datetime(2026, 5, 9, 12, 0, tzinfo=timezone.utc))
        import gzip, json
        files = list((tmp_path / "lake").rglob("*.jsonl.gz"))
        with gzip.open(files[0], "rb") as f:
            rec = json.loads(f.read().splitlines()[0])
        assert rec["EVENT_TYPE"] == "ApiCall"


class TestBoundary:
    def test_event_at_since_excluded(self, tmp_path):
        wm = LocalFileWatermarkStore(tmp_path / "state")
        wm.put("salesforce", "acme.my.salesforce.com", "events",
               Watermark(last_event_time=datetime(2026, 5, 9, 11, 0, tzinfo=timezone.utc)))
        url = "url-1"
        client = _FakeSalesforceClient(
            log_files=[_file_record("X", log_file=url)],
            events_by_url={url: [
                _event("2026-05-09T11:00:00.000+0000", uuid="boundary"),
                _event("2026-05-09T11:30:00.000+0000", uuid="after"),
            ]},
        )
        coll = SalesforceCollector(
            tenant_id="acme.my.salesforce.com",
            watermark_store=wm,
            secret_store=LocalFileSecretStore(tmp_path / "s.json"),
            lake_writer=LocalFileRawLakeWriter(tmp_path / "lake"),
            retry_policy=RetryPolicy(max_attempts=2, base_delay_seconds=0.0, jitter=0.0),
            client_factory=lambda _t: client,
        )
        until = datetime(2026, 5, 9, 12, 0, tzinfo=timezone.utc)
        assert coll.run(until=until).total_events == 1

    def test_event_at_until_excluded(self, tmp_path):
        url = "url-1"
        client = _FakeSalesforceClient(
            log_files=[_file_record("X", log_file=url)],
            events_by_url={url: [_event("2026-05-09T12:00:00.000+0000", uuid="end")]},
        )
        coll = _make(tmp_path, client)
        until = datetime(2026, 5, 9, 12, 0, tzinfo=timezone.utc)
        assert coll.run(until=until).total_events == 0

    def test_log_file_missing_url_skipped(self, tmp_path):
        bad = {"Id": "0AT-bad", "EventType": "Login"}  # no LogFile field
        client = _FakeSalesforceClient(log_files=[bad])
        coll = _make(tmp_path, client)
        until = datetime(2026, 5, 9, 12, 0, tzinfo=timezone.utc)
        result = coll.run(until=until)
        assert result.total_events == 0
        assert client.fetch_calls == []

    def test_event_missing_timestamp_dropped(self, tmp_path):
        url = "url-1"
        bad = {"USER_ID": "u", "REQUEST_ID": "r"}  # no TIMESTAMP / TIMESTAMP_DERIVED
        client = _FakeSalesforceClient(
            log_files=[_file_record("X", log_file=url)],
            events_by_url={url: [bad, _event("2026-05-09T11:00:00.000+0000", uuid="good")]},
        )
        coll = _make(tmp_path, client)
        until = datetime(2026, 5, 9, 12, 0, tzinfo=timezone.utc)
        assert coll.run(until=until).total_events == 1


class TestRetry:
    def test_429_on_list_retried(self, tmp_path):
        url = "url-1"
        client = _FakeSalesforceClient(
            log_files=[_file_record("X", log_file=url)],
            events_by_url={url: [_event("2026-05-09T11:00:00.000+0000", uuid="u1")]},
            list_raises=SalesforceHTTPError("rate", status_code=429, retry_after=0.0),
        )
        coll = _make(tmp_path, client)
        result = coll.run(until=datetime(2026, 5, 9, 12, 0, tzinfo=timezone.utc))
        assert result.total_events == 1
        assert len(client.list_calls) == 2

    def test_404_on_list_not_retried(self, tmp_path):
        client = _FakeSalesforceClient(
            list_raises=SalesforceHTTPError("not found", status_code=404),
        )
        coll = _make(tmp_path, client,
                     retry_policy=RetryPolicy(max_attempts=4, base_delay_seconds=0.0, jitter=0.0))
        result = coll.run(until=datetime(2026, 5, 9, 12, 0, tzinfo=timezone.utc))
        feed = next(f for f in result.feeds if f.feed == "events")
        assert feed.error is not None and "404" in feed.error
        assert len(client.list_calls) == 1

    def test_fetch_error_surfaces_as_feed_error(self, tmp_path):
        url_a = "url-A"
        url_b = "url-B"
        client = _FakeSalesforceClient(
            log_files=[
                _file_record("0AT-A", log_file=url_a),
                _file_record("0AT-B", log_file=url_b),
            ],
            events_by_url={url_a: [_event("2026-05-09T10:55:00.000+0000", uuid="a1")]},
            fetch_raises={url_b: SalesforceHTTPError("server", status_code=503)},
        )
        coll = _make(tmp_path, client)
        result = coll.run(until=datetime(2026, 5, 9, 12, 0, tzinfo=timezone.utc))
        feed = next(f for f in result.feeds if f.feed == "events")
        assert feed.error is not None and "503" in feed.error


class TestSecretsPath:
    def test_missing_secrets_when_no_factory(self, tmp_path):
        coll = SalesforceCollector(
            tenant_id="acme.my.salesforce.com",
            watermark_store=LocalFileWatermarkStore(tmp_path / "state"),
            secret_store=LocalFileSecretStore(tmp_path / "s.json"),
            lake_writer=LocalFileRawLakeWriter(tmp_path / "lake"),
            retry_policy=RetryPolicy(max_attempts=1, base_delay_seconds=0.0, jitter=0.0),
        )
        result = coll.run(until=datetime(2026, 5, 9, 12, 0, tzinfo=timezone.utc))
        feed = next(f for f in result.feeds if f.feed == "events")
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
    params: Optional[dict] = None
    data: Any = None
    headers: Optional[dict] = None


class _FakeTransport:
    def __init__(self, responses: list):
        self.responses = list(responses)
        self.calls: list[_Call] = []

    def post(self, url, data=None, params=None, headers=None, timeout=None):
        self.calls.append(_Call("POST", url, params, data, headers))
        return self.responses.pop(0) if self.responses else _Resp()

    def get(self, url, params=None, headers=None, timeout=None):
        self.calls.append(_Call("GET", url, params, None, headers))
        return self.responses.pop(0) if self.responses else _Resp()


def _token_response(access_token="tok", instance_url="https://acme.my.salesforce.com"):
    return _Resp(status_code=200, body_json={
        "access_token": access_token,
        "instance_url": instance_url,
        "expires_in": 3600,
        "token_type": "Bearer",
    })


class TestParseRetryAfter:
    def test_seconds(self):
        assert _parse_retry_after("30") == 30.0

    def test_blank(self):
        assert _parse_retry_after(None) is None


class TestTokenProvider:
    def test_fetches_with_correct_payload(self):
        transport = _FakeTransport([_token_response()])
        client = SalesforceEventClient(
            instance_url="https://acme.my.salesforce.com",
            client_id="c-1", client_secret="s",
            transport=transport,
        )
        access, instance = client.get_token()
        assert access == "tok"
        assert instance == "https://acme.my.salesforce.com"
        token_call = transport.calls[0]
        assert token_call.url == f"https://acme.my.salesforce.com{LOGIN_TOKEN_PATH}"
        assert token_call.data["grant_type"] == "client_credentials"
        assert token_call.data["client_id"] == "c-1"

    def test_caches_token_within_expiry(self, monkeypatch):
        transport = _FakeTransport([_token_response()])
        clock = [1000.0]
        monkeypatch.setattr(sf_http, "_now", lambda: clock[0])
        client = SalesforceEventClient(
            instance_url="https://acme.my.salesforce.com",
            client_id="c", client_secret="s",
            transport=transport,
        )
        client.get_token()
        clock[0] += 600  # 10 minutes; well within 1 hour
        client.get_token()
        assert len(transport.calls) == 1

    def test_refreshes_near_expiry(self, monkeypatch):
        transport = _FakeTransport([
            _token_response(access_token="old"),
            _token_response(access_token="new"),
        ])
        clock = [1000.0]
        monkeypatch.setattr(sf_http, "_now", lambda: clock[0])
        client = SalesforceEventClient(
            instance_url="https://acme.my.salesforce.com",
            client_id="c", client_secret="s",
            transport=transport,
        )
        assert client.get_token()[0] == "old"
        # Default expires_in=3600. Refresh buffer is 60. Advance to 3590s
        # which is inside the buffer.
        clock[0] += 3590
        assert client.get_token()[0] == "new"

    def test_token_endpoint_failure_raises(self):
        transport = _FakeTransport([_Resp(status_code=400, body_text="invalid client")])
        client = SalesforceEventClient(
            instance_url="https://acme.my.salesforce.com",
            client_id="bad", client_secret="s",
            transport=transport,
        )
        with pytest.raises(SalesforceTokenError) as exc:
            client.get_token()
        assert exc.value.status_code == 400


class TestListLogFiles:
    def test_soql_query_includes_window(self):
        transport = _FakeTransport([
            _token_response(),
            _Resp(status_code=200, body_json={"records": [], "done": True}),
        ])
        client = SalesforceEventClient(
            instance_url="https://acme.my.salesforce.com",
            client_id="c", client_secret="s", transport=transport,
        )
        client.list_log_files(since="2026-05-02T12:00:00Z", until="2026-05-09T12:00:00Z")
        query_call = transport.calls[1]
        assert query_call.method == "GET"
        assert "/services/data/" in query_call.url
        assert DEFAULT_API_VERSION in query_call.url
        q = query_call.params["q"]
        assert "LogDate >= 2026-05-02T12:00:00Z" in q
        assert "LogDate < 2026-05-09T12:00:00Z" in q
        assert "ORDER BY LogDate ASC" in q
        assert query_call.headers["Authorization"] == "Bearer tok"

    def test_paginates_via_nextrecordsurl(self):
        transport = _FakeTransport([
            _token_response(),
            _Resp(status_code=200, body_json={
                "records": [_file_record("A")],
                "done": False,
                "nextRecordsUrl": "/services/data/v59.0/query/01g0001",
            }),
            _Resp(status_code=200, body_json={
                "records": [_file_record("B")],
                "done": True,
            }),
        ])
        client = SalesforceEventClient(
            instance_url="https://acme.my.salesforce.com",
            client_id="c", client_secret="s", transport=transport,
        )
        records = client.list_log_files(since="s", until="u")
        assert [r["Id"] for r in records] == ["A", "B"]
        # 1 token call + 2 SOQL calls
        assert len(transport.calls) == 3
        assert transport.calls[2].url == "https://acme.my.salesforce.com/services/data/v59.0/query/01g0001"
        # Second SOQL call carries no overlay params (URL has its own query)
        assert transport.calls[2].params is None


class TestFetchLogFile:
    def test_parses_csv_into_dicts(self):
        csv_text = (
            "EVENT_TYPE,TIMESTAMP_DERIVED,USER_ID,REQUEST_ID\n"
            "Login,2026-05-09T11:00:00.000+0000,005AAA,REQ-1\n"
            "Login,2026-05-09T11:01:00.000+0000,005BBB,REQ-2\n"
        )
        transport = _FakeTransport([
            _token_response(),
            _Resp(status_code=200, body_text=csv_text),
        ])
        client = SalesforceEventClient(
            instance_url="https://acme.my.salesforce.com",
            client_id="c", client_secret="s", transport=transport,
        )
        rows = client.fetch_log_file(
            "/services/data/v59.0/sobjects/EventLogFile/0AT1/LogFile"
        )
        assert [r["USER_ID"] for r in rows] == ["005AAA", "005BBB"]
        assert rows[0]["TIMESTAMP_DERIVED"] == "2026-05-09T11:00:00.000+0000"
        # URL was resolved against the instance URL.
        fetch_call = transport.calls[1]
        assert fetch_call.url.startswith("https://acme.my.salesforce.com/services/data/")

    def test_absolute_url_passes_through(self):
        transport = _FakeTransport([
            _token_response(),
            _Resp(status_code=200, body_text="EVENT_TYPE\nLogin\n"),
        ])
        client = SalesforceEventClient(
            instance_url="https://acme.my.salesforce.com",
            client_id="c", client_secret="s", transport=transport,
        )
        absolute = "https://acme.my.salesforce.com/services/data/v59.0/sobjects/EventLogFile/X/LogFile"
        client.fetch_log_file(absolute)
        assert transport.calls[1].url == absolute

    def test_empty_body_returns_empty_list(self):
        transport = _FakeTransport([
            _token_response(),
            _Resp(status_code=200, body_text=""),
        ])
        client = SalesforceEventClient(
            instance_url="https://acme.my.salesforce.com",
            client_id="c", client_secret="s", transport=transport,
        )
        assert client.fetch_log_file("/x") == []

    def test_429_on_fetch_wraps_with_retry_after(self):
        transport = _FakeTransport([
            _token_response(),
            _Resp(status_code=429, headers={"Retry-After": "12"}, body_text="rate"),
        ])
        client = SalesforceEventClient(
            instance_url="https://acme.my.salesforce.com",
            client_id="c", client_secret="s", transport=transport,
        )
        with pytest.raises(SalesforceHTTPError) as exc:
            client.fetch_log_file("/x")
        assert exc.value.status_code == 429
        assert exc.value.retry_after == 12.0


class TestAuthInvalidation:
    def test_401_invalidates_token_cache(self):
        transport = _FakeTransport([
            _token_response(),
            _Resp(status_code=401, body_text="auth"),
            _token_response(access_token="fresh"),
            _Resp(status_code=200, body_json={"records": [], "done": True}),
        ])
        client = SalesforceEventClient(
            instance_url="https://acme.my.salesforce.com",
            client_id="c", client_secret="s", transport=transport,
        )
        with pytest.raises(SalesforceHTTPError):
            client.list_log_files(since="s", until="u")
        client.list_log_files(since="s", until="u")
        # Two POSTs to the token endpoint, proving cache was invalidated.
        token_posts = [c for c in transport.calls if c.method == "POST"]
        assert len(token_posts) == 2
