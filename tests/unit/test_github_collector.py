"""
Unit tests for GitHubAuditCollector and GitHubAuditClient
(PR 11 of SAAS_IDENTITY_SPEC, §10 follow-on pack continued).
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

from shared.collectors.github_collector import (  # noqa: E402
    GitHubAuditCollector,
    GitHubHTTPError,
    _format_github_iso,
    _from_millis,
)
from shared.collectors.github_http_client import (  # noqa: E402
    API_BASE_URL,
    GITHUB_API_VERSION,
    GitHubAuditClient,
    _extract_next_url,
    _parse_retry_after,
)
from shared.collectors.saas_lake import LocalFileRawLakeWriter  # noqa: E402
from shared.collectors.saas_retry import RetryPolicy  # noqa: E402
from shared.collectors.saas_secrets import LocalFileSecretStore  # noqa: E402
from shared.collectors.saas_state import LocalFileWatermarkStore, Watermark  # noqa: E402


# ============================================================ helpers


def _millis(year=2026, month=5, day=9, hour=11, minute=0, second=0) -> int:
    dt = datetime(year, month, day, hour, minute, second, tzinfo=timezone.utc)
    return int(dt.timestamp() * 1000)


def _event(doc_id: str, when_ms: int, action: str = "repo.create",
           actor: str = "alice") -> dict:
    return {
        "_document_id": doc_id,
        "@timestamp": when_ms,
        "action": action,
        "actor": actor,
        "org": "acme",
        "repo": "acme/widgets",
    }


class _FakeGitHubClient:
    def __init__(self, pages: Optional[list[dict]] = None,
                 raises: Optional[Exception] = None,
                 raises_on: str = "list_logs"):
        self.pages = list(pages or [])
        self.raises = raises
        self.raises_on = raises_on
        self.list_logs_calls: list[dict] = []
        self.list_next_calls: list[str] = []

    def list_logs(self, phrase, include, per_page):
        self.list_logs_calls.append({"phrase": phrase, "include": include, "per_page": per_page})
        if self.raises is not None and self.raises_on == "list_logs":
            exc = self.raises
            self.raises = None
            raise exc
        return self.pages.pop(0) if self.pages else {"items": [], "next_url": None}

    def list_next(self, url):
        self.list_next_calls.append(url)
        if self.raises is not None and self.raises_on == "list_next":
            exc = self.raises
            self.raises = None
            raise exc
        return self.pages.pop(0) if self.pages else {"items": [], "next_url": None}


def _make(tmp_path, client, tenant="orgs/acme", retry_policy=None, include="all"):
    return GitHubAuditCollector(
        tenant_id=tenant,
        watermark_store=LocalFileWatermarkStore(tmp_path / "state"),
        secret_store=LocalFileSecretStore(tmp_path / "secrets.json"),
        lake_writer=LocalFileRawLakeWriter(tmp_path / "lake"),
        retry_policy=retry_policy or RetryPolicy(max_attempts=3, base_delay_seconds=0.0, jitter=0.0),
        feeds=("audit",),
        client_factory=lambda _t: client,
        include=include,
    )


# ============================================================ helpers


class TestHelpers:
    def test_format_iso(self):
        d = datetime(2026, 5, 9, 11, 0, tzinfo=timezone.utc)
        assert _format_github_iso(d) == "2026-05-09T11:00:00Z"

    def test_from_millis_round_trip(self):
        ms = _millis(2026, 5, 9, 11, 0, 0)
        dt = _from_millis(ms)
        assert dt == datetime(2026, 5, 9, 11, 0, tzinfo=timezone.utc)

    def test_from_millis_handles_none_and_garbage(self):
        assert _from_millis(None) is None
        assert _from_millis("not-a-number") is None


class TestConstructorValidation:
    def test_rejects_bare_org_slug(self, tmp_path):
        with pytest.raises(ValueError, match="tenant_id"):
            GitHubAuditCollector(
                tenant_id="acme",  # missing orgs/ prefix
                watermark_store=LocalFileWatermarkStore(tmp_path / "state"),
                secret_store=LocalFileSecretStore(tmp_path / "s.json"),
                lake_writer=LocalFileRawLakeWriter(tmp_path / "lake"),
                client_factory=lambda _t: _FakeGitHubClient(),
            )

    def test_accepts_orgs_prefix(self, tmp_path):
        coll = _make(tmp_path, _FakeGitHubClient(), tenant="orgs/acme")
        assert coll.tenant_id == "orgs/acme"

    def test_accepts_enterprises_prefix(self, tmp_path):
        coll = _make(tmp_path, _FakeGitHubClient(), tenant="enterprises/big-co")
        assert coll.tenant_id == "enterprises/big-co"

    def test_rejects_bad_include(self, tmp_path):
        with pytest.raises(ValueError, match="include"):
            _make(tmp_path, _FakeGitHubClient(), include="everything")

    def test_unknown_feed_rejected(self, tmp_path):
        with pytest.raises(ValueError):
            GitHubAuditCollector(
                tenant_id="orgs/acme",
                watermark_store=LocalFileWatermarkStore(tmp_path / "state"),
                secret_store=LocalFileSecretStore(tmp_path / "s.json"),
                lake_writer=LocalFileRawLakeWriter(tmp_path / "lake"),
                feeds=("audit", "bogus"),
                client_factory=lambda _t: _FakeGitHubClient(),
            )


# ============================================================ happy path


class TestSinglePage:
    def test_writes_and_advances_watermark(self, tmp_path):
        client = _FakeGitHubClient([{
            "items": [
                _event("d1", _millis(2026, 5, 9, 11, 0)),
                _event("d2", _millis(2026, 5, 9, 11, 30)),
            ],
            "next_url": None,
        }])
        coll = _make(tmp_path, client)
        until = datetime(2026, 5, 9, 12, 0, tzinfo=timezone.utc)
        result = coll.run(until=until)
        assert result.total_events == 2
        wm = coll.watermarks.get("github", "orgs/acme", "audit")
        assert wm.last_event_time == datetime(2026, 5, 9, 11, 30, tzinfo=timezone.utc)
        assert wm.last_event_id == "d2"

    def test_phrase_uses_iso_range_inclusive(self, tmp_path):
        client = _FakeGitHubClient([{"items": [], "next_url": None}])
        coll = _make(tmp_path, client)
        until = datetime(2026, 5, 9, 12, 0, tzinfo=timezone.utc)
        coll.run(until=until)
        call = client.list_logs_calls[0]
        # 7-day default backfill produces since 2026-05-02T12:00:00Z
        assert "created:>=2026-05-02T12:00:00Z" in call["phrase"]
        assert "created:<=2026-05-09T12:00:00Z" in call["phrase"]
        assert call["include"] == "all"
        assert call["per_page"] == 100


class TestPagination:
    def test_two_pages_via_next_url(self, tmp_path):
        client = _FakeGitHubClient([
            {"items": [_event("d1", _millis(2026, 5, 9, 11, 0))],
             "next_url": "https://api.github.com/orgs/acme/audit-log?after=ABC"},
            {"items": [_event("d2", _millis(2026, 5, 9, 11, 30))],
             "next_url": None},
        ])
        coll = _make(tmp_path, client)
        until = datetime(2026, 5, 9, 12, 0, tzinfo=timezone.utc)
        result = coll.run(until=until)
        assert result.total_events == 2
        assert client.list_next_calls == ["https://api.github.com/orgs/acme/audit-log?after=ABC"]


class TestBoundary:
    def test_event_at_since_excluded(self, tmp_path):
        wm = LocalFileWatermarkStore(tmp_path / "state")
        wm.put("github", "orgs/acme", "audit",
               Watermark(last_event_time=datetime(2026, 5, 9, 11, 0, tzinfo=timezone.utc)))
        client = _FakeGitHubClient([{
            "items": [
                _event("boundary", _millis(2026, 5, 9, 11, 0)),
                _event("after", _millis(2026, 5, 9, 11, 30)),
            ],
            "next_url": None,
        }])
        coll = GitHubAuditCollector(
            tenant_id="orgs/acme",
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
        client = _FakeGitHubClient([{
            "items": [_event("end", _millis(2026, 5, 9, 12, 0))],
            "next_url": None,
        }])
        coll = _make(tmp_path, client)
        until = datetime(2026, 5, 9, 12, 0, tzinfo=timezone.utc)
        assert coll.run(until=until).total_events == 0

    def test_missing_timestamp_dropped(self, tmp_path):
        bad = {"_document_id": "bad", "action": "x"}
        client = _FakeGitHubClient([{
            "items": [bad, _event("good", _millis(2026, 5, 9, 11, 0))],
            "next_url": None,
        }])
        coll = _make(tmp_path, client)
        until = datetime(2026, 5, 9, 12, 0, tzinfo=timezone.utc)
        assert coll.run(until=until).total_events == 1


class TestEnrichment:
    def test_event_time_and_id_injected(self, tmp_path):
        client = _FakeGitHubClient([{
            "items": [_event("doc-1", _millis(2026, 5, 9, 11, 0))],
            "next_url": None,
        }])
        coll = _make(tmp_path, client)
        until = datetime(2026, 5, 9, 12, 0, tzinfo=timezone.utc)
        coll.run(until=until)
        import gzip, json
        files = list((tmp_path / "lake").rglob("*.jsonl.gz"))
        with gzip.open(files[0], "rb") as f:
            rec = json.loads(f.read().splitlines()[0])
        assert rec["event_time"] == "2026-05-09T11:00:00Z"
        assert rec["event_id"] == "doc-1"
        # Original fields preserved
        assert rec["action"] == "repo.create"
        assert rec["@timestamp"] == _millis(2026, 5, 9, 11, 0)


class TestRetry:
    def test_429_retried(self, tmp_path):
        client = _FakeGitHubClient(
            pages=[{"items": [_event("d1", _millis(2026, 5, 9, 11, 0))], "next_url": None}],
            raises=GitHubHTTPError("secondary rate limit", status_code=429, retry_after=0.0),
        )
        coll = _make(tmp_path, client)
        assert coll.run(until=datetime(2026, 5, 9, 12, 0, tzinfo=timezone.utc)).total_events == 1
        assert len(client.list_logs_calls) == 2

    def test_404_not_retried(self, tmp_path):
        # 404 on /orgs/foo/audit-log means the token lacks scope for the org.
        client = _FakeGitHubClient(raises=GitHubHTTPError("not found", status_code=404))
        coll = _make(tmp_path, client,
                     retry_policy=RetryPolicy(max_attempts=4, base_delay_seconds=0.0, jitter=0.0))
        result = coll.run(until=datetime(2026, 5, 9, 12, 0, tzinfo=timezone.utc))
        feed = next(f for f in result.feeds if f.feed == "audit")
        assert feed.error is not None and "404" in feed.error
        assert len(client.list_logs_calls) == 1

    def test_streaming_next_error_surfaces(self, tmp_path):
        client = _FakeGitHubClient(
            pages=[{"items": [_event("d1", _millis(2026, 5, 9, 11, 0))],
                    "next_url": "https://api.github.com/orgs/acme/audit-log?after=ABC"}],
            raises=GitHubHTTPError("server", status_code=503),
            raises_on="list_next",
        )
        coll = _make(tmp_path, client)
        result = coll.run(until=datetime(2026, 5, 9, 12, 0, tzinfo=timezone.utc))
        feed = next(f for f in result.feeds if f.feed == "audit")
        assert feed.error is not None and "503" in feed.error


class TestSecretsPath:
    def test_missing_secrets_when_no_factory(self, tmp_path):
        coll = GitHubAuditCollector(
            tenant_id="orgs/acme",
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


class TestExtractNextUrl:
    def test_present(self):
        link = ('<https://api.github.com/orgs/acme/audit-log?after=ABC>; rel="next", '
                '<https://api.github.com/orgs/acme/audit-log>; rel="prev"')
        assert _extract_next_url(link) == "https://api.github.com/orgs/acme/audit-log?after=ABC"

    def test_only_prev(self):
        assert _extract_next_url('<https://api.github.com/x>; rel="prev"') is None


class TestParseRetryAfter:
    def test_seconds(self):
        assert _parse_retry_after("60") == 60.0

    def test_invalid(self):
        assert _parse_retry_after("nope") is None


class TestGitHubClientHTTP:
    def test_org_url_and_headers(self):
        transport = _FakeTransport([_Resp(status_code=200, body_json=[])])
        client = GitHubAuditClient("orgs/acme", token="ghp_xxx", transport=transport)
        client.list_logs(phrase="created:>=2026-05-02 created:<=2026-05-09",
                          include="all", per_page=100)
        call = transport.calls[0]
        assert call.url == f"{API_BASE_URL}/orgs/acme/audit-log"
        assert call.headers["Authorization"] == "Bearer ghp_xxx"
        assert call.headers["Accept"] == "application/vnd.github+json"
        assert call.headers["X-GitHub-Api-Version"] == GITHUB_API_VERSION
        assert call.params["include"] == "all"
        assert call.params["per_page"] == 100
        assert call.params["order"] == "asc"

    def test_enterprise_url(self):
        transport = _FakeTransport([_Resp(status_code=200, body_json=[])])
        client = GitHubAuditClient("enterprises/big-co", token="t", transport=transport)
        client.list_logs(phrase="p", include="all", per_page=50)
        assert transport.calls[0].url == f"{API_BASE_URL}/enterprises/big-co/audit-log"

    def test_constructor_rejects_bad_scope(self):
        with pytest.raises(ValueError, match="scope_path"):
            GitHubAuditClient("acme", token="t")

    def test_next_url_extracted_from_link_header(self):
        next_url = "https://api.github.com/orgs/acme/audit-log?after=ABC"
        link_header = (f'<{next_url}>; rel="next", '
                        f'<https://api.github.com/orgs/acme/audit-log>; rel="first"')
        transport = _FakeTransport([_Resp(status_code=200, body_json=[],
                                           headers={"Link": link_header})])
        client = GitHubAuditClient("orgs/acme", token="t", transport=transport)
        page = client.list_logs(phrase="p", include="all", per_page=100)
        assert page["next_url"] == next_url

    def test_list_next_no_params_overlay(self):
        transport = _FakeTransport([_Resp(status_code=200, body_json=[])])
        client = GitHubAuditClient("orgs/acme", token="t", transport=transport)
        client.list_next("https://api.github.com/orgs/acme/audit-log?after=ABC")
        assert transport.calls[0].params is None

    def test_429_wrapped_with_retry_after(self):
        transport = _FakeTransport([
            _Resp(status_code=429, headers={"Retry-After": "10"}, body_text="rate"),
        ])
        client = GitHubAuditClient("orgs/acme", token="t", transport=transport)
        with pytest.raises(GitHubHTTPError) as exc:
            client.list_logs(phrase="p", include="all", per_page=100)
        assert exc.value.status_code == 429
        assert exc.value.retry_after == 10.0

    def test_429_falls_back_to_ratelimit_reset(self, monkeypatch):
        # 429 without Retry-After but with X-RateLimit-Reset header. Use a
        # reset value 30 seconds from "now"; assert the parsed value is
        # close to 30s.
        import shared.collectors.github_http_client as ghc
        now = 1_000_000.0
        monkeypatch.setattr(
            "shared.collectors.github_http_client.datetime",
            type("FakeDT", (), {
                "now": staticmethod(lambda tz=None: datetime.fromtimestamp(now, tz=tz)),
                "fromtimestamp": staticmethod(datetime.fromtimestamp),
            }),
        )
        transport = _FakeTransport([
            _Resp(status_code=429,
                   headers={"X-RateLimit-Reset": str(now + 30)},
                   body_text="rate"),
        ])
        client = GitHubAuditClient("orgs/acme", token="t", transport=transport)
        with pytest.raises(GitHubHTTPError) as exc:
            client.list_logs(phrase="p", include="all", per_page=100)
        # Allow a small slack to absorb clock difference between parse and check
        assert exc.value.retry_after is not None
        assert 29.0 <= exc.value.retry_after <= 31.0

    def test_403_wrapped(self):
        transport = _FakeTransport([_Resp(status_code=403, body_text="forbidden")])
        client = GitHubAuditClient("orgs/acme", token="t", transport=transport)
        with pytest.raises(GitHubHTTPError) as exc:
            client.list_logs(phrase="p", include="all", per_page=100)
        assert exc.value.status_code == 403

    def test_non_list_body_becomes_empty_items(self):
        transport = _FakeTransport([_Resp(status_code=200, body_json={"oops": True})])
        client = GitHubAuditClient("orgs/acme", token="t", transport=transport)
        assert client.list_logs(phrase="p", include="all", per_page=100)["items"] == []
