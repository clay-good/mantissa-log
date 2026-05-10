"""
Unit tests for PR 9 of SAAS_IDENTITY_SPEC (post-spec follow-on).

Production HTTP clients backing Microsoft365Collector (PR 4) and
MicrosoftGraphCollector (PR 5). Tests cover:

  - TokenProvider: fetch, cache, refresh near expiry, invalidate on 401,
    malformed response handling.
  - ManagementActivityHTTPClient: start_subscription idempotency on
    AF20024, list_content with NextPageUri pagination, fetch_blob,
    Retry-After parsing, 429/5xx error wrapping into
    ManagementActivityHTTPError with retry_after populated.
  - GraphHTTPClient: get with params + bearer auth, ConsistencyLevel
    header for $filter, 429 wrapped into GraphHTTPError with
    retry_after, 401 invalidates token cache.

A fake HTTP transport replaces ``requests`` so tests do not hit the
network. The fake also fakes the clock so we can assert refresh
behaviour deterministically.
"""

from __future__ import annotations

import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Optional

import pytest

ROOT = Path(__file__).resolve().parents[2]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

import shared.collectors.m365_http_client as http_client  # noqa: E402
from shared.collectors.m365_http_client import (  # noqa: E402
    DEFAULT_TIMEOUT_SECONDS,
    GraphHTTPClient,
    GRAPH_SCOPE,
    MANAGEMENT_ACTIVITY_SCOPE,
    ManagementActivityHTTPClient,
    TOKEN_ENDPOINT,
    TokenAcquisitionError,
    TokenProvider,
    _parse_retry_after,
)
from shared.collectors.microsoft365_collector import ManagementActivityHTTPError  # noqa: E402
from shared.collectors.microsoft_graph_collector import GraphHTTPError  # noqa: E402


# --------------------------------------------------------------- helpers


@dataclass
class _FakeResponse:
    status_code: int = 200
    body_json: Any = None
    body_text: str = ""
    headers: dict = field(default_factory=dict)

    def json(self):
        if isinstance(self.body_json, Exception):
            raise self.body_json
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
    timeout: Optional[float] = None


class _FakeTransport:
    """Records HTTP calls and returns canned responses keyed by URL+method.

    ``responses`` is a list. Each call pops the first matching response.
    A response can be raw ``_FakeResponse`` or a callable that receives
    the ``_Call`` and returns one. Useful for asserting on call shape.
    """

    def __init__(self, responses: Optional[list] = None):
        self.responses = list(responses or [])
        self.calls: list[_Call] = []
        self.default_response = _FakeResponse(status_code=200, body_json={})

    def _next(self, call: _Call) -> _FakeResponse:
        self.calls.append(call)
        if not self.responses:
            return self.default_response
        nxt = self.responses.pop(0)
        return nxt(call) if callable(nxt) else nxt

    def post(self, url, data=None, params=None, headers=None, timeout=None):
        return self._next(_Call("POST", url, params=params, data=data,
                                 headers=headers, timeout=timeout))

    def get(self, url, params=None, headers=None, timeout=None):
        return self._next(_Call("GET", url, params=params, data=None,
                                 headers=headers, timeout=timeout))


# ---------------------------------------------------------- parse helpers


class TestParseRetryAfter:
    def test_seconds_numeric(self):
        assert _parse_retry_after("30") == 30.0

    def test_http_date(self):
        # A date far in the future. Any positive value is acceptable.
        v = _parse_retry_after("Wed, 21 Oct 2099 07:28:00 GMT")
        assert v is not None and v > 0

    def test_none_or_blank(self):
        assert _parse_retry_after(None) is None
        assert _parse_retry_after("") is None

    def test_invalid(self):
        assert _parse_retry_after("not-a-thing") is None


# ------------------------------------------------------------ TokenProvider


class TestTokenProvider:
    def test_fetches_token_with_correct_payload(self):
        body = {"access_token": "abc123", "expires_in": 3600, "token_type": "Bearer"}
        transport = _FakeTransport([_FakeResponse(status_code=200, body_json=body)])
        tp = TokenProvider("tenant-guid", "client-1", "secret",
                            scope=MANAGEMENT_ACTIVITY_SCOPE, transport=transport)

        token = tp.get_token()
        assert token == "abc123"
        call = transport.calls[0]
        assert call.method == "POST"
        assert call.url == TOKEN_ENDPOINT.format(tenant_guid="tenant-guid")
        assert call.data["grant_type"] == "client_credentials"
        assert call.data["client_id"] == "client-1"
        assert call.data["client_secret"] == "secret"
        assert call.data["scope"] == MANAGEMENT_ACTIVITY_SCOPE
        assert call.timeout == DEFAULT_TIMEOUT_SECONDS

    def test_caches_token_within_expiry(self, monkeypatch):
        body = {"access_token": "abc", "expires_in": 3600}
        transport = _FakeTransport([_FakeResponse(status_code=200, body_json=body)])
        clock = [1000.0]
        monkeypatch.setattr(http_client, "_now", lambda: clock[0])

        tp = TokenProvider("t", "c", "s", scope=GRAPH_SCOPE, transport=transport)
        assert tp.get_token() == "abc"
        # Move clock forward 10 minutes (well within 60min lifetime)
        clock[0] += 600
        assert tp.get_token() == "abc"  # cached
        assert len(transport.calls) == 1

    def test_refreshes_within_buffer_of_expiry(self, monkeypatch):
        body1 = {"access_token": "old", "expires_in": 100}
        body2 = {"access_token": "new", "expires_in": 100}
        transport = _FakeTransport([
            _FakeResponse(status_code=200, body_json=body1),
            _FakeResponse(status_code=200, body_json=body2),
        ])
        clock = [1000.0]
        monkeypatch.setattr(http_client, "_now", lambda: clock[0])

        tp = TokenProvider("t", "c", "s", scope=GRAPH_SCOPE, transport=transport)
        assert tp.get_token() == "old"
        # Advance to within 60s of expiry (default refresh buffer)
        clock[0] += 50
        assert tp.get_token() == "new"
        assert len(transport.calls) == 2

    def test_invalidate_forces_refresh(self):
        body1 = {"access_token": "old", "expires_in": 3600}
        body2 = {"access_token": "new", "expires_in": 3600}
        transport = _FakeTransport([
            _FakeResponse(status_code=200, body_json=body1),
            _FakeResponse(status_code=200, body_json=body2),
        ])
        tp = TokenProvider("t", "c", "s", scope=GRAPH_SCOPE, transport=transport)
        assert tp.get_token() == "old"
        tp.invalidate()
        assert tp.get_token() == "new"

    def test_non_2xx_raises(self):
        transport = _FakeTransport([
            _FakeResponse(status_code=400, body_text="invalid client"),
        ])
        tp = TokenProvider("t", "c", "s", scope=GRAPH_SCOPE, transport=transport)
        with pytest.raises(TokenAcquisitionError) as exc:
            tp.get_token()
        assert exc.value.status_code == 400
        assert "invalid client" in str(exc.value)

    def test_malformed_response_raises(self):
        transport = _FakeTransport([
            _FakeResponse(status_code=200, body_json={"oops": "no token"}),
        ])
        tp = TokenProvider("t", "c", "s", scope=GRAPH_SCOPE, transport=transport)
        with pytest.raises(TokenAcquisitionError):
            tp.get_token()


# --------------------------------------------- ManagementActivityHTTPClient


def _token_response():
    return _FakeResponse(status_code=200,
                         body_json={"access_token": "tok", "expires_in": 3600})


class TestManagementActivitySubscription:
    def test_start_subscription_posts_with_bearer(self):
        transport = _FakeTransport([
            _token_response(),
            _FakeResponse(status_code=200, body_json={}),
        ])
        client = ManagementActivityHTTPClient("t-guid", "c", "s", transport=transport)
        client.start_subscription("Audit.AzureActiveDirectory")
        # 1st call: token endpoint. 2nd call: subscription start.
        sub_call = transport.calls[1]
        assert sub_call.method == "POST"
        assert "subscriptions/start" in sub_call.url
        assert sub_call.params == {"contentType": "Audit.AzureActiveDirectory"}
        assert sub_call.headers["Authorization"] == "Bearer tok"

    def test_already_started_400_af20024_is_success(self):
        transport = _FakeTransport([
            _token_response(),
            _FakeResponse(status_code=400, body_text="AF20024: subscription already enabled"),
        ])
        client = ManagementActivityHTTPClient("t-guid", "c", "s", transport=transport)
        # Should not raise; AF20024 means idempotent success.
        client.start_subscription("Audit.AzureActiveDirectory")

    def test_other_400_raises(self):
        transport = _FakeTransport([
            _token_response(),
            _FakeResponse(status_code=400, body_text="bad request"),
        ])
        client = ManagementActivityHTTPClient("t-guid", "c", "s", transport=transport)
        with pytest.raises(ManagementActivityHTTPError) as exc:
            client.start_subscription("Audit.AzureActiveDirectory")
        assert exc.value.status_code == 400


class TestManagementActivityListContent:
    def test_single_page(self):
        blobs = [{"contentId": "b1", "contentUri": "https://u/b1"}]
        transport = _FakeTransport([
            _token_response(),
            _FakeResponse(status_code=200, body_json=blobs),
        ])
        client = ManagementActivityHTTPClient("t-guid", "c", "s", transport=transport)
        out = client.list_content("Audit.Exchange", "2026-05-09T00:00:00", "2026-05-09T01:00:00")
        assert out == blobs

    def test_walks_nextpageuri(self):
        page1 = [{"contentId": "b1"}]
        page2 = [{"contentId": "b2"}]
        transport = _FakeTransport([
            _token_response(),
            _FakeResponse(
                status_code=200,
                body_json=page1,
                headers={"NextPageUri": "https://manage.office.com/api/v1.0/.../content?next=2"},
            ),
            _FakeResponse(status_code=200, body_json=page2),
        ])
        client = ManagementActivityHTTPClient("t-guid", "c", "s", transport=transport)
        out = client.list_content("Audit.Exchange", "s", "e")
        assert [b["contentId"] for b in out] == ["b1", "b2"]
        # Three calls: token + page1 + page2
        assert len(transport.calls) == 3
        # Second list call used the next URL with no params.
        assert transport.calls[2].url.endswith("next=2")
        assert transport.calls[2].params is None

    def test_429_wrapped_with_retry_after(self):
        transport = _FakeTransport([
            _token_response(),
            _FakeResponse(status_code=429, headers={"Retry-After": "12"}, body_text="rate limited"),
        ])
        client = ManagementActivityHTTPClient("t-guid", "c", "s", transport=transport)
        with pytest.raises(ManagementActivityHTTPError) as exc:
            client.list_content("Audit.Exchange", "s", "e")
        assert exc.value.status_code == 429
        assert exc.value.retry_after == 12.0

    def test_503_wrapped(self):
        transport = _FakeTransport([
            _token_response(),
            _FakeResponse(status_code=503, body_text="server"),
        ])
        client = ManagementActivityHTTPClient("t-guid", "c", "s", transport=transport)
        with pytest.raises(ManagementActivityHTTPError) as exc:
            client.list_content("Audit.Exchange", "s", "e")
        assert exc.value.status_code == 503


class TestManagementActivityFetchBlob:
    def test_returns_event_list(self):
        events = [{"Id": "e1", "CreationTime": "2026-05-09T11:00:00"}]
        transport = _FakeTransport([
            _token_response(),
            _FakeResponse(status_code=200, body_json=events),
        ])
        client = ManagementActivityHTTPClient("t-guid", "c", "s", transport=transport)
        out = client.fetch_blob("https://manage.office.com/api/v1.0/.../audit/abc")
        assert out == events

    def test_non_list_body_returns_empty(self):
        transport = _FakeTransport([
            _token_response(),
            _FakeResponse(status_code=200, body_json={"unexpected": "shape"}),
        ])
        client = ManagementActivityHTTPClient("t-guid", "c", "s", transport=transport)
        assert client.fetch_blob("https://u/b") == []

    def test_410_wrapped(self):
        # 410 Gone is a common terminal blob fetch failure (blob expired).
        # Should wrap and NOT be classified as transient by the collector
        # (collector tests already cover that classification side).
        transport = _FakeTransport([
            _token_response(),
            _FakeResponse(status_code=410, body_text="gone"),
        ])
        client = ManagementActivityHTTPClient("t-guid", "c", "s", transport=transport)
        with pytest.raises(ManagementActivityHTTPError) as exc:
            client.fetch_blob("https://u/b")
        assert exc.value.status_code == 410


class TestManagementActivityAuthInvalidation:
    def test_401_invalidates_token_cache(self):
        # First request returns 401 -> client invalidates cache and our
        # caller will retry; next call must re-fetch the token.
        transport = _FakeTransport([
            _token_response(),
            _FakeResponse(status_code=401, body_text="auth"),
            _token_response(),
            _FakeResponse(status_code=200, body_json=[{"contentId": "b1"}]),
        ])
        client = ManagementActivityHTTPClient("t-guid", "c", "s", transport=transport)
        with pytest.raises(ManagementActivityHTTPError):
            client.list_content("Audit.Exchange", "s", "e")
        # Token cache was invalidated, so the next call goes through
        # token + list (two calls).
        out = client.list_content("Audit.Exchange", "s", "e")
        assert out == [{"contentId": "b1"}]
        methods = [c.method for c in transport.calls]
        assert methods.count("POST") == 2  # two token fetches


# ------------------------------------------------------------ GraphHTTPClient


class TestGraphClient:
    def test_get_with_params_carries_bearer_and_consistency(self):
        transport = _FakeTransport([
            _token_response(),
            _FakeResponse(status_code=200, body_json={"value": [{"id": "1"}]}),
        ])
        client = GraphHTTPClient("t-guid", "c", "s", transport=transport)
        out = client.get(
            "https://graph.microsoft.com/v1.0/auditLogs/signIns",
            params={"$filter": "createdDateTime ge 2026-05-09T00:00:00.000Z",
                    "$top": "200"},
        )
        assert out == {"value": [{"id": "1"}]}
        call = transport.calls[1]
        assert call.method == "GET"
        assert call.headers["Authorization"] == "Bearer tok"
        assert call.headers["Accept"] == "application/json"
        assert call.headers["ConsistencyLevel"] == "eventual"
        assert call.params["$top"] == "200"

    def test_token_acquired_with_graph_scope(self):
        transport = _FakeTransport([
            _token_response(),
            _FakeResponse(status_code=200, body_json={}),
        ])
        client = GraphHTTPClient("t-guid", "c", "s", transport=transport)
        client.get("https://graph.microsoft.com/v1.0/me")
        token_call = transport.calls[0]
        assert token_call.data["scope"] == GRAPH_SCOPE

    def test_429_wrapped_with_retry_after(self):
        transport = _FakeTransport([
            _token_response(),
            _FakeResponse(status_code=429, headers={"Retry-After": "30"}, body_text="slow down"),
        ])
        client = GraphHTTPClient("t-guid", "c", "s", transport=transport)
        with pytest.raises(GraphHTTPError) as exc:
            client.get("https://graph.microsoft.com/v1.0/x")
        assert exc.value.status_code == 429
        assert exc.value.retry_after == 30.0

    def test_403_wrapped(self):
        # 403 is the canonical "wrong scope" failure. Should NOT be transient.
        transport = _FakeTransport([
            _token_response(),
            _FakeResponse(status_code=403, body_text="forbidden"),
        ])
        client = GraphHTTPClient("t-guid", "c", "s", transport=transport)
        with pytest.raises(GraphHTTPError) as exc:
            client.get("https://graph.microsoft.com/v1.0/x")
        assert exc.value.status_code == 403

    def test_non_dict_body_returns_empty_dict(self):
        transport = _FakeTransport([
            _token_response(),
            _FakeResponse(status_code=200, body_json=[1, 2, 3]),  # list, not dict
        ])
        client = GraphHTTPClient("t-guid", "c", "s", transport=transport)
        assert client.get("https://graph.microsoft.com/v1.0/x") == {}

    def test_401_invalidates_token(self):
        transport = _FakeTransport([
            _token_response(),
            _FakeResponse(status_code=401, body_text="auth"),
            _token_response(),
            _FakeResponse(status_code=200, body_json={"value": []}),
        ])
        client = GraphHTTPClient("t-guid", "c", "s", transport=transport)
        with pytest.raises(GraphHTTPError):
            client.get("https://graph.microsoft.com/v1.0/x")
        client.get("https://graph.microsoft.com/v1.0/x")
        post_count = sum(1 for c in transport.calls if c.method == "POST")
        assert post_count == 2  # two token fetches
