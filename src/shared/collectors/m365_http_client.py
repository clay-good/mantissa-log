"""
Production HTTP clients for the Microsoft 365 collectors.

Two clients ship here:

- ``ManagementActivityHTTPClient`` -- backs ``Microsoft365Collector`` from
  PR 4. Talks to ``manage.office.com`` (Office 365 Management Activity
  API). Three methods: start_subscription, list_content, fetch_blob.

- ``GraphHTTPClient`` -- backs ``MicrosoftGraphCollector`` from PR 5.
  Talks to ``graph.microsoft.com``. One method: get.

Both clients share an internal ``TokenProvider`` that handles OAuth 2.0
client credentials against the Entra tenant. The two APIs use different
OAuth scopes (Management Activity uses ``manage.office.com/.default``;
Graph uses ``graph.microsoft.com/.default``) so each client holds its
own token provider instance.

Design constraints carried from PRs 4 and 5:

- HTTP failures map to the collector-side exception types
  (``ManagementActivityHTTPError`` / ``GraphHTTPError``) so the
  collectors' classifiers (`_classify`) handle them without further
  translation.
- ``Retry-After`` headers (seconds or HTTP-date) populate the
  ``retry_after`` attribute on the wrapping exception, which the
  collector's classifier reads when wrapping as ``TransientError``.
- The HTTP transport is injectable. Production uses ``requests``.
  Tests pass a fake with .get/.post methods.

The clients are deliberately synchronous. The collector run loop is
synchronous and these calls happen on a polling schedule, not in a hot
path; async would add complexity without throughput benefit.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass
from email.utils import parsedate_to_datetime
from datetime import datetime, timezone
from typing import Any, Optional

from .microsoft365_collector import ManagementActivityHTTPError
from .microsoft_graph_collector import GraphHTTPError

logger = logging.getLogger(__name__)

# Entra token endpoint. The tenant GUID interpolates as a path segment.
TOKEN_ENDPOINT = "https://login.microsoftonline.com/{tenant_guid}/oauth2/v2.0/token"

# OAuth scopes for each API surface.
MANAGEMENT_ACTIVITY_SCOPE = "https://manage.office.com/.default"
GRAPH_SCOPE = "https://graph.microsoft.com/.default"

# Time buffer before expiry when we proactively refresh the token. The
# Entra default lifetime is 3600s; 60s of buffer is plenty.
TOKEN_REFRESH_BUFFER_SECONDS = 60.0

# Default request timeout. Operators can override per-client.
DEFAULT_TIMEOUT_SECONDS = 30.0


def _parse_retry_after(value: Optional[str]) -> Optional[float]:
    """Parse an HTTP ``Retry-After`` header. Returns seconds, or None."""
    if not value:
        return None
    value = value.strip()
    try:
        return max(0.0, float(value))
    except ValueError:
        pass
    try:
        when = parsedate_to_datetime(value)
        if when.tzinfo is None:
            when = when.replace(tzinfo=timezone.utc)
        delta = (when - datetime.now(timezone.utc)).total_seconds()
        return max(0.0, delta)
    except (TypeError, ValueError):
        return None


def _now() -> float:
    """Indirection point so tests can override the clock."""
    return time.time()


# ----------------------------------------------------------------- Token


class TokenAcquisitionError(Exception):
    """Raised when the Entra token endpoint refuses to issue a token.

    Carries the HTTP status code and the response body for the operator
    to read in the run-result error string. Common causes: wrong client
    id, wrong tenant guid, secret expired, app not granted the required
    scope, conditional access blocking the service principal.
    """

    def __init__(self, message: str, status_code: int, body: str = ""):
        super().__init__(f"token acquisition failed (HTTP {status_code}): {message}")
        self.status_code = status_code
        self.body = body


@dataclass
class _CachedToken:
    access_token: str
    expires_at: float  # epoch seconds


class TokenProvider:
    """OAuth2 client-credentials token provider with in-memory caching.

    Each instance is scoped to one (tenant, client, scope) tuple. Calling
    :meth:`get_token` returns a cached token until it is within
    :data:`TOKEN_REFRESH_BUFFER_SECONDS` of expiry, then refreshes.
    """

    def __init__(
        self,
        tenant_guid: str,
        client_id: str,
        client_secret: str,
        scope: str,
        transport: Any = None,
        timeout: float = DEFAULT_TIMEOUT_SECONDS,
    ):
        self.tenant_guid = tenant_guid
        self.client_id = client_id
        self.client_secret = client_secret
        self.scope = scope
        self.timeout = timeout
        self._transport = transport
        self._cached: Optional[_CachedToken] = None

    def _get_transport(self) -> Any:
        if self._transport is None:
            import requests
            self._transport = requests.Session()
        return self._transport

    def get_token(self) -> str:
        cached = self._cached
        if cached is not None and cached.expires_at - _now() > TOKEN_REFRESH_BUFFER_SECONDS:
            return cached.access_token
        return self._fetch_token()

    def _fetch_token(self) -> str:
        url = TOKEN_ENDPOINT.format(tenant_guid=self.tenant_guid)
        data = {
            "grant_type": "client_credentials",
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "scope": self.scope,
        }
        response = self._get_transport().post(url, data=data, timeout=self.timeout)
        status = _response_status(response)
        if status < 200 or status >= 300:
            raise TokenAcquisitionError(
                _response_text(response) or "no body",
                status_code=status,
                body=_response_text(response) or "",
            )
        body = _response_json(response)
        access_token = body.get("access_token")
        expires_in = body.get("expires_in")
        if not access_token or not isinstance(expires_in, (int, float)):
            raise TokenAcquisitionError(
                f"malformed token response: keys={sorted(body)}",
                status_code=status,
            )
        self._cached = _CachedToken(
            access_token=access_token,
            expires_at=_now() + float(expires_in),
        )
        return access_token

    def invalidate(self) -> None:
        """Drop the cached token. Used on 401 responses so the next call
        re-fetches even if our local clock disagrees with the server."""
        self._cached = None


# ----------------------------------------- Management Activity API client


class ManagementActivityHTTPClient:
    """Synchronous client for the Office 365 Management Activity API.

    Methods mirror the duck-typed contract the
    :class:`Microsoft365Collector` consumes: ``start_subscription``,
    ``list_content``, ``fetch_blob``.
    """

    BASE_URL = "https://manage.office.com/api/v1.0"

    def __init__(
        self,
        tenant_guid: str,
        client_id: str,
        client_secret: str,
        transport: Any = None,
        timeout: float = DEFAULT_TIMEOUT_SECONDS,
    ):
        self.tenant_guid = tenant_guid
        self.timeout = timeout
        self._transport = transport
        self._token = TokenProvider(
            tenant_guid=tenant_guid,
            client_id=client_id,
            client_secret=client_secret,
            scope=MANAGEMENT_ACTIVITY_SCOPE,
            transport=transport,
            timeout=timeout,
        )

    def _get_transport(self) -> Any:
        if self._transport is None:
            import requests
            self._transport = requests.Session()
        return self._transport

    def _auth_headers(self) -> dict:
        return {"Authorization": f"Bearer {self._token.get_token()}"}

    def _wrap_http(self, response: Any) -> None:
        status = _response_status(response)
        if 200 <= status < 300:
            return
        if status == 401:
            # Token might have been rotated on the server. Drop cache so
            # the next call re-fetches. We still raise here so the caller
            # decides what to do.
            self._token.invalidate()
        retry_after = _parse_retry_after(_response_header(response, "Retry-After"))
        raise ManagementActivityHTTPError(
            _response_text(response) or "no body",
            status_code=status,
            retry_after=retry_after,
        )

    def start_subscription(self, content_type: str) -> None:
        """Idempotent. The API returns 200 if already started."""
        url = f"{self.BASE_URL}/{self.tenant_guid}/activity/feed/subscriptions/start"
        params = {"contentType": content_type}
        response = self._get_transport().post(
            url, params=params, headers=self._auth_headers(), timeout=self.timeout,
        )
        # 400 ``AF20024`` ("subscription already enabled") is success for
        # our purposes. The Management Activity API uses this error code
        # to signal idempotency rather than returning 200.
        status = _response_status(response)
        if status == 400 and "AF20024" in (_response_text(response) or ""):
            return
        self._wrap_http(response)

    def list_content(
        self,
        content_type: str,
        start_time: str,
        end_time: str,
    ) -> list[dict]:
        """List content blobs for the given window. Walks the
        ``NextPageUri`` response header until exhausted.
        """
        url = f"{self.BASE_URL}/{self.tenant_guid}/activity/feed/subscriptions/content"
        params: Optional[dict] = {
            "contentType": content_type,
            "startTime": start_time,
            "endTime": end_time,
        }
        all_blobs: list[dict] = []
        next_url: Optional[str] = url
        while next_url:
            response = self._get_transport().get(
                next_url, params=params, headers=self._auth_headers(), timeout=self.timeout,
            )
            self._wrap_http(response)
            page = _response_json(response) or []
            if isinstance(page, list):
                all_blobs.extend(page)
            next_url = _response_header(response, "NextPageUri")
            # ``params`` only applies to the first call; the NextPageUri
            # carries its own query string.
            params = None
        return all_blobs

    def fetch_blob(self, content_uri: str) -> list[dict]:
        """Download a single blob. Returns the list of event dicts."""
        response = self._get_transport().get(
            content_uri, headers=self._auth_headers(), timeout=self.timeout,
        )
        self._wrap_http(response)
        body = _response_json(response)
        return body if isinstance(body, list) else []


# ------------------------------------------------------------ Graph client


class GraphHTTPClient:
    """Synchronous client for Microsoft Graph.

    Single ``get(url, params=None)`` method per the duck-typed contract
    consumed by :class:`MicrosoftGraphCollector`.
    """

    def __init__(
        self,
        tenant_guid: str,
        client_id: str,
        client_secret: str,
        transport: Any = None,
        timeout: float = DEFAULT_TIMEOUT_SECONDS,
    ):
        self.tenant_guid = tenant_guid
        self.timeout = timeout
        self._transport = transport
        self._token = TokenProvider(
            tenant_guid=tenant_guid,
            client_id=client_id,
            client_secret=client_secret,
            scope=GRAPH_SCOPE,
            transport=transport,
            timeout=timeout,
        )

    def _get_transport(self) -> Any:
        if self._transport is None:
            import requests
            self._transport = requests.Session()
        return self._transport

    def _auth_headers(self) -> dict:
        return {
            "Authorization": f"Bearer {self._token.get_token()}",
            "Accept": "application/json",
            "ConsistencyLevel": "eventual",  # required for $filter on some Graph endpoints
        }

    def get(self, url: str, params: Optional[dict] = None) -> dict:
        response = self._get_transport().get(
            url, params=params, headers=self._auth_headers(), timeout=self.timeout,
        )
        status = _response_status(response)
        if 200 <= status < 300:
            body = _response_json(response)
            return body if isinstance(body, dict) else {}
        if status == 401:
            self._token.invalidate()
        retry_after = _parse_retry_after(_response_header(response, "Retry-After"))
        raise GraphHTTPError(
            _response_text(response) or "no body",
            status_code=status,
            retry_after=retry_after,
        )


# ------------------------------------------------------- transport helpers
# These tiny adapters let the clients work with either a ``requests`` /
# ``requests.Session`` instance or a test fake exposing the same surface.


def _response_status(response: Any) -> int:
    return int(getattr(response, "status_code", 0))


def _response_text(response: Any) -> str:
    return getattr(response, "text", "") or ""


def _response_header(response: Any, name: str) -> Optional[str]:
    headers = getattr(response, "headers", None) or {}
    # case-insensitive lookup
    if hasattr(headers, "get"):
        # Prefer exact case-insensitive match if dict-like
        for key in (name, name.lower(), name.upper()):
            value = headers.get(key)
            if value is not None:
                return value
    return None


def _response_json(response: Any) -> Any:
    json_fn = getattr(response, "json", None)
    if callable(json_fn):
        try:
            return json_fn()
        except Exception:  # noqa: BLE001
            return None
    return None
