"""
Production HTTP client for Salesforce Event Monitoring.

Two methods matching the duck-typed contract :class:`SalesforceCollector`
consumes:

  - list_log_files(since, until) -> list[dict]   # EventLogFile records
  - fetch_log_file(url)          -> list[dict]   # rows from the CSV

Authentication uses OAuth 2.0 client-credentials against the Salesforce
login endpoint. The token response includes both an ``access_token`` and
the org's ``instance_url`` which the client uses thereafter.

Pagination on the SOQL query is handled internally via the standard
``nextRecordsUrl`` / ``done`` fields, so callers see one flat list of
``EventLogFile`` records.

Salesforce returns events as CSV in the ``LogFile`` body. The client
parses the CSV (with ``csv.DictReader``) and yields each row as a dict
so the collector's iterator does not need to know the body format.
"""

from __future__ import annotations

import csv
import io
import logging
import time
from dataclasses import dataclass
from email.utils import parsedate_to_datetime
from datetime import datetime, timezone
from typing import Any, Optional

from .salesforce_collector import SalesforceHTTPError

logger = logging.getLogger(__name__)

DEFAULT_TIMEOUT_SECONDS = 30.0
DEFAULT_API_VERSION = "v59.0"
LOGIN_TOKEN_PATH = "/services/oauth2/token"
TOKEN_REFRESH_BUFFER_SECONDS = 60.0


def _parse_retry_after(value: Optional[str]) -> Optional[float]:
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
    return time.time()


@dataclass
class _CachedToken:
    access_token: str
    instance_url: str
    expires_at: float


class SalesforceTokenError(Exception):
    def __init__(self, message: str, status_code: int, body: str = ""):
        super().__init__(f"salesforce token failed (HTTP {status_code}): {message}")
        self.status_code = status_code
        self.body = body


class SalesforceEventClient:
    """Synchronous client for Salesforce Event Monitoring."""

    def __init__(
        self,
        instance_url: str,
        client_id: str,
        client_secret: str,
        login_url: Optional[str] = None,
        api_version: str = DEFAULT_API_VERSION,
        transport: Any = None,
        timeout: float = DEFAULT_TIMEOUT_SECONDS,
    ):
        # ``instance_url`` is the org's base URL. Used both for the API
        # calls and as the default login host. If the org uses a separate
        # login endpoint (e.g. https://login.salesforce.com), set
        # ``login_url`` explicitly.
        self.instance_url = instance_url.rstrip("/")
        self.login_url = (login_url or instance_url).rstrip("/")
        self.client_id = client_id
        self.client_secret = client_secret
        self.api_version = api_version
        self.timeout = timeout
        self._transport = transport
        self._cached: Optional[_CachedToken] = None

    # ---- token management ---------------------------------------------------

    def _get_transport(self) -> Any:
        if self._transport is None:
            import requests
            self._transport = requests.Session()
        return self._transport

    def get_token(self) -> tuple[str, str]:
        cached = self._cached
        if cached is not None and cached.expires_at - _now() > TOKEN_REFRESH_BUFFER_SECONDS:
            return cached.access_token, cached.instance_url
        return self._fetch_token()

    def _fetch_token(self) -> tuple[str, str]:
        url = f"{self.login_url}{LOGIN_TOKEN_PATH}"
        data = {
            "grant_type": "client_credentials",
            "client_id": self.client_id,
            "client_secret": self.client_secret,
        }
        response = self._get_transport().post(url, data=data, timeout=self.timeout)
        status = _response_status(response)
        if status < 200 or status >= 300:
            raise SalesforceTokenError(
                _response_text(response) or "no body",
                status_code=status,
                body=_response_text(response) or "",
            )
        body = _response_json(response) or {}
        access_token = body.get("access_token")
        instance_url = body.get("instance_url") or self.instance_url
        # Salesforce tokens don't expose expires_in in client-credentials
        # flow; default to 60 minutes which is the documented lifetime.
        expires_in = float(body.get("expires_in") or 3600)
        if not access_token:
            raise SalesforceTokenError(
                f"malformed token response: keys={sorted(body)}",
                status_code=status,
            )
        self._cached = _CachedToken(
            access_token=access_token,
            instance_url=instance_url,
            expires_at=_now() + expires_in,
        )
        return access_token, instance_url

    def invalidate(self) -> None:
        self._cached = None

    # ---- API surface --------------------------------------------------------

    def list_log_files(self, since: str, until: str) -> list[dict]:
        """SOQL-query the EventLogFile records in the time window.

        Walks paginated responses via ``nextRecordsUrl`` and returns one
        flat list to the caller. Each record carries an ``Id``,
        ``EventType``, ``LogDate``, ``LogFileLength``, and ``LogFile`` URL.
        """
        token, instance = self.get_token()
        query = (
            "SELECT Id, EventType, LogDate, LogFileLength, LogFile "
            "FROM EventLogFile "
            f"WHERE LogDate >= {since} AND LogDate < {until} "
            "ORDER BY LogDate ASC"
        )
        url = f"{instance}/services/data/{self.api_version}/query"
        records: list[dict] = []
        params: Optional[dict] = {"q": query}
        while True:
            response = self._get_transport().get(
                url, params=params, headers=self._auth_headers(token), timeout=self.timeout,
            )
            self._wrap_http(response)
            body = _response_json(response) or {}
            for record in body.get("records") or []:
                records.append(record)
            if body.get("done", True):
                break
            next_url = body.get("nextRecordsUrl")
            if not next_url:
                break
            url = f"{instance}{next_url}"
            params = None
        return records

    def fetch_log_file(self, log_file_url: str) -> list[dict]:
        """Fetch a single EventLogFile body and parse the CSV.

        ``log_file_url`` is the relative path Salesforce returns in the
        ``LogFile`` attribute. We resolve it against the instance URL.
        """
        token, instance = self.get_token()
        if log_file_url.startswith("http"):
            url = log_file_url
        else:
            url = f"{instance}{log_file_url}"
        response = self._get_transport().get(
            url, headers=self._auth_headers(token), timeout=self.timeout,
        )
        self._wrap_http(response)
        text = _response_text(response)
        if not text:
            return []
        try:
            reader = csv.DictReader(io.StringIO(text))
            return list(reader)
        except csv.Error as exc:
            raise SalesforceHTTPError(
                f"csv parse error: {exc}", status_code=502,  # treat as bad upstream payload
            )

    # ---- internals ----------------------------------------------------------

    def _auth_headers(self, token: str) -> dict:
        return {
            "Authorization": f"Bearer {token}",
            "Accept": "application/json",
        }

    def _wrap_http(self, response: Any) -> None:
        status = _response_status(response)
        if 200 <= status < 300:
            return
        if status == 401:
            self.invalidate()
        retry_after = _parse_retry_after(_response_header(response, "Retry-After"))
        raise SalesforceHTTPError(
            _response_text(response) or "no body",
            status_code=status,
            retry_after=retry_after,
        )


# ----------------------------------------------------- transport helpers


def _response_status(response: Any) -> int:
    return int(getattr(response, "status_code", 0))


def _response_text(response: Any) -> str:
    return getattr(response, "text", "") or ""


def _response_header(response: Any, name: str) -> Optional[str]:
    headers = getattr(response, "headers", None) or {}
    if hasattr(headers, "get"):
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
