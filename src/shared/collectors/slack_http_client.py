"""
Production HTTP client for the Slack Audit Logs API.

Single class, ``SlackAuditClient``, matching the duck-typed contract
:class:`SlackAuditCollector` consumes:

  - list_logs(oldest, latest, limit) -> {"items": [...], "next_cursor": ...}
  - list_next(cursor)                 -> {"items": [...], "next_cursor": ...}

Slack returns paginated responses with a ``response_metadata.next_cursor``
field. The client normalizes that into a plain ``next_cursor`` string
in the page dict the collector receives.

Slack uses two distinct failure modes:

  - Transport-level HTTP errors (4xx / 5xx with no JSON body, or 429
    with a ``Retry-After`` header).
  - Application-level errors (200 OK with body ``{"ok": false,
    "error": "..."}``). These are common for token / scope issues.

The client surfaces both via ``SlackHTTPError`` so the collector's
classifier can decide which are transient. Application errors keep
the HTTP status at 200 in the exception unless they map to a known
rate-limit-flavoured error code (``ratelimited``), in which case the
client synthesizes a 429.
"""

from __future__ import annotations

import logging
from email.utils import parsedate_to_datetime
from datetime import datetime, timezone
from typing import Any, Optional

from .slack_collector import SlackHTTPError

logger = logging.getLogger(__name__)

DEFAULT_TIMEOUT_SECONDS = 30.0
AUDIT_LOGS_ENDPOINT = "https://api.slack.com/audit/v1/logs"


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


class SlackAuditClient:
    """Synchronous client for the Slack Audit Logs API."""

    def __init__(
        self,
        token: str,
        transport: Any = None,
        timeout: float = DEFAULT_TIMEOUT_SECONDS,
        endpoint: str = AUDIT_LOGS_ENDPOINT,
    ):
        self.token = token
        self.timeout = timeout
        self.endpoint = endpoint
        self._transport = transport

    def _get_transport(self) -> Any:
        if self._transport is None:
            import requests
            self._transport = requests.Session()
        return self._transport

    def _headers(self) -> dict:
        return {
            "Authorization": f"Bearer {self.token}",
            "Accept": "application/json",
        }

    def list_logs(self, oldest: int, latest: int, limit: int = 1000) -> dict:
        params = {"oldest": oldest, "latest": latest, "limit": limit}
        return self._get(params=params)

    def list_next(self, cursor: str) -> dict:
        """Fetch the next page using Slack's cursor.

        Unlike Okta's and GitHub's URL-based pagination, Slack returns a
        bare cursor string that the client carries on the next call as
        a query parameter.
        """
        return self._get(params={"cursor": cursor})

    # ---- internals ----------------------------------------------------------

    def _get(self, params: dict) -> dict:
        response = self._get_transport().get(
            self.endpoint, params=params, headers=self._headers(), timeout=self.timeout,
        )
        status = _response_status(response)
        retry_after = _parse_retry_after(_response_header(response, "Retry-After"))

        # Transport-level error.
        if status < 200 or status >= 300:
            raise SlackHTTPError(
                _response_text(response) or "no body",
                status_code=status,
                retry_after=retry_after,
            )

        # Body-level error. Slack returns 200 OK with ``{"ok": false}``
        # for application failures. We surface those as a synthesized
        # HTTP error so the collector classifier handles them uniformly.
        body = _response_json(response)
        if not isinstance(body, dict):
            return {"items": [], "next_cursor": None}
        if body.get("ok") is False:
            error_code = body.get("error") or "unknown_slack_error"
            # ``ratelimited`` is Slack's app-layer rate-limit signal.
            # Translate it to status 429 so the collector retries with
            # backoff rather than surfacing it as a terminal failure.
            synthesized_status = 429 if error_code == "ratelimited" else 400
            raise SlackHTTPError(
                f"slack.api ok=false error={error_code}",
                status_code=synthesized_status,
                retry_after=retry_after,
            )

        entries = body.get("entries")
        items = entries if isinstance(entries, list) else []
        next_cursor = ((body.get("response_metadata") or {}).get("next_cursor")) or None
        # Slack returns an empty string when there are no more pages.
        if isinstance(next_cursor, str) and next_cursor.strip() == "":
            next_cursor = None
        return {"items": items, "next_cursor": next_cursor}


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
