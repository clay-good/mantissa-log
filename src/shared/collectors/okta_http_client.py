"""
Production HTTP client for the Okta System Log API.

Single class, ``OktaSystemLogClient``. Two methods matching the
duck-typed contract that :class:`OktaCollector` consumes:

  - list_logs(since, until, limit) -> {"items": [...], "next_url": ...}
  - list_next(url)                  -> {"items": [...], "next_url": ...}

Pagination uses the standard Okta ``Link`` header with ``rel="next"``
URLs. The collector receives a normalized ``next_url`` in the page
dict so it does not need to parse Link headers itself.

Authentication uses an Okta API token (``SSWS`` scheme). Tokens live
in the configured ``SecretStore`` under ``okta/{tenant_id}/api_token``.
The token does not expire on its own; rotate per Okta security
guidance.
"""

from __future__ import annotations

import logging
import re
from email.utils import parsedate_to_datetime
from datetime import datetime, timezone
from typing import Any, Optional

from .okta_collector import OktaHTTPError

logger = logging.getLogger(__name__)

DEFAULT_TIMEOUT_SECONDS = 30.0

# Matches a Link header element such as
#   <https://acme.okta.com/api/v1/logs?after=ABC>; rel="next"
_LINK_RE = re.compile(r'<(?P<url>[^>]+)>\s*;\s*rel="(?P<rel>[^"]+)"')


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


def _extract_next_url(link_header: Optional[str]) -> Optional[str]:
    if not link_header:
        return None
    for match in _LINK_RE.finditer(link_header):
        if match.group("rel") == "next":
            return match.group("url")
    return None


class OktaSystemLogClient:
    """Synchronous client for the Okta System Log API."""

    def __init__(
        self,
        domain: str,
        api_token: str,
        transport: Any = None,
        timeout: float = DEFAULT_TIMEOUT_SECONDS,
    ):
        # ``domain`` is e.g. ``acme.okta.com``. Normalize to a base URL.
        if not domain.startswith("http"):
            base = f"https://{domain}"
        else:
            base = domain.rstrip("/")
        self.base_url = base
        self.api_token = api_token
        self.timeout = timeout
        self._transport = transport

    def _get_transport(self) -> Any:
        if self._transport is None:
            import requests
            self._transport = requests.Session()
        return self._transport

    def _headers(self) -> dict:
        return {
            "Authorization": f"SSWS {self.api_token}",
            "Accept": "application/json",
        }

    def list_logs(self, since: str, until: str, limit: int = 1000) -> dict:
        url = f"{self.base_url}/api/v1/logs"
        params = {"since": since, "until": until, "limit": limit}
        return self._get(url, params=params)

    def list_next(self, url: str) -> dict:
        """Fetch the next page using the previously emitted next_url.

        ``next_url`` is fully qualified including all query parameters,
        so this call carries no additional params.
        """
        return self._get(url, params=None)

    # ---- internals ----------------------------------------------------------

    def _get(self, url: str, params: Optional[dict]) -> dict:
        response = self._get_transport().get(
            url, params=params, headers=self._headers(), timeout=self.timeout,
        )
        status = _response_status(response)
        if 200 <= status < 300:
            body = _response_json(response)
            items = body if isinstance(body, list) else []
            next_url = _extract_next_url(_response_header(response, "Link"))
            return {"items": items, "next_url": next_url}
        retry_after = _parse_retry_after(_response_header(response, "Retry-After"))
        raise OktaHTTPError(
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
