"""
Production HTTP client for the GitHub Audit Log API.

Single class, ``GitHubAuditClient``, with the same surface the
:class:`GitHubAuditCollector` consumes:

  - list_logs(phrase, include, per_page) -> {"items": [...], "next_url": ...}
  - list_next(url)                        -> {"items": [...], "next_url": ...}

Two URL prefixes are supported, selected by the ``scope_path`` constructor
argument:

  - ``orgs/{org}``           -> ``GET /orgs/{org}/audit-log``
  - ``enterprises/{ent}``    -> ``GET /enterprises/{ent}/audit-log``

Authentication is a Bearer token. PATs, fine-grained tokens, and
GitHub App installation tokens all use the same ``Authorization:
Bearer ...`` header. The token must hold ``read:audit_log`` for orgs
or ``read:enterprise`` (and the audit-log permission) for enterprises.
"""

from __future__ import annotations

import logging
import re
from email.utils import parsedate_to_datetime
from datetime import datetime, timezone
from typing import Any, Optional

from .github_collector import GitHubHTTPError

logger = logging.getLogger(__name__)

DEFAULT_TIMEOUT_SECONDS = 30.0
API_BASE_URL = "https://api.github.com"

# X-GitHub-Api-Version header value. Pin to a known-good version so the
# response shape doesn't shift under us silently when GitHub introduces
# a new default.
GITHUB_API_VERSION = "2022-11-28"

# Same Link-header shape as Okta: ``<url>; rel="next"``.
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


def _parse_primary_rate_limit_headers(headers: Any) -> Optional[float]:
    """GitHub's primary rate-limit signal sometimes uses ``X-RateLimit-Reset``
    (epoch seconds) instead of ``Retry-After`` for 429 responses. Returning
    seconds-until-reset lets the collector wait the right amount.
    """
    if headers is None or not hasattr(headers, "get"):
        return None
    raw = headers.get("X-RateLimit-Reset") or headers.get("x-ratelimit-reset")
    if not raw:
        return None
    try:
        reset_at = float(raw)
    except (TypeError, ValueError):
        return None
    now = datetime.now(timezone.utc).timestamp()
    return max(0.0, reset_at - now)


class GitHubAuditClient:
    """Synchronous client for the GitHub Audit Log API."""

    def __init__(
        self,
        scope_path: str,
        token: str,
        transport: Any = None,
        timeout: float = DEFAULT_TIMEOUT_SECONDS,
        base_url: str = API_BASE_URL,
    ):
        if not scope_path.startswith(("orgs/", "enterprises/")):
            raise ValueError(
                f"scope_path must be 'orgs/<slug>' or 'enterprises/<slug>', got {scope_path!r}"
            )
        self.scope_path = scope_path
        self.token = token
        self.timeout = timeout
        self.base_url = base_url.rstrip("/")
        self._transport = transport

    def _get_transport(self) -> Any:
        if self._transport is None:
            import requests
            self._transport = requests.Session()
        return self._transport

    def _headers(self) -> dict:
        return {
            "Authorization": f"Bearer {self.token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": GITHUB_API_VERSION,
        }

    def list_logs(self, phrase: str, include: str, per_page: int = 100) -> dict:
        url = f"{self.base_url}/{self.scope_path}/audit-log"
        params = {"phrase": phrase, "include": include, "per_page": per_page, "order": "asc"}
        return self._get(url, params=params)

    def list_next(self, url: str) -> dict:
        """Fetch the next page. ``url`` is fully qualified with all params."""
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
        # Prefer Retry-After; fall back to X-RateLimit-Reset (GitHub-specific).
        retry_after = _parse_retry_after(_response_header(response, "Retry-After"))
        if retry_after is None:
            retry_after = _parse_primary_rate_limit_headers(getattr(response, "headers", None))
        raise GitHubHTTPError(
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
