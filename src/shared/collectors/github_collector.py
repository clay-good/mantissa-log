"""
GitHub Audit Log collector for mantissa-log.

PR 11 of SAAS_IDENTITY_SPEC (§10 follow-on pack, second of three).

GitHub exposes one audit-log endpoint per organization or per
enterprise. The shape is a flat stream of events; pages walk through a
``Link: <...>; rel="next"`` header, the same pattern as Okta.

Why ship this. PR 6's destructive-event rule pack includes
``dest_github_repo_made_public_or_deleted``. Without an audit-log
collector that rule never fires. The parser at
``src/shared/parsers/github.py`` already exists; this PR closes the
ingest gap.

Tenant model. GitHub audit logs live under two roots:

  - ``orgs/{org}/audit-log``        for organizations
  - ``enterprises/{enterprise}/audit-log`` for GitHub Enterprise Cloud

The collector takes the ``tenant_id`` field as the full scope path,
e.g. ``orgs/acme`` or ``enterprises/big-co``. The runtime is the same
either way; only the URL path differs.

Time model. GitHub's audit log uses ``@timestamp`` (Unix epoch
milliseconds) as the event-time field. We normalize this to an ISO
8601 string ``event_time`` so the lake schema stays consistent with
the other collectors. ``_document_id`` is the stable per-event id.

The collector reuses the same boundary-filter pattern (strict open
interval) and the same TransientError classifier shape (429/5xx
retried, 4xx other than 429 surfaces as feed error).
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any, Callable, Iterator, Optional

from .base_saas_collector import BaseSaaSCollector
from .saas_lake import RawLakeWriter
from .saas_retry import RetryPolicy, TransientError
from .saas_secrets import SecretStore
from .saas_state import WatermarkStore

logger = logging.getLogger(__name__)

DEFAULT_BACKFILL_DAYS = 7
MAX_PAGE_SIZE = 100  # GitHub's hard cap on /audit-log

# What audit-log events to include. The "all" value returns Git events
# (clones, pushes) in addition to web/API events. Git events are noisy
# for many tenants but valuable for detecting code exfil; default to
# "all" so destructive-event rules can match repo events that ride the
# Git protocol.
DEFAULT_INCLUDE = "all"


def _format_github_iso(when: datetime) -> str:
    """ISO 8601 with Z, seconds resolution. Matches what GitHub returns."""
    if when.tzinfo is None:
        when = when.replace(tzinfo=timezone.utc)
    return when.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _from_millis(value: Any) -> Optional[datetime]:
    """Parse a GitHub ``@timestamp`` (epoch milliseconds) to a UTC datetime."""
    if value is None:
        return None
    try:
        ms = int(value)
    except (TypeError, ValueError):
        return None
    return datetime.fromtimestamp(ms / 1000.0, tz=timezone.utc)


class GitHubHTTPError(Exception):
    """Wraps any HTTP failure from the GitHub audit-log API."""

    def __init__(self, message: str, status_code: int, retry_after: Optional[float] = None):
        super().__init__(f"HTTP {status_code}: {message}")
        self.status_code = status_code
        self.retry_after = retry_after


def _classify(exc: Exception) -> Optional[TransientError]:
    code = getattr(exc, "status_code", None)
    if code is None:
        return None
    try:
        code = int(code)
    except (TypeError, ValueError):
        return None
    if code == 408 or code == 429 or 500 <= code < 600:
        return TransientError(str(exc), retry_after=getattr(exc, "retry_after", None))
    return None


class GitHubAuditCollector(BaseSaaSCollector):
    source_name = "github"
    default_backfill_days = DEFAULT_BACKFILL_DAYS

    DEFAULT_FEEDS = ("audit",)
    ALL_FEEDS = DEFAULT_FEEDS

    def __init__(
        self,
        tenant_id: str,
        watermark_store: WatermarkStore,
        secret_store: SecretStore,
        lake_writer: RawLakeWriter,
        retry_policy: RetryPolicy = RetryPolicy(),
        feeds: tuple[str, ...] = DEFAULT_FEEDS,
        client_factory: Optional[Callable[[str], Any]] = None,
        page_size: int = MAX_PAGE_SIZE,
        include: str = DEFAULT_INCLUDE,
    ):
        super().__init__(
            tenant_id=tenant_id,
            watermark_store=watermark_store,
            secret_store=secret_store,
            lake_writer=lake_writer,
            retry_policy=retry_policy,
        )
        unknown = set(feeds) - set(self.ALL_FEEDS)
        if unknown:
            raise ValueError(f"unknown github feeds: {sorted(unknown)}")
        if "/" not in tenant_id or not tenant_id.startswith(("orgs/", "enterprises/")):
            raise ValueError(
                f"tenant_id must be 'orgs/<slug>' or 'enterprises/<slug>', got {tenant_id!r}"
            )
        if include not in ("web", "git", "all"):
            raise ValueError(f"include must be 'web', 'git', or 'all', got {include!r}")
        self._feeds = tuple(feeds)
        self._client_factory = client_factory
        self._client: Any = None
        self._page_size = min(page_size, MAX_PAGE_SIZE)
        self._include = include

    def list_feeds(self) -> list[str]:
        return list(self._feeds)

    # ---- client construction -------------------------------------------------

    def _build_client(self) -> Any:
        token = self.secrets.require(f"github/{self.tenant_id}/token")
        from .github_http_client import GitHubAuditClient  # type: ignore[import-not-found]
        return GitHubAuditClient(scope_path=self.tenant_id, token=token)

    def _get_client(self) -> Any:
        if self._client is None:
            if self._client_factory is not None:
                self._client = self._client_factory(self.tenant_id)
            else:
                self._client = self._build_client()
        return self._client

    # ---- fetch ---------------------------------------------------------------

    def fetch_feed(
        self,
        feed: str,
        since: datetime,
        until: datetime,
    ) -> Iterator[dict]:
        if feed not in self.ALL_FEEDS:
            raise ValueError(f"feed not enabled: {feed}")

        client = self._get_client()

        # GitHub uses a ``phrase`` filter for date ranges with the syntax
        # ``created:YYYY-MM-DD..YYYY-MM-DD``. We use the more precise
        # ``created:>=ISO..<=ISO`` form which the API supports and which
        # matches the strict open interval we apply downstream.
        phrase = f"created:>={_format_github_iso(since)} created:<={_format_github_iso(until)}"

        try:
            first_page = client.list_logs(
                phrase=phrase, include=self._include, per_page=self._page_size,
            )
        except Exception as exc:
            transient = _classify(exc)
            if transient is not None:
                raise transient from exc
            raise

        return self._walk(client, first_page, since, until)

    def _walk(
        self,
        client: Any,
        first_page: dict,
        since: datetime,
        until: datetime,
    ) -> Iterator[dict]:
        page = first_page
        while True:
            for item in page.get("items") or []:
                t = _from_millis(item.get("@timestamp"))
                if t is None:
                    logger.warning(
                        "github.event_missing_timestamp document_id=%s",
                        item.get("_document_id"),
                    )
                    continue
                # Strict open interval. GitHub's phrase filter is inclusive
                # on both bounds; this final filter keeps the watermark
                # advance well-defined when an event occurs exactly at the
                # boundary instant.
                if t <= since or t >= until:
                    continue
                # Normalize the event time to a string for the base run loop
                # and store the original millis alongside it for queries.
                iso = t.strftime("%Y-%m-%dT%H:%M:%SZ")
                item.setdefault("event_time", iso)
                item.setdefault("event_id", item.get("_document_id") or "")
                yield item

            next_url = page.get("next_url")
            if not next_url:
                return
            try:
                page = client.list_next(next_url)
            except Exception as exc:
                transient = _classify(exc)
                if transient is not None:
                    raise transient from exc
                raise
