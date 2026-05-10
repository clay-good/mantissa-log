"""
Slack Audit Logs collector for mantissa-log.

PR 12 of SAAS_IDENTITY_SPEC (§10 follow-on pack, third of four).

Slack's Audit Logs API (Enterprise Grid only) exposes one endpoint that
returns a flat stream of audit events. Pagination uses Slack's
``response_metadata.next_cursor`` convention rather than a Link header,
which keeps the client a touch simpler than GitHub's or Okta's.

Why ship this. PR 6's destructive-event rule pack does not yet have a
Slack-specific rule, but the Slack parser exists and operators
ingesting Slack audit data want cross-source identity correlation
(Slack workspace export, channel external sharing, app installs that
touch DLP scopes). Cross-source queries land here once events are in
the lake.

Tenant model. Slack's Enterprise Grid audit API is org-scoped. The
``tenant_id`` is whatever name the operator picks for the workspace or
org (used purely for partitioning the lake; Slack does not encode it
in the URL).

Auth model. A single Slack token with ``auditlogs:read`` scope. Token
lives at ``slack/{tenant_id}/audit_token``. The token is typically an
Enterprise Grid org-level user token issued to an admin who has
installed an app that requests the scope.

Time model. Slack uses ``date_create`` (Unix epoch seconds, integer)
as the event-time field. We normalize to ISO 8601 string ``event_time``
for the lake payload while preserving the original numeric value.
``id`` is the stable per-event identifier.
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
# Slack's documented hard cap is 9999; the practical sweet spot is 1000.
MAX_PAGE_SIZE = 1000


def _to_epoch_seconds(when: datetime) -> int:
    if when.tzinfo is None:
        when = when.replace(tzinfo=timezone.utc)
    return int(when.astimezone(timezone.utc).timestamp())


def _from_epoch_seconds(value: Any) -> Optional[datetime]:
    if value is None:
        return None
    try:
        secs = int(value)
    except (TypeError, ValueError):
        return None
    return datetime.fromtimestamp(secs, tz=timezone.utc)


class SlackHTTPError(Exception):
    """Wraps any HTTP failure from the Slack Audit Logs API.

    Slack's audit endpoint returns 200 with ``{"ok": false, "error": ...}``
    for application-layer failures, plus the standard HTTP status codes
    for transport / rate-limit failures. The client surfaces both via
    this exception so the collector classifier handles them uniformly.
    """

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


class SlackAuditCollector(BaseSaaSCollector):
    source_name = "slack"
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
            raise ValueError(f"unknown slack feeds: {sorted(unknown)}")
        self._feeds = tuple(feeds)
        self._client_factory = client_factory
        self._client: Any = None
        self._page_size = min(page_size, MAX_PAGE_SIZE)

    def list_feeds(self) -> list[str]:
        return list(self._feeds)

    # ---- client construction -------------------------------------------------

    def _build_client(self) -> Any:
        token = self.secrets.require(f"slack/{self.tenant_id}/audit_token")
        from .slack_http_client import SlackAuditClient  # type: ignore[import-not-found]
        return SlackAuditClient(token=token)

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

        try:
            first_page = client.list_logs(
                oldest=_to_epoch_seconds(since),
                latest=_to_epoch_seconds(until),
                limit=self._page_size,
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
                t = _from_epoch_seconds(item.get("date_create"))
                if t is None:
                    logger.warning("slack.event_missing_date_create id=%s", item.get("id"))
                    continue
                if t <= since or t >= until:
                    continue
                item.setdefault("event_time", t.strftime("%Y-%m-%dT%H:%M:%SZ"))
                item.setdefault("event_id", item.get("id") or "")
                yield item

            next_cursor = page.get("next_cursor")
            if not next_cursor:
                return
            try:
                page = client.list_next(next_cursor)
            except Exception as exc:
                transient = _classify(exc)
                if transient is not None:
                    raise transient from exc
                raise
