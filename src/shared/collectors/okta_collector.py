"""
Okta System Log collector for mantissa-log.

PR 10 of SAAS_IDENTITY_SPEC (follow-on §10: SaaS collectors pack).

Okta is structurally simpler than the M365 collectors. The System Log
is a single time-series endpoint exposing every audit event in a flat
stream. There is no subscription model and no blob fetch; pages are
walked via a ``Link`` header with ``rel="next"``.

Why ship this here. PR 6's destructive-event rule pack already
includes two Okta rules (``dest_okta_super_admin_granted`` and
``dest_okta_mfa_factor_reset_for_admin``) that assume Okta events are
in the lake. Without a collector those rules never fire. The Okta
System Log parser at ``src/shared/parsers/okta.py`` was already in
place; this collector closes the ingest gap.

Authentication model. Okta API tokens (Bearer header). Token lives in
``okta/{tenant_id}/api_token``. The tenant id is the Okta domain
(``acme.okta.com`` or ``acme.oktapreview.com``); the collector uses it
both to derive the base URL and as the partition tenant.

Field map:
  - event_time           <-  raw["published"]   (ISO 8601 with Z)
  - event_id             <-  raw["uuid"]
  - actor                <-  raw["actor"]["alternateId"]
  - eventType            <-  raw["eventType"]    (used by Sigma rules)

The collector uses one logical feed ``system`` covering the entire
System Log. Operators wanting per-event-type partitions can re-shape
on read in SQL; pre-splitting at ingest would explode partition count
without query benefit.
"""

from __future__ import annotations

import json
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
MAX_PAGE_SIZE = 1000


def _parse_iso(value: str) -> datetime:
    if value.endswith("Z"):
        value = value[:-1] + "+00:00"
    return datetime.fromisoformat(value).astimezone(timezone.utc)


def _format_okta_iso(when: datetime) -> str:
    """Okta accepts ISO 8601 with millisecond resolution and Z suffix."""
    if when.tzinfo is None:
        when = when.replace(tzinfo=timezone.utc)
    when = when.astimezone(timezone.utc)
    return when.strftime("%Y-%m-%dT%H:%M:%S.000Z")


class OktaHTTPError(Exception):
    """Wraps any HTTP failure from the Okta System Log API.

    Carries ``status_code`` and optional ``retry_after`` so the
    collector classifier wraps retryable failures as ``TransientError``.
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


class OktaCollector(BaseSaaSCollector):
    source_name = "okta"
    default_backfill_days = DEFAULT_BACKFILL_DAYS

    DEFAULT_FEEDS = ("system",)
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
            raise ValueError(f"unknown okta feeds: {sorted(unknown)}")
        self._feeds = tuple(feeds)
        self._client_factory = client_factory
        self._client: Any = None
        self._page_size = min(page_size, MAX_PAGE_SIZE)

    def list_feeds(self) -> list[str]:
        return list(self._feeds)

    # ---- client construction -------------------------------------------------

    def _build_client(self) -> Any:
        api_token = self.secrets.require(f"okta/{self.tenant_id}/api_token")
        from .okta_http_client import OktaSystemLogClient  # type: ignore[import-not-found]
        return OktaSystemLogClient(domain=self.tenant_id, api_token=api_token)

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
                since=_format_okta_iso(since),
                until=_format_okta_iso(until),
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
                t_str = item.get("published")
                if not t_str:
                    logger.warning("okta.event_missing_published uuid=%s", item.get("uuid"))
                    continue
                try:
                    t = _parse_iso(t_str)
                except ValueError:
                    logger.warning("okta.event_bad_time value=%s", t_str)
                    continue
                # Strict open-interval filter on (since, until). Okta's
                # ``since`` is inclusive; without this we'd re-emit the
                # boundary event each poll.
                if t <= since or t >= until:
                    continue
                item.setdefault("event_time", t_str)
                item.setdefault("event_id", item.get("uuid") or "")
                yield item

            next_url = page.get("next_url")
            if not next_url:
                return
            try:
                page = client.list_next(next_url)
            except Exception as exc:
                # Per base contract, streaming errors are not retried by
                # the run loop; the base class catches them as feed-level
                # errors so the operator sees which page failed.
                transient = _classify(exc)
                if transient is not None:
                    raise transient from exc
                raise
