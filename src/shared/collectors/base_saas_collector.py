"""
Base class for SaaS collectors (Google Workspace, Microsoft 365, Okta, etc.).

A SaaS collector is a long-lived, scheduled poller that:

  1. Reads its watermark for each (source, tenant, feed) tuple from the
     watermark store.
  2. Calls a source-specific ``fetch_feed`` to pull events newer than the
     watermark, in time order.
  3. Writes the raw events to the lake's ``raw/`` prefix as gzipped JSONL.
  4. Advances the watermark.
  5. Repeats per scheduled tick or per long-running loop.

Source-specific subclasses (mantissa-log's GoogleWorkspaceCollector,
Microsoft365Collector, etc.) implement two abstract methods:

  - ``list_feeds()``       -> ['login', 'admin', 'drive', 'token', ...]
  - ``fetch_feed(feed, since, until)`` -> Iterator[dict]

Everything else (watermarking, retries, lake writes, backfill semantics) is
handled by this base class. Per the consolidation decision in the spec, this
class is intentionally NOT shared with mantissa-stance. The two tools
duplicate ~200 lines of OAuth glue and the run-loop primitives, and that
is the cheaper trade.
"""

from __future__ import annotations

import logging
import uuid
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Iterable, Iterator, Optional

from .saas_lake import RawLakeWriter
from .saas_retry import RetryPolicy, retry_call
from .saas_secrets import SecretStore
from .saas_state import Watermark, WatermarkStore

logger = logging.getLogger(__name__)


@dataclass
class FeedRunResult:
    feed: str
    events_written: int
    batches_written: int
    bytes_written_estimate: int
    new_watermark: Optional[Watermark]
    error: Optional[str] = None


@dataclass
class CollectorRunResult:
    source: str
    tenant_id: str
    started_at: datetime
    finished_at: datetime
    feeds: list[FeedRunResult] = field(default_factory=list)

    @property
    def total_events(self) -> int:
        return sum(f.events_written for f in self.feeds)

    @property
    def succeeded(self) -> bool:
        return all(f.error is None for f in self.feeds)


class BaseSaaSCollector(ABC):
    """Abstract base class. Subclasses set ``source_name`` and implement the
    two abstract methods. The run loop is provided by this class."""

    #: Stable short identifier used in lake partition paths. e.g. ``gws``.
    source_name: str = ""

    #: How many days back to fetch on first run when no watermark exists.
    default_backfill_days: int = 7

    #: How many events to buffer per batch file in the lake.
    batch_size: int = 1000

    def __init__(
        self,
        tenant_id: str,
        watermark_store: WatermarkStore,
        secret_store: SecretStore,
        lake_writer: RawLakeWriter,
        retry_policy: RetryPolicy = RetryPolicy(),
    ):
        if not self.source_name:
            raise ValueError(f"{type(self).__name__}.source_name must be set")
        self.tenant_id = tenant_id
        self.watermarks = watermark_store
        self.secrets = secret_store
        self.lake = lake_writer
        self.retry_policy = retry_policy

    @abstractmethod
    def list_feeds(self) -> list[str]:
        """Return the logical feed names for this source."""

    @abstractmethod
    def fetch_feed(
        self,
        feed: str,
        since: datetime,
        until: datetime,
    ) -> Iterator[dict]:
        """Return events for ``feed`` in ``(since, until)``, ascending by
        event time. Each event dict must include an ``event_time`` field
        (datetime or ISO-8601 string) and optionally an ``event_id``.

        Contract note. The base run loop wraps this call in retry-with-backoff,
        so any transient failure (auth, first page, rate limit) raised
        synchronously from this method will be retried per ``retry_policy``.
        Errors raised from the returned iterator during streaming are NOT
        retried automatically; they surface as a feed-level failure on the
        run result. Implementations should therefore do their initial auth
        check and first request synchronously inside ``fetch_feed``, then
        return a generator that yields subsequent pages. The standard pattern
        is::

            def fetch_feed(self, feed, since, until):
                client = self._auth_and_open(feed)         # may raise
                first_page = client.list(since=since, ...) # may raise
                return self._stream(client, first_page)

            def _stream(self, client, page):
                for evt in page.items: yield evt
                while page.next_token:
                    page = client.list(page_token=page.next_token)
                    for evt in page.items: yield evt
        """

    def run(
        self,
        until: Optional[datetime] = None,
        feeds: Optional[Iterable[str]] = None,
    ) -> CollectorRunResult:
        """Pull each feed once. Returns per-feed counts and any error."""
        started = datetime.now(timezone.utc)
        until = until or started
        chosen = list(feeds) if feeds is not None else self.list_feeds()
        result = CollectorRunResult(
            source=self.source_name,
            tenant_id=self.tenant_id,
            started_at=started,
            finished_at=started,
        )
        for feed in chosen:
            result.feeds.append(self._run_feed(feed, until))
        result.finished_at = datetime.now(timezone.utc)
        return result

    # internals ---------------------------------------------------------------

    def _run_feed(self, feed: str, until: datetime) -> FeedRunResult:
        wm = self.watermarks.get(self.source_name, self.tenant_id, feed)
        if wm is None:
            since = until - timedelta(days=self.default_backfill_days)
            logger.info(
                "collector.first_run source=%s tenant=%s feed=%s since=%s",
                self.source_name, self.tenant_id, feed, since,
            )
        else:
            since = wm.last_event_time

        if since >= until:
            return FeedRunResult(
                feed=feed,
                events_written=0,
                batches_written=0,
                bytes_written_estimate=0,
                new_watermark=wm,
            )

        try:
            events_iter = retry_call(
                lambda: iter(self.fetch_feed(feed, since, until)),
                policy=self.retry_policy,
            )
        except Exception as exc:  # pragma: no cover - covered by retry tests
            logger.exception("collector.fetch_failed feed=%s", feed)
            return FeedRunResult(
                feed=feed,
                events_written=0,
                batches_written=0,
                bytes_written_estimate=0,
                new_watermark=wm,
                error=f"{type(exc).__name__}: {exc}",
            )

        try:
            return self._drain_to_lake(feed, events_iter, fallback_watermark=wm)
        except Exception as exc:
            # Errors raised from the returned iterator during streaming are
            # NOT retried (per contract on fetch_feed), but they DO surface
            # as a feed-level error so the operator sees which feed failed
            # without crashing the run loop or losing other feeds' progress.
            logger.exception("collector.stream_failed feed=%s", feed)
            return FeedRunResult(
                feed=feed,
                events_written=0,
                batches_written=0,
                bytes_written_estimate=0,
                new_watermark=wm,
                error=f"{type(exc).__name__}: {exc}",
            )

    def _drain_to_lake(
        self,
        feed: str,
        events: Iterator[dict],
        fallback_watermark: Optional[Watermark],
    ) -> FeedRunResult:
        batch: list[dict] = []
        events_written = 0
        batches_written = 0
        bytes_written = 0
        latest_time: Optional[datetime] = None
        latest_id: Optional[str] = None

        def flush() -> None:
            nonlocal batches_written, bytes_written
            if not batch:
                return
            batch_when = _coerce_time(batch[0].get("event_time")) or datetime.now(timezone.utc)
            self.lake.write_batch(
                source=self.source_name,
                tenant_id=self.tenant_id,
                feed=feed,
                events=batch,
                when=batch_when,
                batch_id=uuid.uuid4().hex,
            )
            batches_written += 1
            bytes_written += sum(len(str(e)) for e in batch)
            batch.clear()

        for event in events:
            batch.append(event)
            events_written += 1
            t = _coerce_time(event.get("event_time"))
            if t is not None and (latest_time is None or t > latest_time):
                latest_time = t
                latest_id = event.get("event_id")
            if len(batch) >= self.batch_size:
                flush()
        flush()

        new_wm: Optional[Watermark] = fallback_watermark
        if latest_time is not None:
            new_wm = Watermark(
                last_event_time=latest_time,
                last_event_id=latest_id,
                updated_at=datetime.now(timezone.utc),
            )
            self.watermarks.put(self.source_name, self.tenant_id, feed, new_wm)

        return FeedRunResult(
            feed=feed,
            events_written=events_written,
            batches_written=batches_written,
            bytes_written_estimate=bytes_written,
            new_watermark=new_wm,
        )


def _coerce_time(value) -> Optional[datetime]:
    if value is None:
        return None
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    if isinstance(value, str):
        try:
            v = value
            if v.endswith("Z"):
                v = v[:-1] + "+00:00"
            return datetime.fromisoformat(v).astimezone(timezone.utc)
        except ValueError:
            return None
    return None
