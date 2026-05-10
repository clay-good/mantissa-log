"""
Microsoft 365 Management Activity API collector for mantissa-log.

PR 4 of SAAS_IDENTITY_SPEC. Ships the five Management Activity content types:

  - aad         Audit.AzureActiveDirectory (Entra sign-ins, role grants, app consents)
  - exchange    Audit.Exchange             (mailbox forwarding, transport rules, eDiscovery)
  - sharepoint  Audit.SharePoint           (file access, external sharing, site actions)
  - general     Audit.General              (Teams, Power Platform, Forms, Stream)
  - dlp         DLP.All                    (DLP policy match events)

Graph supplements (signIns, directoryAudits, identityProtection, Defender)
land in PR 5; they have different auth, different ordering, and different
retention semantics, so combining them with the Management Activity flow
would muddle the contract.

The Management Activity API is async and indirect:
    1. Subscribe to a content type. Idempotent.
    2. List the content blobs available in a time window.
    3. Each blob has a contentUri pointing at a JSON array of events.
    4. Fetch each blob to materialize the events.

Authentication is OAuth 2.0 client credentials against the Entra tenant.
The collector accepts an injectable ``client_factory`` so tests can supply
a fake client; production builds the real one lazily from secrets at
``m365/{tenant_id}/client_credentials`` (JSON with ``tenant_id``,
``client_id``, ``client_secret``).

Two design notes worth being explicit about, because they catch
implementers off-guard later:

- **Lookback buffer.** Events in a blob with ``contentCreated`` T can carry
  ``CreationTime`` values from up to ~24h before T. If the collector asks
  the API for content with ``startTime = watermark``, late-arriving events
  for the prior window are silently lost. We therefore widen the upstream
  API window by ``DEFAULT_LOOKBACK_HOURS`` and filter events strictly by
  ``event_time`` in the iterator. Watermark advance is unchanged.

- **Blob fetch errors during streaming are NOT retried.** Per the base
  class contract, the synchronous first request (token + list-content)
  goes through the retry decorator. Errors fetching a specific blob mid-
  stream surface as a feed-level failure on the run result. The next
  scheduled tick re-lists and re-fetches the unprocessed blobs.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Iterator, Optional

from .base_saas_collector import BaseSaaSCollector
from .saas_lake import RawLakeWriter
from .saas_retry import RetryPolicy, TransientError
from .saas_secrets import SecretStore
from .saas_state import WatermarkStore

logger = logging.getLogger(__name__)

DEFAULT_BACKFILL_DAYS = 7
DEFAULT_LOOKBACK_HOURS = 24
MAX_WINDOW_HOURS = 24 * 7  # Management Activity API caps each list call to 7 days.

FEED_TO_CONTENT_TYPE = {
    "aad": "Audit.AzureActiveDirectory",
    "exchange": "Audit.Exchange",
    "sharepoint": "Audit.SharePoint",
    "general": "Audit.General",
    "dlp": "DLP.All",
}


def _parse_iso(value: str) -> datetime:
    if value.endswith("Z"):
        value = value[:-1] + "+00:00"
    return datetime.fromisoformat(value).astimezone(timezone.utc)


def _format_iso(when: datetime) -> str:
    if when.tzinfo is None:
        when = when.replace(tzinfo=timezone.utc)
    # Management Activity API uses ISO 8601 with millisecond resolution.
    return when.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S")


class ManagementActivityHTTPError(Exception):
    """Wraps any HTTP failure from the Management Activity API. Carries
    ``status_code`` and (optional) ``retry_after`` so the collector can
    classify and decide whether to wrap as TransientError.

    The string form embeds the status code so feed-level error messages on
    the run result carry the code without callers having to introspect the
    exception. Operators read run output more often than they introspect
    Python objects.
    """

    def __init__(self, message: str, status_code: int, retry_after: Optional[float] = None):
        super().__init__(f"HTTP {status_code}: {message}")
        self.status_code = status_code
        self.retry_after = retry_after


def _classify(exc: Exception) -> Optional[TransientError]:
    """If ``exc`` looks transient return a wrapping TransientError, else None."""
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


class Microsoft365Collector(BaseSaaSCollector):
    source_name = "m365"
    default_backfill_days = DEFAULT_BACKFILL_DAYS

    DEFAULT_FEEDS = ("aad", "exchange", "sharepoint", "general", "dlp")
    ALL_FEEDS = DEFAULT_FEEDS  # PR 5 adds Graph-side feeds in a separate collector.

    def __init__(
        self,
        tenant_id: str,
        watermark_store: WatermarkStore,
        secret_store: SecretStore,
        lake_writer: RawLakeWriter,
        retry_policy: RetryPolicy = RetryPolicy(),
        feeds: tuple[str, ...] = DEFAULT_FEEDS,
        client_factory: Optional[Callable[[str], Any]] = None,
        lookback_hours: float = DEFAULT_LOOKBACK_HOURS,
    ):
        super().__init__(
            tenant_id=tenant_id,
            watermark_store=watermark_store,
            secret_store=secret_store,
            lake_writer=lake_writer,
            retry_policy=retry_policy,
        )
        unknown = set(feeds) - set(FEED_TO_CONTENT_TYPE)
        if unknown:
            raise ValueError(f"unknown m365 feeds: {sorted(unknown)}")
        self._feeds = tuple(feeds)
        self._client_factory = client_factory
        self._client: Any = None
        self._lookback = timedelta(hours=lookback_hours)
        # Track which (tenant, content_type) pairs we have already subscribed
        # to within this process to avoid an unnecessary round-trip per run.
        self._subscribed: set[str] = set()

    def list_feeds(self) -> list[str]:
        return list(self._feeds)

    # ---- client construction -------------------------------------------------

    def _build_client(self) -> Any:
        """Construct the production Management Activity client from secrets.

        Imported lazily so the requests / msal dependency is optional for
        deployments that bring their own HTTP client.
        """
        raw = self.secrets.require(f"m365/{self.tenant_id}/client_credentials")
        creds = json.loads(raw)
        from .m365_http_client import ManagementActivityHTTPClient  # type: ignore[import-not-found]
        return ManagementActivityHTTPClient(
            tenant_guid=creds["tenant_id"],
            client_id=creds["client_id"],
            client_secret=creds["client_secret"],
        )

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
        content_type = FEED_TO_CONTENT_TYPE.get(feed)
        if content_type is None:
            raise ValueError(f"feed not enabled: {feed}")

        client = self._get_client()

        # Ensure subscription is active. Idempotent on the server side; we
        # also remember it in-process to avoid hitting it every tick.
        if content_type not in self._subscribed:
            try:
                client.start_subscription(content_type)
            except Exception as exc:
                transient = _classify(exc)
                if transient is not None:
                    raise transient from exc
                raise
            self._subscribed.add(content_type)

        # Widen upstream window by the lookback to catch late-arriving events.
        api_since = since - self._lookback
        # Management Activity API caps each list call to 7 days. Chunk the
        # window if the operator runs a long backfill.
        try:
            blobs = self._list_blobs(client, content_type, api_since, until)
        except Exception as exc:
            transient = _classify(exc)
            if transient is not None:
                raise transient from exc
            raise

        return self._walk(client, blobs, content_type, since, until)

    def _list_blobs(
        self,
        client: Any,
        content_type: str,
        api_since: datetime,
        until: datetime,
    ) -> list[dict]:
        """List blobs across the window, chunked at 7 days, deduplicated by
        contentId. The Management Activity API can return the same blob
        across successive list calls (overlap during long backfills, late-
        arrival semantics, retries, etc.); dedup at the collector keeps
        the streaming pass single-pass without re-fetching the same blob.
        """
        cap = timedelta(hours=MAX_WINDOW_HOURS)
        seen: set[str] = set()
        all_blobs: list[dict] = []
        window_start = api_since
        while window_start < until:
            window_end = min(until, window_start + cap)
            page_blobs = client.list_content(
                content_type=content_type,
                start_time=_format_iso(window_start),
                end_time=_format_iso(window_end),
            )
            for blob in page_blobs:
                cid = blob.get("contentId") or blob.get("contentUri")
                if cid in seen:
                    continue
                if cid is not None:
                    seen.add(cid)
                all_blobs.append(blob)
            window_start = window_end
        return all_blobs

    def _walk(
        self,
        client: Any,
        blobs: list[dict],
        content_type: str,
        since: datetime,
        until: datetime,
    ) -> Iterator[dict]:
        for blob in blobs:
            content_uri = blob.get("contentUri")
            if not content_uri:
                logger.warning("m365.blob_missing_uri content_type=%s", content_type)
                continue
            try:
                events = client.fetch_blob(content_uri)
            except Exception as exc:
                # Streaming errors are NOT retried by the base class. We let
                # them surface so the feed-level error captures which blob
                # failed; the next tick re-lists and tries again.
                transient = _classify(exc)
                if transient is not None:
                    raise transient from exc
                raise
            for event in events or []:
                t_str = event.get("CreationTime") or event.get("event_time")
                if not t_str:
                    logger.warning("m365.event_missing_time content_type=%s", content_type)
                    continue
                try:
                    t = _parse_iso(t_str if t_str.endswith("Z") else t_str + "Z")
                except ValueError:
                    logger.warning("m365.event_bad_time content_type=%s value=%s",
                                   content_type, t_str)
                    continue
                # Strict open-interval filter on (since, until).
                if t <= since or t >= until:
                    continue
                event.setdefault("event_time", t_str if t_str.endswith("Z") else t_str + "Z")
                event.setdefault("event_id", event.get("Id") or event.get("event_id") or "")
                yield event
