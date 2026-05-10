"""
Salesforce Event Monitoring collector for mantissa-log.

PR 13 of SAAS_IDENTITY_SPEC (§10 follow-on pack, fourth and final).

Salesforce Event Monitoring is the most structurally different of the
four §10 follow-on collectors. The pattern is two-step:

  1. SOQL query the ``EventLogFile`` object for files in a time window.
     Each result row points to a downloadable CSV via its ``LogFile``
     attribute (a relative URL like
     ``/services/data/v59.0/sobjects/EventLogFile/{id}/LogFile``).
  2. For each ``EventLogFile`` record, fetch the CSV and yield each row
     as an event dict.

This shape is closer to the M365 Management Activity collector (blob
listing + blob fetch) than to the Okta / GitHub / Slack collectors
which all use a single paginated endpoint. We do not share the M365
code: the auth model, the body format (CSV vs JSON), and the response
shapes are too different for a clean shared base.

Tenant model. ``tenant_id`` is the Salesforce org's domain (e.g.
``acme.my.salesforce.com``). The HTTP client uses this as the base
URL when none is provided by the token response.

Auth model. The collector is auth-agnostic. The injected client
encapsulates token acquisition (OAuth 2.0 client-credentials, JWT
bearer flow, or username-password depending on operator preference).
The collector never sees credentials directly.

Time model. Salesforce events use ``TIMESTAMP_DERIVED`` (ISO 8601 with
``+0000`` offset) as the canonical event time when present; ``TIMESTAMP``
(``YYYYMMDDHHMMSS.mmm`` format) is the fallback for older event types.

EventLogFile records have a ``LogDate`` that reflects when the *file*
was created, not when individual events occurred. We filter on the
event's own timestamp in the iterator and use it to advance the
watermark.

Event id is built from ``EVENT_UUID`` → ``REQUEST_ID`` → empty. The
base class accepts empty event ids and falls back to event-time-only
watermark advance, which is correct here.
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


def _format_soql_iso(when: datetime) -> str:
    """SOQL accepts ISO 8601 with Z or with the +HH:MM offset. We emit
    seconds resolution because the EventLogFile.LogDate field is itself
    written at hour precision; finer resolution adds nothing."""
    if when.tzinfo is None:
        when = when.replace(tzinfo=timezone.utc)
    return when.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _parse_sf_iso(value: str) -> Optional[datetime]:
    """Parse a Salesforce ISO timestamp such as ``2026-05-09T11:00:00.000+0000``."""
    if not value:
        return None
    # Normalize ``+0000`` -> ``+00:00`` so fromisoformat accepts it.
    if len(value) > 5 and value[-5] in "+-" and value[-3] != ":":
        value = value[:-2] + ":" + value[-2:]
    if value.endswith("Z"):
        value = value[:-1] + "+00:00"
    try:
        return datetime.fromisoformat(value).astimezone(timezone.utc)
    except ValueError:
        return None


def _parse_sf_compact(value: str) -> Optional[datetime]:
    """Parse the legacy ``YYYYMMDDHHMMSS.mmm`` format used by the
    ``TIMESTAMP`` field of older event types."""
    if not value:
        return None
    # Strip any fractional seconds.
    head = value.split(".", 1)[0]
    if len(head) != 14 or not head.isdigit():
        return None
    try:
        return datetime.strptime(head, "%Y%m%d%H%M%S").replace(tzinfo=timezone.utc)
    except ValueError:
        return None


def _event_time(event: dict) -> Optional[datetime]:
    return (
        _parse_sf_iso(event.get("TIMESTAMP_DERIVED") or "")
        or _parse_sf_compact(event.get("TIMESTAMP") or "")
    )


def _event_id(event: dict) -> str:
    return (
        event.get("EVENT_UUID")
        or event.get("REQUEST_ID")
        or ""
    )


class SalesforceHTTPError(Exception):
    """Wraps any HTTP failure from the Salesforce REST API."""

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


class SalesforceCollector(BaseSaaSCollector):
    source_name = "salesforce"
    default_backfill_days = DEFAULT_BACKFILL_DAYS

    DEFAULT_FEEDS = ("events",)
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
            raise ValueError(f"unknown salesforce feeds: {sorted(unknown)}")
        self._feeds = tuple(feeds)
        self._client_factory = client_factory
        self._client: Any = None

    def list_feeds(self) -> list[str]:
        return list(self._feeds)

    # ---- client construction -------------------------------------------------

    def _build_client(self) -> Any:
        client_id = self.secrets.require(f"salesforce/{self.tenant_id}/client_id")
        client_secret = self.secrets.require(f"salesforce/{self.tenant_id}/client_secret")
        from .salesforce_http_client import SalesforceEventClient  # type: ignore[import-not-found]
        return SalesforceEventClient(
            instance_url=f"https://{self.tenant_id}",
            client_id=client_id,
            client_secret=client_secret,
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
        if feed not in self.ALL_FEEDS:
            raise ValueError(f"feed not enabled: {feed}")

        client = self._get_client()

        # Synchronous: list the EventLogFile records in the window. This
        # is the call retried by the base class on transient failure.
        try:
            log_files = client.list_log_files(
                since=_format_soql_iso(since),
                until=_format_soql_iso(until),
            )
        except Exception as exc:
            transient = _classify(exc)
            if transient is not None:
                raise transient from exc
            raise

        return self._walk(client, log_files, since, until)

    def _walk(
        self,
        client: Any,
        log_files: list[dict],
        since: datetime,
        until: datetime,
    ) -> Iterator[dict]:
        for record in log_files:
            log_file_url = record.get("LogFile")
            if not log_file_url:
                logger.warning(
                    "salesforce.event_log_file_missing_log_file id=%s",
                    record.get("Id"),
                )
                continue
            try:
                events = client.fetch_log_file(log_file_url)
            except Exception as exc:
                # Streaming errors are NOT retried by the base class. They
                # surface as feed-level failures so the operator sees which
                # EventLogFile failed; the next tick re-queries.
                transient = _classify(exc)
                if transient is not None:
                    raise transient from exc
                raise

            event_type_hint = record.get("EventType")
            for event in events or []:
                t = _event_time(event)
                if t is None:
                    logger.warning(
                        "salesforce.event_missing_timestamp event_type=%s",
                        event_type_hint,
                    )
                    continue
                if t <= since or t >= until:
                    continue
                # Annotate with the EventType from the parent file in case
                # the row doesn't carry one explicitly. Helps downstream
                # queries partition by event type.
                if event_type_hint and "EVENT_TYPE" not in event:
                    event["EVENT_TYPE"] = event_type_hint
                event.setdefault("event_time", t.strftime("%Y-%m-%dT%H:%M:%SZ"))
                event.setdefault("event_id", _event_id(event))
                yield event
