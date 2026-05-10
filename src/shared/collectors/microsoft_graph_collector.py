"""
Microsoft Graph audit-event collector for mantissa-log.

PR 5 of SAAS_IDENTITY_SPEC. Adds four Graph-side feeds that complement the
Management Activity API feeds shipped in PR 4:

  - signins          /auditLogs/signIns
  - directory_audits /auditLogs/directoryAudits
  - risk_detections  /identityProtection/riskDetections
  - defender_alerts  /security/alerts_v2

Why a separate collector from ``Microsoft365Collector``. The Management
Activity API uses an async subscribe + blob-fetch model. Graph uses
synchronous list endpoints with ``@odata.nextLink`` pagination. The two
APIs share an Entra tenant and an app registration but require different
OAuth scopes (``manage.office.com`` vs ``graph.microsoft.com``) and have
incompatible request shapes. Keeping them as sibling collectors keeps each
implementation honest to its API and prevents one model's accidental
constraints from leaking into the other.

Both collectors set ``source_name = "m365"`` so all M365 events land in
the same lake partition tree and cross-feed correlations join naturally
on ``UserId`` or ``userPrincipalName`` over the same date range.

Why these four feeds in PR 5. They are the highest-value identity threat
detection signals that the Management Activity API either lacks (Defender
alerts) or under-reports (Graph signIns carries risk score, MFA detail,
conditional-access policy hits that Management Activity strips out).
Risky-users snapshot (current per-user risk state) belongs in mantissa-
stance, not here; it is a posture concept and not an event stream. A
``# TODO`` placeholder is left for that integration so the trail is
documented.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Callable, Iterator, Optional

from .base_saas_collector import BaseSaaSCollector
from .saas_lake import RawLakeWriter
from .saas_retry import RetryPolicy, TransientError
from .saas_secrets import SecretStore
from .saas_state import WatermarkStore

logger = logging.getLogger(__name__)

DEFAULT_BACKFILL_DAYS = 7
GRAPH_BASE = "https://graph.microsoft.com"


def _parse_iso(value: str) -> datetime:
    if value.endswith("Z"):
        value = value[:-1] + "+00:00"
    return datetime.fromisoformat(value).astimezone(timezone.utc)


def _format_graph_iso(when: datetime) -> str:
    """Graph OData filter date format. ISO 8601 with milliseconds and a Z."""
    if when.tzinfo is None:
        when = when.replace(tzinfo=timezone.utc)
    when = when.astimezone(timezone.utc)
    return when.strftime("%Y-%m-%dT%H:%M:%S.000Z")


@dataclass(frozen=True)
class _GraphFeedConfig:
    endpoint: str            # path under graph.microsoft.com
    time_field: str          # name of the event-time field on each item
    filter_template: str     # OData $filter, parameterized on since/until


# The four Graph endpoints shipped in PR 5. Each is a synchronous paginated
# list call with $filter and $top. Time fields differ; the filter template
# uses the matching name.
FEED_CONFIG: dict[str, _GraphFeedConfig] = {
    "signins": _GraphFeedConfig(
        endpoint="/v1.0/auditLogs/signIns",
        time_field="createdDateTime",
        filter_template="createdDateTime ge {since} and createdDateTime lt {until}",
    ),
    "directory_audits": _GraphFeedConfig(
        endpoint="/v1.0/auditLogs/directoryAudits",
        time_field="activityDateTime",
        filter_template="activityDateTime ge {since} and activityDateTime lt {until}",
    ),
    "risk_detections": _GraphFeedConfig(
        endpoint="/v1.0/identityProtection/riskDetections",
        time_field="detectedDateTime",
        filter_template="detectedDateTime ge {since} and detectedDateTime lt {until}",
    ),
    "defender_alerts": _GraphFeedConfig(
        endpoint="/v1.0/security/alerts_v2",
        time_field="createdDateTime",
        filter_template="createdDateTime ge {since} and createdDateTime lt {until}",
    ),
}


class GraphHTTPError(Exception):
    """Thin wrapper around a Graph HTTP failure. Carries ``status_code`` and
    optional ``retry_after`` so the collector can classify the failure as
    transient or terminal."""

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


class MicrosoftGraphCollector(BaseSaaSCollector):
    source_name = "m365"
    default_backfill_days = DEFAULT_BACKFILL_DAYS

    DEFAULT_FEEDS = ("signins", "directory_audits", "risk_detections", "defender_alerts")
    ALL_FEEDS = DEFAULT_FEEDS

    # TODO (post-PR-5). Add risky_users snapshot. RiskyUsers is per-user
    # current state, not an event stream. The cleanest home for it is
    # mantissa-stance under SaaS posture, evaluated on a schedule against
    # a YAML policy ("no user should sit at high risk for more than N
    # hours"). The stance integration is tracked separately; the Graph
    # collector here stays event-stream-only.

    def __init__(
        self,
        tenant_id: str,
        watermark_store: WatermarkStore,
        secret_store: SecretStore,
        lake_writer: RawLakeWriter,
        retry_policy: RetryPolicy = RetryPolicy(),
        feeds: tuple[str, ...] = DEFAULT_FEEDS,
        client_factory: Optional[Callable[[str], Any]] = None,
        page_size: int = 200,
    ):
        super().__init__(
            tenant_id=tenant_id,
            watermark_store=watermark_store,
            secret_store=secret_store,
            lake_writer=lake_writer,
            retry_policy=retry_policy,
        )
        unknown = set(feeds) - set(FEED_CONFIG)
        if unknown:
            raise ValueError(f"unknown graph feeds: {sorted(unknown)}")
        self._feeds = tuple(feeds)
        self._client_factory = client_factory
        self._client: Any = None
        self._page_size = page_size

    def list_feeds(self) -> list[str]:
        return list(self._feeds)

    # ---- client construction -------------------------------------------------

    def _build_client(self) -> Any:
        raw = self.secrets.require(f"m365/{self.tenant_id}/client_credentials")
        creds = json.loads(raw)
        from .m365_http_client import GraphHTTPClient  # type: ignore[import-not-found]
        return GraphHTTPClient(
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
        config = FEED_CONFIG.get(feed)
        if config is None:
            raise ValueError(f"feed not enabled: {feed}")

        client = self._get_client()

        # Synchronous first request goes through retry per base contract.
        params = {
            "$filter": config.filter_template.format(
                since=_format_graph_iso(since), until=_format_graph_iso(until),
            ),
            "$top": str(self._page_size),
        }
        first = self._get(client, GRAPH_BASE + config.endpoint, params=params)
        return self._walk(client, config, first, since, until)

    def _get(self, client: Any, url: str, params: Optional[dict] = None) -> dict:
        try:
            return client.get(url, params=params)
        except Exception as exc:
            transient = _classify(exc)
            if transient is not None:
                raise transient from exc
            raise

    def _walk(
        self,
        client: Any,
        config: _GraphFeedConfig,
        first_page: dict,
        since: datetime,
        until: datetime,
    ) -> Iterator[dict]:
        page = first_page
        while True:
            for item in page.get("value") or []:
                t_str = item.get(config.time_field)
                if not t_str:
                    logger.warning("graph.event_missing_time field=%s endpoint=%s",
                                   config.time_field, config.endpoint)
                    continue
                try:
                    t = _parse_iso(t_str)
                except ValueError:
                    logger.warning("graph.event_bad_time value=%s", t_str)
                    continue
                # OData ge/lt is already strict on the upper side, but the
                # lower side is inclusive. Strict open-interval on (since,
                # until) avoids re-emitting the boundary event on the next
                # poll.
                if t <= since or t >= until:
                    continue
                item.setdefault("event_time", t_str)
                item.setdefault("event_id", item.get("id") or "")
                yield item

            next_link = page.get("@odata.nextLink")
            if not next_link:
                return
            page = self._get(client, next_link)
