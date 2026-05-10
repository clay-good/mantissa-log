"""
Google Workspace audit-event collector for mantissa-log.

Pulls Reports API activity feeds into the lake. PR 2 of SAAS_IDENTITY_SPEC
ships the four highest-value feeds:

  - login          (sign-in events incl. suspicious-login flags)
  - admin          (admin console actions, the highest-value feed)
  - drive          (file create/edit/share/download/delete, perm changes)
  - token          (OAuth grant + revoke events for third-party apps)

Remaining feeds (calendar, groups, gmail, mobile, chrome, meet, chat,
user_accounts, access_transparency, saml, context_aware_access, etc.) ship
in PR 3.

The collector implements ``BaseSaaSCollector``. It does the initial auth
and first list call synchronously inside ``fetch_feed`` so the base class's
retry-with-backoff covers transient auth and first-page failures. It then
returns a generator that paginates through subsequent pages. This matches
the contract documented on ``BaseSaaSCollector.fetch_feed``.

Auth model. A Google service account with domain-wide delegation. The
service-account JSON is held in the configured ``SecretStore`` under the
key ``gws/{tenant_id}/service_account_json``. The subject (the email the
service account impersonates, typically a super-admin) lives at
``gws/{tenant_id}/subject_email``.

For testability the constructor accepts an optional ``service_factory``,
a callable returning a Google Reports API service object. Tests inject a
fake. Production omits it and the collector builds the real one lazily.
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

# Reports API has a documented retention horizon of about 180 days. Backfill
# defaults to 7 days to keep first runs fast; the operator can override per
# tenant via ``default_backfill_days``.
DEFAULT_BACKFILL_DAYS = 7

# Reports API max page size is 1000.
MAX_PAGE_SIZE = 1000

# Reports API ``applicationName`` values that map to our logical feed names.
# Each feed is an independent logical partition in the lake. We use the
# Google ``applicationName`` verbatim as our feed key for round-trip clarity:
# a query against ``feed=token`` directly corresponds to the upstream API
# surface, so anyone debugging an event can trace the ingest path without
# a translation table.
FEED_TO_APPLICATION_NAME = {
    # PR 2 (high-value, on by default)
    "login": "login",
    "admin": "admin",
    "drive": "drive",
    "token": "token",
    # PR 3 (remaining feeds, opt-in via ALL_FEEDS or explicit feeds=...)
    "calendar": "calendar",
    "groups": "groups",
    "groups_enterprise": "groups_enterprise",
    "gmail": "gmail",
    "mobile": "mobile",
    "chrome": "chrome",
    "meet": "meet",
    "chat": "chat",
    "user_accounts": "user_accounts",
    "access_transparency": "access_transparency",
    "saml": "saml",
    "context_aware_access": "context_aware_access",
    "data_studio": "data_studio",       # Looker Studio activity
    "gcp": "gcp",                       # Workspace-side GCP linkage events
    "keep": "keep",
    "jamboard": "jamboard",
    "rules": "rules",                   # Workspace Rules (DLP, alerting, etc.)
}

# Service account scopes required for the Reports API. Reports-only;
# documented in docs/connectors/google_workspace.md so admins can grant the
# minimal set in the Workspace Admin Console.
REQUIRED_SCOPES = (
    "https://www.googleapis.com/auth/admin.reports.audit.readonly",
)


def _parse_iso(value: str) -> datetime:
    """Parse an ISO-8601 string the Reports API returns. Always UTC."""
    if value.endswith("Z"):
        value = value[:-1] + "+00:00"
    return datetime.fromisoformat(value).astimezone(timezone.utc)


def _format_iso(when: datetime) -> str:
    """Format a datetime for the Reports API (RFC 3339 with Z suffix)."""
    if when.tzinfo is None:
        when = when.replace(tzinfo=timezone.utc)
    return when.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _make_event_id(raw: dict) -> str:
    """Stable per-event id derived from Reports API ``id`` dict."""
    rid = raw.get("id", {}) or {}
    time = rid.get("time", "")
    qual = rid.get("uniqueQualifier", "")
    app = rid.get("applicationName", "")
    return f"{time}:{qual}:{app}" if (time or qual) else json.dumps(rid, sort_keys=True)


def _classify_http_error(exc: Exception) -> bool:
    """Return True if the exception looks transient and should be retried."""
    # We classify by attribute presence to avoid hard-importing googleapiclient
    status = getattr(exc, "status_code", None) or getattr(getattr(exc, "resp", None), "status", None)
    if status is None:
        return False
    try:
        status = int(status)
    except (TypeError, ValueError):
        return False
    # 408 timeout, 429 rate limit, 5xx server error
    return status == 408 or status == 429 or 500 <= status < 600


def _retry_after_from(exc: Exception) -> Optional[float]:
    headers = getattr(getattr(exc, "resp", None), "_headers", None) or getattr(exc, "headers", None)
    if not headers:
        return None
    value = headers.get("Retry-After") if hasattr(headers, "get") else None
    if value is None:
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


class GoogleWorkspaceCollector(BaseSaaSCollector):
    source_name = "gws"
    default_backfill_days = DEFAULT_BACKFILL_DAYS

    # High-value feeds enabled by default. Operators wanting full coverage
    # pass ``feeds=GoogleWorkspaceCollector.ALL_FEEDS`` to the constructor.
    # Splitting the lists this way keeps the default deployment cheap (the
    # API charges nothing but storage and parse cost are real at scale) while
    # making full coverage one explicit opt-in away.
    DEFAULT_FEEDS = ("login", "admin", "drive", "token")

    # All feeds covered by this collector. Order is stable for predictable
    # logging and for snapshot tests.
    ALL_FEEDS = (
        "login", "admin", "drive", "token",
        "calendar", "groups", "groups_enterprise", "gmail",
        "mobile", "chrome", "meet", "chat",
        "user_accounts", "access_transparency", "saml",
        "context_aware_access", "data_studio", "gcp",
        "keep", "jamboard", "rules",
    )

    def __init__(
        self,
        tenant_id: str,
        watermark_store: WatermarkStore,
        secret_store: SecretStore,
        lake_writer: RawLakeWriter,
        retry_policy: RetryPolicy = RetryPolicy(),
        feeds: tuple[str, ...] = DEFAULT_FEEDS,
        service_factory: Optional[Callable[[str, str], Any]] = None,
        page_size: int = MAX_PAGE_SIZE,
    ):
        super().__init__(
            tenant_id=tenant_id,
            watermark_store=watermark_store,
            secret_store=secret_store,
            lake_writer=lake_writer,
            retry_policy=retry_policy,
        )
        unknown = set(feeds) - set(FEED_TO_APPLICATION_NAME)
        if unknown:
            raise ValueError(f"unknown gws feeds: {sorted(unknown)}")
        self._feeds = tuple(feeds)
        self._service_factory = service_factory
        self._service: Any = None
        self._page_size = min(page_size, MAX_PAGE_SIZE)

    def list_feeds(self) -> list[str]:
        return list(self._feeds)

    # ---- service construction ------------------------------------------------

    def _build_service(self) -> Any:
        """Build the Reports API service from secret-stored credentials.

        Production path. Imports the Google client libraries lazily so that
        tests can inject a fake service via ``service_factory`` without
        requiring the dependency in the test environment.
        """
        sa_json = self.secrets.require(f"gws/{self.tenant_id}/service_account_json")
        subject = self.secrets.require(f"gws/{self.tenant_id}/subject_email")
        # Lazy imports keep google-api-python-client optional.
        from google.oauth2 import service_account  # type: ignore[import-not-found]
        from googleapiclient.discovery import build  # type: ignore[import-not-found]
        info = json.loads(sa_json)
        creds = service_account.Credentials.from_service_account_info(
            info, scopes=list(REQUIRED_SCOPES), subject=subject,
        )
        return build("admin", "reports_v1", credentials=creds, cache_discovery=False)

    def _get_service(self) -> Any:
        if self._service is None:
            if self._service_factory is not None:
                self._service = self._service_factory(self.tenant_id, "reports")
            else:
                self._service = self._build_service()
        return self._service

    # ---- fetch ---------------------------------------------------------------

    def fetch_feed(
        self,
        feed: str,
        since: datetime,
        until: datetime,
    ) -> Iterator[dict]:
        """Synchronous: build service, run the first list. Then return a
        generator that walks subsequent pages. Per BaseSaaSCollector contract.
        """
        application_name = FEED_TO_APPLICATION_NAME.get(feed)
        if application_name is None:
            raise ValueError(f"feed not enabled: {feed}")

        service = self._get_service()
        first_page = self._list_page(
            service=service,
            application_name=application_name,
            since=since,
            until=until,
            page_token=None,
        )
        return self._walk(service, application_name, since, until, first_page)

    def _list_page(
        self,
        service: Any,
        application_name: str,
        since: datetime,
        until: datetime,
        page_token: Optional[str],
    ) -> dict:
        """Run a single Reports API list call. Translates retryable HTTP
        errors into ``TransientError`` so the base class retry decorator
        catches them.
        """
        try:
            request = service.activities().list(
                userKey="all",
                applicationName=application_name,
                startTime=_format_iso(since),
                endTime=_format_iso(until),
                maxResults=self._page_size,
                pageToken=page_token,
            )
            return request.execute()
        except Exception as exc:  # noqa: BLE001 -- classify, then re-raise
            if _classify_http_error(exc):
                raise TransientError(str(exc), retry_after=_retry_after_from(exc)) from exc
            raise

    def _walk(
        self,
        service: Any,
        application_name: str,
        since: datetime,
        until: datetime,
        first_page: dict,
    ) -> Iterator[dict]:
        """Generator over event dicts from successive Reports API pages.

        Each yielded dict is the raw event from Google with two extra keys
        injected (without overwriting any existing field):
          - ``event_time`` (ISO-8601 string, UTC, from ``id.time``)
          - ``event_id``   (stable string)
        The base class reads those keys to advance the watermark.
        """
        page = first_page
        while True:
            for item in page.get("items") or []:
                event_time_str = (item.get("id") or {}).get("time")
                if not event_time_str:
                    # Drop malformed entries instead of poisoning the watermark.
                    logger.warning("gws.event_missing_time application=%s", application_name)
                    continue
                event_time = _parse_iso(event_time_str)
                # Strict open lower bound. Google's ``startTime`` is inclusive
                # so without this filter we'd re-emit the boundary event.
                if event_time <= since:
                    continue
                if event_time >= until:
                    continue
                item.setdefault("event_time", event_time_str)
                item.setdefault("event_id", _make_event_id(item))
                yield item

            token = page.get("nextPageToken")
            if not token:
                return
            # Subsequent pages: failures here are NOT retried by the base
            # class (per contract). We still classify and raise as
            # TransientError so callers can choose to retry the whole feed
            # on the next scheduled tick.
            page = self._list_page(
                service=service,
                application_name=application_name,
                since=since,
                until=until,
                page_token=token,
            )
