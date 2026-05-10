"""
Integration smoke tests for PR 9.

Wire the production ``ManagementActivityHTTPClient`` and
``GraphHTTPClient`` into the existing ``Microsoft365Collector`` and
``MicrosoftGraphCollector`` via the ``client_factory`` injection point,
using a fake HTTP transport. This proves the end-to-end production path
works without standing up real Entra credentials.

Without these tests the PR 9 unit tests pass but production deployments
could still break at the seam between collector and HTTP client. These
verify the seam.
"""

from __future__ import annotations

import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

ROOT = Path(__file__).resolve().parents[2]
SRC = ROOT / "src"
if str(SRC) not in sys.path:
    sys.path.insert(0, str(SRC))

from shared.collectors.m365_http_client import (  # noqa: E402
    GraphHTTPClient,
    ManagementActivityHTTPClient,
)
from shared.collectors.microsoft365_collector import Microsoft365Collector  # noqa: E402
from shared.collectors.microsoft_graph_collector import MicrosoftGraphCollector  # noqa: E402
from shared.collectors.saas_lake import LocalFileRawLakeWriter  # noqa: E402
from shared.collectors.saas_retry import RetryPolicy  # noqa: E402
from shared.collectors.saas_secrets import LocalFileSecretStore  # noqa: E402
from shared.collectors.saas_state import LocalFileWatermarkStore, Watermark  # noqa: E402


@dataclass
class _Resp:
    status_code: int = 200
    body_json: Any = None
    body_text: str = ""
    headers: dict = field(default_factory=dict)

    def json(self):
        return self.body_json

    @property
    def text(self):
        return self.body_text


class _FakeTransport:
    """Routes by URL pattern: token endpoint, then API endpoints."""

    def __init__(self, blob_events: Optional[dict] = None):
        self.blob_events = blob_events or {}
        self.calls: list[dict] = []

    def post(self, url, data=None, params=None, headers=None, timeout=None):
        self.calls.append({"method": "POST", "url": url, "params": params})
        if "/oauth2/v2.0/token" in url:
            return _Resp(status_code=200,
                         body_json={"access_token": "tok", "expires_in": 3600})
        if "/subscriptions/start" in url:
            return _Resp(status_code=200, body_json={})
        return _Resp(status_code=200, body_json={})

    def get(self, url, params=None, headers=None, timeout=None):
        self.calls.append({"method": "GET", "url": url, "params": params})
        if "/subscriptions/content" in url:
            # Return one blob.
            return _Resp(
                status_code=200,
                body_json=[{
                    "contentId": "b1",
                    "contentUri": "https://manage.office.com/api/v1.0/.../audit/b1",
                    "contentCreated": "2026-05-09T11:00:00Z",
                    "contentType": "Audit.AzureActiveDirectory",
                }],
            )
        if "/audit/" in url:
            return _Resp(
                status_code=200,
                body_json=self.blob_events.get(url, [
                    {"Id": "e1", "CreationTime": "2026-05-09T11:00:00",
                     "Operation": "UserLoggedIn", "UserId": "u@c.com"},
                ]),
            )
        if "graph.microsoft.com" in url:
            return _Resp(
                status_code=200,
                body_json={"value": [
                    {"id": "g1", "createdDateTime": "2026-05-09T11:00:00Z",
                     "userPrincipalName": "u@c.com"},
                ]},
            )
        return _Resp(status_code=200, body_json={})


def test_management_activity_collector_end_to_end(tmp_path):
    transport = _FakeTransport()

    def factory(_tenant_id):
        return ManagementActivityHTTPClient(
            tenant_guid="entra-guid",
            client_id="app-id",
            client_secret="secret",
            transport=transport,
        )

    collector = Microsoft365Collector(
        tenant_id="contoso.onmicrosoft.com",
        watermark_store=LocalFileWatermarkStore(tmp_path / "state"),
        secret_store=LocalFileSecretStore(tmp_path / "secrets.json"),
        lake_writer=LocalFileRawLakeWriter(tmp_path / "lake"),
        retry_policy=RetryPolicy(max_attempts=2, base_delay_seconds=0.0, jitter=0.0),
        feeds=("aad",),
        client_factory=factory,
        lookback_hours=0,
    )
    collector.watermarks.put(
        "m365", "contoso.onmicrosoft.com", "aad",
        Watermark(last_event_time=datetime(2026, 5, 9, 10, 0, tzinfo=timezone.utc)),
    )
    result = collector.run(until=datetime(2026, 5, 9, 12, 0, tzinfo=timezone.utc))

    assert result.total_events == 1
    # Token endpoint, subscription start, list content, fetch blob = 4 calls
    methods = [c["method"] for c in transport.calls]
    urls = [c["url"] for c in transport.calls]
    assert any("/oauth2/v2.0/token" in u for u in urls)
    assert any("/subscriptions/start" in u for u in urls)
    assert any("/subscriptions/content" in u for u in urls)
    assert any("/audit/b1" in u for u in urls)
    # Lake partition created
    files = list((tmp_path / "lake").rglob("*.jsonl.gz"))
    assert len(files) == 1 and "feed=aad" in files[0].as_posix()


def test_graph_collector_end_to_end(tmp_path):
    transport = _FakeTransport()

    def factory(_tenant_id):
        return GraphHTTPClient(
            tenant_guid="entra-guid",
            client_id="app-id",
            client_secret="secret",
            transport=transport,
        )

    collector = MicrosoftGraphCollector(
        tenant_id="contoso.onmicrosoft.com",
        watermark_store=LocalFileWatermarkStore(tmp_path / "state"),
        secret_store=LocalFileSecretStore(tmp_path / "secrets.json"),
        lake_writer=LocalFileRawLakeWriter(tmp_path / "lake"),
        retry_policy=RetryPolicy(max_attempts=2, base_delay_seconds=0.0, jitter=0.0),
        feeds=("signins",),
    )
    collector._client_factory = lambda _t: factory("dummy")  # type: ignore[method-assign]
    collector.watermarks.put(
        "m365", "contoso.onmicrosoft.com", "signins",
        Watermark(last_event_time=datetime(2026, 5, 9, 10, 0, tzinfo=timezone.utc)),
    )
    result = collector.run(until=datetime(2026, 5, 9, 12, 0, tzinfo=timezone.utc))

    assert result.total_events == 1
    urls = [c["url"] for c in transport.calls]
    assert any("/oauth2/v2.0/token" in u for u in urls)
    assert any("graph.microsoft.com" in u and "/auditLogs/signIns" in u for u in urls)
    files = list((tmp_path / "lake").rglob("*.jsonl.gz"))
    assert len(files) == 1 and "feed=signins" in files[0].as_posix()
