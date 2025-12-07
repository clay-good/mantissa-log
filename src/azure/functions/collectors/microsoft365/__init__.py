"""Azure Function handler for Microsoft 365 audit log collection."""

import azure.functions as func
import json
import logging
import os
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List

from azure.identity import DefaultAzureCredential, ClientSecretCredential
from azure.keyvault.secrets import SecretClient
from azure.storage.blob import BlobServiceClient
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from src.shared.parsers.microsoft365 import Microsoft365Parser

logger = logging.getLogger(__name__)


def get_secret(key_vault_url: str, secret_name: str) -> str:
    """Retrieve secret from Azure Key Vault."""
    credential = DefaultAzureCredential()
    client = SecretClient(vault_url=key_vault_url, credential=credential)
    secret = client.get_secret(secret_name)
    return secret.value


def create_session_with_retry() -> requests.Session:
    """Create requests session with retry logic."""
    session = requests.Session()
    retry_strategy = Retry(
        total=3,
        backoff_factor=1,
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=["GET", "POST"]
    )
    adapter = HTTPAdapter(max_retries=retry_strategy)
    session.mount("https://", adapter)
    return session


def upload_to_blob(
    connection_string: str,
    container_name: str,
    events: List[Dict],
    timestamp: datetime
) -> str:
    """Upload events to Azure Blob Storage."""
    blob_service = BlobServiceClient.from_connection_string(connection_string)
    container = blob_service.get_container_client(container_name)

    blob_path = (
        f"microsoft365/{timestamp.year}/{timestamp.month:02d}/{timestamp.day:02d}/"
        f"{timestamp.hour:02d}/{timestamp.strftime('%Y%m%d_%H%M%S')}.json"
    )

    content = "\n".join(json.dumps(event) for event in events)
    blob_client = container.get_blob_client(blob_path)
    blob_client.upload_blob(content, overwrite=True)

    return blob_path


class Microsoft365Collector:
    """Microsoft 365 Management Activity API collector."""

    def __init__(
        self,
        tenant_id: str,
        client_id: str,
        client_secret: str
    ):
        self.tenant_id = tenant_id
        self.client_id = client_id
        self.client_secret = client_secret
        self.session = create_session_with_retry()
        self.access_token = None
        self.token_expiry = None

    def _get_access_token(self) -> str:
        """Get OAuth2 access token for Microsoft Graph API."""
        if self.access_token and self.token_expiry and datetime.now(timezone.utc) < self.token_expiry:
            return self.access_token

        token_url = f"https://login.microsoftonline.com/{self.tenant_id}/oauth2/v2.0/token"

        data = {
            "grant_type": "client_credentials",
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "scope": "https://manage.office.com/.default"
        }

        response = self.session.post(token_url, data=data)
        response.raise_for_status()

        token_data = response.json()
        self.access_token = token_data["access_token"]
        expires_in = token_data.get("expires_in", 3600)
        self.token_expiry = datetime.now(timezone.utc) + timedelta(seconds=expires_in - 60)

        return self.access_token

    def _ensure_subscription(self, content_type: str) -> bool:
        """Ensure subscription exists for content type."""
        token = self._get_access_token()
        headers = {"Authorization": f"Bearer {token}"}

        # Check existing subscriptions
        list_url = f"https://manage.office.com/api/v1.0/{self.tenant_id}/activity/feed/subscriptions/list"
        response = self.session.get(list_url, headers=headers)

        if response.status_code == 200:
            subscriptions = response.json()
            for sub in subscriptions:
                if sub.get("contentType") == content_type and sub.get("status") == "enabled":
                    return True

        # Start subscription if not exists
        start_url = f"https://manage.office.com/api/v1.0/{self.tenant_id}/activity/feed/subscriptions/start"
        params = {"contentType": content_type}
        response = self.session.post(start_url, headers=headers, params=params)

        return response.status_code in [200, 201]

    def fetch_audit_logs(
        self,
        content_types: List[str] = None,
        start_time: datetime = None,
        end_time: datetime = None
    ) -> List[Dict]:
        """Fetch audit logs from Microsoft 365 Management Activity API."""
        if content_types is None:
            content_types = [
                "Audit.AzureActiveDirectory",
                "Audit.Exchange",
                "Audit.SharePoint",
                "Audit.General"
            ]

        if end_time is None:
            end_time = datetime.now(timezone.utc)
        if start_time is None:
            start_time = end_time - timedelta(hours=24)

        token = self._get_access_token()
        headers = {"Authorization": f"Bearer {token}"}

        all_events = []

        for content_type in content_types:
            # Ensure subscription exists
            if not self._ensure_subscription(content_type):
                logger.warning(f"Could not ensure subscription for {content_type}")
                continue

            # List available content
            content_url = f"https://manage.office.com/api/v1.0/{self.tenant_id}/activity/feed/subscriptions/content"
            params = {
                "contentType": content_type,
                "startTime": start_time.strftime("%Y-%m-%dT%H:%M:%S"),
                "endTime": end_time.strftime("%Y-%m-%dT%H:%M:%S")
            }

            try:
                response = self.session.get(content_url, headers=headers, params=params)

                if response.status_code == 429:
                    retry_after = int(response.headers.get("Retry-After", 60))
                    logger.warning(f"Rate limited, waiting {retry_after} seconds")
                    import time
                    time.sleep(retry_after)
                    continue

                response.raise_for_status()
                content_blobs = response.json()

                # Fetch each content blob
                for blob in content_blobs:
                    content_uri = blob.get("contentUri")
                    if content_uri:
                        blob_response = self.session.get(content_uri, headers=headers)
                        if blob_response.status_code == 200:
                            events = blob_response.json()
                            for event in events:
                                event["_content_type"] = content_type
                            all_events.extend(events)

                logger.info(f"Fetched {len(content_blobs)} content blobs for {content_type}")

            except Exception as e:
                logger.error(f"Error fetching {content_type}: {e}")
                continue

        return all_events


def main(req: func.HttpRequest) -> func.HttpResponse:
    """Azure Function handler for Microsoft 365 audit log collection."""
    logger.info("Processing Microsoft 365 audit log collection request")

    key_vault_url = os.environ.get("KEY_VAULT_URL")
    m365_tenant_id = os.environ.get("M365_TENANT_ID")
    m365_client_id = os.environ.get("M365_CLIENT_ID")
    m365_secret_name = os.environ.get("M365_SECRET_NAME", "m365-client-secret")
    storage_connection_string = os.environ.get("STORAGE_CONNECTION_STRING")
    container_name = os.environ.get("STORAGE_CONTAINER", "mantissa-logs")

    if not all([m365_tenant_id, m365_client_id]):
        return func.HttpResponse(
            json.dumps({"error": "M365_TENANT_ID and M365_CLIENT_ID must be set"}),
            status_code=400,
            mimetype="application/json"
        )

    try:
        body = req.get_json() if req.get_body() else {}
        hours_back = body.get("hours_back", 24)
        content_types = body.get("content_types")
    except ValueError:
        hours_back = 24
        content_types = None

    try:
        client_secret = get_secret(key_vault_url, m365_secret_name)
        collector = Microsoft365Collector(
            tenant_id=m365_tenant_id,
            client_id=m365_client_id,
            client_secret=client_secret
        )

        end_time = datetime.now(timezone.utc)
        start_time = end_time - timedelta(hours=hours_back)

        logger.info(f"Collecting Microsoft 365 logs from {start_time} to {end_time}")

        events = collector.fetch_audit_logs(
            content_types=content_types,
            start_time=start_time,
            end_time=end_time
        )
        logger.info(f"Collected {len(events)} Microsoft 365 events")

        if not events:
            return func.HttpResponse(
                json.dumps({
                    "success": True,
                    "message": "No events found in time range",
                    "events_collected": 0
                }),
                status_code=200,
                mimetype="application/json"
            )

        parser = Microsoft365Parser()
        parsed_events = []
        for event in events:
            try:
                parsed = parser.parse(event)
                parsed_events.append(parsed)
            except Exception as e:
                logger.warning(f"Failed to parse event: {e}")
                parsed_events.append(event)

        blob_path = upload_to_blob(
            connection_string=storage_connection_string,
            container_name=container_name,
            events=parsed_events,
            timestamp=datetime.now(timezone.utc)
        )

        logger.info(f"Uploaded {len(parsed_events)} events to {blob_path}")

        return func.HttpResponse(
            json.dumps({
                "success": True,
                "events_collected": len(events),
                "events_parsed": len(parsed_events),
                "blob_path": blob_path,
                "time_range": {
                    "start": start_time.isoformat(),
                    "end": end_time.isoformat()
                }
            }),
            status_code=200,
            mimetype="application/json"
        )

    except Exception as e:
        logger.error(f"Error collecting Microsoft 365 logs: {e}")
        import traceback
        traceback.print_exc()

        return func.HttpResponse(
            json.dumps({"success": False, "error": str(e)}),
            status_code=500,
            mimetype="application/json"
        )


def timer_trigger(timer: func.TimerRequest) -> None:
    """Timer trigger handler for scheduled Microsoft 365 log collection."""
    logger.info("Timer trigger fired for Microsoft 365 collector")

    key_vault_url = os.environ.get("KEY_VAULT_URL")
    m365_tenant_id = os.environ.get("M365_TENANT_ID")
    m365_client_id = os.environ.get("M365_CLIENT_ID")
    m365_secret_name = os.environ.get("M365_SECRET_NAME", "m365-client-secret")
    storage_connection_string = os.environ.get("STORAGE_CONNECTION_STRING")
    container_name = os.environ.get("STORAGE_CONTAINER", "mantissa-logs")

    if not all([m365_tenant_id, m365_client_id]):
        logger.error("M365_TENANT_ID and M365_CLIENT_ID not configured")
        return

    try:
        client_secret = get_secret(key_vault_url, m365_secret_name)
        collector = Microsoft365Collector(
            tenant_id=m365_tenant_id,
            client_id=m365_client_id,
            client_secret=client_secret
        )

        end_time = datetime.now(timezone.utc)
        start_time = end_time - timedelta(hours=1)

        events = collector.fetch_audit_logs(start_time=start_time, end_time=end_time)
        logger.info(f"Collected {len(events)} Microsoft 365 events")

        if events:
            parser = Microsoft365Parser()
            parsed_events = []
            for event in events:
                try:
                    parsed = parser.parse(event)
                    parsed_events.append(parsed)
                except Exception:
                    parsed_events.append(event)

            blob_path = upload_to_blob(
                connection_string=storage_connection_string,
                container_name=container_name,
                events=parsed_events,
                timestamp=datetime.now(timezone.utc)
            )
            logger.info(f"Uploaded to {blob_path}")

    except Exception as e:
        logger.error(f"Error in timer trigger: {e}")
        raise
