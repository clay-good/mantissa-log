"""Azure Function handler for Google Workspace log collection."""

import azure.functions as func
import json
import logging
import os
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List

from azure.identity import DefaultAzureCredential
from azure.keyvault.secrets import SecretClient
from azure.storage.blob import BlobServiceClient

from google.oauth2 import service_account
from googleapiclient.discovery import build

logger = logging.getLogger(__name__)


def get_secret(key_vault_url: str, secret_name: str) -> str:
    """Retrieve secret from Azure Key Vault."""
    credential = DefaultAzureCredential()
    client = SecretClient(vault_url=key_vault_url, credential=credential)
    secret = client.get_secret(secret_name)
    return secret.value


def upload_to_blob(
    connection_string: str,
    container_name: str,
    events: List[Dict],
    timestamp: datetime,
    source: str = "google_workspace"
) -> str:
    """Upload events to Azure Blob Storage."""
    blob_service = BlobServiceClient.from_connection_string(connection_string)
    container = blob_service.get_container_client(container_name)

    blob_path = (
        f"{source}/{timestamp.year}/{timestamp.month:02d}/{timestamp.day:02d}/"
        f"{timestamp.hour:02d}/{timestamp.strftime('%Y%m%d_%H%M%S')}.json"
    )

    content = "\n".join(json.dumps(event) for event in events)
    blob_client = container.get_blob_client(blob_path)
    blob_client.upload_blob(content, overwrite=True)

    return blob_path


class GoogleWorkspaceCollector:
    """Collector for Google Workspace Admin Reports API."""

    def __init__(self, service_account_json: str, delegated_email: str):
        """Initialize with service account credentials."""
        credentials_dict = json.loads(service_account_json)
        credentials = service_account.Credentials.from_service_account_info(
            credentials_dict,
            scopes=['https://www.googleapis.com/auth/admin.reports.audit.readonly'],
            subject=delegated_email
        )
        self.service = build('admin', 'reports_v1', credentials=credentials)

    def fetch_activities(
        self,
        application: str,
        start_time: str,
        end_time: str,
        max_results: int = 1000
    ) -> List[Dict]:
        """Fetch activity logs from Google Workspace.

        Args:
            application: Application name (login, admin, drive, etc.)
            start_time: RFC 3339 formatted start time
            end_time: RFC 3339 formatted end time
            max_results: Maximum results per page
        """
        events = []
        page_token = None

        while True:
            request = self.service.activities().list(
                userKey='all',
                applicationName=application,
                startTime=start_time,
                endTime=end_time,
                maxResults=max_results,
                pageToken=page_token
            )
            response = request.execute()

            items = response.get('items', [])
            events.extend(items)

            page_token = response.get('nextPageToken')
            if not page_token:
                break

        return events


def main(req: func.HttpRequest) -> func.HttpResponse:
    """Azure Function handler for Google Workspace log collection."""
    logger.info("Processing Google Workspace log collection request")

    key_vault_url = os.environ.get("KEY_VAULT_URL")
    gws_secret_name = os.environ.get("GWS_SECRET_NAME", "google-workspace-service-account")
    delegated_email = os.environ.get("GWS_DELEGATED_EMAIL")
    storage_connection_string = os.environ.get("STORAGE_CONNECTION_STRING")
    container_name = os.environ.get("STORAGE_CONTAINER", "mantissa-logs")

    if not delegated_email:
        return func.HttpResponse(
            json.dumps({"error": "GWS_DELEGATED_EMAIL not configured"}),
            status_code=400,
            mimetype="application/json"
        )

    try:
        body = req.get_json() if req.get_body() else {}
        applications = body.get("applications", ["login", "admin", "drive"])
        hours_back = body.get("hours_back", 24)
    except ValueError:
        applications = ["login", "admin", "drive"]
        hours_back = 24

    try:
        service_account_json = get_secret(key_vault_url, gws_secret_name)
        collector = GoogleWorkspaceCollector(service_account_json, delegated_email)

        end_time = datetime.now(timezone.utc)
        start_time = end_time - timedelta(hours=hours_back)

        all_events = []
        for app in applications:
            logger.info(f"Collecting {app} logs")
            events = collector.fetch_activities(
                application=app,
                start_time=start_time.isoformat() + 'Z',
                end_time=end_time.isoformat() + 'Z'
            )
            for event in events:
                event['_application'] = app
            all_events.extend(events)

        logger.info(f"Collected {len(all_events)} total Google Workspace events")

        if all_events:
            blob_path = upload_to_blob(
                connection_string=storage_connection_string,
                container_name=container_name,
                events=all_events,
                timestamp=datetime.now(timezone.utc)
            )
            logger.info(f"Uploaded to {blob_path}")
        else:
            blob_path = None

        return func.HttpResponse(
            json.dumps({
                "success": True,
                "events_collected": len(all_events),
                "applications": applications,
                "blob_path": blob_path
            }),
            status_code=200,
            mimetype="application/json"
        )

    except Exception as e:
        logger.error(f"Error collecting Google Workspace logs: {e}")
        return func.HttpResponse(
            json.dumps({"success": False, "error": str(e)}),
            status_code=500,
            mimetype="application/json"
        )


def timer_trigger(timer: func.TimerRequest) -> None:
    """Timer trigger for scheduled Google Workspace log collection."""
    logger.info("Timer trigger fired for Google Workspace collector")

    key_vault_url = os.environ.get("KEY_VAULT_URL")
    gws_secret_name = os.environ.get("GWS_SECRET_NAME", "google-workspace-service-account")
    delegated_email = os.environ.get("GWS_DELEGATED_EMAIL")
    storage_connection_string = os.environ.get("STORAGE_CONNECTION_STRING")
    container_name = os.environ.get("STORAGE_CONTAINER", "mantissa-logs")

    if not delegated_email:
        logger.error("GWS_DELEGATED_EMAIL not configured")
        return

    try:
        service_account_json = get_secret(key_vault_url, gws_secret_name)
        collector = GoogleWorkspaceCollector(service_account_json, delegated_email)

        end_time = datetime.now(timezone.utc)
        start_time = end_time - timedelta(hours=1)

        all_events = []
        for app in ["login", "admin", "drive"]:
            events = collector.fetch_activities(
                application=app,
                start_time=start_time.isoformat() + 'Z',
                end_time=end_time.isoformat() + 'Z'
            )
            for event in events:
                event['_application'] = app
            all_events.extend(events)

        if all_events:
            upload_to_blob(
                connection_string=storage_connection_string,
                container_name=container_name,
                events=all_events,
                timestamp=datetime.now(timezone.utc)
            )
            logger.info(f"Collected and uploaded {len(all_events)} events")

    except Exception as e:
        logger.error(f"Error in timer trigger: {e}")
        raise
