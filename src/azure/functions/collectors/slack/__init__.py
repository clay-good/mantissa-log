"""Azure Function handler for Slack audit log collection."""

import azure.functions as func
import json
import logging
import os
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List

from azure.identity import DefaultAzureCredential
from azure.keyvault.secrets import SecretClient
from azure.storage.blob import BlobServiceClient
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from src.shared.parsers.slack import SlackParser

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
        allowed_methods=["GET"]
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
        f"slack/{timestamp.year}/{timestamp.month:02d}/{timestamp.day:02d}/"
        f"{timestamp.hour:02d}/{timestamp.strftime('%Y%m%d_%H%M%S')}.json"
    )

    content = "\n".join(json.dumps(event) for event in events)
    blob_client = container.get_blob_client(blob_path)
    blob_client.upload_blob(content, overwrite=True)

    return blob_path


class SlackCollector:
    """Slack Audit Logs API collector."""

    def __init__(self, api_token: str):
        self.api_token = api_token
        self.session = create_session_with_retry()
        self.endpoint = "https://api.slack.com/audit/v1/logs"

    def fetch_audit_logs(
        self,
        oldest: int = None,
        latest: int = None,
        limit: int = 1000
    ) -> List[Dict]:
        """Fetch audit logs from Slack API."""
        if oldest is None:
            oldest = int((datetime.now(timezone.utc) - timedelta(hours=1)).timestamp())

        headers = {
            "Authorization": f"Bearer {self.api_token}",
            "Content-Type": "application/json"
        }

        params = {
            "oldest": oldest,
            "limit": limit
        }

        if latest:
            params["latest"] = latest

        all_entries = []
        cursor = None

        while True:
            if cursor:
                params["cursor"] = cursor

            response = self.session.get(
                self.endpoint,
                headers=headers,
                params=params
            )

            if response.status_code == 429:
                retry_after = int(response.headers.get("Retry-After", 60))
                logger.warning(f"Rate limited, waiting {retry_after} seconds")
                import time
                time.sleep(retry_after)
                continue

            response.raise_for_status()
            data = response.json()

            if not data.get("ok"):
                logger.error(f"Slack API error: {data.get('error')}")
                break

            entries = data.get("entries", [])
            all_entries.extend(entries)

            logger.info(f"Fetched {len(entries)} audit log entries (total: {len(all_entries)})")

            response_metadata = data.get("response_metadata", {})
            cursor = response_metadata.get("next_cursor")

            if not cursor:
                break

        return all_entries


def main(req: func.HttpRequest) -> func.HttpResponse:
    """Azure Function handler for Slack audit log collection."""
    logger.info("Processing Slack audit log collection request")

    key_vault_url = os.environ.get("KEY_VAULT_URL")
    slack_secret_name = os.environ.get("SLACK_SECRET_NAME", "slack-api-token")
    storage_connection_string = os.environ.get("STORAGE_CONNECTION_STRING")
    container_name = os.environ.get("STORAGE_CONTAINER", "mantissa-logs")

    try:
        body = req.get_json() if req.get_body() else {}
        hours_back = body.get("hours_back", 1)
    except ValueError:
        hours_back = 1

    try:
        api_token = get_secret(key_vault_url, slack_secret_name)
        collector = SlackCollector(api_token=api_token)

        end_time = datetime.now(timezone.utc)
        start_time = end_time - timedelta(hours=hours_back)
        oldest = int(start_time.timestamp())
        latest = int(end_time.timestamp())

        logger.info(f"Collecting Slack logs from {start_time} to {end_time}")

        events = collector.fetch_audit_logs(oldest=oldest, latest=latest)
        logger.info(f"Collected {len(events)} Slack events")

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

        parser = SlackParser()
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
        logger.error(f"Error collecting Slack logs: {e}")
        import traceback
        traceback.print_exc()

        return func.HttpResponse(
            json.dumps({"success": False, "error": str(e)}),
            status_code=500,
            mimetype="application/json"
        )


def timer_trigger(timer: func.TimerRequest) -> None:
    """Timer trigger handler for scheduled Slack log collection."""
    logger.info("Timer trigger fired for Slack collector")

    key_vault_url = os.environ.get("KEY_VAULT_URL")
    slack_secret_name = os.environ.get("SLACK_SECRET_NAME", "slack-api-token")
    storage_connection_string = os.environ.get("STORAGE_CONNECTION_STRING")
    container_name = os.environ.get("STORAGE_CONTAINER", "mantissa-logs")

    try:
        api_token = get_secret(key_vault_url, slack_secret_name)
        collector = SlackCollector(api_token=api_token)

        end_time = datetime.now(timezone.utc)
        start_time = end_time - timedelta(minutes=15)
        oldest = int(start_time.timestamp())
        latest = int(end_time.timestamp())

        events = collector.fetch_audit_logs(oldest=oldest, latest=latest)
        logger.info(f"Collected {len(events)} Slack events")

        if events:
            parser = SlackParser()
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
