"""Azure Function handler for 1Password Events API log collection."""

import azure.functions as func
import json
import logging
import os
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

import requests
from azure.identity import DefaultAzureCredential
from azure.keyvault.secrets import SecretClient
from azure.storage.blob import BlobServiceClient

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
    source: str = "1password"
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


class OnePasswordCollector:
    """Collector for 1Password Events API."""

    BASE_URL = "https://events.1password.com"

    def __init__(self, api_token: str):
        """Initialize with 1Password Events API token."""
        self.api_token = api_token
        self.session = requests.Session()
        self.session.headers.update({
            "Authorization": f"Bearer {api_token}",
            "Content-Type": "application/json"
        })

    def fetch_signin_attempts(self, start_time: datetime = None, cursor: str = None) -> Dict[str, Any]:
        """Fetch sign-in attempt events."""
        url = f"{self.BASE_URL}/api/v1/signinattempts"

        payload = {"limit": 1000}

        if cursor:
            payload["cursor"] = cursor
        elif start_time:
            payload["start_time"] = start_time.strftime("%Y-%m-%dT%H:%M:%SZ")

        response = self.session.post(url, json=payload)
        response.raise_for_status()

        return response.json()

    def fetch_item_usages(self, start_time: datetime = None, cursor: str = None) -> Dict[str, Any]:
        """Fetch item usage events."""
        url = f"{self.BASE_URL}/api/v1/itemusages"

        payload = {"limit": 1000}

        if cursor:
            payload["cursor"] = cursor
        elif start_time:
            payload["start_time"] = start_time.strftime("%Y-%m-%dT%H:%M:%SZ")

        response = self.session.post(url, json=payload)
        response.raise_for_status()

        return response.json()

    def fetch_audit_events(self, start_time: datetime = None, cursor: str = None) -> Dict[str, Any]:
        """Fetch audit events."""
        url = f"{self.BASE_URL}/api/v1/auditevents"

        payload = {"limit": 1000}

        if cursor:
            payload["cursor"] = cursor
        elif start_time:
            payload["start_time"] = start_time.strftime("%Y-%m-%dT%H:%M:%SZ")

        response = self.session.post(url, json=payload)
        response.raise_for_status()

        return response.json()

    def fetch_all_signin_attempts(self, start_time: datetime = None) -> List[Dict]:
        """Fetch all sign-in attempts with pagination."""
        all_events = []
        cursor = None

        while True:
            response = self.fetch_signin_attempts(start_time=start_time, cursor=cursor)
            items = response.get("items", [])

            for item in items:
                item["_event_type"] = "signin_attempt"
                item["_collected_at"] = datetime.now(timezone.utc).isoformat()
                all_events.append(item)

            cursor = response.get("cursor")
            has_more = response.get("has_more", False)

            if not has_more or not cursor:
                break

        return all_events

    def fetch_all_item_usages(self, start_time: datetime = None) -> List[Dict]:
        """Fetch all item usage events with pagination."""
        all_events = []
        cursor = None

        while True:
            response = self.fetch_item_usages(start_time=start_time, cursor=cursor)
            items = response.get("items", [])

            for item in items:
                item["_event_type"] = "item_usage"
                item["_collected_at"] = datetime.now(timezone.utc).isoformat()
                all_events.append(item)

            cursor = response.get("cursor")
            has_more = response.get("has_more", False)

            if not has_more or not cursor:
                break

        return all_events

    def fetch_all_audit_events(self, start_time: datetime = None) -> List[Dict]:
        """Fetch all audit events with pagination."""
        all_events = []
        cursor = None

        while True:
            response = self.fetch_audit_events(start_time=start_time, cursor=cursor)
            items = response.get("items", [])

            for item in items:
                item["_event_type"] = "audit_event"
                item["_collected_at"] = datetime.now(timezone.utc).isoformat()
                all_events.append(item)

            cursor = response.get("cursor")
            has_more = response.get("has_more", False)

            if not has_more or not cursor:
                break

        return all_events


def main(req: func.HttpRequest) -> func.HttpResponse:
    """Azure Function handler for 1Password log collection."""
    logger.info("Processing 1Password log collection request")

    key_vault_url = os.environ.get("KEY_VAULT_URL")
    onepassword_creds_secret = os.environ.get("ONEPASSWORD_CREDS_SECRET", "onepassword-credentials")
    storage_connection_string = os.environ.get("STORAGE_CONNECTION_STRING")
    container_name = os.environ.get("STORAGE_CONTAINER", "mantissa-logs")

    try:
        body = req.get_json() if req.get_body() else {}
        hours_back = body.get("hours_back", 1)
        event_types = body.get("event_types", ["signin_attempts", "item_usages", "audit_events"])
    except ValueError:
        hours_back = 1
        event_types = ["signin_attempts", "item_usages", "audit_events"]

    try:
        # Get credentials from Key Vault
        creds_json = get_secret(key_vault_url, onepassword_creds_secret)
        creds = json.loads(creds_json)

        collector = OnePasswordCollector(api_token=creds["api_token"])

        start_time = datetime.now(timezone.utc) - timedelta(hours=hours_back)

        all_events = []

        if "signin_attempts" in event_types:
            signin_events = collector.fetch_all_signin_attempts(start_time)
            all_events.extend(signin_events)
            logger.info(f"Fetched {len(signin_events)} sign-in attempt events")

        if "item_usages" in event_types:
            item_events = collector.fetch_all_item_usages(start_time)
            all_events.extend(item_events)
            logger.info(f"Fetched {len(item_events)} item usage events")

        if "audit_events" in event_types:
            audit_events = collector.fetch_all_audit_events(start_time)
            all_events.extend(audit_events)
            logger.info(f"Fetched {len(audit_events)} audit events")

        if all_events:
            blob_path = upload_to_blob(
                connection_string=storage_connection_string,
                container_name=container_name,
                events=all_events,
                timestamp=datetime.now(timezone.utc)
            )
        else:
            blob_path = None

        return func.HttpResponse(
            json.dumps({
                "success": True,
                "events_collected": len(all_events),
                "blob_path": blob_path
            }),
            status_code=200,
            mimetype="application/json"
        )

    except Exception as e:
        logger.error(f"Error collecting 1Password logs: {e}")
        return func.HttpResponse(
            json.dumps({"success": False, "error": str(e)}),
            status_code=500,
            mimetype="application/json"
        )


def timer_trigger(timer: func.TimerRequest) -> None:
    """Timer trigger for scheduled 1Password log collection."""
    logger.info("Timer trigger fired for 1Password collector")

    key_vault_url = os.environ.get("KEY_VAULT_URL")
    onepassword_creds_secret = os.environ.get("ONEPASSWORD_CREDS_SECRET", "onepassword-credentials")
    storage_connection_string = os.environ.get("STORAGE_CONNECTION_STRING")
    container_name = os.environ.get("STORAGE_CONTAINER", "mantissa-logs")

    try:
        creds_json = get_secret(key_vault_url, onepassword_creds_secret)
        creds = json.loads(creds_json)

        collector = OnePasswordCollector(api_token=creds["api_token"])

        start_time = datetime.now(timezone.utc) - timedelta(hours=1)

        all_events = []
        all_events.extend(collector.fetch_all_signin_attempts(start_time))
        all_events.extend(collector.fetch_all_item_usages(start_time))
        all_events.extend(collector.fetch_all_audit_events(start_time))

        if all_events:
            upload_to_blob(
                connection_string=storage_connection_string,
                container_name=container_name,
                events=all_events,
                timestamp=datetime.now(timezone.utc)
            )
            logger.info(f"Collected and uploaded {len(all_events)} 1Password events")

    except Exception as e:
        logger.error(f"Error in timer trigger: {e}")
        raise
