"""Azure Function handler for Jamf Pro log collection."""

import azure.functions as func
import json
import logging
import os
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List

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
    source: str = "jamf"
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


class JamfCollector:
    """Collector for Jamf Pro Audit Logs and Computer Events."""

    def __init__(self, base_url: str, client_id: str, client_secret: str):
        """Initialize with Jamf Pro API credentials."""
        self.base_url = base_url.rstrip("/")
        self.client_id = client_id
        self.client_secret = client_secret
        self.access_token = None
        self.session = requests.Session()

    def authenticate(self) -> None:
        """Authenticate with Jamf Pro API using OAuth."""
        auth_url = f"{self.base_url}/api/oauth/token"
        data = {
            "grant_type": "client_credentials",
            "client_id": self.client_id,
            "client_secret": self.client_secret
        }

        response = self.session.post(auth_url, data=data)
        response.raise_for_status()

        auth_data = response.json()
        self.access_token = auth_data["access_token"]

    def _get_headers(self) -> Dict[str, str]:
        """Get headers with authentication."""
        if not self.access_token:
            self.authenticate()
        return {
            "Authorization": f"Bearer {self.access_token}",
            "Accept": "application/json"
        }

    def fetch_audit_logs(self, start_date: datetime = None, end_date: datetime = None, page_size: int = 100) -> List[Dict]:
        """Fetch audit logs from Jamf Pro."""
        if not end_date:
            end_date = datetime.now(timezone.utc)
        if not start_date:
            start_date = end_date - timedelta(hours=1)

        # Jamf Pro API v1 audit logs endpoint
        url = f"{self.base_url}/api/v1/jamf-pro-server-url"

        # First, get server info to confirm connectivity
        try:
            response = self.session.get(url, headers=self._get_headers())
            response.raise_for_status()
        except Exception as e:
            logger.warning(f"Server URL check failed: {e}")

        # Fetch audit logs - using Jamf Pro API
        audit_url = f"{self.base_url}/api/v1/audit-logs"
        params = {
            "page": 0,
            "page-size": page_size,
            "sort": "dateTime:desc",
            "filter": f"dateTime>={start_date.strftime('%Y-%m-%dT%H:%M:%SZ')} and dateTime<={end_date.strftime('%Y-%m-%dT%H:%M:%SZ')}"
        }

        all_logs = []
        while True:
            response = self.session.get(audit_url, headers=self._get_headers(), params=params)
            response.raise_for_status()

            data = response.json()
            results = data.get("results", [])

            for log in results:
                log["_event_type"] = "audit_log"
                log["_collected_at"] = datetime.now(timezone.utc).isoformat()
                all_logs.append(log)

            if len(results) < page_size:
                break

            params["page"] += 1

        return all_logs

    def fetch_computer_history(self, page_size: int = 100) -> List[Dict]:
        """Fetch computer management history."""
        url = f"{self.base_url}/api/v1/computers-inventory"
        params = {
            "page": 0,
            "page-size": page_size,
            "section": "GENERAL,HARDWARE,OPERATING_SYSTEM,USER_AND_LOCATION"
        }

        all_computers = []
        while True:
            response = self.session.get(url, headers=self._get_headers(), params=params)
            response.raise_for_status()

            data = response.json()
            results = data.get("results", [])

            for computer in results:
                computer["_event_type"] = "computer_inventory"
                computer["_collected_at"] = datetime.now(timezone.utc).isoformat()
                all_computers.append(computer)

            if len(results) < page_size:
                break

            params["page"] += 1

        return all_computers

    def fetch_mobile_device_history(self, page_size: int = 100) -> List[Dict]:
        """Fetch mobile device management history."""
        url = f"{self.base_url}/api/v2/mobile-devices"
        params = {
            "page": 0,
            "page-size": page_size
        }

        all_devices = []
        while True:
            response = self.session.get(url, headers=self._get_headers(), params=params)
            response.raise_for_status()

            data = response.json()
            results = data.get("results", [])

            for device in results:
                device["_event_type"] = "mobile_device"
                device["_collected_at"] = datetime.now(timezone.utc).isoformat()
                all_devices.append(device)

            if len(results) < page_size:
                break

            params["page"] += 1

        return all_devices

    def fetch_policies(self) -> List[Dict]:
        """Fetch policy execution logs."""
        url = f"{self.base_url}/api/v1/policies"

        response = self.session.get(url, headers=self._get_headers())
        response.raise_for_status()

        data = response.json()
        policies = data.get("results", [])

        for policy in policies:
            policy["_event_type"] = "policy"
            policy["_collected_at"] = datetime.now(timezone.utc).isoformat()

        return policies


def main(req: func.HttpRequest) -> func.HttpResponse:
    """Azure Function handler for Jamf log collection."""
    logger.info("Processing Jamf log collection request")

    key_vault_url = os.environ.get("KEY_VAULT_URL")
    jamf_creds_secret = os.environ.get("JAMF_CREDS_SECRET", "jamf-credentials")
    storage_connection_string = os.environ.get("STORAGE_CONNECTION_STRING")
    container_name = os.environ.get("STORAGE_CONTAINER", "mantissa-logs")

    try:
        body = req.get_json() if req.get_body() else {}
        hours_back = body.get("hours_back", 1)
        event_types = body.get("event_types", ["audit_logs", "computers", "mobile_devices"])
    except ValueError:
        hours_back = 1
        event_types = ["audit_logs", "computers", "mobile_devices"]

    try:
        # Get credentials from Key Vault
        creds_json = get_secret(key_vault_url, jamf_creds_secret)
        creds = json.loads(creds_json)

        collector = JamfCollector(
            base_url=creds["base_url"],
            client_id=creds["client_id"],
            client_secret=creds["client_secret"]
        )

        end_time = datetime.now(timezone.utc)
        start_time = end_time - timedelta(hours=hours_back)

        all_events = []

        if "audit_logs" in event_types:
            audit_logs = collector.fetch_audit_logs(start_time, end_time)
            all_events.extend(audit_logs)
            logger.info(f"Fetched {len(audit_logs)} audit log events")

        if "computers" in event_types:
            computers = collector.fetch_computer_history()
            all_events.extend(computers)
            logger.info(f"Fetched {len(computers)} computer inventory events")

        if "mobile_devices" in event_types:
            mobile_devices = collector.fetch_mobile_device_history()
            all_events.extend(mobile_devices)
            logger.info(f"Fetched {len(mobile_devices)} mobile device events")

        if "policies" in event_types:
            policies = collector.fetch_policies()
            all_events.extend(policies)
            logger.info(f"Fetched {len(policies)} policy events")

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
        logger.error(f"Error collecting Jamf logs: {e}")
        return func.HttpResponse(
            json.dumps({"success": False, "error": str(e)}),
            status_code=500,
            mimetype="application/json"
        )


def timer_trigger(timer: func.TimerRequest) -> None:
    """Timer trigger for scheduled Jamf log collection."""
    logger.info("Timer trigger fired for Jamf collector")

    key_vault_url = os.environ.get("KEY_VAULT_URL")
    jamf_creds_secret = os.environ.get("JAMF_CREDS_SECRET", "jamf-credentials")
    storage_connection_string = os.environ.get("STORAGE_CONNECTION_STRING")
    container_name = os.environ.get("STORAGE_CONTAINER", "mantissa-logs")

    try:
        creds_json = get_secret(key_vault_url, jamf_creds_secret)
        creds = json.loads(creds_json)

        collector = JamfCollector(
            base_url=creds["base_url"],
            client_id=creds["client_id"],
            client_secret=creds["client_secret"]
        )

        end_time = datetime.now(timezone.utc)
        start_time = end_time - timedelta(hours=1)

        all_events = []
        all_events.extend(collector.fetch_audit_logs(start_time, end_time))
        all_events.extend(collector.fetch_computer_history())
        all_events.extend(collector.fetch_mobile_device_history())

        if all_events:
            upload_to_blob(
                connection_string=storage_connection_string,
                container_name=container_name,
                events=all_events,
                timestamp=datetime.now(timezone.utc)
            )
            logger.info(f"Collected and uploaded {len(all_events)} Jamf events")

    except Exception as e:
        logger.error(f"Error in timer trigger: {e}")
        raise
