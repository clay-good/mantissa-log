"""Azure Function handler for Salesforce log collection."""

import azure.functions as func
import json
import logging
import os
import csv
import io
import requests
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List

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
    source: str = "salesforce"
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


class SalesforceCollector:
    """Collector for Salesforce Event Log Files."""

    def __init__(self, instance_url: str, client_id: str, client_secret: str, username: str, password: str):
        """Initialize with OAuth credentials."""
        self.instance_url = instance_url
        self.client_id = client_id
        self.client_secret = client_secret
        self.username = username
        self.password = password
        self.access_token = None
        self.session = requests.Session()

    def authenticate(self) -> None:
        """Authenticate with Salesforce OAuth."""
        auth_url = f"{self.instance_url}/services/oauth2/token"
        data = {
            "grant_type": "password",
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "username": self.username,
            "password": self.password
        }

        response = self.session.post(auth_url, data=data)
        response.raise_for_status()

        auth_data = response.json()
        self.access_token = auth_data["access_token"]
        self.instance_url = auth_data.get("instance_url", self.instance_url)

    def fetch_event_log_files(self, log_date: str = None) -> List[Dict]:
        """Fetch EventLogFile records from Salesforce.

        Args:
            log_date: Date in YYYY-MM-DD format, defaults to yesterday
        """
        if not self.access_token:
            self.authenticate()

        if not log_date:
            log_date = (datetime.now(timezone.utc) - timedelta(days=1)).strftime('%Y-%m-%d')

        query = (
            f"SELECT Id, EventType, LogDate, LogFileLength, LogFile "
            f"FROM EventLogFile WHERE LogDate = {log_date}"
        )

        headers = {"Authorization": f"Bearer {self.access_token}"}
        query_url = f"{self.instance_url}/services/data/v58.0/query"

        response = self.session.get(query_url, headers=headers, params={"q": query})
        response.raise_for_status()

        return response.json().get("records", [])

    def download_log_file(self, log_file_url: str) -> List[Dict]:
        """Download and parse a log file CSV."""
        if not self.access_token:
            self.authenticate()

        headers = {"Authorization": f"Bearer {self.access_token}"}
        full_url = f"{self.instance_url}{log_file_url}"

        response = self.session.get(full_url, headers=headers)
        response.raise_for_status()

        # Parse CSV content
        csv_content = response.text
        reader = csv.DictReader(io.StringIO(csv_content))
        return list(reader)


def main(req: func.HttpRequest) -> func.HttpResponse:
    """Azure Function handler for Salesforce log collection."""
    logger.info("Processing Salesforce log collection request")

    key_vault_url = os.environ.get("KEY_VAULT_URL")
    sf_creds_secret = os.environ.get("SALESFORCE_CREDS_SECRET", "salesforce-credentials")
    storage_connection_string = os.environ.get("STORAGE_CONNECTION_STRING")
    container_name = os.environ.get("STORAGE_CONTAINER", "mantissa-logs")

    try:
        body = req.get_json() if req.get_body() else {}
        log_date = body.get("log_date")
    except ValueError:
        log_date = None

    try:
        # Get credentials from Key Vault
        creds_json = get_secret(key_vault_url, sf_creds_secret)
        creds = json.loads(creds_json)

        collector = SalesforceCollector(
            instance_url=creds["instance_url"],
            client_id=creds["client_id"],
            client_secret=creds["client_secret"],
            username=creds["username"],
            password=creds["password"]
        )

        # Fetch event log file records
        log_files = collector.fetch_event_log_files(log_date)
        logger.info(f"Found {len(log_files)} event log files")

        all_events = []
        for log_file in log_files:
            event_type = log_file.get("EventType")
            log_file_url = log_file.get("LogFile")

            if log_file_url:
                events = collector.download_log_file(log_file_url)
                for event in events:
                    event["_event_type"] = event_type
                    event["_log_date"] = log_file.get("LogDate")
                all_events.extend(events)
                logger.info(f"Downloaded {len(events)} events for {event_type}")

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
                "log_files_processed": len(log_files),
                "events_collected": len(all_events),
                "blob_path": blob_path
            }),
            status_code=200,
            mimetype="application/json"
        )

    except Exception as e:
        logger.error(f"Error collecting Salesforce logs: {e}")
        return func.HttpResponse(
            json.dumps({"success": False, "error": str(e)}),
            status_code=500,
            mimetype="application/json"
        )


def timer_trigger(timer: func.TimerRequest) -> None:
    """Timer trigger for scheduled Salesforce log collection."""
    logger.info("Timer trigger fired for Salesforce collector")

    key_vault_url = os.environ.get("KEY_VAULT_URL")
    sf_creds_secret = os.environ.get("SALESFORCE_CREDS_SECRET", "salesforce-credentials")
    storage_connection_string = os.environ.get("STORAGE_CONNECTION_STRING")
    container_name = os.environ.get("STORAGE_CONTAINER", "mantissa-logs")

    try:
        creds_json = get_secret(key_vault_url, sf_creds_secret)
        creds = json.loads(creds_json)

        collector = SalesforceCollector(
            instance_url=creds["instance_url"],
            client_id=creds["client_id"],
            client_secret=creds["client_secret"],
            username=creds["username"],
            password=creds["password"]
        )

        # Fetch yesterday's logs (Salesforce logs are available next day)
        log_files = collector.fetch_event_log_files()

        all_events = []
        for log_file in log_files:
            log_file_url = log_file.get("LogFile")
            if log_file_url:
                events = collector.download_log_file(log_file_url)
                for event in events:
                    event["_event_type"] = log_file.get("EventType")
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
