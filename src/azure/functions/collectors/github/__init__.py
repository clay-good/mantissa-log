"""Azure Function handler for GitHub audit log collection."""

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

from src.shared.parsers.github import GitHubParser

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
        f"github/{timestamp.year}/{timestamp.month:02d}/{timestamp.day:02d}/"
        f"{timestamp.hour:02d}/{timestamp.strftime('%Y%m%d_%H%M%S')}.json"
    )

    content = "\n".join(json.dumps(event) for event in events)
    blob_client = container.get_blob_client(blob_path)
    blob_client.upload_blob(content, overwrite=True)

    return blob_path


class GitHubCollector:
    """GitHub Enterprise/Organization Audit Log collector."""

    def __init__(self, api_token: str, enterprise: str = None, organization: str = None):
        self.api_token = api_token
        self.enterprise = enterprise
        self.organization = organization
        self.session = create_session_with_retry()

        api_base = "https://api.github.com"
        if self.enterprise:
            self.audit_endpoint = f"{api_base}/enterprises/{self.enterprise}/audit-log"
            self.source_key = f"github_enterprise_{self.enterprise}"
        elif self.organization:
            self.audit_endpoint = f"{api_base}/orgs/{self.organization}/audit-log"
            self.source_key = f"github_org_{self.organization}"
        else:
            raise ValueError("Either enterprise or organization must be specified")

    def fetch_audit_logs(
        self,
        start_timestamp: int,
        end_timestamp: int = None
    ) -> List[Dict]:
        """Fetch audit logs within timestamp range."""
        if end_timestamp is None:
            end_timestamp = int(datetime.now(timezone.utc).timestamp() * 1000)

        start_dt = datetime.fromtimestamp(start_timestamp / 1000, tz=timezone.utc)
        end_dt = datetime.fromtimestamp(end_timestamp / 1000, tz=timezone.utc)

        phrase = f"created:>={start_dt.strftime('%Y-%m-%d')} created:<={end_dt.strftime('%Y-%m-%d')}"

        headers = {
            "Authorization": f"Bearer {self.api_token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28"
        }

        params = {
            "phrase": phrase,
            "include": "all",
            "order": "asc",
            "per_page": 100
        }

        all_events = []
        page = 1

        while True:
            params["page"] = page
            response = self.session.get(
                self.audit_endpoint,
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
            events = response.json()

            if not events:
                break

            all_events.extend(events)
            logger.info(f"Fetched {len(events)} audit log events (page {page}, total: {len(all_events)})")

            link_header = response.headers.get("Link", "")
            if 'rel="next"' not in link_header:
                break

            page += 1

        filtered_events = [
            event for event in all_events
            if start_timestamp <= event.get("@timestamp", 0) <= end_timestamp
        ]

        return filtered_events


def main(req: func.HttpRequest) -> func.HttpResponse:
    """Azure Function handler for GitHub audit log collection."""
    logger.info("Processing GitHub audit log collection request")

    key_vault_url = os.environ.get("KEY_VAULT_URL")
    github_secret_name = os.environ.get("GITHUB_SECRET_NAME", "github-api-token")
    github_enterprise = os.environ.get("GITHUB_ENTERPRISE")
    github_org = os.environ.get("GITHUB_ORG")
    storage_connection_string = os.environ.get("STORAGE_CONNECTION_STRING")
    container_name = os.environ.get("STORAGE_CONTAINER", "mantissa-logs")

    if not github_enterprise and not github_org:
        return func.HttpResponse(
            json.dumps({"error": "Either GITHUB_ENTERPRISE or GITHUB_ORG must be set"}),
            status_code=400,
            mimetype="application/json"
        )

    try:
        body = req.get_json() if req.get_body() else {}
        hours_back = body.get("hours_back", 24)
    except ValueError:
        hours_back = 24

    try:
        api_token = get_secret(key_vault_url, github_secret_name)
        collector = GitHubCollector(
            api_token=api_token,
            enterprise=github_enterprise,
            organization=github_org
        )

        end_time = datetime.now(timezone.utc)
        start_time = end_time - timedelta(hours=hours_back)
        start_timestamp = int(start_time.timestamp() * 1000)
        end_timestamp = int(end_time.timestamp() * 1000)

        logger.info(f"Collecting GitHub logs from {start_time} to {end_time}")

        events = collector.fetch_audit_logs(start_timestamp, end_timestamp)
        logger.info(f"Collected {len(events)} GitHub events")

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

        parser = GitHubParser()
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
        logger.error(f"Error collecting GitHub logs: {e}")
        import traceback
        traceback.print_exc()

        return func.HttpResponse(
            json.dumps({"success": False, "error": str(e)}),
            status_code=500,
            mimetype="application/json"
        )


def timer_trigger(timer: func.TimerRequest) -> None:
    """Timer trigger handler for scheduled GitHub log collection."""
    logger.info("Timer trigger fired for GitHub collector")

    key_vault_url = os.environ.get("KEY_VAULT_URL")
    github_secret_name = os.environ.get("GITHUB_SECRET_NAME", "github-api-token")
    github_enterprise = os.environ.get("GITHUB_ENTERPRISE")
    github_org = os.environ.get("GITHUB_ORG")
    storage_connection_string = os.environ.get("STORAGE_CONNECTION_STRING")
    container_name = os.environ.get("STORAGE_CONTAINER", "mantissa-logs")

    if not github_enterprise and not github_org:
        logger.error("Neither GITHUB_ENTERPRISE nor GITHUB_ORG configured")
        return

    try:
        api_token = get_secret(key_vault_url, github_secret_name)
        collector = GitHubCollector(
            api_token=api_token,
            enterprise=github_enterprise,
            organization=github_org
        )

        end_time = datetime.now(timezone.utc)
        start_time = end_time - timedelta(hours=1)
        start_timestamp = int(start_time.timestamp() * 1000)
        end_timestamp = int(end_time.timestamp() * 1000)

        events = collector.fetch_audit_logs(start_timestamp, end_timestamp)
        logger.info(f"Collected {len(events)} GitHub events")

        if events:
            parser = GitHubParser()
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
