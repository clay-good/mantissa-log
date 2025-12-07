"""Azure Function handler for Okta log collection."""

import azure.functions as func
import json
import logging
import os
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List

from azure.identity import DefaultAzureCredential
from azure.keyvault.secrets import SecretClient
from azure.storage.blob import BlobServiceClient, ContainerClient

from src.shared.parsers.okta import OktaParser
from src.azure.functions.collectors import OktaCollector

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
    timestamp: datetime
) -> str:
    """Upload events to Azure Blob Storage."""
    blob_service = BlobServiceClient.from_connection_string(connection_string)
    container = blob_service.get_container_client(container_name)

    # Create partitioned path: year/month/day/hour/
    blob_path = (
        f"okta/{timestamp.year}/{timestamp.month:02d}/{timestamp.day:02d}/"
        f"{timestamp.hour:02d}/{timestamp.strftime('%Y%m%d_%H%M%S')}.json"
    )

    # Upload as newline-delimited JSON
    content = "\n".join(json.dumps(event) for event in events)
    blob_client = container.get_blob_client(blob_path)
    blob_client.upload_blob(content, overwrite=True)

    return blob_path


def main(req: func.HttpRequest) -> func.HttpResponse:
    """Azure Function handler for Okta log collection.

    Collects Okta System Log events and stores them in Azure Blob Storage.
    """
    logger.info("Processing Okta log collection request")

    # Load configuration
    key_vault_url = os.environ.get("KEY_VAULT_URL")
    okta_secret_name = os.environ.get("OKTA_SECRET_NAME", "okta-api-token")
    okta_org_url = os.environ.get("OKTA_ORG_URL")
    storage_connection_string = os.environ.get("STORAGE_CONNECTION_STRING")
    container_name = os.environ.get("STORAGE_CONTAINER", "mantissa-logs")

    if not okta_org_url:
        return func.HttpResponse(
            json.dumps({"error": "OKTA_ORG_URL environment variable not set"}),
            status_code=400,
            mimetype="application/json"
        )

    try:
        body = req.get_json() if req.get_body() else {}
        since = body.get("since")
        until = body.get("until")
        days_back = body.get("days_back", 1)
    except ValueError:
        body = {}
        since = None
        until = None
        days_back = 1

    try:
        # Get API token from Key Vault
        api_token = get_secret(key_vault_url, okta_secret_name)

        # Initialize collector
        collector = OktaCollector(api_token=api_token, org_url=okta_org_url)

        # Calculate time range
        if not since:
            since = (datetime.now(timezone.utc) - timedelta(days=days_back)).isoformat()
        if not until:
            until = datetime.now(timezone.utc).isoformat()

        logger.info(f"Collecting Okta logs from {since} to {until}")

        # Fetch events
        events = collector.fetch_system_logs(since=since, until=until)
        logger.info(f"Collected {len(events)} Okta events")

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

        # Parse events with Okta parser
        parser = OktaParser()
        parsed_events = []
        for event in events:
            try:
                parsed = parser.parse(event)
                parsed_events.append(parsed)
            except Exception as e:
                logger.warning(f"Failed to parse event: {e}")
                parsed_events.append(event)  # Keep raw event

        # Upload to Blob Storage
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
                    "since": since,
                    "until": until
                }
            }),
            status_code=200,
            mimetype="application/json"
        )

    except Exception as e:
        logger.error(f"Error collecting Okta logs: {e}")
        import traceback
        traceback.print_exc()

        return func.HttpResponse(
            json.dumps({
                "success": False,
                "error": str(e)
            }),
            status_code=500,
            mimetype="application/json"
        )


def timer_trigger(timer: func.TimerRequest) -> None:
    """Timer trigger handler for scheduled Okta log collection.

    Runs every 15 minutes to collect recent logs.
    """
    logger.info("Timer trigger fired for Okta collector")

    key_vault_url = os.environ.get("KEY_VAULT_URL")
    okta_secret_name = os.environ.get("OKTA_SECRET_NAME", "okta-api-token")
    okta_org_url = os.environ.get("OKTA_ORG_URL")
    storage_connection_string = os.environ.get("STORAGE_CONNECTION_STRING")
    container_name = os.environ.get("STORAGE_CONTAINER", "mantissa-logs")

    if not okta_org_url:
        logger.error("OKTA_ORG_URL not configured")
        return

    try:
        # Get API token
        api_token = get_secret(key_vault_url, okta_secret_name)

        # Initialize collector
        collector = OktaCollector(api_token=api_token, org_url=okta_org_url)

        # Collect last 15 minutes
        since = (datetime.now(timezone.utc) - timedelta(minutes=15)).isoformat()
        until = datetime.now(timezone.utc).isoformat()

        events = collector.fetch_system_logs(since=since, until=until)
        logger.info(f"Collected {len(events)} Okta events")

        if events:
            # Parse events
            parser = OktaParser()
            parsed_events = []
            for event in events:
                try:
                    parsed = parser.parse(event)
                    parsed_events.append(parsed)
                except Exception:
                    parsed_events.append(event)

            # Upload to Blob Storage
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
