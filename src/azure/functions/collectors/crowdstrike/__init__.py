"""Azure Function handler for CrowdStrike Falcon audit log collection."""

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

from src.shared.parsers.crowdstrike import CrowdStrikeParser

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
        f"crowdstrike/{timestamp.year}/{timestamp.month:02d}/{timestamp.day:02d}/"
        f"{timestamp.hour:02d}/{timestamp.strftime('%Y%m%d_%H%M%S')}.json"
    )

    content = "\n".join(json.dumps(event) for event in events)
    blob_client = container.get_blob_client(blob_path)
    blob_client.upload_blob(content, overwrite=True)

    return blob_path


class CrowdStrikeCollector:
    """CrowdStrike Falcon API collector."""

    CLOUD_URLS = {
        "us-1": "https://api.crowdstrike.com",
        "us-2": "https://api.us-2.crowdstrike.com",
        "eu-1": "https://api.eu-1.crowdstrike.com",
        "us-gov-1": "https://api.laggar.gcw.crowdstrike.com"
    }

    def __init__(
        self,
        client_id: str,
        client_secret: str,
        cloud: str = "us-1"
    ):
        self.client_id = client_id
        self.client_secret = client_secret
        self.base_url = self.CLOUD_URLS.get(cloud, self.CLOUD_URLS["us-1"])
        self.session = create_session_with_retry()
        self.access_token = None
        self.token_expiry = None

    def _get_access_token(self) -> str:
        """Get OAuth2 access token for CrowdStrike API."""
        if self.access_token and self.token_expiry and datetime.now(timezone.utc) < self.token_expiry:
            return self.access_token

        token_url = f"{self.base_url}/oauth2/token"

        data = {
            "client_id": self.client_id,
            "client_secret": self.client_secret
        }

        response = self.session.post(token_url, data=data)
        response.raise_for_status()

        token_data = response.json()
        self.access_token = token_data["access_token"]
        expires_in = token_data.get("expires_in", 1800)
        self.token_expiry = datetime.now(timezone.utc) + timedelta(seconds=expires_in - 60)

        return self.access_token

    def fetch_detections(
        self,
        start_time: datetime = None,
        end_time: datetime = None,
        limit: int = 500
    ) -> List[Dict]:
        """Fetch detections from CrowdStrike Falcon API."""
        if end_time is None:
            end_time = datetime.now(timezone.utc)
        if start_time is None:
            start_time = end_time - timedelta(hours=24)

        token = self._get_access_token()
        headers = {"Authorization": f"Bearer {token}"}

        # Query for detection IDs
        query_url = f"{self.base_url}/detects/queries/detects/v1"
        filter_str = f"last_behavior:>='{start_time.isoformat()}'+last_behavior:<='{end_time.isoformat()}'"

        params = {
            "filter": filter_str,
            "limit": limit,
            "sort": "last_behavior|asc"
        }

        all_detections = []
        offset = None

        while True:
            if offset:
                params["offset"] = offset

            response = self.session.get(query_url, headers=headers, params=params)

            if response.status_code == 429:
                retry_after = int(response.headers.get("X-RateLimit-RetryAfter", 60))
                logger.warning(f"Rate limited, waiting {retry_after} seconds")
                import time
                time.sleep(retry_after)
                continue

            response.raise_for_status()
            data = response.json()

            detection_ids = data.get("resources", [])
            if not detection_ids:
                break

            # Get detection details
            details_url = f"{self.base_url}/detects/entities/summaries/GET/v1"
            details_response = self.session.post(
                details_url,
                headers=headers,
                json={"ids": detection_ids}
            )
            details_response.raise_for_status()

            detections = details_response.json().get("resources", [])
            all_detections.extend(detections)

            logger.info(f"Fetched {len(detections)} detections (total: {len(all_detections)})")

            # Check for pagination
            meta = data.get("meta", {}).get("pagination", {})
            offset = meta.get("offset")
            total = meta.get("total", 0)

            if not offset or len(all_detections) >= total:
                break

        return all_detections

    def fetch_events(
        self,
        start_time: datetime = None,
        end_time: datetime = None,
        event_types: List[str] = None
    ) -> List[Dict]:
        """Fetch events from CrowdStrike Event Streams."""
        if end_time is None:
            end_time = datetime.now(timezone.utc)
        if start_time is None:
            start_time = end_time - timedelta(hours=1)

        if event_types is None:
            event_types = ["DetectionSummaryEvent", "AuthActivityAuditEvent", "UserActivityAuditEvent"]

        token = self._get_access_token()
        headers = {"Authorization": f"Bearer {token}"}

        all_events = []

        # Discover event stream
        discover_url = f"{self.base_url}/sensors/entities/datafeed/v2"
        params = {"appId": "mantissa-log-collector"}

        response = self.session.get(discover_url, headers=headers, params=params)
        response.raise_for_status()

        streams = response.json().get("resources", [])
        if not streams:
            logger.warning("No event streams available")
            return all_events

        # Process stream (simplified - full implementation would use streaming)
        for stream in streams:
            data_feed_url = stream.get("dataFeedURL")
            session_token = stream.get("sessionToken", {}).get("token")

            if data_feed_url and session_token:
                stream_headers = {
                    "Authorization": f"Token {session_token}",
                    "Accept": "application/json"
                }

                try:
                    # This is simplified - real implementation needs streaming
                    event_response = self.session.get(
                        data_feed_url,
                        headers=stream_headers,
                        timeout=30
                    )
                    if event_response.status_code == 200:
                        events = event_response.json().get("resources", [])
                        all_events.extend(events)
                except Exception as e:
                    logger.warning(f"Error reading event stream: {e}")

        return all_events


def main(req: func.HttpRequest) -> func.HttpResponse:
    """Azure Function handler for CrowdStrike log collection."""
    logger.info("Processing CrowdStrike log collection request")

    key_vault_url = os.environ.get("KEY_VAULT_URL")
    cs_client_id = os.environ.get("CROWDSTRIKE_CLIENT_ID")
    cs_secret_name = os.environ.get("CROWDSTRIKE_SECRET_NAME", "crowdstrike-client-secret")
    cs_cloud = os.environ.get("CROWDSTRIKE_CLOUD", "us-1")
    storage_connection_string = os.environ.get("STORAGE_CONNECTION_STRING")
    container_name = os.environ.get("STORAGE_CONTAINER", "mantissa-logs")

    if not cs_client_id:
        return func.HttpResponse(
            json.dumps({"error": "CROWDSTRIKE_CLIENT_ID must be set"}),
            status_code=400,
            mimetype="application/json"
        )

    try:
        body = req.get_json() if req.get_body() else {}
        hours_back = body.get("hours_back", 24)
        include_detections = body.get("include_detections", True)
    except ValueError:
        hours_back = 24
        include_detections = True

    try:
        client_secret = get_secret(key_vault_url, cs_secret_name)
        collector = CrowdStrikeCollector(
            client_id=cs_client_id,
            client_secret=client_secret,
            cloud=cs_cloud
        )

        end_time = datetime.now(timezone.utc)
        start_time = end_time - timedelta(hours=hours_back)

        logger.info(f"Collecting CrowdStrike logs from {start_time} to {end_time}")

        all_events = []

        if include_detections:
            detections = collector.fetch_detections(start_time=start_time, end_time=end_time)
            for d in detections:
                d["_event_type"] = "detection"
            all_events.extend(detections)

        logger.info(f"Collected {len(all_events)} CrowdStrike events")

        if not all_events:
            return func.HttpResponse(
                json.dumps({
                    "success": True,
                    "message": "No events found in time range",
                    "events_collected": 0
                }),
                status_code=200,
                mimetype="application/json"
            )

        parser = CrowdStrikeParser()
        parsed_events = []
        for event in all_events:
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
                "events_collected": len(all_events),
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
        logger.error(f"Error collecting CrowdStrike logs: {e}")
        import traceback
        traceback.print_exc()

        return func.HttpResponse(
            json.dumps({"success": False, "error": str(e)}),
            status_code=500,
            mimetype="application/json"
        )


def timer_trigger(timer: func.TimerRequest) -> None:
    """Timer trigger handler for scheduled CrowdStrike log collection."""
    logger.info("Timer trigger fired for CrowdStrike collector")

    key_vault_url = os.environ.get("KEY_VAULT_URL")
    cs_client_id = os.environ.get("CROWDSTRIKE_CLIENT_ID")
    cs_secret_name = os.environ.get("CROWDSTRIKE_SECRET_NAME", "crowdstrike-client-secret")
    cs_cloud = os.environ.get("CROWDSTRIKE_CLOUD", "us-1")
    storage_connection_string = os.environ.get("STORAGE_CONNECTION_STRING")
    container_name = os.environ.get("STORAGE_CONTAINER", "mantissa-logs")

    if not cs_client_id:
        logger.error("CROWDSTRIKE_CLIENT_ID not configured")
        return

    try:
        client_secret = get_secret(key_vault_url, cs_secret_name)
        collector = CrowdStrikeCollector(
            client_id=cs_client_id,
            client_secret=client_secret,
            cloud=cs_cloud
        )

        end_time = datetime.now(timezone.utc)
        start_time = end_time - timedelta(hours=1)

        detections = collector.fetch_detections(start_time=start_time, end_time=end_time)
        for d in detections:
            d["_event_type"] = "detection"

        logger.info(f"Collected {len(detections)} CrowdStrike events")

        if detections:
            parser = CrowdStrikeParser()
            parsed_events = []
            for event in detections:
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
