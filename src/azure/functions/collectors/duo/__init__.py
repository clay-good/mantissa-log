"""Azure Function handler for Duo Security audit log collection."""

import azure.functions as func
import json
import logging
import os
import hmac
import hashlib
import base64
import email.utils
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List
from urllib.parse import urlencode

from azure.identity import DefaultAzureCredential
from azure.keyvault.secrets import SecretClient
from azure.storage.blob import BlobServiceClient
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from src.shared.parsers.duo import DuoParser

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
        f"duo/{timestamp.year}/{timestamp.month:02d}/{timestamp.day:02d}/"
        f"{timestamp.hour:02d}/{timestamp.strftime('%Y%m%d_%H%M%S')}.json"
    )

    content = "\n".join(json.dumps(event) for event in events)
    blob_client = container.get_blob_client(blob_path)
    blob_client.upload_blob(content, overwrite=True)

    return blob_path


class DuoCollector:
    """Duo Security Admin API collector."""

    def __init__(
        self,
        integration_key: str,
        secret_key: str,
        api_hostname: str
    ):
        self.integration_key = integration_key
        self.secret_key = secret_key
        self.api_hostname = api_hostname
        self.session = create_session_with_retry()

    def _sign_request(self, method: str, path: str, params: dict) -> Dict[str, str]:
        """Sign request using Duo's authentication scheme."""
        now = email.utils.formatdate()

        # Canonicalize parameters
        canon_params = urlencode(sorted(params.items()))

        # Create signature string
        canon = [
            now,
            method.upper(),
            self.api_hostname.lower(),
            path,
            canon_params
        ]
        signature_string = "\n".join(canon)

        # Sign with HMAC-SHA1
        sig = hmac.new(
            self.secret_key.encode("utf-8"),
            signature_string.encode("utf-8"),
            hashlib.sha1
        )
        auth = f"{self.integration_key}:{sig.hexdigest()}"
        auth_header = f"Basic {base64.b64encode(auth.encode('utf-8')).decode('utf-8')}"

        return {
            "Date": now,
            "Authorization": auth_header,
            "Content-Type": "application/x-www-form-urlencoded"
        }

    def fetch_authentication_logs(
        self,
        mintime: int = None,
        maxtime: int = None
    ) -> List[Dict]:
        """Fetch authentication logs from Duo Admin API."""
        if maxtime is None:
            maxtime = int(datetime.now(timezone.utc).timestamp() * 1000)
        if mintime is None:
            mintime = maxtime - (24 * 60 * 60 * 1000)  # 24 hours

        path = "/admin/v2/logs/authentication"
        url = f"https://{self.api_hostname}{path}"

        all_logs = []
        next_offset = None

        while True:
            params = {
                "mintime": str(mintime),
                "maxtime": str(maxtime),
                "limit": "1000"
            }

            if next_offset:
                params["next_offset"] = next_offset

            headers = self._sign_request("GET", path, params)

            response = self.session.get(url, headers=headers, params=params)

            if response.status_code == 429:
                retry_after = int(response.headers.get("Retry-After", 60))
                logger.warning(f"Rate limited, waiting {retry_after} seconds")
                import time
                time.sleep(retry_after)
                continue

            response.raise_for_status()
            data = response.json()

            if data.get("stat") != "OK":
                raise Exception(f"Duo API error: {data.get('message')}")

            logs = data.get("response", {}).get("authlogs", [])
            all_logs.extend(logs)

            logger.info(f"Fetched {len(logs)} authentication logs (total: {len(all_logs)})")

            # Check for pagination
            metadata = data.get("response", {}).get("metadata", {})
            next_offset = metadata.get("next_offset")

            if not next_offset:
                break

        return all_logs

    def fetch_admin_logs(
        self,
        mintime: int = None
    ) -> List[Dict]:
        """Fetch administrator action logs from Duo Admin API."""
        if mintime is None:
            mintime = int((datetime.now(timezone.utc) - timedelta(hours=24)).timestamp())

        path = "/admin/v1/logs/administrator"
        url = f"https://{self.api_hostname}{path}"

        params = {"mintime": str(mintime)}
        headers = self._sign_request("GET", path, params)

        response = self.session.get(url, headers=headers, params=params)
        response.raise_for_status()
        data = response.json()

        if data.get("stat") != "OK":
            raise Exception(f"Duo API error: {data.get('message')}")

        return data.get("response", [])

    def fetch_telephony_logs(
        self,
        mintime: int = None
    ) -> List[Dict]:
        """Fetch telephony logs from Duo Admin API."""
        if mintime is None:
            mintime = int((datetime.now(timezone.utc) - timedelta(hours=24)).timestamp())

        path = "/admin/v1/logs/telephony"
        url = f"https://{self.api_hostname}{path}"

        params = {"mintime": str(mintime)}
        headers = self._sign_request("GET", path, params)

        response = self.session.get(url, headers=headers, params=params)
        response.raise_for_status()
        data = response.json()

        if data.get("stat") != "OK":
            raise Exception(f"Duo API error: {data.get('message')}")

        return data.get("response", [])


def main(req: func.HttpRequest) -> func.HttpResponse:
    """Azure Function handler for Duo Security log collection."""
    logger.info("Processing Duo Security log collection request")

    key_vault_url = os.environ.get("KEY_VAULT_URL")
    duo_ikey = os.environ.get("DUO_INTEGRATION_KEY")
    duo_skey_name = os.environ.get("DUO_SECRET_NAME", "duo-secret-key")
    duo_api_host = os.environ.get("DUO_API_HOSTNAME")
    storage_connection_string = os.environ.get("STORAGE_CONNECTION_STRING")
    container_name = os.environ.get("STORAGE_CONTAINER", "mantissa-logs")

    if not all([duo_ikey, duo_api_host]):
        return func.HttpResponse(
            json.dumps({"error": "DUO_INTEGRATION_KEY and DUO_API_HOSTNAME must be set"}),
            status_code=400,
            mimetype="application/json"
        )

    try:
        body = req.get_json() if req.get_body() else {}
        hours_back = body.get("hours_back", 24)
        include_admin = body.get("include_admin_logs", True)
        include_telephony = body.get("include_telephony_logs", False)
    except ValueError:
        hours_back = 24
        include_admin = True
        include_telephony = False

    try:
        secret_key = get_secret(key_vault_url, duo_skey_name)
        collector = DuoCollector(
            integration_key=duo_ikey,
            secret_key=secret_key,
            api_hostname=duo_api_host
        )

        end_time = datetime.now(timezone.utc)
        start_time = end_time - timedelta(hours=hours_back)
        mintime = int(start_time.timestamp() * 1000)
        maxtime = int(end_time.timestamp() * 1000)

        logger.info(f"Collecting Duo logs from {start_time} to {end_time}")

        all_events = []

        # Fetch authentication logs
        auth_logs = collector.fetch_authentication_logs(mintime=mintime, maxtime=maxtime)
        for log in auth_logs:
            log["_log_type"] = "authentication"
        all_events.extend(auth_logs)

        # Fetch admin logs
        if include_admin:
            admin_logs = collector.fetch_admin_logs(mintime=int(start_time.timestamp()))
            for log in admin_logs:
                log["_log_type"] = "administrator"
            all_events.extend(admin_logs)

        # Fetch telephony logs
        if include_telephony:
            telephony_logs = collector.fetch_telephony_logs(mintime=int(start_time.timestamp()))
            for log in telephony_logs:
                log["_log_type"] = "telephony"
            all_events.extend(telephony_logs)

        logger.info(f"Collected {len(all_events)} Duo events")

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

        parser = DuoParser()
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
        logger.error(f"Error collecting Duo logs: {e}")
        import traceback
        traceback.print_exc()

        return func.HttpResponse(
            json.dumps({"success": False, "error": str(e)}),
            status_code=500,
            mimetype="application/json"
        )


def timer_trigger(timer: func.TimerRequest) -> None:
    """Timer trigger handler for scheduled Duo log collection."""
    logger.info("Timer trigger fired for Duo collector")

    key_vault_url = os.environ.get("KEY_VAULT_URL")
    duo_ikey = os.environ.get("DUO_INTEGRATION_KEY")
    duo_skey_name = os.environ.get("DUO_SECRET_NAME", "duo-secret-key")
    duo_api_host = os.environ.get("DUO_API_HOSTNAME")
    storage_connection_string = os.environ.get("STORAGE_CONNECTION_STRING")
    container_name = os.environ.get("STORAGE_CONTAINER", "mantissa-logs")

    if not all([duo_ikey, duo_api_host]):
        logger.error("DUO_INTEGRATION_KEY and DUO_API_HOSTNAME not configured")
        return

    try:
        secret_key = get_secret(key_vault_url, duo_skey_name)
        collector = DuoCollector(
            integration_key=duo_ikey,
            secret_key=secret_key,
            api_hostname=duo_api_host
        )

        end_time = datetime.now(timezone.utc)
        start_time = end_time - timedelta(minutes=15)
        mintime = int(start_time.timestamp() * 1000)
        maxtime = int(end_time.timestamp() * 1000)

        auth_logs = collector.fetch_authentication_logs(mintime=mintime, maxtime=maxtime)
        for log in auth_logs:
            log["_log_type"] = "authentication"

        logger.info(f"Collected {len(auth_logs)} Duo events")

        if auth_logs:
            parser = DuoParser()
            parsed_events = []
            for event in auth_logs:
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
