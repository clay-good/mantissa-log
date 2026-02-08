"""
Azure Firewall Log Collector — Azure Function

Collects Azure Firewall logs routed from Azure Monitor diagnostic settings
via Event Hub and stores normalised events in Azure Blob Storage for data
lake analysis.

Azure Firewall logs include Application Rule, Network Rule, and Threat
Intelligence logs.  They are delivered to Event Hub as Azure Monitor
diagnostic logs.

Delivery Method:
  Azure Monitor diagnostic settings route Azure Firewall logs to an
  Event Hub.  This Azure Function uses an Event Hub trigger to process
  incoming batches.

Data Lake Output:
  ``{CONTAINER}/azure_firewall/raw/YYYY/MM/DD/HH/<partition>.json``
  Each file is newline-delimited JSON (NDJSON) of normalised event dicts.

Environment Variables:
    STORAGE_CONNECTION_STRING: Azure Storage connection string
    OUTPUT_CONTAINER: Blob container for the data lake (default: mantissa-logs)
    COSMOS_ENDPOINT: Cosmos DB endpoint for health monitoring
    COSMOS_KEY: Cosmos DB key
    COSMOS_DATABASE: Cosmos DB database name (default: mantissa)
    COSMOS_HEALTH_CONTAINER: Cosmos DB container for health state
    TENANT_ID: Tenant identifier (default: 'default')
    BATCH_SIZE: Max events per output file (default: 10000)
"""

import json
import logging
import os
import sys
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

try:
    import azure.functions as func
except ImportError:
    func = None

try:
    from azure.storage.blob import BlobServiceClient
except ImportError:
    BlobServiceClient = None

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Configuration from environment
STORAGE_CONNECTION_STRING = os.environ.get("STORAGE_CONNECTION_STRING", "")
OUTPUT_CONTAINER = os.environ.get("OUTPUT_CONTAINER", "mantissa-logs")
COSMOS_ENDPOINT = os.environ.get("COSMOS_ENDPOINT", "")
COSMOS_KEY = os.environ.get("COSMOS_KEY", "")
COSMOS_DATABASE = os.environ.get("COSMOS_DATABASE", "mantissa")
COSMOS_HEALTH_CONTAINER = os.environ.get("COSMOS_HEALTH_CONTAINER", "")
TENANT_ID = os.environ.get("TENANT_ID", "default")
BATCH_SIZE = int(os.environ.get("BATCH_SIZE", "10000"))

# ---------------------------------------------------------------------------
# Parser integration
# ---------------------------------------------------------------------------
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "shared"))

from parsers.cloud_firewall import CloudFirewallParser  # noqa: E402

_parser = CloudFirewallParser()


# ===========================================================================
# Event Hub message decoding
# ===========================================================================

def _decode_event_hub_messages(messages: List[Any]) -> List[Dict[str, Any]]:
    """Decode Event Hub messages into firewall log entry dicts.

    Azure Monitor diagnostic logs sent to Event Hub arrive as JSON objects.
    Each Event Hub message body may contain a single log entry or a
    ``records`` array.

    Args:
        messages: List of Event Hub message bodies (bytes, str, or dict).

    Returns:
        List of parsed firewall log entry dicts.
    """
    entries: List[Dict[str, Any]] = []

    for message in messages:
        try:
            if isinstance(message, bytes):
                data = json.loads(message)
            elif isinstance(message, str):
                data = json.loads(message)
            elif isinstance(message, dict):
                data = message
            else:
                continue

            if isinstance(data, dict):
                records = data.get("records", [])
                if records and isinstance(records, list):
                    entries.extend(r for r in records if isinstance(r, dict))
                else:
                    entries.append(data)
            elif isinstance(data, list):
                entries.extend(d for d in data if isinstance(d, dict))

        except (json.JSONDecodeError, TypeError):
            logger.debug("Failed to decode Event Hub message")
            continue

    return entries


def _decode_http_request(request_json: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Decode firewall log entries from an HTTP request body.

    Args:
        request_json: Request JSON body.

    Returns:
        List of firewall log entry dicts.
    """
    entries: List[Dict[str, Any]] = []

    # Records array format
    records = request_json.get("records", [])
    if records and isinstance(records, list):
        entries.extend(r for r in records if isinstance(r, dict))

    # Direct entries array
    if not entries:
        direct = request_json.get("entries", [])
        if isinstance(direct, list):
            entries.extend(e for e in direct if isinstance(e, dict))

    # Single entry
    if not entries and (
        "properties" in request_json or "category" in request_json
    ):
        entries.append(request_json)

    return entries


# ===========================================================================
# Parse, batch, and write
# ===========================================================================

def _parse_firewall_events(
    raw_events: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """Parse raw Azure Firewall log entries using CloudFirewallParser.

    Args:
        raw_events: List of raw firewall log entry dicts.

    Returns:
        List of normalised event dicts.
    """
    parsed = []
    for raw_event in raw_events:
        try:
            if _parser.validate(raw_event):
                result = _parser.parse(raw_event)
                parsed.append(result)
        except Exception:
            logger.debug(
                "Failed to parse firewall event: %s", str(raw_event)[:200]
            )
            continue
    return parsed


def _write_to_blob(
    events: List[Dict[str, Any]],
    connection_string: str,
    container_name: str,
    timestamp: datetime,
    partition_id: str = "",
) -> Optional[str]:
    """Write parsed events to Azure Blob Storage in NDJSON format.

    Args:
        events: List of normalised event dicts.
        connection_string: Azure Storage connection string.
        container_name: Blob container name.
        timestamp: Partition timestamp.
        partition_id: Unique suffix for the blob name.

    Returns:
        Blob path where data was written, or ``None`` on failure.
    """
    if not events:
        return None

    year = timestamp.strftime("%Y")
    month = timestamp.strftime("%m")
    day = timestamp.strftime("%d")
    hour = timestamp.strftime("%H")

    if not partition_id:
        partition_id = timestamp.strftime("%M%S")

    blob_path = (
        f"azure_firewall/raw/{year}/{month}/{day}/{hour}"
        f"/fw_{partition_id}.json"
    )

    content = "\n".join(json.dumps(e) for e in events)

    try:
        blob_service = BlobServiceClient.from_connection_string(
            connection_string
        )
        container = blob_service.get_container_client(container_name)
        blob_client = container.get_blob_client(blob_path)
        blob_client.upload_blob(content, overwrite=True)
        logger.info(
            "Wrote %d events to %s/%s", len(events), container_name, blob_path
        )
        return blob_path
    except Exception:
        logger.exception("Failed to write to Azure Blob Storage")
        return None


def _batch_and_write(
    events: List[Dict[str, Any]],
    connection_string: str,
    container_name: str,
    batch_size: int,
    partition_prefix: str = "",
) -> List[str]:
    """Split events into batches and write each to Blob Storage.

    Args:
        events: All normalised events.
        connection_string: Azure Storage connection string.
        container_name: Blob container name.
        batch_size: Maximum events per output file.
        partition_prefix: Optional prefix for partition IDs.

    Returns:
        List of blob paths written.
    """
    now = datetime.now(timezone.utc)
    paths = []

    for i in range(0, len(events), batch_size):
        batch = events[i : i + batch_size]
        batch_id = (
            f"{partition_prefix}{now.strftime('%M%S')}_{i // batch_size:04d}"
        )
        path = _write_to_blob(
            batch, connection_string, container_name, now, batch_id
        )
        if path:
            paths.append(path)

    return paths


def _report_health(event_count: int) -> None:
    """Report event count to the log source health monitor."""
    try:
        if not COSMOS_ENDPOINT or not COSMOS_HEALTH_CONTAINER:
            return
        from src.shared.health.health_state_store import (
            CosmosHealthStateStore,
        )

        store = CosmosHealthStateStore(
            endpoint=COSMOS_ENDPOINT,
            key=COSMOS_KEY,
            database_name=COSMOS_DATABASE,
            container_name=COSMOS_HEALTH_CONTAINER,
        )
        store.update_event_count(
            source_type="azure_firewall",
            tenant_id=TENANT_ID,
            count_increment=event_count,
            latest_timestamp=datetime.now(timezone.utc),
        )
    except Exception as e:
        logger.warning("Failed to update health state: %s", e)


# ===========================================================================
# Azure Function entry points
# ===========================================================================

def event_hub_trigger(messages: List[Any]) -> Dict[str, Any]:
    """Event Hub triggered function for Azure Firewall logs.

    Processes batches of firewall log entries received from Azure Monitor
    diagnostic settings via Event Hub.

    Args:
        messages: List of Event Hub message bodies.

    Returns:
        Result dict with collection status.
    """
    if not STORAGE_CONNECTION_STRING:
        logger.error("STORAGE_CONNECTION_STRING not configured")
        return {"status": "error", "error": "missing_configuration"}

    entries = _decode_event_hub_messages(messages)
    if not entries:
        return {"status": "success", "mode": "event_hub", "total_events": 0}

    parsed = _parse_firewall_events(entries)
    if not parsed:
        return {"status": "success", "mode": "event_hub", "total_events": 0}

    paths = _batch_and_write(
        parsed,
        STORAGE_CONNECTION_STRING,
        OUTPUT_CONTAINER,
        BATCH_SIZE,
        partition_prefix="eh_",
    )

    _report_health(len(parsed))

    return {
        "status": "success",
        "mode": "event_hub",
        "total_events": len(parsed),
        "files_written": len(paths),
        "output_paths": paths,
    }


def http_trigger(body: Dict[str, Any]) -> Dict[str, Any]:
    """HTTP trigger for on-demand processing of Azure Firewall logs.

    Accepts a JSON body with ``records`` array or ``entries`` array.

    Args:
        body: Request body dict.

    Returns:
        Result dict with collection status.
    """
    if not STORAGE_CONNECTION_STRING:
        return {"status": "error", "error": "missing_configuration"}

    entries = _decode_http_request(body)
    if not entries:
        return {"status": "success", "mode": "http", "total_events": 0}

    parsed = _parse_firewall_events(entries)
    if not parsed:
        return {"status": "success", "mode": "http", "total_events": 0}

    paths = _batch_and_write(
        parsed,
        STORAGE_CONNECTION_STRING,
        OUTPUT_CONTAINER,
        BATCH_SIZE,
        partition_prefix="http_",
    )

    _report_health(len(parsed))

    return {
        "status": "success",
        "mode": "http",
        "total_events": len(parsed),
        "files_written": len(paths),
        "output_paths": paths,
    }
