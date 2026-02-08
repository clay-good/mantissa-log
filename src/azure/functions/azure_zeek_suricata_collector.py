"""
Azure Zeek/Suricata Log Collector — Azure Function

Processes Zeek and Suricata JSON log files uploaded to Azure Blob Storage
by on-prem sensors.  Auto-detects the format and parses using the
appropriate parser.

Delivery Method:
  Blob Storage trigger fires when a new log file is uploaded.

Data Lake Output:
  ``{CONTAINER}/{zeek|suricata}/raw/YYYY/MM/DD/HH/<partition>.json``

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
# Collector integration
# ---------------------------------------------------------------------------
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "shared"))

from collectors.zeek_suricata_collector import parse_uploaded_file  # noqa: E402


# ===========================================================================
# Write to data lake
# ===========================================================================

def _write_to_blob(
    events: List[Dict[str, Any]],
    connection_string: str,
    container_name: str,
    source_format: str,
    timestamp: datetime,
    partition_id: str = "",
) -> Optional[str]:
    """Write parsed events to Azure Blob Storage in NDJSON format.

    Args:
        events: Normalised event dicts.
        connection_string: Azure Storage connection string.
        container_name: Blob container name.
        source_format: ``"zeek"`` or ``"suricata"``.
        timestamp: Partition timestamp.
        partition_id: Unique suffix.

    Returns:
        Blob path or ``None``.
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
        f"{source_format}/raw/{year}/{month}/{day}/{hour}"
        f"/{source_format}_{partition_id}.json"
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
    source_format: str,
    batch_size: int,
    partition_prefix: str = "",
) -> List[str]:
    """Split events into batches and write each to Blob Storage."""
    now = datetime.now(timezone.utc)
    paths = []

    for i in range(0, len(events), batch_size):
        batch = events[i : i + batch_size]
        batch_id = (
            f"{partition_prefix}{now.strftime('%M%S')}_{i // batch_size:04d}"
        )
        path = _write_to_blob(
            batch, connection_string, container_name,
            source_format, now, batch_id,
        )
        if path:
            paths.append(path)

    return paths


def _report_health(event_count: int, source_format: str) -> None:
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
            source_type=source_format,
            tenant_id=TENANT_ID,
            count_increment=event_count,
            latest_timestamp=datetime.now(timezone.utc),
        )
    except Exception as e:
        logger.warning("Failed to update health state: %s", e)


# ===========================================================================
# Azure Function entry points
# ===========================================================================

def blob_trigger(
    blob_content: bytes,
    blob_name: str,
) -> Dict[str, Any]:
    """Process a Zeek/Suricata log file triggered by Blob Storage.

    Args:
        blob_content: Raw file bytes.
        blob_name: Blob path.

    Returns:
        Result dict with collection status.
    """
    if not STORAGE_CONNECTION_STRING:
        logger.error("STORAGE_CONNECTION_STRING not configured")
        return {"status": "error", "error": "missing_configuration"}

    if not blob_content:
        return {"status": "success", "total_events": 0}

    parsed, fmt = parse_uploaded_file(blob_content)
    if not parsed:
        return {"status": "success", "total_events": 0, "format": fmt}

    safe_name = blob_name.replace("/", "_").replace(".", "_")[-32:]
    paths = _batch_and_write(
        parsed,
        STORAGE_CONNECTION_STRING,
        OUTPUT_CONTAINER,
        fmt,
        BATCH_SIZE,
        partition_prefix=f"blob_{safe_name}_",
    )

    _report_health(len(parsed), fmt)

    return {
        "status": "success",
        "source_blob": blob_name,
        "format": fmt,
        "total_events": len(parsed),
        "files_written": len(paths),
        "output_paths": paths,
    }


def http_trigger(body: Dict[str, Any]) -> Dict[str, Any]:
    """HTTP trigger for on-demand Zeek/Suricata file processing.

    Accepts a JSON body with ``container`` and ``blob_name`` fields.

    Args:
        body: Request body dict.

    Returns:
        Result dict with collection status.
    """
    if not STORAGE_CONNECTION_STRING:
        return {"status": "error", "error": "missing_configuration"}

    container_name = body.get("container", "")
    blob_name = body.get("blob_name", "")

    if not container_name or not blob_name:
        return {"status": "error", "error": "missing_container_or_blob"}

    try:
        blob_service = BlobServiceClient.from_connection_string(
            STORAGE_CONNECTION_STRING
        )
        blob_client = blob_service.get_blob_client(container_name, blob_name)
        download = blob_client.download_blob()
        content = download.readall()
    except Exception:
        logger.exception(
            "Failed to read blob %s/%s", container_name, blob_name
        )
        return {"status": "error", "error": "blob_read_failed"}

    parsed, fmt = parse_uploaded_file(content)
    if not parsed:
        return {"status": "success", "total_events": 0, "format": fmt}

    paths = _batch_and_write(
        parsed,
        STORAGE_CONNECTION_STRING,
        OUTPUT_CONTAINER,
        fmt,
        BATCH_SIZE,
    )

    _report_health(len(parsed), fmt)

    return {
        "status": "success",
        "format": fmt,
        "total_events": len(parsed),
        "files_written": len(paths),
        "output_paths": paths,
    }
