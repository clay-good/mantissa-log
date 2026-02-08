"""
Azure NSG Flow Log Collector — Azure Function

Collects Azure Network Security Group (NSG) flow logs from Azure Blob
Storage and stores normalised events in the Mantissa Log data lake.

NSG flow log files are delivered to Blob Storage at paths like:
  resourceId=/SUBSCRIPTIONS/{subId}/RESOURCEGROUPS/{rgName}/
  PROVIDERS/MICROSOFT.NETWORK/NETWORKSECURITYGROUPS/{nsgName}/
  y={year}/m={month}/d={day}/h={hour}/m={minute}/macAddress={mac}/PT1H.json

Each file contains a JSON object with a ``records`` array.  Each record
holds nested ``properties.flows`` with flow tuples.

Delivery Method:
  A Blob Storage trigger or Event Grid trigger fires when a new NSG flow
  log file lands.  The Function reads the file, parses each record using
  AzureNSGFlowParser, and writes normalised events to the data lake
  container.

Data Lake Output:
  ``{CONTAINER}/azure_nsg_flow/raw/YYYY/MM/DD/HH/<partition>.json``
  Each file is newline-delimited JSON (NDJSON).

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
from typing import Any, Dict, List, Optional, Tuple

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

from parsers.azure_nsg_flow import AzureNSGFlowParser  # noqa: E402

_parser = AzureNSGFlowParser()


# ===========================================================================
# File reading and parsing
# ===========================================================================

def _read_nsg_flow_file(content: bytes) -> List[Dict[str, Any]]:
    """Parse the raw bytes of an NSG flow log JSON file.

    NSG flow log files contain a top-level JSON object with a ``records``
    array.

    Args:
        content: Raw file bytes.

    Returns:
        List of record dicts from the ``records`` array.
    """
    try:
        data = json.loads(content)
        records = data.get("records", [])
        if isinstance(records, list):
            return records
        return []
    except (json.JSONDecodeError, TypeError):
        logger.warning("Failed to parse NSG flow log file as JSON")
        return []


def _parse_nsg_records(records: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Parse NSG flow log records using AzureNSGFlowParser.

    The parser returns a list of events per record (one per flow tuple).

    Args:
        records: List of NSG flow log record dicts.

    Returns:
        Flat list of normalised event dicts.
    """
    all_events: List[Dict[str, Any]] = []
    for record in records:
        try:
            if _parser.validate(record):
                events = _parser.parse(record)
                all_events.extend(events)
        except Exception:
            logger.debug("Failed to parse NSG record: %s", str(record)[:200])
            continue
    return all_events


def _extract_blob_metadata(blob_name: str) -> Dict[str, str]:
    """Extract metadata from the NSG flow log blob path.

    Example path:
      resourceId=/SUBSCRIPTIONS/sub123/RESOURCEGROUPS/rg1/
      PROVIDERS/MICROSOFT.NETWORK/NETWORKSECURITYGROUPS/nsg1/
      y=2025/m=06/d=15/h=10/m=00/macAddress=001122334455/PT1H.json

    Args:
        blob_name: Blob path string.

    Returns:
        Dict with extracted fields.
    """
    metadata: Dict[str, str] = {}

    parts = blob_name.upper().split("/")
    for i, part in enumerate(parts):
        if part == "SUBSCRIPTIONS" and i + 1 < len(parts):
            metadata["subscription_id"] = parts[i + 1]
        elif part == "RESOURCEGROUPS" and i + 1 < len(parts):
            metadata["resource_group"] = parts[i + 1]
        elif part == "NETWORKSECURITYGROUPS" and i + 1 < len(parts):
            metadata["nsg_name"] = parts[i + 1]

    # Extract time components
    for part in blob_name.split("/"):
        if part.startswith("y="):
            metadata["year"] = part[2:]
        elif part.startswith("m=") and "month" not in metadata:
            metadata["month"] = part[2:]
        elif part.startswith("d="):
            metadata["day"] = part[2:]
        elif part.startswith("h="):
            metadata["hour"] = part[2:]
        elif part.startswith("macAddress="):
            metadata["mac_address"] = part[11:]

    return metadata


# ===========================================================================
# Write to data lake
# ===========================================================================

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

    blob_path = f"azure_nsg_flow/raw/{year}/{month}/{day}/{hour}/nsg_{partition_id}.json"

    content = "\n".join(json.dumps(e) for e in events)

    try:
        blob_service = BlobServiceClient.from_connection_string(connection_string)
        container = blob_service.get_container_client(container_name)
        blob_client = container.get_blob_client(blob_path)
        blob_client.upload_blob(content, overwrite=True)
        logger.info("Wrote %d events to %s/%s", len(events), container_name, blob_path)
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
        batch_id = f"{partition_prefix}{now.strftime('%M%S')}_{i // batch_size:04d}"
        path = _write_to_blob(batch, connection_string, container_name, now, batch_id)
        if path:
            paths.append(path)

    return paths


def _report_health(event_count: int) -> None:
    """Report event count to the log source health monitor."""
    try:
        if not COSMOS_ENDPOINT or not COSMOS_HEALTH_CONTAINER:
            return
        from src.shared.health.health_state_store import CosmosHealthStateStore

        store = CosmosHealthStateStore(
            endpoint=COSMOS_ENDPOINT,
            key=COSMOS_KEY,
            database_name=COSMOS_DATABASE,
            container_name=COSMOS_HEALTH_CONTAINER,
        )
        store.update_event_count(
            source_type="azure_nsg_flow",
            tenant_id=TENANT_ID,
            count_increment=event_count,
            latest_timestamp=datetime.now(timezone.utc),
        )
    except Exception as e:
        logger.warning("Failed to update health state: %s", e)


# ===========================================================================
# Processing pipeline
# ===========================================================================

def _process_nsg_file(
    content: bytes,
    blob_name: str,
) -> Tuple[int, List[str]]:
    """End-to-end processing of one NSG flow log file.

    Args:
        content: Raw file bytes.
        blob_name: Source blob path (for metadata extraction).

    Returns:
        (event_count, list_of_output_paths)
    """
    records = _read_nsg_flow_file(content)
    if not records:
        return 0, []

    parsed = _parse_nsg_records(records)
    if not parsed:
        return 0, []

    # Derive partition prefix from blob name for uniqueness
    safe_name = blob_name.replace("/", "_").replace(".", "_")[-32:]

    paths = _batch_and_write(
        parsed,
        STORAGE_CONNECTION_STRING,
        OUTPUT_CONTAINER,
        BATCH_SIZE,
        partition_prefix=f"nsg_{safe_name}_",
    )

    return len(parsed), paths


# ===========================================================================
# Azure Function entry points
# ===========================================================================

def blob_trigger(blob_content: bytes, blob_name: str) -> Dict[str, Any]:
    """Process an NSG flow log file triggered by Blob Storage.

    This function is called by the Azure Function host when a new NSG flow
    log file is detected.

    Args:
        blob_content: Raw file bytes.
        blob_name: Blob path.

    Returns:
        Result dict with collection status.
    """
    if not STORAGE_CONNECTION_STRING:
        logger.error("STORAGE_CONNECTION_STRING not configured")
        return {"status": "error", "error": "missing_configuration"}

    logger.info("Processing NSG flow log: %s", blob_name)

    metadata = _extract_blob_metadata(blob_name)
    event_count, paths = _process_nsg_file(blob_content, blob_name)

    if event_count > 0:
        _report_health(event_count)

    return {
        "status": "success",
        "mode": "blob_trigger",
        "source_blob": blob_name,
        "nsg_name": metadata.get("nsg_name", "unknown"),
        "total_events": event_count,
        "files_written": len(paths),
        "output_paths": paths,
    }


def event_grid_trigger(event: Dict[str, Any]) -> Dict[str, Any]:
    """Process an Event Grid event for a new NSG flow log file.

    Azure Event Grid sends a notification when a blob is created.  This
    function reads the blob and processes it.

    Args:
        event: Event Grid event dict.

    Returns:
        Result dict with collection status.
    """
    if not STORAGE_CONNECTION_STRING:
        logger.error("STORAGE_CONNECTION_STRING not configured")
        return {"status": "error", "error": "missing_configuration"}

    # Extract blob info from Event Grid event
    data = event.get("data", {})
    blob_url = data.get("url", "")
    content_length = data.get("contentLength", 0)

    if not blob_url:
        return {"status": "error", "error": "no_blob_url"}

    # Parse blob URL to extract container and blob name
    container_name, blob_name = _parse_blob_url(blob_url)
    if not container_name or not blob_name:
        return {"status": "error", "error": "invalid_blob_url"}

    # Read the blob
    try:
        blob_service = BlobServiceClient.from_connection_string(STORAGE_CONNECTION_STRING)
        blob_client = blob_service.get_blob_client(container_name, blob_name)
        download = blob_client.download_blob()
        content = download.readall()
    except Exception:
        logger.exception("Failed to read blob %s/%s", container_name, blob_name)
        return {"status": "error", "error": "blob_read_failed"}

    metadata = _extract_blob_metadata(blob_name)
    event_count, paths = _process_nsg_file(content, blob_name)

    if event_count > 0:
        _report_health(event_count)

    return {
        "status": "success",
        "mode": "event_grid",
        "source_blob": blob_name,
        "nsg_name": metadata.get("nsg_name", "unknown"),
        "total_events": event_count,
        "files_written": len(paths),
        "output_paths": paths,
    }


def http_trigger(body: Dict[str, Any]) -> Dict[str, Any]:
    """HTTP trigger for on-demand processing of NSG flow log files.

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
        blob_service = BlobServiceClient.from_connection_string(STORAGE_CONNECTION_STRING)
        blob_client = blob_service.get_blob_client(container_name, blob_name)
        download = blob_client.download_blob()
        content = download.readall()
    except Exception:
        logger.exception("Failed to read blob %s/%s", container_name, blob_name)
        return {"status": "error", "error": "blob_read_failed"}

    event_count, paths = _process_nsg_file(content, blob_name)

    if event_count > 0:
        _report_health(event_count)

    return {
        "status": "success",
        "mode": "http",
        "source_blob": blob_name,
        "total_events": event_count,
        "files_written": len(paths),
        "output_paths": paths,
    }


# ===========================================================================
# Helpers
# ===========================================================================

def _parse_blob_url(url: str) -> Tuple[str, str]:
    """Parse an Azure Blob Storage URL into container and blob name.

    Expected format:
      https://{account}.blob.core.windows.net/{container}/{blob_path}

    Args:
        url: Full blob URL.

    Returns:
        (container_name, blob_name) or ("", "") on failure.
    """
    try:
        # Remove protocol
        if "://" in url:
            url = url.split("://", 1)[1]

        # Remove host
        parts = url.split("/", 1)
        if len(parts) < 2:
            return "", ""

        path = parts[1]
        # First segment is container, rest is blob name
        segments = path.split("/", 1)
        if len(segments) < 2:
            return "", ""

        return segments[0], segments[1]
    except Exception:
        return "", ""
