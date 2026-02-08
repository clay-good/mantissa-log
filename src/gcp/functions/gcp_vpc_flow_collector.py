"""
GCP VPC Flow Log Collector — Cloud Function

Collects GCP VPC Flow Logs routed from Cloud Logging via a Pub/Sub logging
sink and stores normalised events in Cloud Storage for BigQuery analysis.

Delivery Method:
  A Cloud Logging sink filters for VPC flow log entries and routes them to a
  Pub/Sub topic.  This Cloud Function subscribes to that topic and processes
  each batch of flow log messages.

  Logging sink filter:
    resource.type="gce_subnetwork" AND
    logName:"compute.googleapis.com/vpc_flows"

Data Lake Output:
  ``gs://{GCS_BUCKET}/gcp_vpc_flow/raw/YYYY/MM/DD/HH/<partition>.json``
  Each file is newline-delimited JSON (NDJSON) of normalised event dicts.

Deployment: GCP Cloud Functions (2nd gen)
Trigger: Pub/Sub
Runtime: Python 3.11

Environment Variables:
    GCS_BUCKET: Cloud Storage bucket for the data lake
    PROJECT_ID: GCP project ID
    HEALTH_STATE_COLLECTION: Firestore collection for health monitoring
    TENANT_ID: Tenant identifier (default: 'default')
    BATCH_SIZE: Max events per output file (default: 10000)
"""

import base64
import json
import logging
import os
import sys
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

try:
    import functions_framework
except ImportError:
    # Allow import without functions_framework for testing
    import types
    functions_framework = types.ModuleType("functions_framework")
    functions_framework.cloud_event = lambda f: f
    functions_framework.http = lambda f: f

try:
    from google.cloud import storage as _gcs_storage
except ImportError:
    _gcs_storage = None

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Configuration from environment
GCS_BUCKET = os.environ.get("GCS_BUCKET")
PROJECT_ID = os.environ.get("PROJECT_ID")
HEALTH_STATE_COLLECTION = os.environ.get("HEALTH_STATE_COLLECTION")
TENANT_ID = os.environ.get("TENANT_ID", "default")
BATCH_SIZE = int(os.environ.get("BATCH_SIZE", "10000"))

# ---------------------------------------------------------------------------
# Parser integration
# ---------------------------------------------------------------------------
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "shared"))

from parsers.gcp_vpc_flow import GCPVPCFlowParser  # noqa: E402

_parser = GCPVPCFlowParser()


# ===========================================================================
# Pub/Sub message decoding
# ===========================================================================

def _decode_pubsub_message(cloud_event: Any) -> Optional[Dict[str, Any]]:
    """Decode a Cloud Logging sink Pub/Sub message into a log entry dict.

    Cloud Logging sinks publish messages whose ``data`` field is a
    base64-encoded JSON representation of the log entry.

    Args:
        cloud_event: CloudEvent received from Pub/Sub.

    Returns:
        Parsed log entry dict, or ``None`` on failure.
    """
    try:
        data = cloud_event.data
        if isinstance(data, dict):
            message = data.get("message", {})
            raw_data = message.get("data", "")
        else:
            raw_data = data if isinstance(data, str) else ""

        if not raw_data:
            return None

        decoded = base64.b64decode(raw_data)
        entry = json.loads(decoded)
        return entry if isinstance(entry, dict) else None
    except Exception:
        logger.debug("Failed to decode Pub/Sub message")
        return None


def _decode_pubsub_batch(cloud_event: Any) -> List[Dict[str, Any]]:
    """Decode a Pub/Sub message that may contain a single entry or a batch.

    Cloud Logging sinks can batch multiple log entries into one Pub/Sub
    message.  This function handles both single-entry and batched formats.

    Args:
        cloud_event: CloudEvent received from Pub/Sub.

    Returns:
        List of parsed log entry dicts.
    """
    try:
        data = cloud_event.data
        if isinstance(data, dict):
            message = data.get("message", {})
            raw_data = message.get("data", "")
        else:
            raw_data = data if isinstance(data, str) else ""

        if not raw_data:
            return []

        decoded = base64.b64decode(raw_data)
        payload = json.loads(decoded)

        # Single entry
        if isinstance(payload, dict):
            return [payload]

        # Batched entries
        if isinstance(payload, list):
            return [e for e in payload if isinstance(e, dict)]

        return []
    except Exception:
        logger.debug("Failed to decode Pub/Sub batch message")
        return []


def _decode_http_request(request_json: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Decode flow log entries from an HTTP request body.

    Supports both direct log entry submission and Pub/Sub push format.

    Args:
        request_json: Request JSON body.

    Returns:
        List of parsed log entry dicts.
    """
    entries = []

    # Pub/Sub push format
    message = request_json.get("message", {})
    if message:
        raw_data = message.get("data", "")
        if raw_data:
            try:
                decoded = base64.b64decode(raw_data)
                payload = json.loads(decoded)
                if isinstance(payload, dict):
                    entries.append(payload)
                elif isinstance(payload, list):
                    entries.extend(e for e in payload if isinstance(e, dict))
            except Exception:
                logger.debug("Failed to decode HTTP Pub/Sub push message")

    # Direct entries array
    if not entries:
        direct_entries = request_json.get("entries", [])
        if isinstance(direct_entries, list):
            entries.extend(e for e in direct_entries if isinstance(e, dict))

    # Single entry (the body itself looks like a log entry)
    if not entries and "jsonPayload" in request_json:
        entries.append(request_json)

    return entries


# ===========================================================================
# Parse, batch, and write
# ===========================================================================

def _parse_flow_events(raw_events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Parse raw GCP VPC Flow Log entries using the parser.

    Args:
        raw_events: List of raw Cloud Logging entry dicts.

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
            logger.debug("Failed to parse flow event: %s", str(raw_event)[:200])
            continue
    return parsed


def _write_to_gcs(
    events: List[Dict[str, Any]],
    bucket_name: str,
    timestamp: datetime,
    partition_id: str = "",
) -> Optional[str]:
    """Write parsed events to GCS in partitioned NDJSON format.

    Args:
        events: List of normalised event dicts.
        bucket_name: GCS bucket name.
        timestamp: Partition timestamp.
        partition_id: Unique suffix for the blob name.

    Returns:
        GCS blob path where data was written, or ``None`` on failure.
    """
    if not events:
        return None

    year = timestamp.strftime("%Y")
    month = timestamp.strftime("%m")
    day = timestamp.strftime("%d")
    hour = timestamp.strftime("%H")

    if not partition_id:
        partition_id = timestamp.strftime("%M%S")

    blob_path = f"gcp_vpc_flow/raw/{year}/{month}/{day}/{hour}/flow_{partition_id}.json"

    content = "\n".join(json.dumps(e) for e in events)

    try:
        client = _gcs_storage.Client(project=PROJECT_ID)
        bucket = client.bucket(bucket_name)
        blob = bucket.blob(blob_path)
        blob.upload_from_string(content, content_type="application/x-ndjson")
        logger.info("Wrote %d events to gs://%s/%s", len(events), bucket_name, blob_path)
        return blob_path
    except Exception:
        logger.exception("Failed to write to GCS")
        return None


def _batch_and_write(
    events: List[Dict[str, Any]],
    bucket_name: str,
    batch_size: int,
    partition_prefix: str = "",
) -> List[str]:
    """Split events into batches and write each to GCS.

    Args:
        events: All normalised events.
        bucket_name: GCS bucket name.
        batch_size: Maximum events per output file.
        partition_prefix: Optional prefix for partition IDs.

    Returns:
        List of GCS blob paths written.
    """
    now = datetime.now(timezone.utc)
    paths = []

    for i in range(0, len(events), batch_size):
        batch = events[i : i + batch_size]
        batch_id = f"{partition_prefix}{now.strftime('%M%S')}_{i // batch_size:04d}"
        path = _write_to_gcs(batch, bucket_name, now, batch_id)
        if path:
            paths.append(path)

    return paths


def _report_health(event_count: int) -> None:
    """Report event count to the log source health monitor."""
    try:
        if not HEALTH_STATE_COLLECTION:
            return
        from src.shared.health.health_state_store import FirestoreHealthStateStore

        store = FirestoreHealthStateStore(
            collection_name=HEALTH_STATE_COLLECTION,
            project_id=PROJECT_ID,
        )
        store.update_event_count(
            source_type="gcp_vpc_flow",
            tenant_id=TENANT_ID,
            count_increment=event_count,
            latest_timestamp=datetime.now(timezone.utc),
        )
    except Exception as e:
        logger.warning("Failed to update health state: %s", e)


# ===========================================================================
# Cloud Function entry points
# ===========================================================================

@functions_framework.cloud_event
def vpc_flow_pubsub(cloud_event):
    """Pub/Sub triggered Cloud Function for GCP VPC Flow Logs.

    Receives flow log entries routed from Cloud Logging via a Pub/Sub sink,
    parses them, and writes normalised events to GCS.

    Args:
        cloud_event: CloudEvent from Pub/Sub subscription.

    Returns:
        Response dict with collection status.
    """
    if not GCS_BUCKET:
        logger.error("GCS_BUCKET not configured")
        return {"status": "error", "error": "missing_configuration"}

    # Decode entries from Pub/Sub message
    entries = _decode_pubsub_batch(cloud_event)
    if not entries:
        return {"status": "success", "total_events": 0}

    # Parse
    parsed = _parse_flow_events(entries)
    if not parsed:
        return {"status": "success", "total_events": 0}

    # Write to GCS
    paths = _batch_and_write(parsed, GCS_BUCKET, BATCH_SIZE, partition_prefix="pubsub_")

    # Report health
    _report_health(len(parsed))

    return {
        "status": "success",
        "mode": "pubsub",
        "total_events": len(parsed),
        "files_written": len(paths),
        "output_paths": paths,
    }


@functions_framework.http
def vpc_flow_http(request):
    """HTTP triggered Cloud Function for GCP VPC Flow Logs.

    Supports:
    - Pub/Sub push subscriptions (JSON body with ``message.data``)
    - Direct log entry submission (JSON body with ``entries`` array)

    Args:
        request: Flask request object.

    Returns:
        JSON response with collection status.
    """
    if not GCS_BUCKET:
        logger.error("GCS_BUCKET not configured")
        return {"status": "error", "error": "missing_configuration"}, 500

    try:
        request_json = request.get_json(silent=True)
        if not request_json:
            return {"status": "error", "error": "empty_request"}, 400
    except Exception:
        return {"status": "error", "error": "invalid_json"}, 400

    # Decode entries
    entries = _decode_http_request(request_json)
    if not entries:
        return {"status": "success", "total_events": 0}

    # Parse
    parsed = _parse_flow_events(entries)
    if not parsed:
        return {"status": "success", "total_events": 0}

    # Write to GCS
    paths = _batch_and_write(parsed, GCS_BUCKET, BATCH_SIZE, partition_prefix="http_")

    # Report health
    _report_health(len(parsed))

    return {
        "status": "success",
        "mode": "http",
        "total_events": len(parsed),
        "files_written": len(paths),
        "output_paths": paths,
    }
