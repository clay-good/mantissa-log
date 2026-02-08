"""
GCP Cloud Firewall Log Collector — Cloud Function

Collects GCP VPC Firewall Rule logs from Cloud Logging via Pub/Sub and
stores normalised events in GCS for data lake analysis.

GCP VPC Firewall Rule logs are available in Cloud Logging with
resource.type="gce_firewall_rule".  A Cloud Logging sink routes matching
logs to a Pub/Sub topic which triggers this Cloud Function.

Delivery Methods:
1. **Pub/Sub trigger** — Cloud Logging sink pushes firewall log entries
   to Pub/Sub; this function decodes and processes each batch.
2. **HTTP trigger** — For direct submission or Pub/Sub push endpoints.

Data Lake Output:
  ``gs://{GCS_BUCKET}/gcp_firewall/raw/YYYY/MM/DD/HH/<partition>.json``
  Each file is newline-delimited JSON (NDJSON) of normalised event dicts.

Environment Variables:
    GCS_BUCKET: GCS bucket for the data lake
    PROJECT_ID: GCP project ID
    HEALTH_STATE_COLLECTION: Firestore collection for health state
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
PROJECT_ID = os.environ.get("PROJECT_ID", "")
HEALTH_STATE_COLLECTION = os.environ.get("HEALTH_STATE_COLLECTION", "")
TENANT_ID = os.environ.get("TENANT_ID", "default")
BATCH_SIZE = int(os.environ.get("BATCH_SIZE", "10000"))

# ---------------------------------------------------------------------------
# Parser integration
# ---------------------------------------------------------------------------
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "shared"))

from parsers.cloud_firewall import CloudFirewallParser  # noqa: E402

_parser = CloudFirewallParser()


# ===========================================================================
# Pub/Sub decoding
# ===========================================================================

def _decode_pubsub_batch(cloud_event: Any) -> List[Dict[str, Any]]:
    """Decode a Pub/Sub CloudEvent into firewall log entry dicts.

    Cloud Logging sinks deliver log entries as base64-encoded JSON in
    Pub/Sub messages.  The payload may be a single entry (dict) or a
    batch (list of dicts).

    Args:
        cloud_event: CloudEvents object with ``data.message.data``.

    Returns:
        List of raw firewall log entry dicts.
    """
    try:
        data = cloud_event.data.get("message", {}).get("data", "")
        if not data:
            return []

        decoded = base64.b64decode(data).decode("utf-8")
        parsed = json.loads(decoded)

        if isinstance(parsed, dict):
            return [parsed]
        if isinstance(parsed, list):
            return [e for e in parsed if isinstance(e, dict)]
        return []
    except Exception:
        logger.debug("Failed to decode Pub/Sub message")
        return []


def _decode_http_request(
    request_json: Dict[str, Any],
) -> List[Dict[str, Any]]:
    """Decode firewall log entries from an HTTP request body.

    Supports Pub/Sub push format, direct entries array, and single entry.

    Args:
        request_json: Request JSON body.

    Returns:
        List of raw firewall log entry dicts.
    """
    entries: List[Dict[str, Any]] = []

    # Pub/Sub push format
    message = request_json.get("message", {})
    if isinstance(message, dict) and "data" in message:
        try:
            decoded = base64.b64decode(message["data"]).decode("utf-8")
            parsed = json.loads(decoded)
            if isinstance(parsed, dict):
                entries.append(parsed)
            elif isinstance(parsed, list):
                entries.extend(e for e in parsed if isinstance(e, dict))
        except Exception:
            pass

    # Direct entries array
    if not entries:
        direct = request_json.get("entries", [])
        if isinstance(direct, list):
            entries.extend(e for e in direct if isinstance(e, dict))

    # Single entry
    if not entries and (
        "jsonPayload" in request_json or "resource" in request_json
    ):
        entries.append(request_json)

    return entries


# ===========================================================================
# Parse, batch, and write
# ===========================================================================

def _parse_firewall_events(
    raw_events: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """Parse raw GCP firewall log entries using CloudFirewallParser.

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


def _write_to_gcs(
    events: List[Dict[str, Any]],
    bucket_name: str,
    timestamp: datetime,
    partition_id: str = "",
) -> Optional[str]:
    """Write parsed events to GCS in NDJSON format.

    Args:
        events: List of normalised event dicts.
        bucket_name: GCS bucket name.
        timestamp: Partition timestamp.
        partition_id: Unique suffix for the blob name.

    Returns:
        GCS path where data was written, or ``None`` on failure.
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
        f"gcp_firewall/raw/{year}/{month}/{day}/{hour}"
        f"/fw_{partition_id}.json"
    )

    content = "\n".join(json.dumps(e) for e in events)

    try:
        client = _gcs_storage.Client()
        bucket = client.bucket(bucket_name)
        blob = bucket.blob(blob_path)
        blob.upload_from_string(content, content_type="application/json")
        logger.info(
            "Wrote %d events to gs://%s/%s", len(events), bucket_name, blob_path
        )
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
        List of GCS paths written.
    """
    now = datetime.now(timezone.utc)
    paths = []

    for i in range(0, len(events), batch_size):
        batch = events[i : i + batch_size]
        batch_id = (
            f"{partition_prefix}{now.strftime('%M%S')}_{i // batch_size:04d}"
        )
        path = _write_to_gcs(batch, bucket_name, now, batch_id)
        if path:
            paths.append(path)

    return paths


def _report_health(event_count: int) -> None:
    """Report event count to the log source health monitor."""
    try:
        if not HEALTH_STATE_COLLECTION:
            return
        from src.shared.health.health_state_store import (
            FirestoreHealthStateStore,
        )

        store = FirestoreHealthStateStore(
            collection_name=HEALTH_STATE_COLLECTION
        )
        store.update_event_count(
            source_type="gcp_firewall",
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
def firewall_pubsub(cloud_event: Any) -> Dict[str, Any]:
    """Pub/Sub Cloud Function entry point for GCP firewall logs.

    Args:
        cloud_event: CloudEvents Pub/Sub message.

    Returns:
        Result dict with collection status.
    """
    if not GCS_BUCKET:
        logger.error("GCS_BUCKET not configured")
        return {"status": "error", "error": "missing_configuration"}

    entries = _decode_pubsub_batch(cloud_event)
    if not entries:
        return {"status": "success", "mode": "pubsub", "total_events": 0}

    parsed = _parse_firewall_events(entries)
    if not parsed:
        return {"status": "success", "mode": "pubsub", "total_events": 0}

    paths = _batch_and_write(
        parsed, GCS_BUCKET, BATCH_SIZE, partition_prefix="ps_"
    )

    _report_health(len(parsed))

    return {
        "status": "success",
        "mode": "pubsub",
        "total_events": len(parsed),
        "files_written": len(paths),
        "output_paths": paths,
    }


@functions_framework.http
def firewall_http(request: Any) -> Any:
    """HTTP Cloud Function entry point for GCP firewall logs.

    Args:
        request: Flask request object.

    Returns:
        JSON response with collection status.
    """
    if not GCS_BUCKET:
        return ({"status": "error", "error": "missing_configuration"}, 500)

    try:
        request_json = request.get_json(silent=True)
    except Exception:
        request_json = None

    if not request_json:
        return ({"status": "error", "error": "invalid_request"}, 400)

    entries = _decode_http_request(request_json)
    if not entries:
        return {"status": "success", "mode": "http", "total_events": 0}

    parsed = _parse_firewall_events(entries)
    if not parsed:
        return {"status": "success", "mode": "http", "total_events": 0}

    paths = _batch_and_write(
        parsed, GCS_BUCKET, BATCH_SIZE, partition_prefix="http_"
    )

    _report_health(len(parsed))

    return {
        "status": "success",
        "mode": "http",
        "total_events": len(parsed),
        "files_written": len(paths),
        "output_paths": paths,
    }
