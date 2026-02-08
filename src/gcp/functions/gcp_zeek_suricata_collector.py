"""
GCP Zeek/Suricata Log Collector — Cloud Function

Processes Zeek and Suricata JSON log files uploaded to GCS by on-prem
sensors.  Auto-detects the format and parses using the appropriate parser.

Delivery Method:
  GCS object finalize event triggers this Cloud Function when a new log
  file is uploaded to the configured bucket/prefix.

Data Lake Output:
  ``gs://{GCS_OUTPUT_BUCKET}/{zeek|suricata}/raw/YYYY/MM/DD/HH/<partition>.json``

Environment Variables:
    GCS_OUTPUT_BUCKET: GCS bucket for the data lake output
    HEALTH_STATE_COLLECTION: Firestore collection for health state
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
GCS_OUTPUT_BUCKET = os.environ.get("GCS_OUTPUT_BUCKET")
HEALTH_STATE_COLLECTION = os.environ.get("HEALTH_STATE_COLLECTION", "")
TENANT_ID = os.environ.get("TENANT_ID", "default")
BATCH_SIZE = int(os.environ.get("BATCH_SIZE", "10000"))

# ---------------------------------------------------------------------------
# Collector integration
# ---------------------------------------------------------------------------
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "shared"))

from collectors.zeek_suricata_collector import parse_uploaded_file  # noqa: E402


# ===========================================================================
# GCS file reading
# ===========================================================================

def _read_gcs_file(bucket_name: str, blob_name: str) -> bytes:
    """Read raw bytes from a GCS object.

    Args:
        bucket_name: GCS bucket name.
        blob_name: Blob path.

    Returns:
        Raw file bytes.
    """
    try:
        client = _gcs_storage.Client()
        bucket = client.bucket(bucket_name)
        blob = bucket.blob(blob_name)
        return blob.download_as_bytes()
    except Exception:
        logger.exception("Failed to read gs://%s/%s", bucket_name, blob_name)
        return b""


# ===========================================================================
# Write to data lake
# ===========================================================================

def _write_to_gcs(
    events: List[Dict[str, Any]],
    bucket_name: str,
    source_format: str,
    timestamp: datetime,
    partition_id: str = "",
) -> Optional[str]:
    """Write parsed events to GCS in NDJSON format.

    Args:
        events: Normalised event dicts.
        bucket_name: GCS bucket.
        source_format: ``"zeek"`` or ``"suricata"``.
        timestamp: Partition timestamp.
        partition_id: Unique suffix.

    Returns:
        GCS path or ``None``.
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
        client = _gcs_storage.Client()
        bucket = client.bucket(bucket_name)
        blob = bucket.blob(blob_path)
        blob.upload_from_string(content, content_type="application/json")
        logger.info(
            "Wrote %d events to gs://%s/%s",
            len(events), bucket_name, blob_path,
        )
        return blob_path
    except Exception:
        logger.exception("Failed to write to GCS")
        return None


def _batch_and_write(
    events: List[Dict[str, Any]],
    bucket_name: str,
    source_format: str,
    batch_size: int,
    partition_prefix: str = "",
) -> List[str]:
    """Split events into batches and write each to GCS."""
    now = datetime.now(timezone.utc)
    paths = []

    for i in range(0, len(events), batch_size):
        batch = events[i : i + batch_size]
        batch_id = (
            f"{partition_prefix}{now.strftime('%M%S')}_{i // batch_size:04d}"
        )
        path = _write_to_gcs(
            batch, bucket_name, source_format, now, batch_id
        )
        if path:
            paths.append(path)

    return paths


def _report_health(event_count: int, source_format: str) -> None:
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
            source_type=source_format,
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
def zeek_suricata_gcs(cloud_event: Any) -> Dict[str, Any]:
    """GCS-triggered Cloud Function for Zeek/Suricata log files.

    Triggered when a new file is uploaded to the configured GCS bucket.

    Args:
        cloud_event: CloudEvents object with GCS metadata.

    Returns:
        Result dict with collection status.
    """
    if not GCS_OUTPUT_BUCKET:
        logger.error("GCS_OUTPUT_BUCKET not configured")
        return {"status": "error", "error": "missing_configuration"}

    data = cloud_event.data
    bucket_name = data.get("bucket", "")
    blob_name = data.get("name", "")

    if not bucket_name or not blob_name:
        return {"status": "error", "error": "missing_bucket_or_blob"}

    content = _read_gcs_file(bucket_name, blob_name)
    if not content:
        return {"status": "success", "total_events": 0}

    parsed, fmt = parse_uploaded_file(content)
    if not parsed:
        return {"status": "success", "total_events": 0, "format": fmt}

    safe_name = blob_name.replace("/", "_").replace(".", "_")[-32:]
    paths = _batch_and_write(
        parsed,
        GCS_OUTPUT_BUCKET,
        fmt,
        BATCH_SIZE,
        partition_prefix=f"gcs_{safe_name}_",
    )

    _report_health(len(parsed), fmt)

    return {
        "status": "success",
        "source_blob": f"gs://{bucket_name}/{blob_name}",
        "format": fmt,
        "total_events": len(parsed),
        "files_written": len(paths),
        "output_paths": paths,
    }


@functions_framework.http
def zeek_suricata_http(request: Any) -> Any:
    """HTTP Cloud Function for on-demand Zeek/Suricata processing.

    Accepts a JSON body with ``bucket`` and ``name`` fields.

    Args:
        request: Flask request object.

    Returns:
        JSON response with collection status.
    """
    if not GCS_OUTPUT_BUCKET:
        return ({"status": "error", "error": "missing_configuration"}, 500)

    try:
        request_json = request.get_json(silent=True)
    except Exception:
        request_json = None

    if not request_json:
        return ({"status": "error", "error": "invalid_request"}, 400)

    bucket_name = request_json.get("bucket", "")
    blob_name = request_json.get("name", "")

    if not bucket_name or not blob_name:
        return ({"status": "error", "error": "missing_bucket_or_blob"}, 400)

    content = _read_gcs_file(bucket_name, blob_name)
    if not content:
        return {"status": "success", "total_events": 0}

    parsed, fmt = parse_uploaded_file(content)
    if not parsed:
        return {"status": "success", "total_events": 0, "format": fmt}

    paths = _batch_and_write(
        parsed, GCS_OUTPUT_BUCKET, fmt, BATCH_SIZE
    )

    _report_health(len(parsed), fmt)

    return {
        "status": "success",
        "format": fmt,
        "total_events": len(parsed),
        "files_written": len(paths),
        "output_paths": paths,
    }
