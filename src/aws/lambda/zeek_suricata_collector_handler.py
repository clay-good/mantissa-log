"""
AWS Zeek/Suricata Log Collector

Processes Zeek and Suricata JSON log files uploaded to S3 by on-prem
sensors.  Auto-detects the format and parses using the appropriate parser.

Delivery Method:
  S3 Event Notification triggers this Lambda when a new log file is uploaded.

Data Lake Output:
  ``{LOGS_BUCKET}/{zeek|suricata}/raw/YYYY/MM/DD/HH/<partition>.json``
  Each file is newline-delimited JSON (NDJSON) of normalised event dicts.

Environment Variables:
    LOGS_BUCKET: S3 bucket for the data lake
    LOG_SOURCE_HEALTH_TABLE: DynamoDB table for health monitoring
    TENANT_ID: Tenant identifier (default: 'default')
    CHECKPOINT_TABLE: DynamoDB table for checkpoint tracking
    BATCH_SIZE: Max events per output file (default: 10000)
"""

import gzip
import json
import logging
import os
import sys
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import boto3

logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Lazy-initialised AWS clients
_s3_client = None
_dynamodb_resource = None


def _get_s3():
    global _s3_client
    if _s3_client is None:
        _s3_client = boto3.client("s3")
    return _s3_client


def _get_dynamodb():
    global _dynamodb_resource
    if _dynamodb_resource is None:
        _dynamodb_resource = boto3.resource("dynamodb")
    return _dynamodb_resource


# ---------------------------------------------------------------------------
# Collector integration
# ---------------------------------------------------------------------------
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../../shared"))

from collectors.zeek_suricata_collector import parse_uploaded_file  # noqa: E402


# ===========================================================================
# S3 file reading
# ===========================================================================

def _read_s3_file(bucket: str, key: str) -> bytes:
    """Read raw bytes from an S3 object, decompressing if gzipped.

    Args:
        bucket: S3 bucket name.
        key: S3 object key.

    Returns:
        Raw file bytes.
    """
    try:
        response = _get_s3().get_object(Bucket=bucket, Key=key)
        raw = response["Body"].read()

        if key.endswith(".gz") or raw[:2] == b"\x1f\x8b":
            raw = gzip.decompress(raw)

        return raw
    except Exception:
        logger.exception("Failed to read s3://%s/%s", bucket, key)
        return b""


def _extract_s3_events(event: Dict[str, Any]) -> List[Dict[str, str]]:
    """Extract S3 bucket/key pairs from an S3 event notification."""
    s3_refs: List[Dict[str, str]] = []

    for record in event.get("Records", []):
        s3_info = record.get("s3")
        if s3_info:
            bucket = s3_info.get("bucket", {}).get("name", "")
            key = s3_info.get("object", {}).get("key", "")
            if bucket and key:
                s3_refs.append({"bucket": bucket, "key": key})
            continue

        # SQS-wrapped
        body = record.get("body", "")
        if isinstance(body, str):
            try:
                body_json = json.loads(body)
                for inner in body_json.get("Records", []):
                    inner_s3 = inner.get("s3")
                    if inner_s3:
                        bucket = inner_s3.get("bucket", {}).get("name", "")
                        key = inner_s3.get("object", {}).get("key", "")
                        if bucket and key:
                            s3_refs.append({"bucket": bucket, "key": key})
            except (json.JSONDecodeError, TypeError):
                continue

    return s3_refs


# ===========================================================================
# Write to data lake
# ===========================================================================

def _write_to_data_lake(
    events: List[Dict[str, Any]],
    bucket: str,
    source_format: str,
    timestamp: datetime,
    partition_id: str = "",
) -> Optional[str]:
    """Write parsed events to the data lake in partitioned NDJSON format.

    Args:
        events: Normalised event dicts.
        bucket: S3 bucket.
        source_format: ``"zeek"`` or ``"suricata"``.
        timestamp: Partition timestamp.
        partition_id: Unique suffix.

    Returns:
        S3 key or ``None``.
    """
    if not events:
        return None

    year = timestamp.strftime("%Y")
    month = timestamp.strftime("%m")
    day = timestamp.strftime("%d")
    hour = timestamp.strftime("%H")

    if not partition_id:
        partition_id = timestamp.strftime("%M%S")

    s3_key = (
        f"{source_format}/raw/{year}/{month}/{day}/{hour}"
        f"/{source_format}_{partition_id}.json"
    )

    data = "\n".join(json.dumps(e) for e in events)

    try:
        _get_s3().put_object(
            Bucket=bucket,
            Key=s3_key,
            Body=data.encode("utf-8"),
            ContentType="application/json",
        )
        logger.info("Wrote %d events to s3://%s/%s", len(events), bucket, s3_key)
        return s3_key
    except Exception:
        logger.exception("Failed to write to data lake")
        return None


def _batch_and_write(
    events: List[Dict[str, Any]],
    bucket: str,
    source_format: str,
    batch_size: int,
    partition_prefix: str = "",
) -> List[str]:
    """Split events into batches and write each to the data lake."""
    now = datetime.now(timezone.utc)
    keys = []

    for i in range(0, len(events), batch_size):
        batch = events[i : i + batch_size]
        batch_id = (
            f"{partition_prefix}{now.strftime('%M%S')}_{i // batch_size:04d}"
        )
        key = _write_to_data_lake(batch, bucket, source_format, now, batch_id)
        if key:
            keys.append(key)

    return keys


def _report_health(event_count: int, source_format: str) -> None:
    """Report event count to the log source health monitor."""
    try:
        from src.shared.health.health_state_store import DynamoDBHealthStateStore

        health_table = os.environ.get("LOG_SOURCE_HEALTH_TABLE")
        tenant_id = os.environ.get("TENANT_ID", "default")
        if health_table:
            store = DynamoDBHealthStateStore(table_name=health_table)
            store.update_event_count(
                source_type=source_format,
                tenant_id=tenant_id,
                count_increment=event_count,
                latest_timestamp=datetime.now(timezone.utc),
            )
    except Exception as e:
        logger.warning("Failed to update health state: %s", e)


# ===========================================================================
# Checkpoint management
# ===========================================================================

def _is_processed(source_key: str) -> bool:
    """Check if an S3 key has already been processed."""
    table_name = os.environ.get("CHECKPOINT_TABLE")
    if not table_name:
        return False
    try:
        table = _get_dynamodb().Table(table_name)
        resp = table.get_item(Key={"source": f"zeek_suricata:{source_key}"})
        return "Item" in resp
    except Exception:
        return False


def _save_checkpoint(source_key: str) -> None:
    """Mark an S3 key as processed."""
    table_name = os.environ.get("CHECKPOINT_TABLE")
    if not table_name:
        return
    try:
        table = _get_dynamodb().Table(table_name)
        table.put_item(
            Item={
                "source": f"zeek_suricata:{source_key}",
                "processed_at": datetime.now(timezone.utc).isoformat(),
            }
        )
    except Exception:
        logger.warning("Failed to save checkpoint for %s", source_key)


# ===========================================================================
# Lambda handler
# ===========================================================================

def lambda_handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """AWS Lambda handler for Zeek/Suricata log file processing.

    Triggered by S3 event notifications when on-prem sensors upload
    JSON log files.

    Environment Variables:
        LOGS_BUCKET: S3 bucket for the data lake
        LOG_SOURCE_HEALTH_TABLE: DynamoDB table for health monitoring
        TENANT_ID: Tenant identifier
        CHECKPOINT_TABLE: DynamoDB table for checkpoints
        BATCH_SIZE: Max events per output file (default 10000)
    """
    logs_bucket = os.environ.get("LOGS_BUCKET", "mantissa-log-data")
    batch_size = int(os.environ.get("BATCH_SIZE", "10000"))

    try:
        s3_refs = _extract_s3_events(event)
        if not s3_refs:
            return {
                "statusCode": 200,
                "mode": "s3_event",
                "total_events": 0,
            }

        total_events = 0
        total_written = 0
        output_keys: List[str] = []
        formats_seen: Dict[str, int] = {}

        for ref in s3_refs:
            source_key = f"{ref['bucket']}/{ref['key']}"

            if _is_processed(source_key):
                logger.info("Skipping already processed: %s", source_key)
                continue

            content = _read_s3_file(ref["bucket"], ref["key"])
            if not content:
                _save_checkpoint(source_key)
                continue

            parsed, fmt = parse_uploaded_file(content)
            if not parsed:
                _save_checkpoint(source_key)
                continue

            formats_seen[fmt] = formats_seen.get(fmt, 0) + len(parsed)

            safe_name = ref["key"].replace("/", "_").replace(".", "_")[-32:]
            keys = _batch_and_write(
                parsed,
                logs_bucket,
                fmt,
                batch_size,
                partition_prefix=f"s3_{safe_name}_",
            )

            total_events += len(parsed)
            total_written += len(keys)
            output_keys.extend(keys)

            _save_checkpoint(source_key)

        if total_events > 0:
            # Report health per format
            for fmt, count in formats_seen.items():
                _report_health(count, fmt)

        return {
            "statusCode": 200,
            "mode": "s3_event",
            "files_processed": len(s3_refs),
            "total_events": total_events,
            "formats": formats_seen,
            "files_written": total_written,
            "output_keys": output_keys,
        }

    except Exception:
        logger.exception("Zeek/Suricata log collection failed")
        return {"statusCode": 500, "error": "collection_failed"}
