"""
AWS Network Firewall Log Collector

Collects AWS Network Firewall alert and flow logs and normalises them
into the Mantissa Log data lake.

AWS Network Firewall delivers logs to S3 and/or CloudWatch Logs in
Suricata-compatible EVE JSON format.  Each log entry contains an ``event``
object with fields like ``event_type``, ``src_ip``, ``dest_ip``, and
protocol-specific details (alert, flow, tls, http, dns).

Delivery Methods:
1. **S3 Event Notification** — New log files landing in S3 trigger this
   Lambda (directly or via SQS).
2. **CloudWatch Logs Subscription Filter** — A subscription filter on the
   Network Firewall log group streams events.

Data Lake Output:
  ``{LOGS_BUCKET}/network_firewall/raw/YYYY/MM/DD/HH/<partition>.json``
  Each file is newline-delimited JSON (NDJSON) of normalised event dicts.

Environment Variables:
    LOGS_BUCKET: S3 bucket for the data lake
    LOG_SOURCE_HEALTH_TABLE: DynamoDB table for health monitoring
    TENANT_ID: Tenant identifier (default: 'default')
    CHECKPOINT_TABLE: DynamoDB table for checkpoint tracking
    BATCH_SIZE: Max events per output file (default: 10000)
"""

import base64
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
# Parser integration
# ---------------------------------------------------------------------------
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../../shared"))

from parsers.cloud_firewall import CloudFirewallParser  # noqa: E402

_parser = CloudFirewallParser()


# ===========================================================================
# S3 file reading
# ===========================================================================

def _read_s3_file(bucket: str, key: str) -> List[Dict[str, Any]]:
    """Read and parse a Network Firewall log file from S3.

    Network Firewall writes JSON logs — one JSON object per line (NDJSON),
    or a single JSON object per file depending on configuration.  Files
    may be gzip-compressed.

    Args:
        bucket: S3 bucket name.
        key: S3 object key.

    Returns:
        List of parsed JSON dictionaries.
    """
    try:
        response = _get_s3().get_object(Bucket=bucket, Key=key)
        raw = response["Body"].read()

        # Decompress if gzipped
        if key.endswith(".gz") or raw[:2] == b"\x1f\x8b":
            raw = gzip.decompress(raw)

        content = raw.decode("utf-8", errors="replace")

        events: List[Dict[str, Any]] = []
        for line in content.strip().split("\n"):
            line = line.strip()
            if not line:
                continue
            try:
                parsed = json.loads(line)
                if isinstance(parsed, dict):
                    events.append(parsed)
                elif isinstance(parsed, list):
                    events.extend(e for e in parsed if isinstance(e, dict))
            except (json.JSONDecodeError, TypeError):
                continue

        return events
    except Exception:
        logger.exception("Failed to read s3://%s/%s", bucket, key)
        return []


# ===========================================================================
# CloudWatch Logs decoding
# ===========================================================================

def _decode_cloudwatch_logs(event: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Decode a CloudWatch Logs subscription filter event.

    Args:
        event: Lambda event with ``awslogs.data`` payload.

    Returns:
        List of parsed JSON dictionaries.
    """
    try:
        data = event.get("awslogs", {}).get("data", "")
        if not data:
            return []

        raw = base64.b64decode(data)
        payload = json.loads(gzip.decompress(raw))

        events: List[Dict[str, Any]] = []
        for log_event in payload.get("logEvents", []):
            message = log_event.get("message", "").strip()
            if not message:
                continue
            try:
                parsed = json.loads(message)
                if isinstance(parsed, dict):
                    events.append(parsed)
            except (json.JSONDecodeError, TypeError):
                continue

        return events
    except Exception:
        logger.exception("Failed to decode CloudWatch Logs event")
        return []


# ===========================================================================
# S3 event extraction
# ===========================================================================

def _extract_s3_events(event: Dict[str, Any]) -> List[Dict[str, str]]:
    """Extract S3 bucket/key pairs from an S3 event notification.

    Handles both direct S3 events and SQS-wrapped S3 events.

    Args:
        event: Lambda event.

    Returns:
        List of dicts with ``bucket`` and ``key`` fields.
    """
    s3_refs: List[Dict[str, str]] = []

    records = event.get("Records", [])
    for record in records:
        # Direct S3 event
        s3_info = record.get("s3")
        if s3_info:
            bucket = s3_info.get("bucket", {}).get("name", "")
            key = s3_info.get("object", {}).get("key", "")
            if bucket and key:
                s3_refs.append({"bucket": bucket, "key": key})
            continue

        # SQS-wrapped S3 event
        body = record.get("body", "")
        if isinstance(body, str):
            try:
                body_json = json.loads(body)
                for inner_record in body_json.get("Records", []):
                    inner_s3 = inner_record.get("s3")
                    if inner_s3:
                        bucket = inner_s3.get("bucket", {}).get("name", "")
                        key = inner_s3.get("object", {}).get("key", "")
                        if bucket and key:
                            s3_refs.append({"bucket": bucket, "key": key})
            except (json.JSONDecodeError, TypeError):
                continue

    return s3_refs


# ===========================================================================
# Parse, batch, and write
# ===========================================================================

def _parse_firewall_events(
    raw_events: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """Parse raw Network Firewall log entries using the CloudFirewallParser.

    Args:
        raw_events: List of raw firewall event dicts.

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


def _write_to_data_lake(
    events: List[Dict[str, Any]],
    bucket: str,
    timestamp: datetime,
    partition_id: str = "",
) -> Optional[str]:
    """Write parsed events to the data lake in partitioned NDJSON format.

    Args:
        events: List of normalised event dicts.
        bucket: S3 bucket for the data lake.
        timestamp: Partition timestamp.
        partition_id: Unique suffix for the file name.

    Returns:
        S3 key where data was written, or ``None`` on failure.
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
        f"network_firewall/raw/{year}/{month}/{day}/{hour}"
        f"/fw_{partition_id}.json"
    )

    data = "\n".join(json.dumps(e) for e in events)

    try:
        _get_s3().put_object(
            Bucket=bucket,
            Key=s3_key,
            Body=data.encode("utf-8"),
            ContentType="application/json",
        )
        logger.info(
            "Wrote %d events to s3://%s/%s", len(events), bucket, s3_key
        )
        return s3_key
    except Exception:
        logger.exception("Failed to write to data lake")
        return None


def _batch_and_write(
    events: List[Dict[str, Any]],
    bucket: str,
    batch_size: int,
    partition_prefix: str = "",
) -> List[str]:
    """Split events into batches and write each to the data lake.

    Args:
        events: All normalised events.
        bucket: Data lake S3 bucket.
        batch_size: Maximum events per output file.
        partition_prefix: Optional prefix for partition IDs.

    Returns:
        List of S3 keys written.
    """
    now = datetime.now(timezone.utc)
    keys = []

    for i in range(0, len(events), batch_size):
        batch = events[i : i + batch_size]
        batch_id = (
            f"{partition_prefix}{now.strftime('%M%S')}_{i // batch_size:04d}"
        )
        key = _write_to_data_lake(batch, bucket, now, batch_id)
        if key:
            keys.append(key)

    return keys


def _report_health(event_count: int) -> None:
    """Report event count to the log source health monitor."""
    try:
        from src.shared.health.health_state_store import DynamoDBHealthStateStore

        health_table = os.environ.get("LOG_SOURCE_HEALTH_TABLE")
        tenant_id = os.environ.get("TENANT_ID", "default")
        if health_table:
            store = DynamoDBHealthStateStore(table_name=health_table)
            store.update_event_count(
                source_type="network_firewall",
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
        resp = table.get_item(Key={"source": f"network_firewall:{source_key}"})
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
                "source": f"network_firewall:{source_key}",
                "processed_at": datetime.now(timezone.utc).isoformat(),
            }
        )
    except Exception:
        logger.warning("Failed to save checkpoint for %s", source_key)


# ===========================================================================
# Lambda handler
# ===========================================================================

def lambda_handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """AWS Lambda handler for Network Firewall log collection.

    Supports two invocation modes:

    1. **S3 Event Notification** — Triggered when a new firewall log file
       lands in S3 (directly or via SQS).
    2. **CloudWatch Logs Subscription Filter** — Triggered by a subscription
       filter on the Network Firewall log group.

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
        # Mode 1: CloudWatch Logs Subscription Filter
        if "awslogs" in event:
            return _handle_cloudwatch_subscription(
                event, logs_bucket, batch_size
            )

        # Mode 2: S3 Event Notification
        if "Records" in event:
            return _handle_s3_event(event, logs_bucket, batch_size)

        logger.warning("Unrecognised event format")
        return {"statusCode": 400, "error": "unknown_event_format"}

    except Exception:
        logger.exception("Network Firewall log collection failed")
        return {"statusCode": 500, "error": "collection_failed"}


# ===========================================================================
# Mode handlers
# ===========================================================================

def _handle_cloudwatch_subscription(
    event: Dict[str, Any],
    logs_bucket: str,
    batch_size: int,
) -> Dict[str, Any]:
    """Process CloudWatch Logs subscription filter event."""
    raw_events = _decode_cloudwatch_logs(event)
    if not raw_events:
        return {
            "statusCode": 200,
            "mode": "cloudwatch_subscription",
            "total_events": 0,
        }

    parsed = _parse_firewall_events(raw_events)

    keys = _batch_and_write(
        parsed, logs_bucket, batch_size, partition_prefix="sub_"
    )

    if parsed:
        _report_health(len(parsed))

    return {
        "statusCode": 200,
        "mode": "cloudwatch_subscription",
        "total_events": len(parsed),
        "files_written": len(keys),
        "output_keys": keys,
    }


def _handle_s3_event(
    event: Dict[str, Any],
    logs_bucket: str,
    batch_size: int,
) -> Dict[str, Any]:
    """Process S3 event notification (direct or SQS-wrapped)."""
    s3_refs = _extract_s3_events(event)
    if not s3_refs:
        return {"statusCode": 200, "mode": "s3_event", "total_events": 0}

    total_events = 0
    total_written = 0
    output_keys: List[str] = []

    for ref in s3_refs:
        source_key = f"{ref['bucket']}/{ref['key']}"

        if _is_processed(source_key):
            logger.info("Skipping already processed: %s", source_key)
            continue

        raw_events = _read_s3_file(ref["bucket"], ref["key"])
        if not raw_events:
            _save_checkpoint(source_key)
            continue

        parsed = _parse_firewall_events(raw_events)

        safe_name = ref["key"].replace("/", "_").replace(".", "_")[-32:]
        keys = _batch_and_write(
            parsed,
            logs_bucket,
            batch_size,
            partition_prefix=f"s3_{safe_name}_",
        )

        total_events += len(parsed)
        total_written += len(keys)
        output_keys.extend(keys)

        _save_checkpoint(source_key)

    if total_events > 0:
        _report_health(total_events)

    return {
        "statusCode": 200,
        "mode": "s3_event",
        "files_processed": len(s3_refs),
        "total_events": total_events,
        "files_written": total_written,
        "output_keys": output_keys,
    }
