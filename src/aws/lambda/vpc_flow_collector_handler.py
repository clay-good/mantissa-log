"""
AWS VPC Flow Log Collector

Collects VPC Flow Logs from two delivery methods and normalises them into
the Mantissa Log data lake.

Delivery Methods:
1. **S3 delivery** (most common): Flow logs are published to an S3 bucket.
   New files trigger the collector via S3 event notifications (directly or
   via SQS).  Each file contains a header line followed by space-separated
   flow records.
2. **CloudWatch Logs delivery**: A subscription filter streams flow records
   to the Lambda via CloudWatch Logs.

Data Lake Output:
  ``{LOGS_BUCKET}/vpc_flow/raw/YYYY/MM/DD/HH/<partition>.json``
  Each file is newline-delimited JSON (NDJSON) of normalized ``ParsedEvent``
  dictionaries.

Environment Variables:
    LOGS_BUCKET: S3 bucket for the data lake
    LOG_SOURCE_HEALTH_TABLE: DynamoDB table for health monitoring
    TENANT_ID: Tenant identifier (default: 'default')
    CHECKPOINT_TABLE: DynamoDB table for checkpoint tracking
    BATCH_SIZE: Max events per output file (default: 10000)
    AGGREGATE_FLOWS: Enable flow aggregation (default: 'false')
    AGGREGATE_WINDOW_SECONDS: Aggregation window (default: 300)
"""

import base64
import gzip
import json
import logging
import os
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

import boto3

logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Lazy-initialized AWS clients
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
# Default field order for VPC Flow Log v2 (14 fields).
# When an S3 file has no header, this order is assumed.
# ---------------------------------------------------------------------------
_V2_DEFAULT_FIELDS = [
    "version", "account-id", "interface-id", "srcaddr", "dstaddr",
    "srcport", "dstport", "protocol", "packets", "bytes",
    "start", "end", "action", "log-status",
]


# ---------------------------------------------------------------------------
# Parser integration — import VPCFlowLogsParser
# ---------------------------------------------------------------------------
import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../../shared"))

from parsers.vpc_flow import VPCFlowLogsParser  # noqa: E402

_parser = VPCFlowLogsParser()


# ===========================================================================
# S3 file reading
# ===========================================================================

def _read_s3_flow_log_file(bucket: str, key: str) -> List[str]:
    """Read a VPC Flow Log file from S3 and return individual flow lines.

    Handles gzip-compressed files automatically.  The first line may be a
    header row (starting with ``version`` or ``"version"``); if so it is
    returned as the first element.

    Returns:
        List of raw lines (including any header).
    """
    try:
        response = _get_s3().get_object(Bucket=bucket, Key=key)
        content = response["Body"].read()

        # Decompress if gzipped
        if key.endswith(".gz") or key.endswith(".log.gz") or content[:2] == b"\x1f\x8b":
            content = gzip.decompress(content)

        text = content.decode("utf-8")
        lines = [line for line in text.strip().split("\n") if line.strip()]
        return lines
    except Exception:
        logger.exception("Failed to read S3 object s3://%s/%s", bucket, key)
        return []


def _detect_header(lines: List[str]) -> Tuple[Optional[List[str]], List[str]]:
    """Detect and strip the header line from flow log lines.

    VPC Flow Log files published to S3 start with a header line that lists
    the field names.  Custom log formats may have fields in any order, so
    the header doesn't always start with ``version``.

    Args:
        lines: Raw file lines.

    Returns:
        (field_names, data_lines) where field_names is ``None`` if no header
        was detected (in which case v2 defaults are assumed).
    """
    if not lines:
        return None, []

    first = lines[0].strip()
    tokens = first.split()

    # Header detection: first line contains known VPC flow field names
    # and the first token is NOT a digit (data lines start with version number)
    _KNOWN_FIELDS = {
        "version", "account-id", "interface-id", "srcaddr", "dstaddr",
        "srcport", "dstport", "protocol", "packets", "bytes", "start",
        "end", "action", "log-status", "vpc-id", "subnet-id",
        "instance-id", "tcp-flags", "type", "pkt-srcaddr", "pkt-dstaddr",
        "region", "az-id", "sublocation-type", "sublocation-id",
        "pkt-src-aws-service", "pkt-dst-aws-service", "flow-direction",
        "traffic-path",
    }

    if tokens and not tokens[0].isdigit():
        # Check if most tokens are known field names
        matches = sum(1 for t in tokens if t.lower() in _KNOWN_FIELDS)
        if matches >= len(tokens) * 0.5:
            return tokens, lines[1:]

    return None, lines


def _reconstruct_flow_line(field_names: List[str], line: str) -> str:
    """Reconstruct a flow line into the positional format expected by the parser.

    The ``VPCFlowLogsParser`` expects the standard v2 positional format:
      ``version account-id interface-id srcaddr dstaddr srcport dstport
        protocol packets bytes start end action log-status [extended...]``

    When the S3 file uses a custom field order (indicated by its header), we
    re-order the fields to match the standard positional format so the parser
    can handle them.

    If the file uses the default v2 order, the line is returned as-is.
    """
    if field_names == _V2_DEFAULT_FIELDS:
        return line

    values = line.strip().split()
    if len(values) != len(field_names):
        # Mismatch — return raw and let the parser decide
        return line

    field_map = dict(zip(field_names, values))

    # Build the standard v2 positional fields first, then append extras
    ordered_values = []
    for name in _V2_DEFAULT_FIELDS:
        ordered_values.append(field_map.get(name, "-"))

    # Append any extra fields (v3-v5 extended) in the order they appear
    # in the file header, skipping ones already included in v2.
    v2_set = set(_V2_DEFAULT_FIELDS)
    for name in field_names:
        if name not in v2_set:
            ordered_values.append(field_map.get(name, "-"))

    return " ".join(ordered_values)


# ===========================================================================
# CloudWatch Logs decoding
# ===========================================================================

def _decode_cloudwatch_logs(event: Dict[str, Any]) -> List[str]:
    """Decode a CloudWatch Logs subscription filter event.

    The event payload is base64-encoded gzipped JSON containing ``logEvents``.

    Returns:
        List of flow log lines (raw strings).
    """
    try:
        data = event.get("awslogs", {}).get("data", "")
        if not data:
            return []

        raw = base64.b64decode(data)
        payload = json.loads(gzip.decompress(raw))

        lines = []
        for log_event in payload.get("logEvents", []):
            message = log_event.get("message", "").strip()
            if message:
                lines.append(message)

        return lines
    except Exception:
        logger.exception("Failed to decode CloudWatch Logs event")
        return []


# ===========================================================================
# Flow aggregation (optional)
# ===========================================================================

def _aggregate_flows(
    events: List[Dict[str, Any]],
    window_seconds: int = 300,
) -> List[Dict[str, Any]]:
    """Aggregate parsed flow events that share the same 5-tuple within a time window.

    Aggregation key: (source_ip, destination_ip, source_port, destination_port, protocol).
    Within each window, packets, bytes, and duration are summed.

    This reduces storage volume for high-traffic environments.

    Args:
        events: List of parsed event dicts (from ``ParsedEvent.to_dict()``).
        window_seconds: Time window for aggregation in seconds.

    Returns:
        Aggregated list of event dicts.
    """
    if not events:
        return events

    # Group by 5-tuple + time window
    buckets: Dict[str, Dict[str, Any]] = {}

    for event in events:
        meta = event.get("metadata", {})
        src_ip = event.get("source_ip", "")
        dst_ip = event.get("destination_ip", "")
        src_port = meta.get("source_port", 0)
        dst_port = meta.get("destination_port", 0)
        protocol = meta.get("protocol_name", "")

        # Time window bucket
        start_epoch = meta.get("start", 0)
        if isinstance(start_epoch, (int, float)) and start_epoch > 0:
            window_start = int(start_epoch) // window_seconds * window_seconds
        else:
            window_start = 0

        key = f"{src_ip}|{dst_ip}|{src_port}|{dst_port}|{protocol}|{window_start}"

        if key not in buckets:
            buckets[key] = {
                **event,
                "metadata": {
                    **meta,
                    "aggregated_count": 1,
                },
            }
        else:
            existing = buckets[key]
            existing_meta = existing["metadata"]
            existing_meta["aggregated_count"] = existing_meta.get("aggregated_count", 1) + 1

            # Sum numeric fields
            for field in ("bytes", "bytes_transferred", "packets"):
                old_val = existing_meta.get(field, 0)
                new_val = meta.get(field, 0)
                if isinstance(old_val, (int, float)) and isinstance(new_val, (int, float)):
                    existing_meta[field] = old_val + new_val

            # Max duration
            old_dur = existing_meta.get("duration_seconds", 0)
            new_dur = meta.get("duration_seconds", 0)
            if isinstance(old_dur, (int, float)) and isinstance(new_dur, (int, float)):
                existing_meta["duration_seconds"] = max(old_dur, new_dur)

    return list(buckets.values())


# ===========================================================================
# Parse, batch, and write
# ===========================================================================

def _parse_flow_lines(lines: List[str], field_names: Optional[List[str]]) -> List[Dict[str, Any]]:
    """Parse raw VPC Flow Log lines using the parser.

    Args:
        lines: Raw flow log lines (not including header).
        field_names: Field names from the file header, or ``None`` for v2 default.

    Returns:
        List of parsed event dicts.
    """
    parsed = []
    for line in lines:
        line = line.strip()
        if not line:
            continue

        # Skip header-like lines that may appear in CloudWatch delivery
        if line.lower().startswith("version"):
            continue

        # Re-order fields if custom header
        if field_names is not None:
            line = _reconstruct_flow_line(field_names, line)

        try:
            if _parser.validate(line):
                event = _parser.parse(line)
                parsed.append(event.to_dict())
        except Exception:
            logger.debug("Failed to parse flow line: %s", line[:200])
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
        events: List of parsed event dicts.
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

    s3_key = f"vpc_flow/raw/{year}/{month}/{day}/{hour}/flow_{partition_id}.json"

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
    """Split events into batches and write each batch to the data lake.

    Args:
        events: All parsed events.
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
        batch_id = f"{partition_prefix}{now.strftime('%M%S')}_{i // batch_size:04d}"
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
                source_type="vpc_flow_logs",
                tenant_id=tenant_id,
                count_increment=event_count,
                latest_timestamp=datetime.now(timezone.utc),
            )
    except Exception as e:
        logger.warning("Failed to update health state: %s", e)


# ===========================================================================
# Checkpoint management
# ===========================================================================

def _get_checkpoint(source_id: str) -> Optional[str]:
    """Retrieve the last processed S3 key from DynamoDB."""
    table_name = os.environ.get("CHECKPOINT_TABLE")
    if not table_name:
        return None
    try:
        table = _get_dynamodb().Table(table_name)
        resp = table.get_item(Key={"source": f"vpc_flow:{source_id}"})
        return resp.get("Item", {}).get("last_processed_key")
    except Exception:
        logger.warning("Failed to get checkpoint for %s", source_id)
        return None


def _save_checkpoint(source_id: str, s3_key: str) -> None:
    """Save the last processed S3 key to DynamoDB."""
    table_name = os.environ.get("CHECKPOINT_TABLE")
    if not table_name:
        return
    try:
        table = _get_dynamodb().Table(table_name)
        table.put_item(
            Item={
                "source": f"vpc_flow:{source_id}",
                "last_processed_key": s3_key,
                "updated_at": datetime.now(timezone.utc).isoformat(),
            }
        )
    except Exception:
        logger.warning("Failed to save checkpoint for %s", source_id)


# ===========================================================================
# Lambda handlers
# ===========================================================================

def lambda_handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """AWS Lambda handler for VPC Flow Log collection.

    Supports three invocation modes:

    1. **S3 Event Notification** — Triggered when new flow log files land
       in S3 (via S3 event notifications or SQS).
    2. **CloudWatch Logs Subscription** — Triggered by a CloudWatch Logs
       subscription filter streaming flow records.
    3. **Scheduled** — EventBridge scheduled rule that scans an S3 prefix
       for unprocessed files.

    Environment Variables:
        LOGS_BUCKET: S3 bucket for the data lake
        SOURCE_BUCKET: S3 bucket where raw flow logs are delivered
        SOURCE_PREFIX: S3 prefix for raw flow log files
        LOG_SOURCE_HEALTH_TABLE: DynamoDB table for health monitoring
        TENANT_ID: Tenant identifier
        CHECKPOINT_TABLE: DynamoDB table for checkpoints
        BATCH_SIZE: Max events per output file (default 10000)
        AGGREGATE_FLOWS: 'true' to enable flow aggregation
        AGGREGATE_WINDOW_SECONDS: Aggregation window (default 300)
    """
    logs_bucket = os.environ.get("LOGS_BUCKET", "mantissa-log-data")
    batch_size = int(os.environ.get("BATCH_SIZE", "10000"))
    aggregate = os.environ.get("AGGREGATE_FLOWS", "false").lower() == "true"
    agg_window = int(os.environ.get("AGGREGATE_WINDOW_SECONDS", "300"))

    try:
        # -----------------------------------------------------------------
        # Mode 1: S3 Event Notification
        # -----------------------------------------------------------------
        if "Records" in event:
            records = event["Records"]

            # SQS-wrapped S3 events
            if records and records[0].get("eventSource") == "aws:sqs":
                return _handle_sqs_s3_events(
                    records, logs_bucket, batch_size, aggregate, agg_window
                )

            # Direct S3 events
            if records and records[0].get("eventSource") == "aws:s3":
                return _handle_s3_events(
                    records, logs_bucket, batch_size, aggregate, agg_window
                )

        # -----------------------------------------------------------------
        # Mode 2: CloudWatch Logs Subscription Filter
        # -----------------------------------------------------------------
        if "awslogs" in event:
            return _handle_cloudwatch_logs(
                event, logs_bucket, batch_size, aggregate, agg_window
            )

        # -----------------------------------------------------------------
        # Mode 3: Scheduled scan
        # -----------------------------------------------------------------
        return _handle_scheduled(
            event, logs_bucket, batch_size, aggregate, agg_window
        )

    except Exception:
        logger.exception("VPC Flow Log collection failed")
        return {"statusCode": 500, "error": "collection_failed"}


# ===========================================================================
# Mode handlers
# ===========================================================================

def _handle_s3_events(
    records: List[Dict[str, Any]],
    logs_bucket: str,
    batch_size: int,
    aggregate: bool,
    agg_window: int,
) -> Dict[str, Any]:
    """Process direct S3 event notification records."""
    total_events = 0
    total_written = 0
    output_keys: List[str] = []

    for record in records:
        s3_info = record.get("s3", {})
        bucket = s3_info.get("bucket", {}).get("name", "")
        key = s3_info.get("object", {}).get("key", "")
        if not bucket or not key:
            continue

        events, keys = _process_s3_file(
            bucket, key, logs_bucket, batch_size, aggregate, agg_window
        )
        total_events += events
        total_written += len(keys)
        output_keys.extend(keys)

    if total_events > 0:
        _report_health(total_events)

    return {
        "statusCode": 200,
        "mode": "s3_event",
        "total_events": total_events,
        "files_written": total_written,
        "output_keys": output_keys,
    }


def _handle_sqs_s3_events(
    records: List[Dict[str, Any]],
    logs_bucket: str,
    batch_size: int,
    aggregate: bool,
    agg_window: int,
) -> Dict[str, Any]:
    """Process SQS messages wrapping S3 event notifications."""
    total_events = 0
    total_written = 0
    output_keys: List[str] = []

    for sqs_record in records:
        try:
            body = json.loads(sqs_record.get("body", "{}"))
        except (json.JSONDecodeError, TypeError):
            continue

        s3_records = body.get("Records", [])
        for record in s3_records:
            if record.get("eventSource") != "aws:s3":
                continue
            s3_info = record.get("s3", {})
            bucket = s3_info.get("bucket", {}).get("name", "")
            key = s3_info.get("object", {}).get("key", "")
            if not bucket or not key:
                continue

            events, keys = _process_s3_file(
                bucket, key, logs_bucket, batch_size, aggregate, agg_window
            )
            total_events += events
            total_written += len(keys)
            output_keys.extend(keys)

    if total_events > 0:
        _report_health(total_events)

    return {
        "statusCode": 200,
        "mode": "sqs_s3_event",
        "total_events": total_events,
        "files_written": total_written,
        "output_keys": output_keys,
    }


def _handle_cloudwatch_logs(
    event: Dict[str, Any],
    logs_bucket: str,
    batch_size: int,
    aggregate: bool,
    agg_window: int,
) -> Dict[str, Any]:
    """Process CloudWatch Logs subscription filter event."""
    lines = _decode_cloudwatch_logs(event)
    if not lines:
        return {"statusCode": 200, "mode": "cloudwatch_logs", "total_events": 0}

    parsed = _parse_flow_lines(lines, field_names=None)

    if aggregate and parsed:
        parsed = _aggregate_flows(parsed, agg_window)

    keys = _batch_and_write(parsed, logs_bucket, batch_size, partition_prefix="cw_")

    if parsed:
        _report_health(len(parsed))

    return {
        "statusCode": 200,
        "mode": "cloudwatch_logs",
        "total_events": len(parsed),
        "files_written": len(keys),
        "output_keys": keys,
    }


def _handle_scheduled(
    event: Dict[str, Any],
    logs_bucket: str,
    batch_size: int,
    aggregate: bool,
    agg_window: int,
) -> Dict[str, Any]:
    """Scheduled scan: process unprocessed files from source bucket/prefix."""
    source_bucket = os.environ.get("SOURCE_BUCKET", "")
    source_prefix = os.environ.get("SOURCE_PREFIX", "")
    max_files = int(os.environ.get("MAX_FILES_PER_RUN", "100"))

    if not source_bucket or not source_prefix:
        logger.warning("SOURCE_BUCKET and SOURCE_PREFIX required for scheduled mode")
        return {"statusCode": 400, "error": "missing_configuration"}

    source_id = event.get("source_id", "default")
    last_key = _get_checkpoint(source_id)

    # List unprocessed files
    files = _list_unprocessed_files(source_bucket, source_prefix, last_key, max_files)
    logger.info("Found %d unprocessed files", len(files))

    total_events = 0
    total_written = 0
    output_keys: List[str] = []

    for s3_key in files:
        events, keys = _process_s3_file(
            source_bucket, s3_key, logs_bucket, batch_size, aggregate, agg_window
        )
        total_events += events
        total_written += len(keys)
        output_keys.extend(keys)
        _save_checkpoint(source_id, s3_key)

    if total_events > 0:
        _report_health(total_events)

    return {
        "statusCode": 200,
        "mode": "scheduled",
        "files_scanned": len(files),
        "total_events": total_events,
        "files_written": total_written,
        "output_keys": output_keys,
    }


# ===========================================================================
# Shared helpers
# ===========================================================================

def _process_s3_file(
    source_bucket: str,
    source_key: str,
    logs_bucket: str,
    batch_size: int,
    aggregate: bool,
    agg_window: int,
) -> Tuple[int, List[str]]:
    """Read, parse, and write a single S3 flow log file.

    Returns:
        (event_count, list_of_output_keys)
    """
    logger.info("Processing s3://%s/%s", source_bucket, source_key)

    lines = _read_s3_flow_log_file(source_bucket, source_key)
    if not lines:
        return 0, []

    field_names, data_lines = _detect_header(lines)
    parsed = _parse_flow_lines(data_lines, field_names)

    if aggregate and parsed:
        parsed = _aggregate_flows(parsed, agg_window)

    # Derive partition prefix from source key for uniqueness
    safe_key = source_key.replace("/", "_").replace(".", "_")[-32:]
    keys = _batch_and_write(parsed, logs_bucket, batch_size, partition_prefix=f"s3_{safe_key}_")

    return len(parsed), keys


def _list_unprocessed_files(
    bucket: str,
    prefix: str,
    last_key: Optional[str],
    max_files: int,
) -> List[str]:
    """List S3 files under *prefix* that haven't been processed yet.

    Args:
        bucket: Source S3 bucket.
        prefix: S3 prefix to scan.
        last_key: Last processed S3 key (checkpoint).
        max_files: Maximum files to return.

    Returns:
        Sorted list of S3 keys.
    """
    paginator = _get_s3().get_paginator("list_objects_v2")
    files: List[str] = []

    kwargs: Dict[str, Any] = {"Bucket": bucket, "Prefix": prefix}
    if last_key:
        kwargs["StartAfter"] = last_key

    for page in paginator.paginate(**kwargs):
        for obj in page.get("Contents", []):
            key = obj["Key"]
            if key.endswith("/"):
                continue
            files.append(key)
            if len(files) >= max_files:
                return sorted(files)

    return sorted(files)
