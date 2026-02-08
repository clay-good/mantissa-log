"""
AWS Route 53 DNS Query Log Collector

Collects Route 53 Resolver DNS query logs and normalises them into the
Mantissa Log data lake.

Route 53 Resolver query logs are delivered to CloudWatch Logs.  Each log
group follows the pattern ``/aws/route53/{hosted_zone_id}``.

Delivery Methods:
1. **CloudWatch Logs subscription filter** — A subscription filter on the
   Route 53 log group streams batches of log events to this Lambda.
2. **Scheduled poll** — An EventBridge schedule triggers the Lambda to poll
   one or more CloudWatch Logs log groups using the GetLogEvents API.

Data Lake Output:
  ``{LOGS_BUCKET}/route53_dns/raw/YYYY/MM/DD/HH/<partition>.json``
  Each file is newline-delimited JSON (NDJSON) of normalised event dicts.

Environment Variables:
    LOGS_BUCKET: S3 bucket for the data lake
    LOG_SOURCE_HEALTH_TABLE: DynamoDB table for health monitoring
    TENANT_ID: Tenant identifier (default: 'default')
    CHECKPOINT_TABLE: DynamoDB table for checkpoint tracking
    BATCH_SIZE: Max events per output file (default: 10000)
    LOG_GROUP_NAMES: Comma-separated CloudWatch Logs log group names to poll
    POLL_WINDOW_MINUTES: How many minutes back to poll (default: 10)
"""

import base64
import gzip
import json
import logging
import os
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

import boto3

logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Lazy-initialised AWS clients
_s3_client = None
_logs_client = None
_dynamodb_resource = None


def _get_s3():
    global _s3_client
    if _s3_client is None:
        _s3_client = boto3.client("s3")
    return _s3_client


def _get_logs():
    global _logs_client
    if _logs_client is None:
        _logs_client = boto3.client("logs")
    return _logs_client


def _get_dynamodb():
    global _dynamodb_resource
    if _dynamodb_resource is None:
        _dynamodb_resource = boto3.resource("dynamodb")
    return _dynamodb_resource


# ---------------------------------------------------------------------------
# Parser integration — import Route53DNSParser
# ---------------------------------------------------------------------------
import sys
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "../../shared"))

from parsers.route53_dns import Route53DNSParser  # noqa: E402

_parser = Route53DNSParser()


# ===========================================================================
# CloudWatch Logs decoding
# ===========================================================================

def _decode_cloudwatch_logs(event: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Decode a CloudWatch Logs subscription filter event.

    The event payload is base64-encoded gzipped JSON containing ``logEvents``.
    Each log event message is a JSON-encoded Route 53 DNS query log entry.

    Returns:
        List of parsed JSON dictionaries (one per DNS query).
    """
    try:
        data = event.get("awslogs", {}).get("data", "")
        if not data:
            return []

        raw = base64.b64decode(data)
        payload = json.loads(gzip.decompress(raw))

        events = []
        for log_event in payload.get("logEvents", []):
            message = log_event.get("message", "").strip()
            if not message:
                continue
            try:
                parsed = json.loads(message)
                if isinstance(parsed, dict):
                    events.append(parsed)
            except (json.JSONDecodeError, TypeError):
                logger.debug("Skipping non-JSON log event: %s", message[:200])
                continue

        return events
    except Exception:
        logger.exception("Failed to decode CloudWatch Logs event")
        return []


# ===========================================================================
# CloudWatch Logs polling
# ===========================================================================

def _poll_log_group(
    log_group_name: str,
    start_time_ms: int,
    end_time_ms: int,
) -> List[Dict[str, Any]]:
    """Poll a CloudWatch Logs log group for DNS query log events.

    Uses FilterLogEvents to retrieve all events in the time window.

    Args:
        log_group_name: CloudWatch Logs log group name.
        start_time_ms: Start timestamp in milliseconds since epoch.
        end_time_ms: End timestamp in milliseconds since epoch.

    Returns:
        List of parsed JSON dictionaries.
    """
    events: List[Dict[str, Any]] = []
    client = _get_logs()

    try:
        kwargs: Dict[str, Any] = {
            "logGroupName": log_group_name,
            "startTime": start_time_ms,
            "endTime": end_time_ms,
            "limit": 10000,
        }

        while True:
            response = client.filter_log_events(**kwargs)

            for log_event in response.get("events", []):
                message = log_event.get("message", "").strip()
                if not message:
                    continue
                try:
                    parsed = json.loads(message)
                    if isinstance(parsed, dict):
                        events.append(parsed)
                except (json.JSONDecodeError, TypeError):
                    continue

            next_token = response.get("nextToken")
            if not next_token:
                break
            kwargs["nextToken"] = next_token

    except Exception:
        logger.exception("Failed to poll log group %s", log_group_name)

    return events


# ===========================================================================
# Parse, batch, and write
# ===========================================================================

def _parse_dns_events(raw_events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Parse raw Route 53 DNS query log dicts using the parser.

    Args:
        raw_events: List of raw Route 53 query log dicts.

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
            logger.debug("Failed to parse DNS event: %s", str(raw_event)[:200])
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

    s3_key = f"route53_dns/raw/{year}/{month}/{day}/{hour}/dns_{partition_id}.json"

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
                source_type="route53_dns",
                tenant_id=tenant_id,
                count_increment=event_count,
                latest_timestamp=datetime.now(timezone.utc),
            )
    except Exception as e:
        logger.warning("Failed to update health state: %s", e)


# ===========================================================================
# Checkpoint management (for scheduled polling)
# ===========================================================================

def _get_checkpoint(log_group: str) -> Optional[int]:
    """Retrieve the last poll timestamp (ms since epoch) from DynamoDB."""
    table_name = os.environ.get("CHECKPOINT_TABLE")
    if not table_name:
        return None
    try:
        table = _get_dynamodb().Table(table_name)
        resp = table.get_item(Key={"source": f"route53_dns:{log_group}"})
        item = resp.get("Item", {})
        val = item.get("last_poll_timestamp_ms")
        return int(val) if val is not None else None
    except Exception:
        logger.warning("Failed to get checkpoint for %s", log_group)
        return None


def _save_checkpoint(log_group: str, timestamp_ms: int) -> None:
    """Save the last poll timestamp (ms since epoch) to DynamoDB."""
    table_name = os.environ.get("CHECKPOINT_TABLE")
    if not table_name:
        return
    try:
        table = _get_dynamodb().Table(table_name)
        table.put_item(
            Item={
                "source": f"route53_dns:{log_group}",
                "last_poll_timestamp_ms": timestamp_ms,
                "updated_at": datetime.now(timezone.utc).isoformat(),
            }
        )
    except Exception:
        logger.warning("Failed to save checkpoint for %s", log_group)


# ===========================================================================
# Lambda handler
# ===========================================================================

def lambda_handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """AWS Lambda handler for Route 53 DNS query log collection.

    Supports two invocation modes:

    1. **CloudWatch Logs Subscription Filter** — Triggered by a subscription
       filter on the Route 53 log group.
    2. **Scheduled poll** — EventBridge schedule triggers polling of one or
       more CloudWatch Logs log groups for new events.

    Environment Variables:
        LOGS_BUCKET: S3 bucket for the data lake
        LOG_SOURCE_HEALTH_TABLE: DynamoDB table for health monitoring
        TENANT_ID: Tenant identifier
        CHECKPOINT_TABLE: DynamoDB table for checkpoints
        BATCH_SIZE: Max events per output file (default 10000)
        LOG_GROUP_NAMES: Comma-separated log group names for scheduled poll
        POLL_WINDOW_MINUTES: Minutes to look back when polling (default 10)
    """
    logs_bucket = os.environ.get("LOGS_BUCKET", "mantissa-log-data")
    batch_size = int(os.environ.get("BATCH_SIZE", "10000"))

    try:
        # -----------------------------------------------------------------
        # Mode 1: CloudWatch Logs Subscription Filter
        # -----------------------------------------------------------------
        if "awslogs" in event:
            return _handle_cloudwatch_subscription(event, logs_bucket, batch_size)

        # -----------------------------------------------------------------
        # Mode 2: Scheduled poll
        # -----------------------------------------------------------------
        return _handle_scheduled_poll(event, logs_bucket, batch_size)

    except Exception:
        logger.exception("Route 53 DNS log collection failed")
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
        return {"statusCode": 200, "mode": "cloudwatch_subscription", "total_events": 0}

    parsed = _parse_dns_events(raw_events)

    keys = _batch_and_write(parsed, logs_bucket, batch_size, partition_prefix="sub_")

    if parsed:
        _report_health(len(parsed))

    return {
        "statusCode": 200,
        "mode": "cloudwatch_subscription",
        "total_events": len(parsed),
        "files_written": len(keys),
        "output_keys": keys,
    }


def _handle_scheduled_poll(
    event: Dict[str, Any],
    logs_bucket: str,
    batch_size: int,
) -> Dict[str, Any]:
    """Poll CloudWatch Logs log groups for new DNS query log events."""
    log_group_names_str = os.environ.get("LOG_GROUP_NAMES", "")
    poll_window_minutes = int(os.environ.get("POLL_WINDOW_MINUTES", "10"))

    if not log_group_names_str:
        logger.warning("LOG_GROUP_NAMES not configured for scheduled poll")
        return {"statusCode": 400, "error": "missing_configuration"}

    log_group_names = [
        name.strip()
        for name in log_group_names_str.split(",")
        if name.strip()
    ]

    now_ms = int(time.time() * 1000)
    default_start_ms = now_ms - (poll_window_minutes * 60 * 1000)

    total_events = 0
    total_written = 0
    output_keys: List[str] = []

    for log_group in log_group_names:
        # Use checkpoint if available, otherwise use poll window
        checkpoint_ms = _get_checkpoint(log_group)
        start_ms = checkpoint_ms if checkpoint_ms is not None else default_start_ms

        logger.info(
            "Polling %s from %d to %d", log_group, start_ms, now_ms
        )

        raw_events = _poll_log_group(log_group, start_ms, now_ms)
        if not raw_events:
            _save_checkpoint(log_group, now_ms)
            continue

        parsed = _parse_dns_events(raw_events)

        safe_name = log_group.replace("/", "_").replace(".", "_")[-32:]
        keys = _batch_and_write(
            parsed, logs_bucket, batch_size,
            partition_prefix=f"poll_{safe_name}_",
        )

        total_events += len(parsed)
        total_written += len(keys)
        output_keys.extend(keys)

        _save_checkpoint(log_group, now_ms)

    if total_events > 0:
        _report_health(total_events)

    return {
        "statusCode": 200,
        "mode": "scheduled_poll",
        "log_groups_polled": len(log_group_names),
        "total_events": total_events,
        "files_written": total_written,
        "output_keys": output_keys,
    }
