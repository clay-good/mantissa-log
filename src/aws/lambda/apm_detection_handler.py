"""APM Detection Lambda Handler.

Scheduled Lambda function that runs APM detection rules against recent
trace and metric data. Generates alerts for triggered rules and routes
them through the existing alerting system.

EventBridge Schedule: rate(5 minutes)
"""

import json
import logging
import os
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

import boto3

# Configure logging
logger = logging.getLogger()
logger.setLevel(logging.INFO)

# Configuration from environment
RULES_PATH = os.environ.get("APM_RULES_PATH", "s3://mantissa-rules/sigma/apm/")
DASHBOARD_BASE_URL = os.environ.get("DASHBOARD_BASE_URL", "")
ALERT_SNS_TOPIC = os.environ.get("ALERT_SNS_TOPIC", "")
ATHENA_DATABASE = os.environ.get("ATHENA_DATABASE", "mantissa_logs")
ATHENA_WORKGROUP = os.environ.get("ATHENA_WORKGROUP", "primary")
ATHENA_OUTPUT_LOCATION = os.environ.get("ATHENA_OUTPUT_LOCATION", "")
EVALUATION_WINDOW_MINUTES = int(os.environ.get("EVALUATION_WINDOW_MINUTES", "5"))


def lambda_handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """Lambda entry point.

    Args:
        event: Lambda event (EventBridge scheduled event)
        context: Lambda context

    Returns:
        Response with detection results
    """
    logger.info("Starting APM detection run")

    try:
        # Initialize detector
        from ...shared.apm.apm_detector import APMDetector

        detector = APMDetector(
            query_executor=execute_athena_query,
            dashboard_base_url=DASHBOARD_BASE_URL,
        )

        # Load APM rules
        if RULES_PATH.startswith("s3://"):
            rules = load_rules_from_s3(RULES_PATH, detector)
        else:
            rules = detector.load_apm_rules(RULES_PATH)

        if not rules:
            logger.warning("No APM rules loaded")
            return {
                "statusCode": 200,
                "body": json.dumps({"message": "No APM rules to evaluate"})
            }

        logger.info(f"Loaded {len(rules)} APM rules")

        # Calculate time window
        end_time = datetime.utcnow()
        start_time = end_time - timedelta(minutes=EVALUATION_WINDOW_MINUTES)

        # Run all APM rules
        results = detector.run_all_apm_rules(start_time, end_time)

        # Filter triggered rules
        triggered_results = [r for r in results if r.triggered]

        logger.info(f"Detection complete: {len(triggered_results)} rules triggered out of {len(results)}")

        # Generate and route alerts for triggered rules
        alerts_sent = 0
        for result in triggered_results:
            try:
                alert = generate_apm_alert(result)
                route_alert(alert)
                alerts_sent += 1
            except Exception as e:
                logger.error(f"Error generating alert for {result.rule_id}: {e}")

        return {
            "statusCode": 200,
            "body": json.dumps({
                "rules_evaluated": len(results),
                "rules_triggered": len(triggered_results),
                "alerts_sent": alerts_sent,
                "evaluation_window": {
                    "start": start_time.isoformat(),
                    "end": end_time.isoformat(),
                }
            })
        }

    except Exception as e:
        logger.error(f"APM detection failed: {e}", exc_info=True)
        return {
            "statusCode": 500,
            "body": json.dumps({"error": str(e)})
        }


def load_rules_from_s3(s3_path: str, detector) -> List:
    """Load APM rules from S3 bucket.

    Args:
        s3_path: S3 path in format s3://bucket/prefix/
        detector: APMDetector instance

    Returns:
        List of loaded rules
    """
    import tempfile
    import yaml

    s3_client = boto3.client("s3")

    # Parse S3 path
    path_parts = s3_path[5:].split("/", 1)
    bucket_name = path_parts[0]
    prefix = path_parts[1] if len(path_parts) > 1 else ""

    rules = []

    try:
        # List objects in bucket
        paginator = s3_client.get_paginator("list_objects_v2")
        pages = paginator.paginate(Bucket=bucket_name, Prefix=prefix)

        for page in pages:
            for obj in page.get("Contents", []):
                key = obj["Key"]

                # Only process YAML files
                if not (key.endswith(".yml") or key.endswith(".yaml")):
                    continue

                # Skip README
                if "readme" in key.lower():
                    continue

                try:
                    # Download and parse rule
                    response = s3_client.get_object(Bucket=bucket_name, Key=key)
                    content = response["Body"].read().decode("utf-8")
                    rule_dict = yaml.safe_load(content)

                    if not rule_dict:
                        continue

                    # Verify it's an APM rule
                    logsource = rule_dict.get("logsource", {})
                    if logsource.get("product") != "apm":
                        continue

                    from ...shared.apm.apm_detector import APMRule
                    rule = APMRule.from_dict(rule_dict)
                    rules.append(rule)
                    detector.rules[rule.id] = rule

                except Exception as e:
                    logger.warning(f"Error loading rule from {key}: {e}")

    except Exception as e:
        logger.error(f"Error accessing S3 bucket {bucket_name}: {e}")

    return rules


def execute_athena_query(query: str) -> List[Dict[str, Any]]:
    """Execute a query against Athena.

    Args:
        query: SQL query string

    Returns:
        List of result rows as dictionaries
    """
    athena_client = boto3.client("athena")

    # Start query execution
    response = athena_client.start_query_execution(
        QueryString=query,
        QueryExecutionContext={
            "Database": ATHENA_DATABASE
        },
        WorkGroup=ATHENA_WORKGROUP,
        ResultConfiguration={
            "OutputLocation": ATHENA_OUTPUT_LOCATION
        }
    )

    execution_id = response["QueryExecutionId"]

    # Wait for query to complete
    import time
    max_attempts = 30
    attempt = 0

    while attempt < max_attempts:
        response = athena_client.get_query_execution(
            QueryExecutionId=execution_id
        )
        status = response["QueryExecution"]["Status"]["State"]

        if status == "SUCCEEDED":
            break
        elif status in ["FAILED", "CANCELLED"]:
            reason = response["QueryExecution"]["Status"].get("StateChangeReason", "Unknown")
            raise Exception(f"Query {status}: {reason}")

        time.sleep(1)
        attempt += 1

    if attempt >= max_attempts:
        raise Exception("Query timed out")

    # Get results
    results = []
    paginator = athena_client.get_paginator("get_query_results")
    pages = paginator.paginate(QueryExecutionId=execution_id)

    headers = None
    for page in pages:
        rows = page["ResultSet"]["Rows"]

        # First row is headers
        if headers is None:
            headers = [col.get("VarCharValue", "") for col in rows[0]["Data"]]
            rows = rows[1:]

        for row in rows:
            values = [col.get("VarCharValue") for col in row["Data"]]
            row_dict = dict(zip(headers, values))

            # Convert numeric strings to numbers
            for key, value in row_dict.items():
                if value and value.replace(".", "").replace("-", "").isdigit():
                    try:
                        row_dict[key] = float(value) if "." in value else int(value)
                    except ValueError:
                        pass

            results.append(row_dict)

    return results


def generate_apm_alert(result) -> Dict[str, Any]:
    """Generate an alert from APM detection result.

    Args:
        result: APMDetectionResult instance

    Returns:
        Alert dictionary
    """
    from ...shared.detection.alert_generator import Alert, AlertGenerator

    generator = AlertGenerator()

    # Build alert title
    if len(result.services_affected) == 1:
        title = f"[APM] {result.rule_name}: {result.services_affected[0]}"
    else:
        title = f"[APM] {result.rule_name}: {len(result.services_affected)} services affected"

    # Build description with metrics
    description_lines = [result.details.get("description", "")]

    if result.metrics:
        description_lines.append("\nAffected Services:")
        for service, metrics in result.metrics.items():
            metric_str = ", ".join(f"{k}: {v}" for k, v in metrics.items())
            description_lines.append(f"  - {service}: {metric_str}")

    if result.trace_ids:
        description_lines.append(f"\nSample Trace IDs: {', '.join(result.trace_ids[:3])}")

    description = "\n".join(description_lines)

    # Create alert
    alert = generator.generate_alert(
        rule_id=result.rule_id,
        rule_name=result.rule_name,
        severity=result.severity,
        title=title,
        description=description,
        results=[result.to_dict()],
        tags=["apm", "performance"],
    )

    # Add APM-specific metadata
    alert.metadata["services_affected"] = result.services_affected
    alert.metadata["apm_metrics"] = result.metrics
    alert.metadata["dashboard_link"] = result.dashboard_link
    alert.metadata["trace_ids"] = result.trace_ids

    return alert


def route_alert(alert) -> None:
    """Route alert to configured destinations.

    Args:
        alert: Alert instance
    """
    # Publish to SNS for downstream processing
    if ALERT_SNS_TOPIC:
        sns_client = boto3.client("sns")

        # Format for SNS
        message = {
            "default": json.dumps(alert.to_dict()),
            "slack": json.dumps(format_apm_alert_for_slack(alert)),
            "pagerduty": json.dumps(format_apm_alert_for_pagerduty(alert)),
        }

        sns_client.publish(
            TopicArn=ALERT_SNS_TOPIC,
            Message=json.dumps(message),
            MessageStructure="json",
            Subject=f"[APM Alert] {alert.title}",
            MessageAttributes={
                "severity": {
                    "DataType": "String",
                    "StringValue": alert.severity
                },
                "alert_type": {
                    "DataType": "String",
                    "StringValue": "apm"
                }
            }
        )

        logger.info(f"Alert published to SNS: {alert.id}")


def format_apm_alert_for_slack(alert) -> Dict[str, Any]:
    """Format APM alert for Slack.

    Args:
        alert: Alert instance

    Returns:
        Slack message payload
    """
    # Severity colors
    severity_colors = {
        "critical": "#ff0000",
        "high": "#ff6600",
        "medium": "#ffaa00",
        "low": "#ffdd00",
    }

    color = severity_colors.get(alert.severity, "#999999")

    # Build fields
    fields = [
        {
            "title": "Severity",
            "value": alert.severity.upper(),
            "short": True
        },
        {
            "title": "Services",
            "value": ", ".join(alert.metadata.get("services_affected", [])),
            "short": True
        },
    ]

    # Add metrics summary
    metrics = alert.metadata.get("apm_metrics", {})
    if metrics:
        # Get first service's metrics for summary
        first_service = list(metrics.keys())[0] if metrics else None
        if first_service:
            service_metrics = metrics[first_service]

            if "error_rate" in service_metrics:
                fields.append({
                    "title": "Error Rate",
                    "value": f"{service_metrics['error_rate']}%",
                    "short": True
                })

            if "p95_duration_ms" in service_metrics:
                fields.append({
                    "title": "P95 Latency",
                    "value": f"{service_metrics['p95_duration_ms']}ms",
                    "short": True
                })

    # Build actions
    actions = []
    if alert.metadata.get("dashboard_link"):
        actions.append({
            "type": "button",
            "text": "View in Dashboard",
            "url": alert.metadata["dashboard_link"]
        })

    trace_ids = alert.metadata.get("trace_ids", [])
    if trace_ids:
        actions.append({
            "type": "button",
            "text": "View Traces",
            "url": f"{DASHBOARD_BASE_URL}/apm?tab=traces&traceId={trace_ids[0]}"
        })

    attachment = {
        "color": color,
        "title": alert.title,
        "text": alert.description,
        "fields": fields,
        "footer": "Mantissa Log APM",
        "ts": int(alert.timestamp.timestamp())
    }

    if actions:
        attachment["actions"] = actions

    return {
        "attachments": [attachment]
    }


def format_apm_alert_for_pagerduty(alert) -> Dict[str, Any]:
    """Format APM alert for PagerDuty.

    Args:
        alert: Alert instance

    Returns:
        PagerDuty event payload
    """
    # Map severity to PagerDuty severity
    severity_map = {
        "critical": "critical",
        "high": "error",
        "medium": "warning",
        "low": "info",
    }

    # Build deduplication key
    services_key = "-".join(sorted(alert.metadata.get("services_affected", [])))
    hour = alert.timestamp.strftime("%Y%m%d%H")
    dedup_key = f"{alert.rule_id}:{services_key}:{hour}"

    return {
        "routing_key": "",  # To be filled by alert router
        "event_action": "trigger",
        "dedup_key": dedup_key,
        "payload": {
            "summary": alert.title,
            "severity": severity_map.get(alert.severity, "info"),
            "source": "mantissa-log-apm",
            "timestamp": alert.timestamp.isoformat(),
            "class": "apm",
            "component": alert.metadata.get("services_affected", ["unknown"])[0],
            "group": "apm-alerts",
            "custom_details": {
                "rule_id": alert.rule_id,
                "rule_name": alert.rule_name,
                "services_affected": alert.metadata.get("services_affected", []),
                "metrics": alert.metadata.get("apm_metrics", {}),
                "trace_ids": alert.metadata.get("trace_ids", []),
                "dashboard_link": alert.metadata.get("dashboard_link", ""),
            }
        },
        "links": [
            {
                "href": alert.metadata.get("dashboard_link", ""),
                "text": "View in APM Dashboard"
            }
        ] if alert.metadata.get("dashboard_link") else []
    }
