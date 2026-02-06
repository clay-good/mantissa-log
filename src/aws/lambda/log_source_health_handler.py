"""AWS Lambda handler for log source health monitoring.

Provides two handler functions triggered by separate EventBridge rules:

1. ``lambda_handler`` — runs on a 5-minute schedule to evaluate all
   configured log sources, detect latency / silence / volume anomalies,
   and route health alerts through the standard alert pipeline.

2. ``baseline_handler`` — runs on a daily schedule to compute hourly
   volume baselines from the data lake for z-score anomaly detection.

EventBridge Rules (Terraform):
```hcl
resource "aws_cloudwatch_event_rule" "log_source_health_check" {
  name                = "mantissa-log-source-health-check"
  description         = "Trigger log source health checks every 5 minutes"
  schedule_expression = "rate(5 minutes)"
}

resource "aws_cloudwatch_event_target" "log_source_health_check" {
  rule = aws_cloudwatch_event_rule.log_source_health_check.name
  arn  = aws_lambda_function.log_source_health.arn
}

resource "aws_cloudwatch_event_rule" "log_source_health_baseline" {
  name                = "mantissa-log-source-health-baseline"
  description         = "Compute log source volume baselines daily"
  schedule_expression = "rate(1 day)"
}

resource "aws_cloudwatch_event_target" "log_source_health_baseline" {
  rule = aws_cloudwatch_event_rule.log_source_health_baseline.name
  arn  = aws_lambda_function.log_source_health.arn
  input = jsonencode({ "action": "compute_baselines" })
}
```

Environment Variables:
    LOG_SOURCE_HEALTH_TABLE: DynamoDB table for health state (default: mantissa-log-source-health)
    ATHENA_DATABASE: Athena database name (default: mantissa_logs)
    ATHENA_OUTPUT_LOCATION: S3 location for Athena query results
    AWS_REGION: AWS region (default: us-east-1)
    TENANT_ID: Tenant identifier (default: default)
    HEALTH_CONFIG_S3_BUCKET: Optional S3 bucket containing custom health configs
    HEALTH_CONFIG_S3_KEY: S3 key for health config JSON (default: config/health_configs.json)
    SECRETS_PREFIX: Prefix for Secrets Manager entries (default: mantissa-log)
    DEFAULT_DESTINATIONS: Comma-separated default alert destinations (default: slack)
    SEVERITY_ROUTING: JSON severity-to-destinations mapping
"""

import json
import logging
import os
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

logger = logging.getLogger()
logger.setLevel(logging.INFO)


def lambda_handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """Lambda handler for scheduled log source health checks.

    Triggered by EventBridge on a 5-minute schedule. Evaluates the health
    of all configured log sources, generates alerts for status transitions
    and anomalies, and routes them through the alert pipeline.

    Can also dispatch to ``baseline_handler`` when the event contains
    ``{"action": "compute_baselines"}``.

    Args:
        event: Lambda event (from EventBridge or manual invocation).
        context: Lambda context.

    Returns:
        Response with health check summary.
    """
    # Route to baseline handler if requested
    if event.get("action") == "compute_baselines":
        return baseline_handler(event, context)

    start_time = time.time()
    logger.info("Log source health check started: %s", json.dumps(event))

    config = _get_config()

    try:
        # Initialize components
        health_state_store, query_executor, config_map = _initialize_components(config)

        from shared.health import HealthCheckEngine, HealthAlertGenerator

        engine = HealthCheckEngine(
            health_state_store=health_state_store,
            config_map=config_map,
            query_executor=query_executor,
        )

        # Initialize alert generator with optional router
        try:
            alert_router = _build_alert_router(config)
        except Exception as e:
            logger.warning("Could not initialize alert router: %s", e)
            alert_router = None

        alert_gen = HealthAlertGenerator(
            health_state_store=health_state_store,
            config_map=config_map,
            alert_router=alert_router,
            default_destinations=_get_default_destinations(),
        )

        tenant_id = config["tenant_id"]
        now = datetime.now(timezone.utc)

        # Run health checks for all enabled sources
        logger.info("Evaluating health of all enabled log sources for tenant '%s'", tenant_id)
        results = engine.check_all_sources(tenant_id, now=now)
        logger.info("Health check complete: %d source(s) evaluated", len(results))

        # Process results: generate and route alerts
        alerts_generated = 0
        alerts_suppressed = 0
        alerts_routed = 0
        source_statuses: Dict[str, str] = {}

        for result in results:
            source_statuses[result.source_type] = result.new_status.value

            # Log every result for operational visibility
            logger.info(
                "Health check [%s]: %s -> %s (failures=%d, alert=%s) — %s",
                result.source_type,
                result.old_status.value,
                result.new_status.value,
                result.consecutive_failures,
                result.should_alert,
                result.detail_message,
            )

            # Generate alert if warranted
            try:
                outcome = alert_gen.generate_health_alert(result, now=now)

                if outcome.suppressed:
                    alerts_suppressed += 1
                else:
                    alerts_generated += 1
                    if outcome.routing_result and outcome.routing_result.success:
                        alerts_routed += 1
                        logger.info(
                            "Alert routed for %s: %s -> %s",
                            result.source_type,
                            ", ".join(outcome.routing_result.destinations_succeeded),
                            outcome.alert.title if outcome.alert else "N/A",
                        )
                    elif outcome.routing_result and not outcome.routing_result.success:
                        logger.warning(
                            "Alert routing failed for %s: %s",
                            result.source_type,
                            outcome.routing_result.destinations_failed,
                        )

                # Generate gap reports if gaps were detected
                if result.gap_windows:
                    gap_outcome = alert_gen.generate_gap_report(
                        source_type=result.source_type,
                        tenant_id=tenant_id,
                        gaps=result.gap_windows,
                        event_count_before=result.event_count_previous,
                        event_count_after=result.event_count_current,
                        now=now,
                    )
                    if not gap_outcome.suppressed:
                        alerts_generated += 1
                        logger.info(
                            "Gap report generated for %s: %d gap(s)",
                            result.source_type,
                            len(result.gap_windows),
                        )

            except Exception as e:
                logger.error(
                    "Error generating alert for %s: %s",
                    result.source_type,
                    e,
                )

        duration_ms = int((time.time() - start_time) * 1000)

        # Count statuses for summary
        status_counts: Dict[str, int] = {}
        for status in source_statuses.values():
            status_counts[status] = status_counts.get(status, 0) + 1

        logger.info(
            "Health check summary: %d sources, %d alerts generated, "
            "%d suppressed, %d routed, %dms",
            len(results),
            alerts_generated,
            alerts_suppressed,
            alerts_routed,
            duration_ms,
        )

        return _build_response(200, {
            "timestamp": now.isoformat(),
            "tenant_id": tenant_id,
            "sources_checked": len(results),
            "alerts_generated": alerts_generated,
            "alerts_suppressed": alerts_suppressed,
            "alerts_routed": alerts_routed,
            "status_counts": status_counts,
            "source_statuses": source_statuses,
            "duration_ms": duration_ms,
        })

    except Exception as e:
        logger.error("Fatal error in log source health check: %s", e)
        import traceback
        traceback.print_exc()

        return _build_response(500, {
            "error": str(e),
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "duration_ms": int((time.time() - start_time) * 1000),
        })


def baseline_handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """Lambda handler for daily log source volume baseline computation.

    Triggered by EventBridge on a daily schedule. Computes hourly event
    volume baselines for all enabled sources using historical data from
    the data lake. These baselines are used by the health check engine
    for z-score volume anomaly detection.

    Args:
        event: Lambda event (from EventBridge).
        context: Lambda context.

    Returns:
        Response with baseline computation summary.
    """
    start_time = time.time()
    logger.info("Log source baseline computation started: %s", json.dumps(event))

    config = _get_config()

    try:
        health_state_store, query_executor, config_map = _initialize_components(config)

        from shared.health import HealthCheckEngine

        engine = HealthCheckEngine(
            health_state_store=health_state_store,
            config_map=config_map,
            query_executor=query_executor,
        )

        tenant_id = config["tenant_id"]
        now = datetime.now(timezone.utc)

        logger.info("Computing baselines for tenant '%s'", tenant_id)
        baselines = engine.compute_baselines(tenant_id, now=now)

        # Log each computed baseline for audit purposes
        for source_type, (mean, stddev) in baselines.items():
            logger.info(
                "Baseline computed [%s]: mean=%.1f stddev=%.1f events/hour",
                source_type,
                mean,
                stddev,
            )

        duration_ms = int((time.time() - start_time) * 1000)

        logger.info(
            "Baseline computation complete: %d baselines computed, %dms",
            len(baselines),
            duration_ms,
        )

        return _build_response(200, {
            "timestamp": now.isoformat(),
            "tenant_id": tenant_id,
            "baselines_computed": len(baselines),
            "baselines": {
                src: {"mean": round(m, 1), "stddev": round(s, 1)}
                for src, (m, s) in baselines.items()
            },
            "duration_ms": duration_ms,
        })

    except Exception as e:
        logger.error("Fatal error in baseline computation: %s", e)
        import traceback
        traceback.print_exc()

        return _build_response(500, {
            "error": str(e),
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "duration_ms": int((time.time() - start_time) * 1000),
        })


# ------------------------------------------------------------------
# Configuration
# ------------------------------------------------------------------


def _get_config() -> Dict[str, str]:
    """Load configuration from environment variables."""
    return {
        "log_source_health_table": os.environ.get(
            "LOG_SOURCE_HEALTH_TABLE", "mantissa-log-source-health"
        ),
        "athena_database": os.environ.get("ATHENA_DATABASE", "mantissa_logs"),
        "athena_output_location": os.environ.get("ATHENA_OUTPUT_LOCATION"),
        "aws_region": os.environ.get("AWS_REGION", "us-east-1"),
        "tenant_id": os.environ.get("TENANT_ID", "default"),
        "health_config_s3_bucket": os.environ.get("HEALTH_CONFIG_S3_BUCKET"),
        "health_config_s3_key": os.environ.get(
            "HEALTH_CONFIG_S3_KEY", "config/health_configs.json"
        ),
        "secrets_prefix": os.environ.get("SECRETS_PREFIX", "mantissa-log"),
    }


def _initialize_components(config: Dict[str, str]):
    """Initialize health check components.

    Args:
        config: Configuration dictionary from _get_config().

    Returns:
        Tuple of (DynamoDBHealthStateStore, AthenaQueryExecutor, config_map).
    """
    from shared.health import DynamoDBHealthStateStore
    from shared.detection import AthenaQueryExecutor

    # Initialize health state store
    health_state_store = DynamoDBHealthStateStore(
        table_name=config["log_source_health_table"],
        region=config["aws_region"],
    )

    # Initialize Athena query executor
    query_executor = AthenaQueryExecutor(
        database=config["athena_database"],
        output_location=config["athena_output_location"],
        region=config["aws_region"],
    )

    # Load custom health configs if S3 bucket is configured
    config_map = _load_health_configs(config)

    return health_state_store, query_executor, config_map


def _load_health_configs(config: Dict[str, str]) -> Dict:
    """Load custom health configs from S3 or use defaults.

    If HEALTH_CONFIG_S3_BUCKET is set, reads a JSON file from S3 containing
    per-source health config overrides. Otherwise, returns an empty dict
    to use the built-in DEFAULT_HEALTH_CONFIGS.

    Expected S3 JSON format:
    ```json
    {
        "okta": {
            "source_type": "okta",
            "expected_max_latency_seconds": 600,
            "silence_threshold_seconds": 7200,
            "alert_destinations": ["pagerduty", "slack"]
        },
        ...
    }
    ```

    Args:
        config: Configuration dictionary.

    Returns:
        Dict of source_type -> LogSourceHealthConfig, or empty dict.
    """
    s3_bucket = config.get("health_config_s3_bucket")
    if not s3_bucket:
        logger.info("No HEALTH_CONFIG_S3_BUCKET set, using default health configs")
        return {}

    s3_key = config["health_config_s3_key"]

    try:
        import boto3

        s3_client = boto3.client("s3", region_name=config["aws_region"])
        response = s3_client.get_object(Bucket=s3_bucket, Key=s3_key)
        body = response["Body"].read().decode("utf-8")
        raw_configs = json.loads(body)

        from shared.health import LogSourceHealthConfig

        config_map = {}
        for source_type, cfg_dict in raw_configs.items():
            cfg_dict["source_type"] = source_type
            config_map[source_type] = LogSourceHealthConfig.from_dict(cfg_dict)

        logger.info(
            "Loaded %d custom health configs from s3://%s/%s",
            len(config_map),
            s3_bucket,
            s3_key,
        )
        return config_map

    except Exception as e:
        logger.warning(
            "Failed to load health configs from S3 (using defaults): %s", e
        )
        return {}


# ------------------------------------------------------------------
# Alert routing setup
# ------------------------------------------------------------------


def _build_alert_router(config: Dict[str, str]):
    """Build an AlertRouter with handlers loaded from Secrets Manager.

    Follows the same pattern as alert_router_handler.py for loading
    handler configurations from Secrets Manager.

    Args:
        config: Configuration dictionary.

    Returns:
        AlertRouter instance, or None if no handlers could be loaded.
    """
    import boto3
    from botocore.exceptions import ClientError

    from shared.alerting import AlertRouter, RouterConfig
    from shared.alerting.handlers import (
        SlackHandler,
        PagerDutyHandler,
        EmailHandler,
        WebhookHandler,
    )

    secrets_prefix = config["secrets_prefix"]
    region = config["aws_region"]
    handlers = {}

    secrets_client = boto3.client("secretsmanager", region_name=region)

    # Load Slack handler
    try:
        secret = secrets_client.get_secret_value(
            SecretId=f"{secrets_prefix}/slack"
        )
        slack_config = json.loads(secret["SecretString"])
        handlers["slack"] = SlackHandler(
            webhook_url=slack_config["webhook_url"],
            channel=slack_config.get("channel"),
            username=slack_config.get("username", "Mantissa Log"),
        )
        logger.info("Loaded Slack handler")
    except ClientError as e:
        if e.response["Error"]["Code"] != "ResourceNotFoundException":
            logger.error("Error loading Slack config: %s", e)

    # Load PagerDuty handler
    try:
        secret = secrets_client.get_secret_value(
            SecretId=f"{secrets_prefix}/pagerduty"
        )
        pd_config = json.loads(secret["SecretString"])
        handlers["pagerduty"] = PagerDutyHandler(
            routing_key=pd_config["routing_key"],
        )
        logger.info("Loaded PagerDuty handler")
    except ClientError as e:
        if e.response["Error"]["Code"] != "ResourceNotFoundException":
            logger.error("Error loading PagerDuty config: %s", e)

    # Load Email handler
    try:
        secret = secrets_client.get_secret_value(
            SecretId=f"{secrets_prefix}/email"
        )
        email_config = json.loads(secret["SecretString"])
        handlers["email"] = EmailHandler(
            recipients=email_config["recipients"],
            smtp_host=email_config.get("smtp_host"),
            smtp_port=email_config.get("smtp_port"),
            smtp_username=email_config.get("smtp_username"),
            smtp_password=email_config.get("smtp_password"),
            smtp_use_tls=email_config.get("smtp_use_tls", True),
            from_address=email_config.get("from_address", "mantissa-log@example.com"),
            use_ses=email_config.get("use_ses", False),
            ses_region=email_config.get("ses_region", region),
        )
        logger.info("Loaded Email handler")
    except ClientError as e:
        if e.response["Error"]["Code"] != "ResourceNotFoundException":
            logger.error("Error loading Email config: %s", e)

    # Load Webhook handler
    try:
        secret = secrets_client.get_secret_value(
            SecretId=f"{secrets_prefix}/webhook"
        )
        webhook_config = json.loads(secret["SecretString"])
        handlers["webhook"] = WebhookHandler(
            webhook_url=webhook_config["webhook_url"],
            headers=webhook_config.get("headers"),
            method=webhook_config.get("method", "POST"),
        )
        logger.info("Loaded Webhook handler")
    except ClientError as e:
        if e.response["Error"]["Code"] != "ResourceNotFoundException":
            logger.error("Error loading Webhook config: %s", e)

    if not handlers:
        logger.warning("No alert handlers configured — alerts will be generated but not routed")
        return None

    router_config = RouterConfig(
        default_destinations=_get_default_destinations(),
        severity_routing=_get_severity_routing(),
        enrichment_enabled=False,
        max_concurrent_sends=5,
    )

    return AlertRouter(
        handlers=handlers,
        config=router_config,
    )


def _get_default_destinations() -> List[str]:
    """Get default alert destinations from environment."""
    default_str = os.environ.get("DEFAULT_DESTINATIONS", "slack")
    return [d.strip() for d in default_str.split(",") if d.strip()]


def _get_severity_routing() -> Dict[str, List[str]]:
    """Get severity-based routing configuration from environment."""
    routing = {
        "critical": ["slack", "pagerduty", "email"],
        "high": ["slack", "email"],
        "medium": ["slack"],
        "low": ["slack"],
        "info": ["slack"],
    }

    severity_routing_str = os.environ.get("SEVERITY_ROUTING")
    if severity_routing_str:
        try:
            routing = json.loads(severity_routing_str)
        except json.JSONDecodeError as e:
            logger.error("Error parsing SEVERITY_ROUTING: %s", e)

    return routing


# ------------------------------------------------------------------
# Utilities
# ------------------------------------------------------------------


def _build_response(status_code: int, body: Dict[str, Any]) -> Dict[str, Any]:
    """Build Lambda response."""
    return {
        "statusCode": status_code,
        "body": json.dumps(body),
    }
