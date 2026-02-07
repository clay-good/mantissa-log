"""GCP Cloud Function handler for log source health monitoring.

Provides two entry points triggered by Cloud Scheduler via Pub/Sub:

1. ``health_check_scheduled`` — runs on a 5-minute schedule to evaluate all
   configured log sources, detect latency / silence / volume anomalies,
   and route health alerts through the standard alert pipeline.

2. ``baseline_scheduled`` — runs on a daily schedule to compute hourly
   volume baselines from BigQuery for z-score anomaly detection.

Cloud Scheduler + Pub/Sub Configuration (Terraform):
```hcl
resource "google_pubsub_topic" "log_source_health_trigger" {
  name = "mantissa-log-source-health-trigger"
}

resource "google_cloud_scheduler_job" "log_source_health_check" {
  name        = "mantissa-log-source-health-check"
  description = "Trigger log source health checks every 5 minutes"
  schedule    = "*/5 * * * *"
  time_zone   = "UTC"

  pubsub_target {
    topic_name = google_pubsub_topic.log_source_health_trigger.id
    data       = base64encode(jsonencode({ "action": "health_check" }))
  }
}

resource "google_pubsub_topic" "log_source_health_baseline_trigger" {
  name = "mantissa-log-source-health-baseline-trigger"
}

resource "google_cloud_scheduler_job" "log_source_health_baseline" {
  name        = "mantissa-log-source-health-baseline"
  description = "Compute log source volume baselines daily"
  schedule    = "0 3 * * *"
  time_zone   = "UTC"

  pubsub_target {
    topic_name = google_pubsub_topic.log_source_health_baseline_trigger.id
    data       = base64encode(jsonencode({ "action": "compute_baselines" }))
  }
}

resource "google_cloudfunctions2_function" "log_source_health" {
  name        = "mantissa-log-source-health"
  location    = var.region

  build_config {
    runtime     = "python311"
    entry_point = "health_check_scheduled"
    source {
      storage_source {
        bucket = google_storage_bucket.functions.name
        object = google_storage_bucket_object.log_source_health.name
      }
    }
  }

  event_trigger {
    trigger_region = var.region
    event_type     = "google.cloud.pubsub.topic.v1.messagePublished"
    pubsub_topic   = google_pubsub_topic.log_source_health_trigger.id
  }
}

resource "google_cloudfunctions2_function" "log_source_health_baseline" {
  name        = "mantissa-log-source-health-baseline"
  location    = var.region

  build_config {
    runtime     = "python311"
    entry_point = "baseline_scheduled"
    source {
      storage_source {
        bucket = google_storage_bucket.functions.name
        object = google_storage_bucket_object.log_source_health.name
      }
    }
  }

  event_trigger {
    trigger_region = var.region
    event_type     = "google.cloud.pubsub.topic.v1.messagePublished"
    pubsub_topic   = google_pubsub_topic.log_source_health_baseline_trigger.id
  }
}
```

Environment Variables:
    GCP_PROJECT_ID: GCP project identifier
    BIGQUERY_DATASET: BigQuery dataset name (default: mantissa_logs)
    HEALTH_STATE_COLLECTION: Firestore collection for health state (default: log_source_health)
    TENANT_ID: Tenant identifier (default: default)
    HEALTH_CONFIG_GCS_BUCKET: Optional GCS bucket containing custom health configs
    HEALTH_CONFIG_GCS_PATH: GCS object path for health config JSON (default: config/health_configs.json)
    DEFAULT_DESTINATIONS: Comma-separated default alert destinations (default: slack)
    SEVERITY_ROUTING: JSON severity-to-destinations mapping
"""

import base64
import json
import logging
import os
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

import functions_framework

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)


# ------------------------------------------------------------------
# BigQuery adapter
# ------------------------------------------------------------------


@dataclass
class _QueryResult:
    """Lightweight query result compatible with HealthCheckEngine expectations.

    The engine accesses ``qr.data`` — a list of row dicts.
    """

    data: List[Dict[str, Any]] = field(default_factory=list)
    row_count: int = 0


class BigQueryQueryExecutor:
    """Query executor adapter wrapping ``BigQueryExecutor`` for health checks.

    Provides the ``execute_query(sql, timeout_seconds=...)`` interface that
    ``HealthCheckEngine`` expects, returning a ``_QueryResult`` with ``.data``.
    """

    def __init__(self, project_id: str, dataset_id: str):
        from src.gcp.bigquery.executor import BigQueryExecutor

        self.executor = BigQueryExecutor(
            project_id=project_id, dataset_id=dataset_id
        )

    def execute_query(
        self, query: str, timeout_seconds: int = 120
    ) -> _QueryResult:
        """Execute a BigQuery SQL query.

        Args:
            query: Standard SQL query string.
            timeout_seconds: Query timeout (used for logging, BigQuery
                manages its own timeouts).

        Returns:
            ``_QueryResult`` with ``.data`` containing row dicts.
        """
        raw = self.executor.execute_query(query, use_cache=True)
        rows = raw.get("results", [])
        return _QueryResult(data=rows, row_count=len(rows))


# ------------------------------------------------------------------
# Configuration
# ------------------------------------------------------------------


def _get_config() -> Dict[str, Any]:
    """Load configuration from environment variables."""
    return {
        "project_id": os.environ.get("GCP_PROJECT_ID"),
        "bigquery_dataset": os.environ.get("BIGQUERY_DATASET", "mantissa_logs"),
        "health_state_collection": os.environ.get(
            "HEALTH_STATE_COLLECTION", "log_source_health"
        ),
        "tenant_id": os.environ.get("TENANT_ID", "default"),
        "health_config_gcs_bucket": os.environ.get("HEALTH_CONFIG_GCS_BUCKET"),
        "health_config_gcs_path": os.environ.get(
            "HEALTH_CONFIG_GCS_PATH", "config/health_configs.json"
        ),
    }


def _initialize_components(config: Dict[str, Any]):
    """Initialize health check components.

    Args:
        config: Configuration dictionary from ``_get_config()``.

    Returns:
        Tuple of (FirestoreHealthStateStore, BigQueryQueryExecutor, config_map).
    """
    from src.shared.health import FirestoreHealthStateStore

    health_state_store = FirestoreHealthStateStore(
        collection_name=config["health_state_collection"],
        project_id=config["project_id"],
    )

    query_executor = BigQueryQueryExecutor(
        project_id=config["project_id"],
        dataset_id=config["bigquery_dataset"],
    )

    config_map = _load_health_configs(config)

    return health_state_store, query_executor, config_map


def _load_health_configs(config: Dict[str, Any]) -> Dict:
    """Load custom health configs from GCS or use defaults.

    If ``HEALTH_CONFIG_GCS_BUCKET`` is set, reads a JSON file from GCS
    containing per-source health config overrides.  Otherwise returns an
    empty dict so the built-in ``DEFAULT_HEALTH_CONFIGS`` are used.

    Expected GCS JSON format::

        {
            "okta": {
                "source_type": "okta",
                "expected_max_latency_seconds": 600,
                "alert_destinations": ["pagerduty", "slack"]
            }
        }

    Args:
        config: Configuration dictionary.

    Returns:
        Dict of source_type -> LogSourceHealthConfig, or empty dict.
    """
    gcs_bucket = config.get("health_config_gcs_bucket")
    if not gcs_bucket:
        logger.info("No HEALTH_CONFIG_GCS_BUCKET set, using default health configs")
        return {}

    gcs_path = config["health_config_gcs_path"]

    try:
        from google.cloud import storage

        storage_client = storage.Client(project=config["project_id"])
        bucket = storage_client.bucket(gcs_bucket)
        blob = bucket.blob(gcs_path)
        raw_json = blob.download_as_text()
        raw_configs = json.loads(raw_json)

        from src.shared.health import LogSourceHealthConfig

        config_map = {}
        for source_type, cfg_dict in raw_configs.items():
            cfg_dict["source_type"] = source_type
            config_map[source_type] = LogSourceHealthConfig.from_dict(cfg_dict)

        logger.info(
            "Loaded %d custom health configs from gs://%s/%s",
            len(config_map),
            gcs_bucket,
            gcs_path,
        )
        return config_map

    except Exception as e:
        logger.warning(
            "Failed to load health configs from GCS (using defaults): %s", e
        )
        return {}


# ------------------------------------------------------------------
# Alert routing setup
# ------------------------------------------------------------------


def _build_alert_router(config: Dict[str, Any]):
    """Build an AlertRouter with handler credentials from Secret Manager.

    Follows the same pattern as the GCP alert_router Cloud Function.

    Args:
        config: Configuration dictionary.

    Returns:
        AlertRouter instance, or None if no handlers could be loaded.
    """
    from google.cloud import secretmanager

    from src.shared.alerting import AlertRouter, RouterConfig
    from src.shared.alerting.handlers import (
        SlackHandler,
        PagerDutyHandler,
        EmailHandler,
        WebhookHandler,
    )

    project_id = config["project_id"]
    handlers: Dict[str, Any] = {}

    sm_client = secretmanager.SecretManagerServiceClient()

    def _get_secret(secret_name: str) -> Optional[str]:
        """Retrieve a secret value, returning None if not found."""
        try:
            name = f"projects/{project_id}/secrets/{secret_name}/versions/latest"
            response = sm_client.access_secret_version(request={"name": name})
            return response.payload.data.decode("UTF-8")
        except Exception:
            return None

    # Load Slack handler
    slack_json = _get_secret("mantissa-slack")
    if slack_json:
        try:
            slack_config = json.loads(slack_json)
            handlers["slack"] = SlackHandler(
                webhook_url=slack_config["webhook_url"],
                channel=slack_config.get("channel"),
                username=slack_config.get("username", "Mantissa Log"),
            )
            logger.info("Loaded Slack handler")
        except Exception as e:
            logger.error("Error parsing Slack config: %s", e)

    # Load PagerDuty handler
    pd_json = _get_secret("mantissa-pagerduty")
    if pd_json:
        try:
            pd_config = json.loads(pd_json)
            handlers["pagerduty"] = PagerDutyHandler(
                routing_key=pd_config["routing_key"],
            )
            logger.info("Loaded PagerDuty handler")
        except Exception as e:
            logger.error("Error parsing PagerDuty config: %s", e)

    # Load Email handler
    email_json = _get_secret("mantissa-email")
    if email_json:
        try:
            email_config = json.loads(email_json)
            handlers["email"] = EmailHandler(
                recipients=email_config["recipients"],
                smtp_host=email_config.get("smtp_host"),
                smtp_port=email_config.get("smtp_port"),
                smtp_username=email_config.get("smtp_username"),
                smtp_password=email_config.get("smtp_password"),
                smtp_use_tls=email_config.get("smtp_use_tls", True),
                from_address=email_config.get(
                    "from_address", "mantissa-log@example.com"
                ),
            )
            logger.info("Loaded Email handler")
        except Exception as e:
            logger.error("Error parsing Email config: %s", e)

    # Load Webhook handler
    webhook_json = _get_secret("mantissa-webhook")
    if webhook_json:
        try:
            webhook_config = json.loads(webhook_json)
            handlers["webhook"] = WebhookHandler(
                webhook_url=webhook_config["webhook_url"],
                headers=webhook_config.get("headers"),
                method=webhook_config.get("method", "POST"),
            )
            logger.info("Loaded Webhook handler")
        except Exception as e:
            logger.error("Error parsing Webhook config: %s", e)

    if not handlers:
        logger.warning(
            "No alert handlers configured — alerts will be generated but not routed"
        )
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
# Scheduled health check handler
# ------------------------------------------------------------------


@functions_framework.cloud_event
def health_check_scheduled(cloud_event):
    """Cloud Scheduler trigger for log source health checks.

    Evaluates the health of all configured log sources, generates alerts
    for status transitions and anomalies, and routes them through the
    alert pipeline.
    """
    start_time = time.time()
    logger.info("Log source health check triggered")

    config = _get_config()

    try:
        health_state_store, query_executor, config_map = _initialize_components(
            config
        )

        from src.shared.health import HealthCheckEngine, HealthAlertGenerator

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

        # Run health checks
        logger.info(
            "Evaluating health of all enabled log sources for tenant '%s'",
            tenant_id,
        )
        results = engine.check_all_sources(tenant_id, now=now)
        logger.info("Health check complete: %d source(s) evaluated", len(results))

        # Process results
        alerts_generated = 0
        alerts_suppressed = 0
        alerts_routed = 0

        for result in results:
            logger.info(
                "Health check [%s]: %s -> %s (failures=%d, alert=%s) — %s",
                result.source_type,
                result.old_status.value,
                result.new_status.value,
                result.consecutive_failures,
                result.should_alert,
                result.detail_message,
            )

            try:
                outcome = alert_gen.generate_health_alert(result, now=now)

                if outcome.suppressed:
                    alerts_suppressed += 1
                else:
                    alerts_generated += 1
                    if outcome.routing_result and outcome.routing_result.success:
                        alerts_routed += 1

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

            except Exception as e:
                logger.error(
                    "Error generating alert for %s: %s", result.source_type, e
                )

        duration_ms = int((time.time() - start_time) * 1000)

        logger.info(
            "Health check summary: %d sources, %d alerts generated, "
            "%d suppressed, %d routed, %dms",
            len(results),
            alerts_generated,
            alerts_suppressed,
            alerts_routed,
            duration_ms,
        )

    except Exception as e:
        logger.error("Fatal error in log source health check: %s", e)
        import traceback

        traceback.print_exc()
        raise


# ------------------------------------------------------------------
# Scheduled baseline handler
# ------------------------------------------------------------------


@functions_framework.cloud_event
def baseline_scheduled(cloud_event):
    """Cloud Scheduler trigger for daily volume baseline computation.

    Computes hourly event volume baselines for all enabled sources using
    historical data from BigQuery.  These baselines are used by the
    health check engine for z-score volume anomaly detection.
    """
    start_time = time.time()
    logger.info("Log source baseline computation triggered")

    config = _get_config()

    try:
        health_state_store, query_executor, config_map = _initialize_components(
            config
        )

        from src.shared.health import HealthCheckEngine

        engine = HealthCheckEngine(
            health_state_store=health_state_store,
            config_map=config_map,
            query_executor=query_executor,
        )

        tenant_id = config["tenant_id"]
        now = datetime.now(timezone.utc)

        logger.info("Computing baselines for tenant '%s'", tenant_id)
        baselines = engine.compute_baselines(tenant_id, now=now)

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

    except Exception as e:
        logger.error("Fatal error in baseline computation: %s", e)
        import traceback

        traceback.print_exc()
        raise
