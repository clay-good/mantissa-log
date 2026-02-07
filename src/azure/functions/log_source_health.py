"""Azure Function handler for log source health monitoring.

Provides two entry points:

1. ``timer_trigger`` — runs on a 5-minute Timer trigger schedule to evaluate
   all configured log sources, detect latency / silence / volume anomalies,
   and route health alerts through the standard alert pipeline.

2. ``baseline_timer_trigger`` — runs on a daily Timer trigger schedule to
   compute hourly volume baselines from Synapse Analytics for z-score
   anomaly detection.

An HTTP endpoint (``main``) is also provided for on-demand health checks.

Azure Configuration (function.json for health check timer):
```json
{
  "bindings": [
    {
      "name": "timer",
      "type": "timerTrigger",
      "direction": "in",
      "schedule": "0 */5 * * * *"
    }
  ]
}
```

Azure Configuration (function.json for baseline timer):
```json
{
  "bindings": [
    {
      "name": "timer",
      "type": "timerTrigger",
      "direction": "in",
      "schedule": "0 0 3 * * *"
    }
  ]
}
```

Terraform:
```hcl
resource "azurerm_linux_function_app" "mantissa" {
  # ... existing function app ...
}

resource "azurerm_function_app_function" "log_source_health_check" {
  name            = "log-source-health-check"
  function_app_id = azurerm_linux_function_app.mantissa.id
  language        = "Python"

  config_json = jsonencode({
    bindings = [
      {
        name      = "timer"
        type      = "timerTrigger"
        direction = "in"
        schedule  = "0 */5 * * * *"
      }
    ]
  })
}

resource "azurerm_function_app_function" "log_source_health_baseline" {
  name            = "log-source-health-baseline"
  function_app_id = azurerm_linux_function_app.mantissa.id
  language        = "Python"

  config_json = jsonencode({
    bindings = [
      {
        name      = "timer"
        type      = "timerTrigger"
        direction = "in"
        schedule  = "0 0 3 * * *"
      }
    ]
  })
}
```

Environment Variables:
    COSMOS_ENDPOINT: Azure Cosmos DB endpoint URL
    COSMOS_KEY: Cosmos DB primary key
    COSMOS_DATABASE: Cosmos DB database name (default: mantissa)
    COSMOS_HEALTH_CONTAINER: Cosmos DB container for health state (default: log_source_health)
    SYNAPSE_WORKSPACE_NAME: Azure Synapse workspace name
    SYNAPSE_DATABASE: Synapse database name (default: mantissa_logs)
    TENANT_ID: Tenant identifier (default: default)
    HEALTH_CONFIG_BLOB_CONTAINER: Optional Azure Blob container for custom health configs
    HEALTH_CONFIG_BLOB_PATH: Blob path for health config JSON (default: config/health_configs.json)
    STORAGE_CONNECTION_STRING: Azure Storage connection string (for config blob)
    KEY_VAULT_URL: Azure Key Vault URL for loading alert handler credentials
    DEFAULT_DESTINATIONS: Comma-separated default alert destinations (default: slack)
    SEVERITY_ROUTING: JSON severity-to-destinations mapping
"""

import azure.functions as func
import json
import logging
import os
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)


# ------------------------------------------------------------------
# Synapse adapter
# ------------------------------------------------------------------


@dataclass
class _QueryResult:
    """Lightweight query result compatible with HealthCheckEngine expectations.

    The engine accesses ``qr.data`` — a list of row dicts.
    """

    data: List[Dict[str, Any]] = field(default_factory=list)
    row_count: int = 0


class SynapseQueryExecutor:
    """Query executor adapter wrapping ``SynapseExecutor`` for health checks.

    Provides the ``execute_query(sql, timeout_seconds=...)`` interface that
    ``HealthCheckEngine`` expects, returning a ``_QueryResult`` with ``.data``.
    """

    def __init__(
        self,
        workspace_name: str,
        database_name: str,
        use_serverless: bool = True,
    ):
        from src.azure.synapse.executor import SynapseExecutor

        self.executor = SynapseExecutor(
            workspace_name=workspace_name,
            database_name=database_name,
            use_serverless=use_serverless,
        )

    def execute_query(
        self, query: str, timeout_seconds: int = 120
    ) -> _QueryResult:
        """Execute a Synapse SQL query.

        Args:
            query: T-SQL query string.
            timeout_seconds: Query timeout (used for logging, Synapse
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
        "cosmos_endpoint": os.environ.get("COSMOS_ENDPOINT"),
        "cosmos_key": os.environ.get("COSMOS_KEY"),
        "cosmos_database": os.environ.get("COSMOS_DATABASE", "mantissa"),
        "cosmos_health_container": os.environ.get(
            "COSMOS_HEALTH_CONTAINER", "log_source_health"
        ),
        "synapse_workspace": os.environ.get("SYNAPSE_WORKSPACE_NAME"),
        "synapse_database": os.environ.get("SYNAPSE_DATABASE", "mantissa_logs"),
        "tenant_id": os.environ.get("TENANT_ID", "default"),
        "health_config_blob_container": os.environ.get("HEALTH_CONFIG_BLOB_CONTAINER"),
        "health_config_blob_path": os.environ.get(
            "HEALTH_CONFIG_BLOB_PATH", "config/health_configs.json"
        ),
        "storage_connection_string": os.environ.get("STORAGE_CONNECTION_STRING"),
        "key_vault_url": os.environ.get("KEY_VAULT_URL"),
    }


def _initialize_components(config: Dict[str, Any]):
    """Initialize health check components.

    Args:
        config: Configuration dictionary from ``_get_config()``.

    Returns:
        Tuple of (CosmosHealthStateStore, SynapseQueryExecutor, config_map).
    """
    from src.shared.health import CosmosHealthStateStore

    health_state_store = CosmosHealthStateStore(
        endpoint=config["cosmos_endpoint"],
        key=config["cosmos_key"],
        database_name=config["cosmos_database"],
        container_name=config["cosmos_health_container"],
    )

    query_executor = SynapseQueryExecutor(
        workspace_name=config["synapse_workspace"],
        database_name=config["synapse_database"],
    )

    config_map = _load_health_configs(config)

    return health_state_store, query_executor, config_map


def _load_health_configs(config: Dict[str, Any]) -> Dict:
    """Load custom health configs from Azure Blob Storage or use defaults.

    If ``HEALTH_CONFIG_BLOB_CONTAINER`` is set, reads a JSON file from
    Azure Blob Storage containing per-source health config overrides.
    Otherwise returns an empty dict so the built-in
    ``DEFAULT_HEALTH_CONFIGS`` are used.

    Expected blob JSON format::

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
    blob_container = config.get("health_config_blob_container")
    if not blob_container:
        logger.info(
            "No HEALTH_CONFIG_BLOB_CONTAINER set, using default health configs"
        )
        return {}

    blob_path = config["health_config_blob_path"]
    connection_string = config.get("storage_connection_string")

    if not connection_string:
        logger.warning(
            "HEALTH_CONFIG_BLOB_CONTAINER set but no STORAGE_CONNECTION_STRING — "
            "using default health configs"
        )
        return {}

    try:
        from azure.storage.blob import BlobServiceClient

        blob_service = BlobServiceClient.from_connection_string(connection_string)
        blob_client = blob_service.get_blob_client(
            container=blob_container, blob=blob_path
        )
        raw_json = blob_client.download_blob().readall().decode("utf-8")
        raw_configs = json.loads(raw_json)

        from src.shared.health import LogSourceHealthConfig

        config_map = {}
        for source_type, cfg_dict in raw_configs.items():
            cfg_dict["source_type"] = source_type
            config_map[source_type] = LogSourceHealthConfig.from_dict(cfg_dict)

        logger.info(
            "Loaded %d custom health configs from blob %s/%s",
            len(config_map),
            blob_container,
            blob_path,
        )
        return config_map

    except Exception as e:
        logger.warning(
            "Failed to load health configs from Blob Storage (using defaults): %s",
            e,
        )
        return {}


# ------------------------------------------------------------------
# Alert routing setup
# ------------------------------------------------------------------


def _get_key_vault_secret(vault_url: str, secret_name: str) -> Optional[str]:
    """Retrieve a secret value from Azure Key Vault.

    Args:
        vault_url: Key Vault URL.
        secret_name: Name of the secret.

    Returns:
        Secret value string, or None if not found.
    """
    try:
        from azure.identity import DefaultAzureCredential
        from azure.keyvault.secrets import SecretClient

        credential = DefaultAzureCredential()
        client = SecretClient(vault_url=vault_url, credential=credential)
        secret = client.get_secret(secret_name)
        return secret.value
    except Exception:
        return None


def _build_alert_router(config: Dict[str, Any]):
    """Build an AlertRouter with handler credentials from Azure Key Vault.

    Follows the same pattern as the Azure alert_router Function.

    Args:
        config: Configuration dictionary.

    Returns:
        AlertRouter instance, or None if no handlers could be loaded.
    """
    from src.shared.alerting import AlertRouter, RouterConfig
    from src.shared.alerting.handlers import (
        SlackHandler,
        PagerDutyHandler,
        EmailHandler,
        WebhookHandler,
    )

    key_vault_url = config.get("key_vault_url")
    if not key_vault_url:
        logger.warning(
            "No KEY_VAULT_URL configured — alerts will be generated but not routed"
        )
        return None

    handlers: Dict[str, Any] = {}

    # Load Slack handler
    slack_json = _get_key_vault_secret(key_vault_url, "mantissa-slack")
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
    pd_json = _get_key_vault_secret(key_vault_url, "mantissa-pagerduty")
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
    email_json = _get_key_vault_secret(key_vault_url, "mantissa-email")
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
    webhook_json = _get_key_vault_secret(key_vault_url, "mantissa-webhook")
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
# Timer trigger: scheduled health check (5-minute interval)
# ------------------------------------------------------------------


def timer_trigger(timer: func.TimerRequest) -> None:
    """Timer trigger handler for scheduled log source health checks.

    Evaluates the health of all configured log sources, generates alerts
    for status transitions and anomalies, and routes them through the
    alert pipeline.
    """
    start_time = time.time()

    if timer.past_due:
        logger.warning("Health check timer trigger is past due!")

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
# Timer trigger: daily baseline computation
# ------------------------------------------------------------------


def baseline_timer_trigger(timer: func.TimerRequest) -> None:
    """Timer trigger handler for daily volume baseline computation.

    Computes hourly event volume baselines for all enabled sources using
    historical data from Synapse Analytics.  These baselines are used by
    the health check engine for z-score volume anomaly detection.
    """
    start_time = time.time()

    if timer.past_due:
        logger.warning("Baseline computation timer trigger is past due!")

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


# ------------------------------------------------------------------
# HTTP trigger: on-demand health check
# ------------------------------------------------------------------


def main(req: func.HttpRequest) -> func.HttpResponse:
    """HTTP trigger handler for on-demand log source health checks.

    Supports both full health checks and single-source checks.

    Query parameters:
        source_type: Optional specific source to check (checks all if omitted).
        action: Optional "compute_baselines" to trigger baseline computation.
    """
    start_time = time.time()

    logger.info("Manual health check request: %s %s", req.method, req.url)

    config = _get_config()

    try:
        try:
            body = req.get_json() if req.get_body() else {}
        except ValueError:
            body = {}

        action = body.get("action") or req.params.get("action")

        # Dispatch to baseline computation if requested
        if action == "compute_baselines":
            return _handle_baseline_request(config, start_time)

        source_type = body.get("source_type") or req.params.get("source_type")

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

        if source_type:
            result = engine.evaluate_single_source(source_type, tenant_id, now=now)
            results = [result]
        else:
            results = engine.check_all_sources(tenant_id, now=now)

        source_statuses = {}
        for result in results:
            source_statuses[result.source_type] = result.new_status.value

        status_counts: Dict[str, int] = {}
        for status in source_statuses.values():
            status_counts[status] = status_counts.get(status, 0) + 1

        duration_ms = int((time.time() - start_time) * 1000)

        response_body = {
            "success": True,
            "timestamp": now.isoformat(),
            "tenant_id": tenant_id,
            "sources_checked": len(results),
            "status_counts": status_counts,
            "source_statuses": source_statuses,
            "duration_ms": duration_ms,
        }

        return func.HttpResponse(
            json.dumps(response_body),
            status_code=200,
            mimetype="application/json",
        )

    except Exception as e:
        logger.error("Error in manual health check: %s", e)
        import traceback

        traceback.print_exc()

        return func.HttpResponse(
            json.dumps({
                "success": False,
                "error": str(e),
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "duration_ms": int((time.time() - start_time) * 1000),
            }),
            status_code=500,
            mimetype="application/json",
        )


def _handle_baseline_request(
    config: Dict[str, Any], start_time: float
) -> func.HttpResponse:
    """Handle an HTTP baseline computation request.

    Args:
        config: Configuration dictionary.
        start_time: Request start timestamp.

    Returns:
        HTTP response with baseline computation results.
    """
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

        baselines = engine.compute_baselines(tenant_id, now=now)

        duration_ms = int((time.time() - start_time) * 1000)

        response_body = {
            "success": True,
            "timestamp": now.isoformat(),
            "tenant_id": tenant_id,
            "baselines_computed": len(baselines),
            "baselines": {
                src: {"mean": round(m, 1), "stddev": round(s, 1)}
                for src, (m, s) in baselines.items()
            },
            "duration_ms": duration_ms,
        }

        return func.HttpResponse(
            json.dumps(response_body),
            status_code=200,
            mimetype="application/json",
        )

    except Exception as e:
        logger.error("Error in baseline computation: %s", e)
        import traceback

        traceback.print_exc()

        return func.HttpResponse(
            json.dumps({
                "success": False,
                "error": str(e),
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "duration_ms": int((time.time() - start_time) * 1000),
            }),
            status_code=500,
            mimetype="application/json",
        )
