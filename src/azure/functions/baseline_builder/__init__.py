"""Azure Function handler for scheduled baseline builder execution.

This handler is triggered by a Timer trigger on a schedule (hourly by default)
to process new identity events and update user baselines.

Azure Configuration (function.json):
```json
{
  "bindings": [
    {
      "name": "timer",
      "type": "timerTrigger",
      "direction": "in",
      "schedule": "0 0 * * * *"
    }
  ]
}
```

Terraform:
```hcl
resource "azurerm_function_app_function" "baseline_builder" {
  name            = "baseline-builder"
  function_app_id = azurerm_linux_function_app.mantissa.id
  language        = "Python"

  config_json = jsonencode({
    bindings = [
      {
        name      = "timer"
        type      = "timerTrigger"
        direction = "in"
        schedule  = "0 0 * * * *"
      }
    ]
  })
}
```
"""

import azure.functions as func
import json
import logging
import os
import time
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)


class SynapseQueryExecutor:
    """Query executor adapter for Synapse Analytics."""

    def __init__(
        self, workspace_name: str, database_name: str, use_serverless: bool = True
    ):
        from src.azure.synapse.executor import SynapseExecutor

        self.executor = SynapseExecutor(
            workspace_name=workspace_name,
            database_name=database_name,
            use_serverless=use_serverless,
        )

    def execute_query(self, query: str, timeout_seconds: int = 300) -> Any:
        """Execute query and return results."""
        from dataclasses import dataclass, field

        @dataclass
        class QueryResult:
            rows: List[Dict[str, Any]] = field(default_factory=list)
            row_count: int = 0

        result = self.executor.execute_query(query, use_cache=False)
        rows = result.get("results", [])
        return QueryResult(rows=rows, row_count=len(rows))


class CosmosCheckpointManager:
    """Checkpoint manager using Azure Cosmos DB."""

    def __init__(
        self,
        connection_string: str = None,
        database_name: str = "mantissa",
        container_name: str = "checkpoints",
    ):
        from azure.cosmos import CosmosClient

        self.connection_string = connection_string or os.environ.get(
            "COSMOS_CONNECTION_STRING"
        )
        self.client = CosmosClient.from_connection_string(self.connection_string)
        self.database = self.client.get_database_client(database_name)
        self.container = self.database.get_container_client(container_name)

    def get_checkpoint(self, checkpoint_id: str) -> Optional[datetime]:
        """Get checkpoint timestamp."""
        try:
            item = self.container.read_item(
                item=checkpoint_id, partition_key=checkpoint_id
            )
            timestamp = item.get("timestamp")
            if isinstance(timestamp, str):
                return datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
            return None
        except Exception:
            return None

    def set_checkpoint(
        self, timestamp: datetime, checkpoint_id: str, metadata: Dict[str, Any] = None
    ) -> None:
        """Set checkpoint timestamp."""
        data = {
            "id": checkpoint_id,
            "checkpoint_id": checkpoint_id,
            "timestamp": timestamp.isoformat(),
            "updated_at": datetime.now(timezone.utc).isoformat(),
        }
        if metadata:
            data["metadata"] = metadata

        self.container.upsert_item(data)


def _get_config() -> Dict[str, Any]:
    """Load configuration from environment variables."""
    return {
        "synapse_workspace": os.environ.get("SYNAPSE_WORKSPACE_NAME"),
        "synapse_database": os.environ.get("SYNAPSE_DATABASE", "mantissa_logs"),
        "cosmos_connection_string": os.environ.get("COSMOS_CONNECTION_STRING"),
        "cosmos_database": os.environ.get("COSMOS_DATABASE", "mantissa"),
        "baseline_container": os.environ.get(
            "BASELINE_CONTAINER", "identity_baselines"
        ),
        "checkpoint_container": os.environ.get("CHECKPOINT_CONTAINER", "checkpoints"),
        "learning_period_days": int(os.environ.get("LEARNING_PERIOD_DAYS", "14")),
        "identity_events_table": os.environ.get(
            "IDENTITY_EVENTS_TABLE", "identity_events"
        ),
    }


def _initialize_components(config: Dict[str, Any]):
    """Initialize service components.

    Args:
        config: Configuration dictionary

    Returns:
        Tuple of (BaselineService, CheckpointManager, QueryExecutor)
    """
    from shared.identity import get_cosmos_baseline_store
    from shared.identity.baseline_service import (
        BaselineService,
        BaselineServiceConfig,
    )
    from shared.models.identity_event import IdentityEventNormalizer

    # Initialize baseline store
    baseline_store = get_cosmos_baseline_store(
        endpoint=os.environ.get("COSMOS_ENDPOINT"),
        key=os.environ.get("COSMOS_KEY"),
        database_name=config["cosmos_database"],
        container_name=config["baseline_container"],
    )

    # Initialize query executor
    query_executor = SynapseQueryExecutor(
        workspace_name=config["synapse_workspace"],
        database_name=config["synapse_database"],
    )

    # Initialize checkpoint manager
    checkpoint_manager = CosmosCheckpointManager(
        connection_string=config["cosmos_connection_string"],
        database_name=config["cosmos_database"],
        container_name=config["checkpoint_container"],
    )

    # Initialize baseline service
    service_config = BaselineServiceConfig(
        learning_period_days=config["learning_period_days"],
    )

    baseline_service = BaselineService(
        baseline_store=baseline_store,
        event_normalizer=IdentityEventNormalizer(),
        query_executor=query_executor,
        config=service_config,
    )

    return baseline_service, checkpoint_manager, query_executor


def _query_new_events(query_executor, config: Dict[str, Any], hours: int):
    """Query new identity events from Synapse Analytics.

    Args:
        query_executor: Synapse query executor
        config: Configuration dictionary
        hours: Number of hours to look back

    Returns:
        List of IdentityEvent objects
    """
    from shared.models.identity_event import IdentityEventNormalizer

    cutoff = datetime.now(timezone.utc) - timedelta(hours=hours)
    cutoff_str = cutoff.strftime("%Y-%m-%d %H:%M:%S")

    # Query identity events from Synapse
    query = f"""
        SELECT *
        FROM {config['identity_events_table']}
        WHERE event_timestamp >= '{cutoff_str}'
        ORDER BY event_timestamp ASC
        OFFSET 0 ROWS FETCH NEXT 50000 ROWS ONLY
    """

    try:
        result = query_executor.execute_query(query, timeout_seconds=300)

        normalizer = IdentityEventNormalizer()
        events = []

        for row in result.rows:
            try:
                event = normalizer.normalize_auto(row)
                if event:
                    events.append(event)
            except Exception as e:
                logger.warning(f"Error normalizing event: {e}")
                continue

        return events

    except Exception as e:
        logger.error(f"Error querying events: {e}")
        return []


def timer_trigger(timer: func.TimerRequest) -> None:
    """Timer trigger handler for scheduled baseline builder execution.

    This function is triggered by Azure Timer trigger (hourly by default) and:
    1. Gets checkpoint from Cosmos DB (last processed timestamp)
    2. Queries identity events since checkpoint from Synapse
    3. Updates baselines for affected users
    4. Updates checkpoint

    For cold start (no checkpoint), processes last 14 days.
    """
    start_time = time.time()

    logger.info(
        f"Baseline builder timer trigger fired at {datetime.now(timezone.utc).isoformat()}"
    )

    if timer.past_due:
        logger.warning("Timer trigger is past due!")

    config = _get_config()

    try:
        # Initialize components
        baseline_service, checkpoint_manager, query_executor = _initialize_components(
            config
        )

        # Get checkpoint (last processed timestamp)
        last_checkpoint = checkpoint_manager.get_checkpoint("baseline_builder")

        if last_checkpoint is None:
            # Cold start - process last 14 days
            logger.info("Cold start detected, processing last 14 days")
            lookback_hours = 14 * 24
        else:
            # Calculate hours since last checkpoint
            now = datetime.now(timezone.utc)
            hours_since = (now - last_checkpoint).total_seconds() / 3600
            lookback_hours = min(int(hours_since) + 1, 24 * 14)  # Cap at 14 days
            logger.info(f"Processing events since {last_checkpoint.isoformat()}")

        # Query new identity events
        events = _query_new_events(query_executor, config, lookback_hours)

        if not events:
            logger.info("No new events to process")
            return

        # Process events and update baselines
        logger.info(f"Processing {len(events)} identity events")
        updated_baselines = baseline_service.process_new_events(events)

        # Update checkpoint to latest event timestamp
        latest_event_time = max(e.timestamp for e in events)
        if latest_event_time.tzinfo is None:
            latest_event_time = latest_event_time.replace(tzinfo=timezone.utc)

        checkpoint_manager.set_checkpoint(
            timestamp=latest_event_time,
            checkpoint_id="baseline_builder",
            metadata={
                "events_processed": len(events),
                "users_updated": len(updated_baselines),
                "execution_duration_ms": int((time.time() - start_time) * 1000),
            },
        )

        # Calculate metrics
        duration_ms = int((time.time() - start_time) * 1000)
        mature_baselines = sum(
            1 for b in updated_baselines.values() if b.confidence_score >= 0.8
        )

        logger.info(
            f"Baseline builder complete: {len(events)} events processed, "
            f"{len(updated_baselines)} users updated, {mature_baselines} mature baselines, "
            f"{duration_ms}ms"
        )

    except Exception as e:
        logger.error(f"Error in baseline builder: {e}")
        import traceback

        traceback.print_exc()
        raise


def main(req: func.HttpRequest) -> func.HttpResponse:
    """HTTP trigger handler for manual baseline rebuild.

    Triggered manually to rebuild all baselines from scratch or for a specific user.
    Use with caution - this can be resource intensive.

    Request body (optional):
        user_email: Email of specific user to rebuild baseline for
    """
    start_time = time.time()

    logger.info("Manual baseline rebuild triggered via HTTP")

    config = _get_config()

    try:
        body = req.get_json() if req.get_body() else {}
        user_email = body.get("user_email")

        baseline_service, _, _ = _initialize_components(config)

        if user_email:
            logger.info(f"Rebuilding baseline for user: {user_email}")
            baseline = baseline_service.build_baseline_from_history(
                user_email=user_email,
                days=config["learning_period_days"],
            )

            response = {
                "success": True,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "user_email": user_email,
                "event_count": baseline.event_count,
                "confidence_score": baseline.confidence_score,
                "duration_ms": int((time.time() - start_time) * 1000),
            }

        else:
            logger.info("Rebuilding all baselines")
            rebuilt_count = baseline_service.rebuild_all_baselines()

            response = {
                "success": True,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "baselines_rebuilt": rebuilt_count,
                "duration_ms": int((time.time() - start_time) * 1000),
            }

        return func.HttpResponse(
            json.dumps(response), status_code=200, mimetype="application/json"
        )

    except ValueError as e:
        return func.HttpResponse(
            json.dumps({"success": False, "error": f"Invalid request body: {e}"}),
            status_code=400,
            mimetype="application/json",
        )

    except Exception as e:
        logger.error(f"Error in manual rebuild: {e}")
        import traceback

        traceback.print_exc()

        return func.HttpResponse(
            json.dumps(
                {
                    "success": False,
                    "error": str(e),
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                }
            ),
            status_code=500,
            mimetype="application/json",
        )
