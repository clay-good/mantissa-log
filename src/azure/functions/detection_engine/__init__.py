"""Azure Function handler for detection engine execution."""

import azure.functions as func
import json
import logging
import os
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List

from src.shared.detection.engine import DetectionEngine
from src.shared.detection.rule import RuleLoader
from src.azure.synapse.executor import SynapseExecutor

logger = logging.getLogger(__name__)


class SynapseQueryExecutor:
    """Query executor adapter for Synapse Analytics."""

    def __init__(self, workspace_name: str, database_name: str, use_serverless: bool = True):
        self.executor = SynapseExecutor(
            workspace_name=workspace_name,
            database_name=database_name,
            use_serverless=use_serverless
        )

    def execute_query(self, query: str, timeout: int = 120) -> List[Dict[str, Any]]:
        """Execute query and return results."""
        result = self.executor.execute_query(query, use_cache=True)
        return result.get("results", [])


class CosmosDBStateManager:
    """State manager using Azure Cosmos DB."""

    def __init__(self, connection_string: str = None, database_name: str = "mantissa", container_name: str = "detection_state"):
        from azure.cosmos import CosmosClient

        self.connection_string = connection_string or os.environ.get("COSMOS_CONNECTION_STRING")
        self.client = CosmosClient.from_connection_string(self.connection_string)
        self.database = self.client.get_database_client(database_name)
        self.container = self.database.get_container_client(container_name)

    def get_last_execution_time(self, rule_id: str) -> datetime:
        """Get last execution time for rule."""
        try:
            item = self.container.read_item(item=rule_id, partition_key=rule_id)
            return datetime.fromisoformat(item.get("last_execution", "1970-01-01T00:00:00Z"))
        except Exception:
            return datetime.now(timezone.utc) - timedelta(days=1)

    def set_last_execution_time(self, rule_id: str, execution_time: datetime) -> None:
        """Set last execution time for rule."""
        self.container.upsert_item({
            "id": rule_id,
            "rule_id": rule_id,
            "last_execution": execution_time.isoformat()
        })

    def is_suppressed(self, suppression_key: str, suppression_duration: timedelta) -> bool:
        """Check if alert is suppressed."""
        try:
            item = self.container.read_item(item=f"suppression_{suppression_key}", partition_key=f"suppression_{suppression_key}")
            suppressed_until = datetime.fromisoformat(item.get("suppressed_until"))
            return datetime.now(timezone.utc) < suppressed_until
        except Exception:
            return False

    def set_suppression(self, suppression_key: str, suppression_duration: timedelta) -> None:
        """Set suppression for alert."""
        suppressed_until = datetime.now(timezone.utc) + suppression_duration
        self.container.upsert_item({
            "id": f"suppression_{suppression_key}",
            "suppression_key": suppression_key,
            "suppressed_until": suppressed_until.isoformat()
        })


def main(req: func.HttpRequest) -> func.HttpResponse:
    """Azure Function handler for detection engine.

    Executes detection rules against Synapse Analytics and generates alerts.
    Can be triggered via HTTP (for testing) or timer trigger (for production).
    """
    logger.info("Processing detection engine request")

    # Load configuration
    rules_path = os.environ.get("RULES_PATH", "rules/sigma")
    database_name = os.environ.get("SYNAPSE_DATABASE", "mantissa_logs")
    workspace_name = os.environ.get("SYNAPSE_WORKSPACE_NAME")
    alert_topic_endpoint = os.environ.get("ALERT_TOPIC_ENDPOINT")

    try:
        body = req.get_json() if req.get_body() else {}
        rule_ids = body.get("rule_ids")  # Optional: specific rules to run
        time_window_minutes = body.get("time_window_minutes", 15)
    except ValueError:
        body = {}
        rule_ids = None
        time_window_minutes = 15

    try:
        # Initialize components
        logger.info(f"Initializing detection engine for database: {database_name}")

        # Load rules
        rule_loader = RuleLoader(rules_path=rules_path, backend_type="synapse")
        rules = rule_loader.load_all_rules()

        if rule_ids:
            rules = [r for r in rules if r.id in rule_ids]

        logger.info(f"Loaded {len(rules)} detection rules")

        # Initialize query executor
        query_executor = SynapseQueryExecutor(
            workspace_name=workspace_name,
            database_name=database_name
        )

        # Initialize state manager
        state_manager = None
        if os.environ.get("COSMOS_CONNECTION_STRING"):
            state_manager = CosmosDBStateManager()

        # Initialize detection engine
        engine = DetectionEngine(
            query_executor=query_executor,
            state_manager=state_manager,
            rules=rules
        )

        # Calculate time window
        end_time = datetime.now(timezone.utc)
        start_time = end_time - timedelta(minutes=time_window_minutes)

        # Execute all rules
        results = engine.execute_all_rules(
            time_window_start=start_time,
            time_window_end=end_time
        )

        # Collect alerts
        alerts = []
        for result in results:
            if result.triggered and result.alerts:
                for alert in result.alerts:
                    alerts.append({
                        "rule_id": result.rule_id,
                        "rule_name": result.rule.name if result.rule else result.rule_id,
                        "severity": result.rule.severity if result.rule else "medium",
                        "alert": alert,
                        "timestamp": end_time.isoformat()
                    })

        # Send alerts to Event Grid if configured
        if alerts and alert_topic_endpoint:
            from azure.eventgrid import EventGridPublisherClient
            from azure.core.credentials import AzureKeyCredential
            from azure.eventgrid import EventGridEvent

            key = os.environ.get("ALERT_TOPIC_KEY")
            if key:
                client = EventGridPublisherClient(alert_topic_endpoint, AzureKeyCredential(key))

                events = [
                    EventGridEvent(
                        subject=f"mantissa/detection/{alert['rule_id']}",
                        event_type="Mantissa.Detection.Alert",
                        data=alert,
                        data_version="1.0"
                    )
                    for alert in alerts
                ]

                client.send(events)
                logger.info(f"Sent {len(events)} alerts to Event Grid")

        # Build response
        response = {
            "success": True,
            "rules_executed": len(results),
            "rules_triggered": len([r for r in results if r.triggered]),
            "alerts_generated": len(alerts),
            "time_window": {
                "start": start_time.isoformat(),
                "end": end_time.isoformat()
            },
            "alerts": alerts[:100]  # Limit response size
        }

        return func.HttpResponse(
            json.dumps(response),
            status_code=200,
            mimetype="application/json"
        )

    except Exception as e:
        logger.error(f"Error in detection engine: {e}")
        import traceback
        traceback.print_exc()

        return func.HttpResponse(
            json.dumps({
                "success": False,
                "error": str(e)
            }),
            status_code=500,
            mimetype="application/json"
        )


def timer_trigger(timer: func.TimerRequest) -> None:
    """Timer trigger handler for scheduled detection execution."""
    logger.info("Timer trigger fired for detection engine")

    # Load configuration
    rules_path = os.environ.get("RULES_PATH", "rules/sigma")
    database_name = os.environ.get("SYNAPSE_DATABASE", "mantissa_logs")
    workspace_name = os.environ.get("SYNAPSE_WORKSPACE_NAME")
    alert_topic_endpoint = os.environ.get("ALERT_TOPIC_ENDPOINT")

    try:
        # Initialize components
        rule_loader = RuleLoader(rules_path=rules_path, backend_type="synapse")
        rules = rule_loader.load_all_rules()
        enabled_rules = [r for r in rules if r.enabled]

        logger.info(f"Running {len(enabled_rules)} enabled detection rules")

        query_executor = SynapseQueryExecutor(
            workspace_name=workspace_name,
            database_name=database_name
        )

        state_manager = None
        if os.environ.get("COSMOS_CONNECTION_STRING"):
            state_manager = CosmosDBStateManager()

        engine = DetectionEngine(
            query_executor=query_executor,
            state_manager=state_manager,
            rules=enabled_rules
        )

        # Calculate time window (last 15 minutes)
        end_time = datetime.now(timezone.utc)
        start_time = end_time - timedelta(minutes=15)

        # Execute rules
        results = engine.execute_all_rules(
            time_window_start=start_time,
            time_window_end=end_time
        )

        triggered_count = len([r for r in results if r.triggered])
        logger.info(f"Detection complete: {triggered_count}/{len(results)} rules triggered")

    except Exception as e:
        logger.error(f"Error in timer trigger: {e}")
        raise
