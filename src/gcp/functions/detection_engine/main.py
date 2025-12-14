"""GCP Cloud Function handler for detection engine execution."""

import json
import logging
import os
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List

import functions_framework
from flask import Request
from google.cloud import firestore, pubsub_v1

from src.shared.detection.engine import DetectionEngine
from src.shared.detection.rule import RuleLoader
from src.gcp.bigquery.executor import BigQueryExecutor
from src.shared.auth.gcp import verify_firebase_token, get_cors_headers, AuthenticationError

logger = logging.getLogger(__name__)


class BigQueryQueryExecutor:
    """Query executor adapter for BigQuery."""

    def __init__(self, project_id: str, dataset_id: str):
        self.executor = BigQueryExecutor(project_id=project_id, dataset_id=dataset_id)

    def execute_query(self, query: str, timeout: int = 120) -> List[Dict[str, Any]]:
        """Execute query and return results."""
        result = self.executor.execute_query(query, use_cache=True)
        return result.get("results", [])


class FirestoreStateManager:
    """State manager using Google Cloud Firestore."""

    def __init__(self, project_id: str = None, database: str = "(default)", collection: str = "detection_state"):
        self.project_id = project_id or os.environ.get("GCP_PROJECT_ID")
        self.collection = collection
        self.client = firestore.Client(project=self.project_id, database=database)

    def get_last_execution_time(self, rule_id: str) -> datetime:
        """Get last execution time for rule."""
        doc_ref = self.client.collection(self.collection).document(rule_id)
        doc = doc_ref.get()
        if doc.exists:
            data = doc.to_dict()
            return datetime.fromisoformat(data.get("last_execution", "1970-01-01T00:00:00Z"))
        return datetime.now(timezone.utc) - timedelta(days=1)

    def set_last_execution_time(self, rule_id: str, execution_time: datetime) -> None:
        """Set last execution time for rule."""
        doc_ref = self.client.collection(self.collection).document(rule_id)
        doc_ref.set({"rule_id": rule_id, "last_execution": execution_time.isoformat()}, merge=True)

    def is_suppressed(self, suppression_key: str, suppression_duration: timedelta) -> bool:
        """Check if alert is suppressed."""
        doc_ref = self.client.collection(f"{self.collection}_suppression").document(suppression_key)
        doc = doc_ref.get()
        if doc.exists:
            data = doc.to_dict()
            suppressed_until = datetime.fromisoformat(data.get("suppressed_until"))
            return datetime.now(timezone.utc) < suppressed_until
        return False

    def set_suppression(self, suppression_key: str, suppression_duration: timedelta) -> None:
        """Set suppression for alert."""
        doc_ref = self.client.collection(f"{self.collection}_suppression").document(suppression_key)
        suppressed_until = datetime.now(timezone.utc) + suppression_duration
        doc_ref.set({"suppression_key": suppression_key, "suppressed_until": suppressed_until.isoformat()})


@functions_framework.http
def detection_engine(request: Request):
    """Cloud Function handler for detection engine.

    Executes detection rules against BigQuery and generates alerts.
    """
    cors_headers = get_cors_headers(request)

    # Handle CORS
    if request.method == "OPTIONS":
        return ("", 204, {
            **cors_headers,
            "Access-Control-Allow-Methods": "POST, OPTIONS",
            "Access-Control-Allow-Headers": "Content-Type, Authorization",
            "Access-Control-Max-Age": "3600"
        })

    # Authenticate user from Firebase/Identity Platform token
    try:
        user_id = verify_firebase_token(request)
    except AuthenticationError as e:
        return (
            json.dumps({"error": "Authentication required", "details": str(e)}),
            401,
            {"Content-Type": "application/json", **cors_headers}
        )

    logger.info(f"Processing detection engine request for user: {user_id}")

    # Load configuration
    project_id = os.environ.get("GCP_PROJECT_ID")
    dataset_id = os.environ.get("BIGQUERY_DATASET", "mantissa_logs")
    rules_path = os.environ.get("RULES_PATH", "rules/sigma")
    alert_topic = os.environ.get("ALERT_TOPIC")

    try:
        body = request.get_json(silent=True) or {}
        rule_ids = body.get("rule_ids")
        time_window_minutes = body.get("time_window_minutes", 15)
    except Exception:
        body = {}
        rule_ids = None
        time_window_minutes = 15

    try:
        # Initialize components
        logger.info(f"Initializing detection engine for dataset: {dataset_id}")

        # Load rules
        rule_loader = RuleLoader(rules_path=rules_path, backend_type="bigquery")
        rules = rule_loader.load_all_rules()

        if rule_ids:
            rules = [r for r in rules if r.id in rule_ids]

        logger.info(f"Loaded {len(rules)} detection rules")

        # Initialize query executor
        query_executor = BigQueryQueryExecutor(project_id=project_id, dataset_id=dataset_id)

        # Initialize state manager
        state_manager = FirestoreStateManager(project_id=project_id)

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

        # Publish alerts to Pub/Sub if configured
        if alerts and alert_topic:
            publisher = pubsub_v1.PublisherClient()
            topic_path = publisher.topic_path(project_id, alert_topic)

            for alert in alerts:
                data = json.dumps(alert).encode("utf-8")
                future = publisher.publish(topic_path, data)
                future.result()

            logger.info(f"Published {len(alerts)} alerts to Pub/Sub")

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
            "alerts": alerts[:100]
        }

        return (
            json.dumps(response),
            200,
            {"Content-Type": "application/json", **cors_headers}
        )

    except Exception as e:
        logger.error(f"Error in detection engine: {e}")
        import traceback
        traceback.print_exc()

        return (
            json.dumps({"success": False, "error": str(e)}),
            500,
            {"Content-Type": "application/json", **cors_headers}
        )


@functions_framework.cloud_event
def detection_scheduled(cloud_event):
    """Cloud Scheduler trigger for scheduled detection execution."""
    logger.info("Scheduled detection trigger fired")

    project_id = os.environ.get("GCP_PROJECT_ID")
    dataset_id = os.environ.get("BIGQUERY_DATASET", "mantissa_logs")
    rules_path = os.environ.get("RULES_PATH", "rules/sigma")
    alert_topic = os.environ.get("ALERT_TOPIC")

    try:
        # Load and run enabled rules
        rule_loader = RuleLoader(rules_path=rules_path, backend_type="bigquery")
        rules = rule_loader.load_all_rules()
        enabled_rules = [r for r in rules if r.enabled]

        logger.info(f"Running {len(enabled_rules)} enabled detection rules")

        query_executor = BigQueryQueryExecutor(project_id=project_id, dataset_id=dataset_id)
        state_manager = FirestoreStateManager(project_id=project_id)

        engine = DetectionEngine(
            query_executor=query_executor,
            state_manager=state_manager,
            rules=enabled_rules
        )

        # Last 15 minutes
        end_time = datetime.now(timezone.utc)
        start_time = end_time - timedelta(minutes=15)

        results = engine.execute_all_rules(
            time_window_start=start_time,
            time_window_end=end_time
        )

        triggered_count = len([r for r in results if r.triggered])
        logger.info(f"Detection complete: {triggered_count}/{len(results)} rules triggered")

    except Exception as e:
        logger.error(f"Error in scheduled detection: {e}")
        raise
