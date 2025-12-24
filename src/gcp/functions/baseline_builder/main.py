"""GCP Cloud Function handler for scheduled baseline builder execution.

This handler is triggered by Cloud Scheduler on a schedule (hourly by default)
to process new identity events and update user baselines.

Cloud Scheduler Configuration:
```yaml
# Terraform
resource "google_cloud_scheduler_job" "baseline_builder" {
  name        = "mantissa-baseline-builder-schedule"
  description = "Trigger baseline builder hourly"
  schedule    = "0 * * * *"  # Every hour
  time_zone   = "UTC"

  pubsub_target {
    topic_name = google_pubsub_topic.baseline_builder_trigger.id
    data       = base64encode("{}")
  }
}

resource "google_pubsub_topic" "baseline_builder_trigger" {
  name = "mantissa-baseline-builder-trigger"
}

resource "google_cloudfunctions2_function" "baseline_builder" {
  name        = "mantissa-baseline-builder"
  location    = var.region

  build_config {
    runtime     = "python311"
    entry_point = "baseline_scheduled"
    source {
      storage_source {
        bucket = google_storage_bucket.functions.name
        object = google_storage_bucket_object.baseline_builder.name
      }
    }
  }

  event_trigger {
    trigger_region = var.region
    event_type     = "google.cloud.pubsub.topic.v1.messagePublished"
    pubsub_topic   = google_pubsub_topic.baseline_builder_trigger.id
  }
}
```
"""

import json
import logging
import os
import time
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List

import functions_framework
from flask import Request
from google.cloud import firestore

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)


class BigQueryQueryExecutor:
    """Query executor adapter for BigQuery."""

    def __init__(self, project_id: str, dataset_id: str):
        from google.cloud import bigquery

        self.project_id = project_id
        self.dataset_id = dataset_id
        self.client = bigquery.Client(project=project_id)

    def execute_query(self, query: str, timeout_seconds: int = 300) -> Any:
        """Execute query and return results."""
        from dataclasses import dataclass, field

        @dataclass
        class QueryResult:
            rows: List[Dict[str, Any]] = field(default_factory=list)
            row_count: int = 0

        job_config = self.client.QueryJobConfig()
        job_config.timeout_ms = timeout_seconds * 1000

        query_job = self.client.query(query, job_config=job_config)
        results = query_job.result(timeout=timeout_seconds)

        rows = [dict(row) for row in results]
        return QueryResult(rows=rows, row_count=len(rows))


class FirestoreCheckpointManager:
    """Checkpoint manager using Google Cloud Firestore."""

    def __init__(
        self,
        project_id: str = None,
        database: str = "(default)",
        collection: str = "mantissa_checkpoints",
    ):
        self.project_id = project_id or os.environ.get("GCP_PROJECT_ID")
        self.collection = collection
        self.client = firestore.Client(project=self.project_id, database=database)

    def get_checkpoint(self, checkpoint_id: str) -> datetime | None:
        """Get checkpoint timestamp."""
        doc_ref = self.client.collection(self.collection).document(checkpoint_id)
        doc = doc_ref.get()

        if doc.exists:
            data = doc.to_dict()
            timestamp = data.get("timestamp")
            if isinstance(timestamp, str):
                return datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
            elif hasattr(timestamp, "isoformat"):
                return timestamp
        return None

    def set_checkpoint(
        self, timestamp: datetime, checkpoint_id: str, metadata: Dict[str, Any] = None
    ) -> None:
        """Set checkpoint timestamp."""
        doc_ref = self.client.collection(self.collection).document(checkpoint_id)
        data = {
            "checkpoint_id": checkpoint_id,
            "timestamp": timestamp.isoformat(),
            "updated_at": datetime.now(timezone.utc).isoformat(),
        }
        if metadata:
            data["metadata"] = metadata

        doc_ref.set(data, merge=True)


def _get_config() -> Dict[str, Any]:
    """Load configuration from environment variables."""
    return {
        "project_id": os.environ.get("GCP_PROJECT_ID"),
        "bigquery_dataset": os.environ.get("BIGQUERY_DATASET", "mantissa_logs"),
        "baseline_collection": os.environ.get(
            "BASELINE_COLLECTION", "identity_baselines"
        ),
        "checkpoint_collection": os.environ.get(
            "CHECKPOINT_COLLECTION", "mantissa_checkpoints"
        ),
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
    from shared.identity import get_firestore_baseline_store
    from shared.identity.baseline_service import (
        BaselineService,
        BaselineServiceConfig,
    )
    from shared.models.identity_event import IdentityEventNormalizer

    # Initialize baseline store
    baseline_store = get_firestore_baseline_store(
        collection_name=config["baseline_collection"],
        project_id=config["project_id"],
    )

    # Initialize query executor
    query_executor = BigQueryQueryExecutor(
        project_id=config["project_id"],
        dataset_id=config["bigquery_dataset"],
    )

    # Initialize checkpoint manager
    checkpoint_manager = FirestoreCheckpointManager(
        project_id=config["project_id"],
        collection=config["checkpoint_collection"],
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
    """Query new identity events from BigQuery.

    Args:
        query_executor: BigQuery query executor
        config: Configuration dictionary
        hours: Number of hours to look back

    Returns:
        List of IdentityEvent objects
    """
    from shared.models.identity_event import IdentityEventNormalizer

    cutoff = datetime.now(timezone.utc) - timedelta(hours=hours)
    cutoff_str = cutoff.strftime("%Y-%m-%d %H:%M:%S")

    # Query identity events from BigQuery
    query = f"""
        SELECT *
        FROM `{config['project_id']}.{config['bigquery_dataset']}.{config['identity_events_table']}`
        WHERE event_timestamp >= TIMESTAMP('{cutoff_str}')
        ORDER BY event_timestamp ASC
        LIMIT 50000
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


@functions_framework.cloud_event
def baseline_scheduled(cloud_event):
    """Cloud Scheduler trigger for scheduled baseline builder execution.

    This function is triggered by Cloud Scheduler via Pub/Sub and:
    1. Gets checkpoint from Firestore (last processed timestamp)
    2. Queries identity events since checkpoint from BigQuery
    3. Updates baselines for affected users
    4. Updates checkpoint

    For cold start (no checkpoint), processes last 14 days.
    """
    start_time = time.time()

    logger.info("Baseline builder scheduled trigger fired")

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


@functions_framework.http
def baseline_manual(request: Request):
    """HTTP trigger for manual baseline rebuild.

    Triggered manually to rebuild all baselines from scratch or for a specific user.
    Use with caution - this can be resource intensive.

    Request body (optional):
        user_email: Email of specific user to rebuild baseline for
    """
    start_time = time.time()

    logger.info("Manual baseline rebuild triggered")

    # Handle CORS preflight
    if request.method == "OPTIONS":
        headers = {
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Methods": "POST, OPTIONS",
            "Access-Control-Allow-Headers": "Content-Type, Authorization",
            "Access-Control-Max-Age": "3600",
        }
        return ("", 204, headers)

    headers = {
        "Access-Control-Allow-Origin": "*",
        "Content-Type": "application/json",
    }

    config = _get_config()

    try:
        body = request.get_json(silent=True) or {}
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

        return (json.dumps(response), 200, headers)

    except Exception as e:
        logger.error(f"Error in manual rebuild: {e}")
        import traceback

        traceback.print_exc()

        return (
            json.dumps(
                {
                    "success": False,
                    "error": str(e),
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                }
            ),
            500,
            headers,
        )
