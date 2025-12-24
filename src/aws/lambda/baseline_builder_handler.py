"""
AWS Lambda handler for scheduled baseline builder execution.

This handler is triggered by EventBridge on a schedule (hourly by default)
to process new identity events and update user baselines.

EventBridge Rule (CloudFormation):
```yaml
BaselineBuilderSchedule:
  Type: AWS::Events::Rule
  Properties:
    Name: mantissa-baseline-builder-schedule
    Description: Trigger baseline builder hourly
    ScheduleExpression: rate(1 hour)
    State: ENABLED
    Targets:
      - Id: baseline-builder-lambda
        Arn: !GetAtt BaselineBuilderFunction.Arn
```

Terraform:
```hcl
resource "aws_cloudwatch_event_rule" "baseline_builder" {
  name                = "mantissa-baseline-builder-schedule"
  description         = "Trigger baseline builder hourly"
  schedule_expression = "rate(1 hour)"
}

resource "aws_cloudwatch_event_target" "baseline_builder" {
  rule = aws_cloudwatch_event_rule.baseline_builder.name
  arn  = aws_lambda_function.baseline_builder.arn
}
```
"""

import json
import logging
import os
import time
from datetime import datetime, timezone, timedelta
from typing import Any, Dict

logger = logging.getLogger()
logger.setLevel(logging.INFO)


def lambda_handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """Lambda handler for baseline builder execution.

    This function is triggered by EventBridge on a schedule and:
    1. Gets checkpoint from DynamoDB (last processed timestamp)
    2. Queries identity events since checkpoint
    3. Updates baselines for affected users
    4. Updates checkpoint

    For cold start (no checkpoint), processes last 14 days.

    Args:
        event: Lambda event (from EventBridge or manual trigger)
        context: Lambda context

    Returns:
        Response with execution summary
    """
    start_time = time.time()

    logger.info(f"Baseline builder started: {json.dumps(event)}")

    # Load configuration from environment
    config = _get_config()

    try:
        # Initialize components
        baseline_service, checkpoint_manager, query_executor = _initialize_components(config)

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
            return _build_response(200, {
                "message": "No new events to process",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "duration_ms": int((time.time() - start_time) * 1000),
            })

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
            }
        )

        # Calculate metrics
        duration_ms = int((time.time() - start_time) * 1000)
        mature_baselines = sum(
            1 for b in updated_baselines.values()
            if b.confidence_score >= 0.8
        )

        logger.info(
            f"Baseline builder complete: {len(events)} events processed, "
            f"{len(updated_baselines)} users updated, {duration_ms}ms"
        )

        return _build_response(200, {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "events_processed": len(events),
            "users_updated": len(updated_baselines),
            "mature_baselines": mature_baselines,
            "duration_ms": duration_ms,
            "checkpoint": latest_event_time.isoformat(),
        })

    except Exception as e:
        logger.error(f"Error in baseline builder: {e}")
        import traceback
        traceback.print_exc()

        return _build_response(500, {
            "error": str(e),
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "duration_ms": int((time.time() - start_time) * 1000),
        })


def _get_config() -> Dict[str, str]:
    """Load configuration from environment variables."""
    return {
        "athena_database": os.environ.get("ATHENA_DATABASE", "mantissa_logs"),
        "athena_output_location": os.environ.get("ATHENA_OUTPUT_LOCATION"),
        "baseline_table": os.environ.get("BASELINE_TABLE", "mantissa-identity-baselines"),
        "checkpoint_table": os.environ.get("CHECKPOINT_TABLE", "mantissa-log-state"),
        "aws_region": os.environ.get("AWS_REGION", "us-east-1"),
        "learning_period_days": int(os.environ.get("LEARNING_PERIOD_DAYS", "14")),
        "identity_events_table": os.environ.get("IDENTITY_EVENTS_TABLE", "identity_events"),
    }


def _initialize_components(config: Dict[str, str]):
    """Initialize service components.

    Args:
        config: Configuration dictionary

    Returns:
        Tuple of (BaselineService, CheckpointManager, QueryExecutor)
    """
    from shared.identity import get_dynamodb_baseline_store
    from shared.identity.baseline_service import (
        BaselineService,
        BaselineServiceConfig,
        CheckpointManager,
    )
    from shared.models.identity_event import IdentityEventNormalizer
    from shared.detection import AthenaQueryExecutor

    # Initialize baseline store
    baseline_store = get_dynamodb_baseline_store(
        table_name=config["baseline_table"],
        region=config["aws_region"],
    )

    # Initialize query executor
    query_executor = AthenaQueryExecutor(
        database=config["athena_database"],
        output_location=config["athena_output_location"],
        region=config["aws_region"],
    )

    # Initialize checkpoint manager
    checkpoint_manager = CheckpointManager(
        table_name=config["checkpoint_table"],
        region=config["aws_region"],
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


def _query_new_events(query_executor, config: Dict[str, str], hours: int):
    """Query new identity events from Athena.

    Args:
        query_executor: Athena query executor
        config: Configuration dictionary
        hours: Number of hours to look back

    Returns:
        List of IdentityEvent objects
    """
    from shared.models.identity_event import IdentityEventNormalizer

    cutoff = datetime.now(timezone.utc) - timedelta(hours=hours)
    cutoff_str = cutoff.strftime("%Y-%m-%d %H:%M:%S")

    # Query identity events from all providers
    # The actual table/schema will depend on how events are stored
    query = f"""
        SELECT *
        FROM {config['identity_events_table']}
        WHERE event_timestamp >= TIMESTAMP '{cutoff_str}'
        ORDER BY event_timestamp ASC
        LIMIT 50000
    """

    try:
        result = query_executor.execute_query(query, timeout_seconds=300)

        normalizer = IdentityEventNormalizer()
        events = []

        for row in result.rows:
            try:
                # Try to auto-detect provider and normalize
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


def _build_response(status_code: int, body: Dict[str, Any]) -> Dict[str, Any]:
    """Build Lambda response.

    Args:
        status_code: HTTP status code
        body: Response body

    Returns:
        Lambda response dictionary
    """
    return {
        "statusCode": status_code,
        "body": json.dumps(body),
    }


# Manual trigger support
def manual_rebuild_handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """Handler for manual baseline rebuild.

    Triggered manually to rebuild all baselines from scratch.
    Use with caution - this can be resource intensive.

    Args:
        event: Lambda event with optional user_email for single user rebuild
        context: Lambda context

    Returns:
        Response with rebuild summary
    """
    start_time = time.time()

    logger.info(f"Manual baseline rebuild started: {json.dumps(event)}")

    config = _get_config()

    try:
        baseline_service, _, _ = _initialize_components(config)

        # Check if rebuilding single user or all
        user_email = event.get("user_email")

        if user_email:
            logger.info(f"Rebuilding baseline for user: {user_email}")
            baseline = baseline_service.build_baseline_from_history(
                user_email=user_email,
                days=config["learning_period_days"],
            )

            return _build_response(200, {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "user_email": user_email,
                "event_count": baseline.event_count,
                "confidence_score": baseline.confidence_score,
                "duration_ms": int((time.time() - start_time) * 1000),
            })

        else:
            logger.info("Rebuilding all baselines")
            rebuilt_count = baseline_service.rebuild_all_baselines()

            return _build_response(200, {
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "baselines_rebuilt": rebuilt_count,
                "duration_ms": int((time.time() - start_time) * 1000),
            })

    except Exception as e:
        logger.error(f"Error in manual rebuild: {e}")
        import traceback
        traceback.print_exc()

        return _build_response(500, {
            "error": str(e),
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })
