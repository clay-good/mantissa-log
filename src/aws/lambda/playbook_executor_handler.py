"""
Playbook Executor Handler

Lambda function that executes SOAR playbooks. Can be invoked by:
- Alert router (automated response to alerts)
- API Gateway (manual execution)
- EventBridge (scheduled execution)
- Step Functions (workflow orchestration)
"""

import json
import logging
import os
import sys
from datetime import datetime, timezone
from decimal import Decimal
from typing import Any, Dict, Optional

# Add shared modules to path
sys.path.insert(0, '/opt/python')
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../../shared'))

# Import SOAR modules
from soar import (
    PlaybookExecution,
    PlaybookTriggerType,
    ExecutionStatus,
    get_playbook_store,
    get_execution_store,
    get_approval_service,
    get_action_log,
    PlaybookExecutionEngine,
    get_execution_engine,
)

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

# Configuration
PLAYBOOK_STORE_TYPE = os.environ.get('PLAYBOOK_STORE_TYPE', 'dynamodb')
PLAYBOOK_TABLE = os.environ.get('PLAYBOOK_TABLE', 'mantissa-soar-playbooks')
EXECUTION_TABLE = os.environ.get('EXECUTION_TABLE', 'mantissa-soar-executions')
APPROVAL_TABLE = os.environ.get('APPROVAL_TABLE', 'mantissa-soar-approvals')
ACTION_LOG_TABLE = os.environ.get('ACTION_LOG_TABLE', 'mantissa-soar-action-log')
DEFAULT_DRY_RUN = os.environ.get('DEFAULT_DRY_RUN', 'true').lower() == 'true'

# Lazy-initialized engine
_execution_engine: Optional[PlaybookExecutionEngine] = None


def _get_execution_engine() -> PlaybookExecutionEngine:
    """Get lazily-initialized execution engine."""
    global _execution_engine
    if _execution_engine is None:
        _execution_engine = get_execution_engine(
            playbook_store=get_playbook_store(
                store_type=PLAYBOOK_STORE_TYPE,
                table_name=PLAYBOOK_TABLE,
            ),
            execution_store=get_execution_store(
                store_type='dynamodb',
                table_name=EXECUTION_TABLE,
            ),
            approval_service=get_approval_service(
                store_type='dynamodb',
                table_name=APPROVAL_TABLE,
            ),
            action_log=get_action_log(
                store_type='dynamodb',
                table_name=ACTION_LOG_TABLE,
            ),
        )
    return _execution_engine


class DecimalEncoder(json.JSONEncoder):
    """JSON encoder that handles Decimal types from DynamoDB."""
    def default(self, obj):
        if isinstance(obj, Decimal):
            return float(obj)
        if isinstance(obj, datetime):
            return obj.isoformat()
        return super().default(obj)


def lambda_handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """
    Execute a playbook.

    Event structure depends on trigger type:

    Alert trigger (from alert router):
    {
        "trigger_type": "alert",
        "playbook_id": "pb-xxx",
        "alert": { ... alert data ... },
        "dry_run": false
    }

    Manual trigger (from API):
    {
        "trigger_type": "manual",
        "playbook_id": "pb-xxx",
        "parameters": { ... custom parameters ... },
        "user_id": "user@example.com",
        "dry_run": true
    }

    Scheduled trigger (from EventBridge):
    {
        "trigger_type": "scheduled",
        "playbook_id": "pb-xxx",
        "schedule_context": { ... schedule info ... }
    }

    Webhook trigger (from external systems):
    {
        "trigger_type": "webhook",
        "playbook_id": "pb-xxx",
        "webhook_payload": { ... webhook data ... }
    }

    Resume execution (after approval):
    {
        "action": "resume",
        "execution_id": "exec-xxx",
        "approval_granted": true,
        "approver": "approver@example.com",
        "notes": "Approved for production"
    }
    """
    try:
        logger.info(f"Playbook executor invoked: {json.dumps(event)[:500]}")

        # Check for resume action
        if event.get('action') == 'resume':
            return handle_resume(event)

        # Get playbook ID
        playbook_id = event.get('playbook_id')
        if not playbook_id:
            return _error_response(400, 'playbook_id is required')

        # Determine trigger type
        trigger_type_str = event.get('trigger_type', 'manual')
        try:
            trigger_type = PlaybookTriggerType(trigger_type_str)
        except ValueError:
            return _error_response(400, f'Invalid trigger_type: {trigger_type_str}')

        # Build trigger context
        trigger_context = build_trigger_context(event, trigger_type)

        # Get dry_run flag
        dry_run = event.get('dry_run', DEFAULT_DRY_RUN)
        if isinstance(dry_run, str):
            dry_run = dry_run.lower() == 'true'

        # Execute playbook
        engine = _get_execution_engine()
        execution = engine.execute_playbook(
            playbook_id=playbook_id,
            trigger_context=trigger_context,
            dry_run=dry_run,
            trigger_type=trigger_type,
        )

        logger.info(
            f"Playbook execution completed: {execution.execution_id}, "
            f"status: {execution.status.value}"
        )

        return _success_response(execution.to_dict())

    except ValueError as e:
        logger.error(f'Validation error: {e}')
        return _error_response(400, str(e))
    except Exception as e:
        logger.error(f'Playbook execution failed: {e}', exc_info=True)
        return _error_response(500, f'Execution failed: {str(e)}')


def handle_resume(event: Dict[str, Any]) -> Dict[str, Any]:
    """Handle resuming a paused execution after approval."""
    execution_id = event.get('execution_id')
    if not execution_id:
        return _error_response(400, 'execution_id is required for resume')

    approval_granted = event.get('approval_granted', False)
    approver = event.get('approver', 'unknown')
    notes = event.get('notes')

    try:
        engine = _get_execution_engine()
        execution = engine.resume_execution(
            execution_id=execution_id,
            approval_granted=approval_granted,
            approver=approver,
            notes=notes,
        )

        logger.info(
            f"Execution resumed: {execution_id}, "
            f"approval_granted: {approval_granted}, "
            f"status: {execution.status.value}"
        )

        return _success_response(execution.to_dict())

    except ValueError as e:
        logger.error(f'Resume validation error: {e}')
        return _error_response(400, str(e))
    except Exception as e:
        logger.error(f'Resume execution failed: {e}', exc_info=True)
        return _error_response(500, f'Resume failed: {str(e)}')


def build_trigger_context(
    event: Dict[str, Any],
    trigger_type: PlaybookTriggerType
) -> Dict[str, Any]:
    """Build trigger context from event based on trigger type."""
    context = {
        'trigger_type': trigger_type.value,
        'triggered_at': datetime.now(timezone.utc).isoformat(),
    }

    if trigger_type == PlaybookTriggerType.ALERT:
        context['alert'] = event.get('alert', {})
        context['alert_id'] = event.get('alert_id') or context['alert'].get('id')
        context['rule_id'] = event.get('rule_id') or context['alert'].get('rule_id')

    elif trigger_type == PlaybookTriggerType.MANUAL:
        context['parameters'] = event.get('parameters', {})
        context['user_id'] = event.get('user_id', 'unknown')
        context['reason'] = event.get('reason', 'Manual execution')

    elif trigger_type == PlaybookTriggerType.SCHEDULED:
        context['schedule_context'] = event.get('schedule_context', {})
        context['schedule_name'] = event.get('schedule_name', 'unknown')

    elif trigger_type == PlaybookTriggerType.WEBHOOK:
        context['webhook_payload'] = event.get('webhook_payload', {})
        context['webhook_source'] = event.get('source', 'unknown')

    return context


def _success_response(data: Dict[str, Any]) -> Dict[str, Any]:
    """Create a successful response."""
    return {
        'statusCode': 200,
        'body': json.dumps(data, cls=DecimalEncoder),
    }


def _error_response(status_code: int, message: str) -> Dict[str, Any]:
    """Create an error response."""
    return {
        'statusCode': status_code,
        'body': json.dumps({'error': message}),
    }


# Entry point for direct invocation (testing)
if __name__ == '__main__':
    # Test event
    test_event = {
        'trigger_type': 'manual',
        'playbook_id': 'pb-test-001',
        'parameters': {
            'user_email': 'test@example.com',
        },
        'dry_run': True,
    }

    result = lambda_handler(test_event, None)
    print(json.dumps(result, indent=2))
