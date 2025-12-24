"""
Execution Status Handler

Lambda function to handle execution status API requests.
Provides monitoring and management of playbook executions.
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

# Import authentication and CORS utilities
from auth import (
    get_authenticated_user_id,
    AuthenticationError,
)
from auth.cors import get_cors_headers, cors_preflight_response

# Import SOAR modules
from soar import (
    ExecutionStatus,
    get_execution_store,
    get_action_log,
    get_execution_engine,
    get_playbook_store,
    get_approval_service,
)

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

# Configuration
EXECUTION_TABLE = os.environ.get('EXECUTION_TABLE', 'mantissa-soar-executions')
ACTION_LOG_TABLE = os.environ.get('ACTION_LOG_TABLE', 'mantissa-soar-action-log')
PLAYBOOK_TABLE = os.environ.get('PLAYBOOK_TABLE', 'mantissa-soar-playbooks')

# Lazy-initialized services
_execution_store = None
_action_log = None
_execution_engine = None


def _get_execution_store():
    """Get lazily-initialized execution store."""
    global _execution_store
    if _execution_store is None:
        _execution_store = get_execution_store(
            store_type='dynamodb',
            table_name=EXECUTION_TABLE,
        )
    return _execution_store


def _get_action_log():
    """Get lazily-initialized action log."""
    global _action_log
    if _action_log is None:
        _action_log = get_action_log(
            store_type='dynamodb',
            table_name=ACTION_LOG_TABLE,
        )
    return _action_log


def _get_execution_engine():
    """Get lazily-initialized execution engine."""
    global _execution_engine
    if _execution_engine is None:
        _execution_engine = get_execution_engine(
            playbook_store=get_playbook_store(
                store_type='dynamodb',
                table_name=PLAYBOOK_TABLE,
            ),
            execution_store=_get_execution_store(),
            approval_service=get_approval_service(store_type='dynamodb'),
            action_log=_get_action_log(),
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
    Handle execution status API requests.

    Routes:
    - GET /executions - List executions
    - GET /executions/{id} - Get execution details
    - GET /executions/{id}/logs - Get execution logs
    - POST /executions/{id}/cancel - Cancel running execution
    """
    # Handle CORS preflight
    method = event.get('httpMethod', 'GET')
    if method == 'OPTIONS':
        return cors_preflight_response(event)

    try:
        # Authenticate user
        try:
            user_id = get_authenticated_user_id(event)
        except AuthenticationError:
            return _error_response(event, 401, 'Authentication required')

        path = event.get('path', '')
        body = json.loads(event.get('body', '{}')) if event.get('body') else {}
        params = event.get('queryStringParameters', {}) or {}

        # Route requests
        if path == '/executions' and method == 'GET':
            return handle_list_executions(event, user_id, params)
        elif path.endswith('/logs') and method == 'GET':
            execution_id = path.split('/')[-2]
            return handle_get_logs(event, user_id, execution_id, params)
        elif path.endswith('/cancel') and method == 'POST':
            execution_id = path.split('/')[-2]
            return handle_cancel_execution(event, user_id, execution_id, body)
        elif path.startswith('/executions/') and method == 'GET':
            execution_id = path.split('/')[-1]
            return handle_get_execution(event, user_id, execution_id)
        else:
            return _error_response(event, 404, 'Not found')

    except Exception as e:
        logger.error(f'Error in execution status handler: {e}', exc_info=True)
        return _error_response(event, 500, 'Internal server error')


def handle_list_executions(
    event: Dict[str, Any],
    user_id: str,
    params: Dict[str, str]
) -> Dict[str, Any]:
    """
    List playbook executions.

    Query parameters:
    - playbook_id: Filter by playbook ID
    - status: Filter by status (pending, running, completed, failed, etc.)
    - page: Page number (default 1)
    - page_size: Page size (default 50, max 100)
    """
    store = _get_execution_store()

    # Parse filters
    playbook_id = params.get('playbook_id')
    status_filter = params.get('status')
    status = None
    if status_filter:
        try:
            status = ExecutionStatus(status_filter)
        except ValueError:
            return _error_response(event, 400, f'Invalid status: {status_filter}')

    # Pagination
    page = int(params.get('page', 1))
    page_size = min(int(params.get('page_size', 50)), 100)
    offset = (page - 1) * page_size

    # Get executions
    executions = store.list(
        playbook_id=playbook_id,
        status=status,
        limit=page_size,
        offset=offset,
    )

    return _success_response(event, {
        'executions': [e.to_dict() for e in executions],
        'page': page,
        'page_size': page_size,
    })


def handle_get_execution(
    event: Dict[str, Any],
    user_id: str,
    execution_id: str
) -> Dict[str, Any]:
    """Get details of a specific execution."""
    store = _get_execution_store()

    execution = store.get(execution_id)
    if not execution:
        return _error_response(event, 404, f'Execution not found: {execution_id}')

    response_data = execution.to_dict()

    # Add computed fields
    response_data['is_complete'] = execution.is_complete
    response_data['duration_ms'] = execution.duration_ms

    return _success_response(event, {
        'execution': response_data,
    })


def handle_get_logs(
    event: Dict[str, Any],
    user_id: str,
    execution_id: str,
    params: Dict[str, str]
) -> Dict[str, Any]:
    """Get action logs for an execution."""
    store = _get_execution_store()
    action_log = _get_action_log()

    # Verify execution exists
    execution = store.get(execution_id)
    if not execution:
        return _error_response(event, 404, f'Execution not found: {execution_id}')

    # Get limit parameter
    limit = int(params.get('limit', 100))

    # Get action logs
    logs = action_log.get_actions(execution_id, limit=limit)

    return _success_response(event, {
        'execution_id': execution_id,
        'logs': [log.to_dict() for log in logs],
        'total': len(logs),
    })


def handle_cancel_execution(
    event: Dict[str, Any],
    user_id: str,
    execution_id: str,
    body: Dict[str, Any]
) -> Dict[str, Any]:
    """Cancel a running execution."""
    engine = _get_execution_engine()
    store = _get_execution_store()

    # Get execution
    execution = store.get(execution_id)
    if not execution:
        return _error_response(event, 404, f'Execution not found: {execution_id}')

    # Check if execution can be cancelled
    if execution.is_complete:
        return _error_response(
            event, 400,
            f'Execution is already {execution.status.value} and cannot be cancelled'
        )

    # Get cancellation reason
    reason = body.get('reason', f'Cancelled by {user_id}')

    # Cancel execution
    success = engine.cancel_execution(execution_id)
    if not success:
        return _error_response(event, 500, 'Failed to cancel execution')

    logger.info(f'Execution {execution_id} cancelled by {user_id}: {reason}')

    return _success_response(event, {
        'message': 'Execution cancelled successfully',
        'execution_id': execution_id,
        'cancelled_by': user_id,
        'reason': reason,
    })


def _success_response(
    event: Dict[str, Any],
    data: Dict[str, Any],
    status_code: int = 200
) -> Dict[str, Any]:
    """Create a successful API response."""
    return {
        'statusCode': status_code,
        'headers': get_cors_headers(event),
        'body': json.dumps(data, cls=DecimalEncoder),
    }


def _error_response(
    event: Dict[str, Any],
    status_code: int,
    message: str
) -> Dict[str, Any]:
    """Create an error API response."""
    return {
        'statusCode': status_code,
        'headers': get_cors_headers(event),
        'body': json.dumps({'error': message}),
    }
