"""
Approval Handler

Lambda function to handle approval workflow API requests.
Manages approval requests for dangerous security actions.
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
    ApprovalRequest,
    get_approval_service,
    get_execution_engine,
    get_playbook_store,
    get_execution_store,
    get_action_log,
)

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

# Configuration
APPROVAL_TABLE = os.environ.get('APPROVAL_TABLE', 'mantissa-soar-approvals')
EXECUTION_TABLE = os.environ.get('EXECUTION_TABLE', 'mantissa-soar-executions')
PLAYBOOK_TABLE = os.environ.get('PLAYBOOK_TABLE', 'mantissa-soar-playbooks')

# Lazy-initialized services
_approval_service = None
_execution_engine = None


def _get_approval_service():
    """Get lazily-initialized approval service."""
    global _approval_service
    if _approval_service is None:
        _approval_service = get_approval_service(
            store_type='dynamodb',
            table_name=APPROVAL_TABLE,
        )
    return _approval_service


def _get_execution_engine():
    """Get lazily-initialized execution engine."""
    global _execution_engine
    if _execution_engine is None:
        _execution_engine = get_execution_engine(
            playbook_store=get_playbook_store(
                store_type='dynamodb',
                table_name=PLAYBOOK_TABLE,
            ),
            execution_store=get_execution_store(
                store_type='dynamodb',
                table_name=EXECUTION_TABLE,
            ),
            approval_service=_get_approval_service(),
            action_log=get_action_log(store_type='dynamodb'),
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
    Handle approval workflow API requests.

    Routes:
    - GET /approvals - List pending approvals (for current user)
    - GET /approvals/{id} - Get approval details
    - POST /approvals/{id}/approve - Approve action
    - POST /approvals/{id}/deny - Deny action
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
        if path == '/approvals' and method == 'GET':
            return handle_list_approvals(event, user_id, params)
        elif path.endswith('/approve') and method == 'POST':
            approval_id = path.split('/')[-2]
            return handle_approve(event, user_id, approval_id, body)
        elif path.endswith('/deny') and method == 'POST':
            approval_id = path.split('/')[-2]
            return handle_deny(event, user_id, approval_id, body)
        elif path.startswith('/approvals/') and method == 'GET':
            approval_id = path.split('/')[-1]
            return handle_get_approval(event, user_id, approval_id)
        else:
            return _error_response(event, 404, 'Not found')

    except Exception as e:
        logger.error(f'Error in approval handler: {e}', exc_info=True)
        return _error_response(event, 500, 'Internal server error')


def handle_list_approvals(
    event: Dict[str, Any],
    user_id: str,
    params: Dict[str, str]
) -> Dict[str, Any]:
    """
    List pending approvals for the current user.

    Query parameters:
    - status: Filter by status (pending, approved, denied, expired)
    - limit: Maximum number of results (default 50)
    """
    service = _get_approval_service()

    # Get filter parameters
    limit = int(params.get('limit', 50))
    status_filter = params.get('status')

    # Get pending approvals for user
    approvals = service.list_pending(approver=user_id, limit=limit)

    # Filter by status if specified (pending is already filtered)
    if status_filter and status_filter != 'pending':
        approvals = [a for a in approvals if a.status == status_filter]

    return _success_response(event, {
        'approvals': [a.to_dict() for a in approvals],
        'total': len(approvals),
    })


def handle_get_approval(
    event: Dict[str, Any],
    user_id: str,
    approval_id: str
) -> Dict[str, Any]:
    """Get details of a specific approval request."""
    service = _get_approval_service()

    approval = service.get_approval_request(approval_id)
    if not approval:
        return _error_response(event, 404, f'Approval not found: {approval_id}')

    # Check if user can view this approval
    if user_id not in approval.approvers and 'admin' not in approval.approvers:
        # Allow viewing but flag that user cannot approve
        can_approve = False
    else:
        can_approve = True

    response_data = approval.to_dict()
    response_data['can_approve'] = can_approve
    response_data['is_expired'] = approval.is_expired

    return _success_response(event, {
        'approval': response_data,
    })


def handle_approve(
    event: Dict[str, Any],
    user_id: str,
    approval_id: str,
    body: Dict[str, Any]
) -> Dict[str, Any]:
    """Approve an action."""
    service = _get_approval_service()
    engine = _get_execution_engine()

    # Get approval request
    approval = service.get_approval_request(approval_id)
    if not approval:
        return _error_response(event, 404, f'Approval not found: {approval_id}')

    # Check if user can approve
    if user_id not in approval.approvers and 'admin' not in approval.approvers:
        return _error_response(event, 403, 'You are not authorized to approve this action')

    # Check if already decided
    if approval.status != 'pending':
        return _error_response(event, 400, f'Approval already {approval.status}')

    # Check if expired
    if approval.is_expired:
        return _error_response(event, 400, 'Approval request has expired')

    # Get approval notes
    notes = body.get('notes', '')

    # Approve the request
    success = service.approve(approval_id, user_id, notes)
    if not success:
        return _error_response(event, 500, 'Failed to approve request')

    logger.info(f'Approval {approval_id} approved by {user_id}')

    # Resume execution
    try:
        execution = engine.resume_execution(
            execution_id=approval.execution_id,
            approval_granted=True,
            approver=user_id,
            notes=notes,
        )

        return _success_response(event, {
            'message': 'Action approved and execution resumed',
            'approval_id': approval_id,
            'execution_id': approval.execution_id,
            'execution_status': execution.status.value,
        })

    except Exception as e:
        logger.error(f'Failed to resume execution after approval: {e}')
        return _success_response(event, {
            'message': 'Action approved but execution resume failed',
            'approval_id': approval_id,
            'execution_id': approval.execution_id,
            'error': str(e),
        })


def handle_deny(
    event: Dict[str, Any],
    user_id: str,
    approval_id: str,
    body: Dict[str, Any]
) -> Dict[str, Any]:
    """Deny an action."""
    service = _get_approval_service()
    engine = _get_execution_engine()

    # Get approval request
    approval = service.get_approval_request(approval_id)
    if not approval:
        return _error_response(event, 404, f'Approval not found: {approval_id}')

    # Check if user can deny
    if user_id not in approval.approvers and 'admin' not in approval.approvers:
        return _error_response(event, 403, 'You are not authorized to deny this action')

    # Check if already decided
    if approval.status != 'pending':
        return _error_response(event, 400, f'Approval already {approval.status}')

    # Get denial reason (required for deny)
    notes = body.get('notes', body.get('reason', ''))
    if not notes:
        return _error_response(event, 400, 'Denial reason is required')

    # Deny the request
    success = service.deny(approval_id, user_id, notes)
    if not success:
        return _error_response(event, 500, 'Failed to deny request')

    logger.info(f'Approval {approval_id} denied by {user_id}: {notes}')

    # Update execution status
    try:
        execution = engine.resume_execution(
            execution_id=approval.execution_id,
            approval_granted=False,
            approver=user_id,
            notes=notes,
        )

        return _success_response(event, {
            'message': 'Action denied and execution stopped',
            'approval_id': approval_id,
            'execution_id': approval.execution_id,
            'execution_status': execution.status.value,
        })

    except Exception as e:
        logger.error(f'Failed to update execution after denial: {e}')
        return _success_response(event, {
            'message': 'Action denied',
            'approval_id': approval_id,
            'execution_id': approval.execution_id,
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
