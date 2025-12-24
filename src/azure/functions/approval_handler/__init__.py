"""Azure Function handler for Approval Handler.

Handles approval requests for SOAR playbook actions.
Provides endpoints for listing, approving, and denying approval requests.
"""

import azure.functions as func
import json
import logging
import os
import re
import sys
from datetime import datetime, timezone
from typing import Any, Dict, Optional

from azure.cosmos import CosmosClient

# Add shared modules to path for Azure Functions
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../../..'))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../../../shared'))

try:
    from shared.auth.azure import verify_azure_ad_token, get_cors_headers, AuthenticationError
except ImportError:
    # Fallback for local development
    from src.shared.auth.azure import verify_azure_ad_token, get_cors_headers, AuthenticationError

logger = logging.getLogger(__name__)

# Configuration
COSMOS_CONNECTION_STRING = os.environ.get('COSMOS_CONNECTION_STRING', '')
COSMOS_DATABASE = os.environ.get('COSMOS_DATABASE', 'mantissa')

# Clients
_cosmos_client: Optional[CosmosClient] = None


def _get_cosmos_client() -> CosmosClient:
    """Get lazily-initialized Cosmos DB client."""
    global _cosmos_client
    if _cosmos_client is None:
        _cosmos_client = CosmosClient.from_connection_string(COSMOS_CONNECTION_STRING)
    return _cosmos_client


def _get_user_id(req: func.HttpRequest) -> str:
    """Extract user ID from request."""
    try:
        return verify_azure_ad_token(req)
    except AuthenticationError:
        return req.headers.get('X-User-Id', 'anonymous')


def handle_list_approvals(req: func.HttpRequest) -> func.HttpResponse:
    """List approval requests with optional filtering."""
    cors_headers = get_cors_headers(req)
    params = req.params

    status = params.get('status', 'pending')
    limit = min(int(params.get('limit', 50)), 100)

    try:
        client = _get_cosmos_client()
        database = client.get_database_client(COSMOS_DATABASE)
        container = database.get_container_client('soar_approvals')

        # Use parameterized query to prevent SQL injection
        query = "SELECT * FROM c WHERE c.status = @status ORDER BY c.created_at DESC"
        items = list(container.query_items(
            query,
            parameters=[{"name": "@status", "value": status}],
            max_item_count=limit
        ))

        return func.HttpResponse(
            json.dumps({'approvals': items, 'count': len(items)}),
            status_code=200,
            mimetype='application/json',
            headers=cors_headers,
        )

    except Exception as e:
        logger.error(f"Error listing approvals: {e}", exc_info=True)
        return func.HttpResponse(
            json.dumps({'error': str(e)}),
            status_code=500,
            mimetype='application/json',
            headers=cors_headers,
        )


def handle_get_approval(req: func.HttpRequest, approval_id: str) -> func.HttpResponse:
    """Get a specific approval request."""
    cors_headers = get_cors_headers(req)

    try:
        client = _get_cosmos_client()
        database = client.get_database_client(COSMOS_DATABASE)
        container = database.get_container_client('soar_approvals')

        approval = container.read_item(item=approval_id, partition_key=approval_id)

        # Get execution details
        execution_id = approval.get('execution_id')
        if execution_id:
            exec_container = database.get_container_client('soar_executions')
            try:
                execution = exec_container.read_item(item=execution_id, partition_key=execution_id)
                approval['execution'] = execution
            except Exception:
                pass

        return func.HttpResponse(
            json.dumps(approval),
            status_code=200,
            mimetype='application/json',
            headers=cors_headers,
        )

    except Exception as e:
        if 'NotFound' in str(e):
            return func.HttpResponse(
                json.dumps({'error': f'Approval not found: {approval_id}'}),
                status_code=404,
                mimetype='application/json',
                headers=cors_headers,
            )
        logger.error(f"Error getting approval: {e}", exc_info=True)
        return func.HttpResponse(
            json.dumps({'error': str(e)}),
            status_code=500,
            mimetype='application/json',
            headers=cors_headers,
        )


def handle_approve(req: func.HttpRequest, approval_id: str) -> func.HttpResponse:
    """Approve an approval request."""
    cors_headers = get_cors_headers(req)

    try:
        body = req.get_json() or {}
    except ValueError:
        body = {}

    try:
        client = _get_cosmos_client()
        database = client.get_database_client(COSMOS_DATABASE)
        container = database.get_container_client('soar_approvals')

        approval = container.read_item(item=approval_id, partition_key=approval_id)

        if approval.get('status') != 'pending':
            return func.HttpResponse(
                json.dumps({'error': f"Approval is not pending: {approval.get('status')}"}),
                status_code=400,
                mimetype='application/json',
                headers=cors_headers,
            )

        user_id = _get_user_id(req)
        now = datetime.now(timezone.utc).isoformat()
        notes = body.get('notes', '')

        # Update approval status
        approval['status'] = 'approved'
        approval['approved_by'] = user_id
        approval['approved_at'] = now
        approval['notes'] = notes

        container.replace_item(item=approval_id, body=approval)

        # Update execution
        execution_id = approval.get('execution_id')
        if execution_id:
            exec_container = database.get_container_client('soar_executions')
            try:
                execution = exec_container.read_item(item=execution_id, partition_key=execution_id)
                execution['approval_status'] = 'approved'
                execution['approved_by'] = user_id
                execution['approved_at'] = now
                exec_container.replace_item(item=execution_id, body=execution)
            except Exception as e:
                logger.warning(f"Failed to update execution: {e}")

        logger.info(f"Approval {approval_id} approved by {user_id}")

        return func.HttpResponse(
            json.dumps({
                'approval_id': approval_id,
                'status': 'approved',
                'approved_by': user_id,
                'approved_at': now,
                'message': 'Approval granted. Execution will resume.',
            }),
            status_code=200,
            mimetype='application/json',
            headers=cors_headers,
        )

    except Exception as e:
        if 'NotFound' in str(e):
            return func.HttpResponse(
                json.dumps({'error': f'Approval not found: {approval_id}'}),
                status_code=404,
                mimetype='application/json',
                headers=cors_headers,
            )
        logger.error(f"Error approving: {e}", exc_info=True)
        return func.HttpResponse(
            json.dumps({'error': str(e)}),
            status_code=500,
            mimetype='application/json',
            headers=cors_headers,
        )


def handle_deny(req: func.HttpRequest, approval_id: str) -> func.HttpResponse:
    """Deny an approval request."""
    cors_headers = get_cors_headers(req)

    try:
        body = req.get_json() or {}
    except ValueError:
        body = {}

    try:
        client = _get_cosmos_client()
        database = client.get_database_client(COSMOS_DATABASE)
        container = database.get_container_client('soar_approvals')

        approval = container.read_item(item=approval_id, partition_key=approval_id)

        if approval.get('status') != 'pending':
            return func.HttpResponse(
                json.dumps({'error': f"Approval is not pending: {approval.get('status')}"}),
                status_code=400,
                mimetype='application/json',
                headers=cors_headers,
            )

        user_id = _get_user_id(req)
        now = datetime.now(timezone.utc).isoformat()
        reason = body.get('reason', 'No reason provided')

        # Update approval status
        approval['status'] = 'denied'
        approval['denied_by'] = user_id
        approval['denied_at'] = now
        approval['denial_reason'] = reason

        container.replace_item(item=approval_id, body=approval)

        # Update execution to cancelled
        execution_id = approval.get('execution_id')
        if execution_id:
            exec_container = database.get_container_client('soar_executions')
            try:
                execution = exec_container.read_item(item=execution_id, partition_key=execution_id)
                execution['status'] = 'cancelled'
                execution['approval_status'] = 'denied'
                execution['denied_by'] = user_id
                execution['denied_at'] = now
                execution['cancelled_reason'] = f"Approval denied: {reason}"
                exec_container.replace_item(item=execution_id, body=execution)
            except Exception as e:
                logger.warning(f"Failed to update execution: {e}")

        logger.info(f"Approval {approval_id} denied by {user_id}: {reason}")

        return func.HttpResponse(
            json.dumps({
                'approval_id': approval_id,
                'status': 'denied',
                'denied_by': user_id,
                'denied_at': now,
                'reason': reason,
                'message': 'Approval denied. Execution has been cancelled.',
            }),
            status_code=200,
            mimetype='application/json',
            headers=cors_headers,
        )

    except Exception as e:
        if 'NotFound' in str(e):
            return func.HttpResponse(
                json.dumps({'error': f'Approval not found: {approval_id}'}),
                status_code=404,
                mimetype='application/json',
                headers=cors_headers,
            )
        logger.error(f"Error denying: {e}", exc_info=True)
        return func.HttpResponse(
            json.dumps({'error': str(e)}),
            status_code=500,
            mimetype='application/json',
            headers=cors_headers,
        )


def handle_health(req: func.HttpRequest) -> func.HttpResponse:
    """Health check endpoint."""
    cors_headers = get_cors_headers(req)

    return func.HttpResponse(
        json.dumps({
            'status': 'healthy',
            'service': 'approval-handler',
            'timestamp': datetime.now(timezone.utc).isoformat(),
        }),
        status_code=200,
        mimetype='application/json',
        headers=cors_headers,
    )


def main(req: func.HttpRequest) -> func.HttpResponse:
    """Main entry point for Approval Handler."""
    cors_headers = get_cors_headers(req)

    if req.method == 'OPTIONS':
        return func.HttpResponse('', status_code=204, headers=cors_headers)

    path = req.route_params.get('path', '')

    # Normalize path
    for prefix in ['api/soar/', 'soar/']:
        if path.startswith(prefix):
            path = path[len(prefix):]
            break

    logger.info(f"Approval Handler request: {req.method} /{path}")

    try:
        if path == 'health' and req.method == 'GET':
            return handle_health(req)

        if path == 'approvals' and req.method == 'GET':
            return handle_list_approvals(req)

        # Match /approvals/{id}
        approval_match = re.match(r'^approvals/([^/]+)$', path)
        if approval_match and req.method == 'GET':
            return handle_get_approval(req, approval_match.group(1))

        # Match /approvals/{id}/approve
        approve_match = re.match(r'^approvals/([^/]+)/approve$', path)
        if approve_match and req.method == 'POST':
            return handle_approve(req, approve_match.group(1))

        # Match /approvals/{id}/deny
        deny_match = re.match(r'^approvals/([^/]+)/deny$', path)
        if deny_match and req.method == 'POST':
            return handle_deny(req, deny_match.group(1))

        return func.HttpResponse(
            json.dumps({'error': f'Not found: {req.method} /{path}'}),
            status_code=404,
            mimetype='application/json',
            headers=cors_headers,
        )

    except Exception as e:
        logger.error(f"Request failed: {e}", exc_info=True)
        return func.HttpResponse(
            json.dumps({'error': str(e)}),
            status_code=500,
            mimetype='application/json',
            headers=cors_headers,
        )
