"""Azure Function handler for SOAR API.

Handles SOAR (Security Orchestration, Automation and Response) API requests.
Provides endpoints for playbook management, execution, and quick actions.
"""

import azure.functions as func
import json
import logging
import os
import re
import sys
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from uuid import uuid4

from azure.cosmos import CosmosClient
from azure.storage.blob import BlobServiceClient

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
STORAGE_CONNECTION_STRING = os.environ.get('STORAGE_CONNECTION_STRING', '')
PLAYBOOKS_CONTAINER = os.environ.get('PLAYBOOKS_CONTAINER', 'soar-playbooks')

# Clients (lazy initialization)
_cosmos_client: Optional[CosmosClient] = None
_blob_client: Optional[BlobServiceClient] = None


def _get_cosmos_client() -> CosmosClient:
    """Get lazily-initialized Cosmos DB client."""
    global _cosmos_client
    if _cosmos_client is None:
        _cosmos_client = CosmosClient.from_connection_string(COSMOS_CONNECTION_STRING)
    return _cosmos_client


def _get_blob_client() -> BlobServiceClient:
    """Get lazily-initialized Blob Storage client."""
    global _blob_client
    if _blob_client is None:
        _blob_client = BlobServiceClient.from_connection_string(STORAGE_CONNECTION_STRING)
    return _blob_client


def _get_user_id(req: func.HttpRequest) -> str:
    """Extract user ID from request."""
    try:
        return verify_azure_ad_token(req)
    except AuthenticationError:
        return req.headers.get('X-User-Id', 'anonymous')


def handle_list_playbooks(req: func.HttpRequest) -> func.HttpResponse:
    """List all playbooks with optional filtering."""
    cors_headers = get_cors_headers(req)
    params = req.params

    status = params.get('status')
    limit = min(int(params.get('limit', 50)), 100)

    try:
        client = _get_cosmos_client()
        database = client.get_database_client(COSMOS_DATABASE)
        container = database.get_container_client('soar_playbooks')

        # Use parameterized queries to prevent SQL injection
        if status:
            query = "SELECT * FROM c WHERE c.status = @status ORDER BY c.updated_at DESC"
            parameters = [{"name": "@status", "value": status}]
        else:
            query = "SELECT * FROM c WHERE c.status != 'deleted' ORDER BY c.updated_at DESC"
            parameters = []

        items = list(container.query_items(
            query,
            parameters=parameters if parameters else None,
            max_item_count=limit
        ))

        return func.HttpResponse(
            json.dumps({'playbooks': items, 'count': len(items)}),
            status_code=200,
            mimetype='application/json',
            headers=cors_headers,
        )

    except Exception as e:
        logger.error(f"Error listing playbooks: {e}", exc_info=True)
        return func.HttpResponse(
            json.dumps({'error': str(e)}),
            status_code=500,
            mimetype='application/json',
            headers=cors_headers,
        )


def handle_create_playbook(req: func.HttpRequest) -> func.HttpResponse:
    """Create a new playbook."""
    cors_headers = get_cors_headers(req)

    try:
        body = req.get_json()
    except ValueError:
        return func.HttpResponse(
            json.dumps({'error': 'Invalid JSON body'}),
            status_code=400,
            mimetype='application/json',
            headers=cors_headers,
        )

    name = body.get('name')
    if not name:
        return func.HttpResponse(
            json.dumps({'error': 'name is required'}),
            status_code=400,
            mimetype='application/json',
            headers=cors_headers,
        )

    user_id = _get_user_id(req)
    playbook_id = f"pb-{uuid4().hex[:12]}"
    now = datetime.now(timezone.utc).isoformat()

    playbook = {
        'id': playbook_id,
        'name': name,
        'description': body.get('description', ''),
        'status': 'draft',
        'version': 1,
        'tags': body.get('tags', []),
        'trigger_types': body.get('trigger_types', ['manual']),
        'steps': body.get('steps', []),
        'created_by': user_id,
        'created_at': now,
        'updated_at': now,
        'updated_by': user_id,
    }

    try:
        client = _get_cosmos_client()
        database = client.get_database_client(COSMOS_DATABASE)
        container = database.get_container_client('soar_playbooks')
        container.create_item(playbook)

        logger.info(f"Created playbook {playbook_id}: {name}")

        return func.HttpResponse(
            json.dumps(playbook),
            status_code=201,
            mimetype='application/json',
            headers=cors_headers,
        )

    except Exception as e:
        logger.error(f"Error creating playbook: {e}", exc_info=True)
        return func.HttpResponse(
            json.dumps({'error': str(e)}),
            status_code=500,
            mimetype='application/json',
            headers=cors_headers,
        )


def handle_get_playbook(req: func.HttpRequest, playbook_id: str) -> func.HttpResponse:
    """Get a specific playbook by ID."""
    cors_headers = get_cors_headers(req)

    try:
        client = _get_cosmos_client()
        database = client.get_database_client(COSMOS_DATABASE)
        container = database.get_container_client('soar_playbooks')

        playbook = container.read_item(item=playbook_id, partition_key=playbook_id)

        return func.HttpResponse(
            json.dumps(playbook),
            status_code=200,
            mimetype='application/json',
            headers=cors_headers,
        )

    except Exception as e:
        if 'NotFound' in str(e):
            return func.HttpResponse(
                json.dumps({'error': f'Playbook not found: {playbook_id}'}),
                status_code=404,
                mimetype='application/json',
                headers=cors_headers,
            )
        logger.error(f"Error getting playbook: {e}", exc_info=True)
        return func.HttpResponse(
            json.dumps({'error': str(e)}),
            status_code=500,
            mimetype='application/json',
            headers=cors_headers,
        )


def handle_update_playbook(req: func.HttpRequest, playbook_id: str) -> func.HttpResponse:
    """Update an existing playbook."""
    cors_headers = get_cors_headers(req)

    try:
        body = req.get_json()
    except ValueError:
        return func.HttpResponse(
            json.dumps({'error': 'Invalid JSON body'}),
            status_code=400,
            mimetype='application/json',
            headers=cors_headers,
        )

    try:
        client = _get_cosmos_client()
        database = client.get_database_client(COSMOS_DATABASE)
        container = database.get_container_client('soar_playbooks')

        playbook = container.read_item(item=playbook_id, partition_key=playbook_id)

        user_id = _get_user_id(req)
        now = datetime.now(timezone.utc).isoformat()

        # Update fields
        for field in ['name', 'description', 'status', 'tags', 'trigger_types', 'steps']:
            if field in body:
                playbook[field] = body[field]

        # Increment version if steps changed
        if 'steps' in body:
            playbook['version'] = playbook.get('version', 0) + 1

        playbook['updated_at'] = now
        playbook['updated_by'] = user_id

        container.replace_item(item=playbook_id, body=playbook)

        logger.info(f"Updated playbook {playbook_id}")

        return func.HttpResponse(
            json.dumps(playbook),
            status_code=200,
            mimetype='application/json',
            headers=cors_headers,
        )

    except Exception as e:
        if 'NotFound' in str(e):
            return func.HttpResponse(
                json.dumps({'error': f'Playbook not found: {playbook_id}'}),
                status_code=404,
                mimetype='application/json',
                headers=cors_headers,
            )
        logger.error(f"Error updating playbook: {e}", exc_info=True)
        return func.HttpResponse(
            json.dumps({'error': str(e)}),
            status_code=500,
            mimetype='application/json',
            headers=cors_headers,
        )


def handle_delete_playbook(req: func.HttpRequest, playbook_id: str) -> func.HttpResponse:
    """Delete a playbook (soft delete)."""
    cors_headers = get_cors_headers(req)

    try:
        client = _get_cosmos_client()
        database = client.get_database_client(COSMOS_DATABASE)
        container = database.get_container_client('soar_playbooks')

        playbook = container.read_item(item=playbook_id, partition_key=playbook_id)

        user_id = _get_user_id(req)
        now = datetime.now(timezone.utc).isoformat()

        playbook['status'] = 'deleted'
        playbook['deleted_at'] = now
        playbook['deleted_by'] = user_id

        container.replace_item(item=playbook_id, body=playbook)

        logger.info(f"Deleted playbook {playbook_id}")

        return func.HttpResponse(
            json.dumps({'message': f'Playbook {playbook_id} deleted'}),
            status_code=200,
            mimetype='application/json',
            headers=cors_headers,
        )

    except Exception as e:
        if 'NotFound' in str(e):
            return func.HttpResponse(
                json.dumps({'error': f'Playbook not found: {playbook_id}'}),
                status_code=404,
                mimetype='application/json',
                headers=cors_headers,
            )
        logger.error(f"Error deleting playbook: {e}", exc_info=True)
        return func.HttpResponse(
            json.dumps({'error': str(e)}),
            status_code=500,
            mimetype='application/json',
            headers=cors_headers,
        )


def handle_deploy_playbook(req: func.HttpRequest, playbook_id: str) -> func.HttpResponse:
    """Deploy a playbook (activate for execution)."""
    cors_headers = get_cors_headers(req)

    try:
        client = _get_cosmos_client()
        database = client.get_database_client(COSMOS_DATABASE)
        container = database.get_container_client('soar_playbooks')

        playbook = container.read_item(item=playbook_id, partition_key=playbook_id)

        if not playbook.get('steps'):
            return func.HttpResponse(
                json.dumps({'error': 'Playbook has no steps defined'}),
                status_code=400,
                mimetype='application/json',
                headers=cors_headers,
            )

        user_id = _get_user_id(req)
        now = datetime.now(timezone.utc).isoformat()

        playbook['status'] = 'deployed'
        playbook['deployed_at'] = now
        playbook['deployed_by'] = user_id

        container.replace_item(item=playbook_id, body=playbook)

        logger.info(f"Deployed playbook {playbook_id}")

        return func.HttpResponse(
            json.dumps({
                'playbook_id': playbook_id,
                'status': 'deployed',
                'deployed_at': now,
                'message': 'Playbook deployed successfully',
            }),
            status_code=200,
            mimetype='application/json',
            headers=cors_headers,
        )

    except Exception as e:
        if 'NotFound' in str(e):
            return func.HttpResponse(
                json.dumps({'error': f'Playbook not found: {playbook_id}'}),
                status_code=404,
                mimetype='application/json',
                headers=cors_headers,
            )
        logger.error(f"Error deploying playbook: {e}", exc_info=True)
        return func.HttpResponse(
            json.dumps({'error': str(e)}),
            status_code=500,
            mimetype='application/json',
            headers=cors_headers,
        )


def handle_create_execution(req: func.HttpRequest) -> func.HttpResponse:
    """Create a new playbook execution."""
    cors_headers = get_cors_headers(req)

    try:
        body = req.get_json()
    except ValueError:
        return func.HttpResponse(
            json.dumps({'error': 'Invalid JSON body'}),
            status_code=400,
            mimetype='application/json',
            headers=cors_headers,
        )

    playbook_id = body.get('playbook_id')
    if not playbook_id:
        return func.HttpResponse(
            json.dumps({'error': 'playbook_id is required'}),
            status_code=400,
            mimetype='application/json',
            headers=cors_headers,
        )

    try:
        client = _get_cosmos_client()
        database = client.get_database_client(COSMOS_DATABASE)
        playbook_container = database.get_container_client('soar_playbooks')
        exec_container = database.get_container_client('soar_executions')

        playbook = playbook_container.read_item(item=playbook_id, partition_key=playbook_id)

        user_id = _get_user_id(req)
        execution_id = f"exec-{uuid4().hex[:12]}"
        now = datetime.now(timezone.utc).isoformat()

        execution = {
            'id': execution_id,
            'playbook_id': playbook_id,
            'playbook_name': playbook.get('name'),
            'status': 'pending',
            'trigger_type': body.get('trigger_type', 'manual'),
            'trigger_context': body.get('context', {}),
            'parameters': body.get('parameters', {}),
            'dry_run': body.get('dry_run', False),
            'initiated_by': user_id,
            'created_at': now,
            'updated_at': now,
        }

        exec_container.create_item(execution)

        logger.info(f"Created execution {execution_id} for playbook {playbook_id}")

        return func.HttpResponse(
            json.dumps(execution),
            status_code=201,
            mimetype='application/json',
            headers=cors_headers,
        )

    except Exception as e:
        if 'NotFound' in str(e):
            return func.HttpResponse(
                json.dumps({'error': f'Playbook not found: {playbook_id}'}),
                status_code=404,
                mimetype='application/json',
                headers=cors_headers,
            )
        logger.error(f"Error creating execution: {e}", exc_info=True)
        return func.HttpResponse(
            json.dumps({'error': str(e)}),
            status_code=500,
            mimetype='application/json',
            headers=cors_headers,
        )


# Quick Actions (standardized across all platforms)
QUICK_ACTIONS = {
    'isolate_host': {
        'id': 'isolate_host',
        'name': 'Isolate Host',
        'description': 'Isolate a host from the network',
        'icon': 'shield',
        'severity': 'high',
        'requires_approval': True,
        'parameters': [
            {'name': 'hostname', 'type': 'string', 'required': True},
            {'name': 'reason', 'type': 'string', 'required': False},
        ],
    },
    'disable_user': {
        'id': 'disable_user',
        'name': 'Disable User Account',
        'description': 'Disable a user account in Active Directory',
        'icon': 'user-minus',
        'severity': 'high',
        'requires_approval': True,
        'parameters': [
            {'name': 'username', 'type': 'string', 'required': True},
            {'name': 'reason', 'type': 'string', 'required': False},
        ],
    },
    'block_ip': {
        'id': 'block_ip',
        'name': 'Block IP Address',
        'description': 'Block an IP address at the firewall',
        'icon': 'ban',
        'severity': 'high',
        'requires_approval': True,
        'parameters': [
            {'name': 'ip_address', 'type': 'string', 'required': True},
            {'name': 'duration_hours', 'type': 'number', 'required': False, 'default': 24},
            {'name': 'reason', 'type': 'string', 'required': False},
        ],
    },
    'reset_password': {
        'id': 'reset_password',
        'name': 'Reset Password',
        'description': 'Force password reset for a user',
        'icon': 'key',
        'severity': 'high',
        'requires_approval': True,
        'parameters': [
            {'name': 'username', 'type': 'string', 'required': True},
            {'name': 'notify_user', 'type': 'boolean', 'required': False, 'default': True},
        ],
    },
    'create_ticket': {
        'id': 'create_ticket',
        'name': 'Create Ticket',
        'description': 'Create a ticket in the ticketing system',
        'icon': 'ticket',
        'severity': 'low',
        'requires_approval': False,
        'parameters': [
            {'name': 'title', 'type': 'string', 'required': True},
            {'name': 'description', 'type': 'string', 'required': True},
            {'name': 'priority', 'type': 'string', 'required': False, 'default': 'medium'},
        ],
    },
    'send_notification': {
        'id': 'send_notification',
        'name': 'Send Notification',
        'description': 'Send a notification to a channel or user',
        'icon': 'bell',
        'severity': 'low',
        'requires_approval': False,
        'parameters': [
            {'name': 'channel', 'type': 'string', 'required': True},
            {'name': 'message', 'type': 'string', 'required': True},
        ],
    },
}


def handle_list_quick_actions(req: func.HttpRequest) -> func.HttpResponse:
    """List available quick actions."""
    cors_headers = get_cors_headers(req)

    return func.HttpResponse(
        json.dumps({
            'actions': list(QUICK_ACTIONS.values()),
            'count': len(QUICK_ACTIONS),
        }),
        status_code=200,
        mimetype='application/json',
        headers=cors_headers,
    )


def handle_execute_quick_action(req: func.HttpRequest) -> func.HttpResponse:
    """Execute a quick action."""
    cors_headers = get_cors_headers(req)

    try:
        body = req.get_json()
    except ValueError:
        return func.HttpResponse(
            json.dumps({'error': 'Invalid JSON body'}),
            status_code=400,
            mimetype='application/json',
            headers=cors_headers,
        )

    action_id = body.get('action_id')
    if not action_id or action_id not in QUICK_ACTIONS:
        return func.HttpResponse(
            json.dumps({'error': f'Unknown action: {action_id}'}),
            status_code=404,
            mimetype='application/json',
            headers=cors_headers,
        )

    action = QUICK_ACTIONS[action_id]
    user_id = _get_user_id(req)
    execution_id = f"qa-{uuid4().hex[:12]}"
    now = datetime.now(timezone.utc).isoformat()

    try:
        client = _get_cosmos_client()
        database = client.get_database_client(COSMOS_DATABASE)
        container = database.get_container_client('soar_quick_actions')

        execution = {
            'id': execution_id,
            'action_id': action_id,
            'action_name': action['name'],
            'parameters': body.get('parameters', {}),
            'status': 'pending_approval' if action['requires_approval'] else 'executing',
            'initiated_by': user_id,
            'created_at': now,
            'alert_id': body.get('alert_id'),
        }

        container.create_item(execution)

        logger.info(f"Quick action {action_id} initiated: {execution_id}")

        return func.HttpResponse(
            json.dumps(execution),
            status_code=201,
            mimetype='application/json',
            headers=cors_headers,
        )

    except Exception as e:
        logger.error(f"Error executing quick action: {e}", exc_info=True)
        return func.HttpResponse(
            json.dumps({'error': str(e)}),
            status_code=500,
            mimetype='application/json',
            headers=cors_headers,
        )


# ============================================================================
# Execution Handlers (for unified API)
# ============================================================================

def handle_list_executions(req: func.HttpRequest) -> func.HttpResponse:
    """List executions with optional filtering."""
    cors_headers = get_cors_headers(req)
    params = req.params

    status = params.get('status')
    playbook_id = params.get('playbook_id')
    limit = min(int(params.get('limit', 50)), 100)

    try:
        client = _get_cosmos_client()
        database = client.get_database_client(COSMOS_DATABASE)
        container = database.get_container_client('soar_executions')

        # Use parameterized queries to prevent SQL injection
        conditions = []
        parameters = []

        if status:
            conditions.append("c.status = @status")
            parameters.append({"name": "@status", "value": status})
        if playbook_id:
            conditions.append("c.playbook_id = @playbook_id")
            parameters.append({"name": "@playbook_id", "value": playbook_id})

        where_clause = ' AND '.join(conditions) if conditions else '1=1'
        query = f"SELECT * FROM c WHERE {where_clause} ORDER BY c.created_at DESC"

        items = list(container.query_items(
            query,
            parameters=parameters if parameters else None,
            max_item_count=limit
        ))

        return func.HttpResponse(
            json.dumps({'executions': items, 'count': len(items)}),
            status_code=200,
            mimetype='application/json',
            headers=cors_headers,
        )

    except Exception as e:
        logger.error(f"Error listing executions: {e}", exc_info=True)
        return func.HttpResponse(
            json.dumps({'error': str(e)}),
            status_code=500,
            mimetype='application/json',
            headers=cors_headers,
        )


def handle_get_execution(req: func.HttpRequest, execution_id: str) -> func.HttpResponse:
    """Get a specific execution by ID."""
    cors_headers = get_cors_headers(req)

    try:
        client = _get_cosmos_client()
        database = client.get_database_client(COSMOS_DATABASE)
        container = database.get_container_client('soar_executions')

        execution = container.read_item(item=execution_id, partition_key=execution_id)

        return func.HttpResponse(
            json.dumps({'execution': execution}),
            status_code=200,
            mimetype='application/json',
            headers=cors_headers,
        )

    except Exception as e:
        if 'NotFound' in str(e):
            return func.HttpResponse(
                json.dumps({'error': f'Execution not found: {execution_id}'}),
                status_code=404,
                mimetype='application/json',
                headers=cors_headers,
            )
        logger.error(f"Error getting execution: {e}", exc_info=True)
        return func.HttpResponse(
            json.dumps({'error': str(e)}),
            status_code=500,
            mimetype='application/json',
            headers=cors_headers,
        )


def handle_get_execution_logs(req: func.HttpRequest, execution_id: str) -> func.HttpResponse:
    """Get logs for a specific execution."""
    cors_headers = get_cors_headers(req)
    params = req.params
    limit = min(int(params.get('limit', 100)), 500)

    try:
        client = _get_cosmos_client()
        database = client.get_database_client(COSMOS_DATABASE)

        # Verify execution exists
        exec_container = database.get_container_client('soar_executions')
        try:
            exec_container.read_item(item=execution_id, partition_key=execution_id)
        except Exception:
            return func.HttpResponse(
                json.dumps({'error': f'Execution not found: {execution_id}'}),
                status_code=404,
                mimetype='application/json',
                headers=cors_headers,
            )

        # Get action logs using parameterized query
        log_container = database.get_container_client('soar_action_log')
        query = "SELECT * FROM c WHERE c.execution_id = @execution_id ORDER BY c.timestamp ASC"
        logs = list(log_container.query_items(
            query,
            parameters=[{"name": "@execution_id", "value": execution_id}],
            max_item_count=limit
        ))

        return func.HttpResponse(
            json.dumps({
                'execution_id': execution_id,
                'logs': logs,
                'count': len(logs),
            }),
            status_code=200,
            mimetype='application/json',
            headers=cors_headers,
        )

    except Exception as e:
        logger.error(f"Error getting execution logs: {e}", exc_info=True)
        return func.HttpResponse(
            json.dumps({'error': str(e)}),
            status_code=500,
            mimetype='application/json',
            headers=cors_headers,
        )


def handle_cancel_execution(req: func.HttpRequest, execution_id: str) -> func.HttpResponse:
    """Cancel a running or pending execution."""
    cors_headers = get_cors_headers(req)

    try:
        body = req.get_json() or {}
    except ValueError:
        body = {}

    try:
        client = _get_cosmos_client()
        database = client.get_database_client(COSMOS_DATABASE)
        container = database.get_container_client('soar_executions')

        execution = container.read_item(item=execution_id, partition_key=execution_id)
        current_status = execution.get('status')

        cancellable_statuses = ['pending', 'running', 'paused', 'waiting_approval']
        if current_status not in cancellable_statuses:
            return func.HttpResponse(
                json.dumps({'error': f'Cannot cancel execution in status: {current_status}'}),
                status_code=400,
                mimetype='application/json',
                headers=cors_headers,
            )

        user_id = _get_user_id(req)
        now = datetime.now(timezone.utc).isoformat()
        reason = body.get('reason', 'Cancelled by user')

        execution['status'] = 'cancelled'
        execution['cancelled_at'] = now
        execution['cancelled_by'] = user_id
        execution['cancelled_reason'] = reason
        execution['updated_at'] = now

        container.replace_item(item=execution_id, body=execution)

        logger.info(f"Execution {execution_id} cancelled by {user_id}")

        return func.HttpResponse(
            json.dumps({
                'execution_id': execution_id,
                'status': 'cancelled',
                'cancelled_by': user_id,
                'cancelled_at': now,
                'message': 'Execution cancelled successfully',
            }),
            status_code=200,
            mimetype='application/json',
            headers=cors_headers,
        )

    except Exception as e:
        if 'NotFound' in str(e):
            return func.HttpResponse(
                json.dumps({'error': f'Execution not found: {execution_id}'}),
                status_code=404,
                mimetype='application/json',
                headers=cors_headers,
            )
        logger.error(f"Error cancelling execution: {e}", exc_info=True)
        return func.HttpResponse(
            json.dumps({'error': str(e)}),
            status_code=500,
            mimetype='application/json',
            headers=cors_headers,
        )


# ============================================================================
# Approval Handlers (for unified API)
# ============================================================================

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
            json.dumps({'approval': approval}),
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


# ============================================================================
# Playbook Version/Code Handlers (for unified API)
# ============================================================================

def handle_list_playbook_versions(req: func.HttpRequest, playbook_id: str) -> func.HttpResponse:
    """List all versions of a playbook."""
    cors_headers = get_cors_headers(req)

    try:
        client = _get_cosmos_client()
        database = client.get_database_client(COSMOS_DATABASE)
        container = database.get_container_client('soar_playbook_versions')

        # Query versions for this playbook
        query = "SELECT * FROM c WHERE c.playbook_id = @playbook_id ORDER BY c.version DESC"
        items = list(container.query_items(
            query,
            parameters=[{"name": "@playbook_id", "value": playbook_id}],
            max_item_count=100
        ))

        return func.HttpResponse(
            json.dumps({
                'playbook_id': playbook_id,
                'versions': items,
                'count': len(items),
            }),
            status_code=200,
            mimetype='application/json',
            headers=cors_headers,
        )

    except Exception as e:
        logger.error(f"Error listing playbook versions: {e}", exc_info=True)
        return func.HttpResponse(
            json.dumps({'error': str(e)}),
            status_code=500,
            mimetype='application/json',
            headers=cors_headers,
        )


def handle_get_playbook_code(req: func.HttpRequest, playbook_id: str) -> func.HttpResponse:
    """Get generated code for a playbook."""
    cors_headers = get_cors_headers(req)

    try:
        client = _get_cosmos_client()
        database = client.get_database_client(COSMOS_DATABASE)
        container = database.get_container_client('soar_playbooks')

        playbook = container.read_item(item=playbook_id, partition_key=playbook_id)

        # Generate simple Python code from playbook steps
        code_lines = [
            '"""Auto-generated playbook code."""',
            'import logging',
            'from datetime import datetime',
            '',
            f'# Playbook: {playbook.get("name", "Unknown")}',
            f'# Generated: {datetime.now(timezone.utc).isoformat()}',
            '',
            'logger = logging.getLogger(__name__)',
            '',
            'def execute_playbook(context):',
            '    """Execute the playbook with the given context."""',
            '    results = []',
            '',
        ]

        for i, step in enumerate(playbook.get('steps', []), 1):
            step_name = step.get('name', f'Step {i}')
            action = step.get('action', 'unknown')
            code_lines.append(f'    # Step {i}: {step_name}')
            code_lines.append(f'    logger.info("Executing step {i}: {step_name}")')
            code_lines.append(f'    results.append({{"step": {i}, "action": "{action}", "status": "completed"}})')
            code_lines.append('')

        code_lines.extend([
            '    return {"status": "completed", "results": results}',
            '',
            'if __name__ == "__main__":',
            '    result = execute_playbook({})',
            '    print(result)',
        ])

        code = '\n'.join(code_lines)

        return func.HttpResponse(
            json.dumps({
                'playbook_id': playbook_id,
                'code': code,
                'language': 'python',
            }),
            status_code=200,
            mimetype='application/json',
            headers=cors_headers,
        )

    except Exception as e:
        if 'NotFound' in str(e):
            return func.HttpResponse(
                json.dumps({'error': f'Playbook not found: {playbook_id}'}),
                status_code=404,
                mimetype='application/json',
                headers=cors_headers,
            )
        logger.error(f"Error getting playbook code: {e}", exc_info=True)
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
            'service': 'soar-api',
            'timestamp': datetime.now(timezone.utc).isoformat(),
        }),
        status_code=200,
        mimetype='application/json',
        headers=cors_headers,
    )


def main(req: func.HttpRequest) -> func.HttpResponse:
    """Main entry point for SOAR API Azure Function."""
    cors_headers = get_cors_headers(req)

    if req.method == 'OPTIONS':
        return func.HttpResponse('', status_code=204, headers=cors_headers)

    path = req.route_params.get('path', '')

    # Normalize path
    for prefix in ['api/soar/', 'soar/']:
        if path.startswith(prefix):
            path = path[len(prefix):]
            break

    logger.info(f"SOAR API request: {req.method} /{path}")

    try:
        if path == 'health' and req.method == 'GET':
            return handle_health(req)

        if path == 'playbooks' and req.method == 'GET':
            return handle_list_playbooks(req)

        if path == 'playbooks' and req.method == 'POST':
            return handle_create_playbook(req)

        # Execution routes (unified API)
        if path == 'executions' and req.method == 'GET':
            return handle_list_executions(req)

        if path == 'executions' and req.method == 'POST':
            return handle_create_execution(req)

        # Execution by ID routes
        exec_match = re.match(r'^executions/([^/]+)$', path)
        if exec_match and req.method == 'GET':
            return handle_get_execution(req, exec_match.group(1))

        # Execution logs route
        logs_match = re.match(r'^executions/([^/]+)/logs$', path)
        if logs_match and req.method == 'GET':
            return handle_get_execution_logs(req, logs_match.group(1))

        # Execution cancel route
        cancel_match = re.match(r'^executions/([^/]+)/cancel$', path)
        if cancel_match and req.method == 'POST':
            return handle_cancel_execution(req, cancel_match.group(1))

        # Approval routes (unified API)
        if path == 'approvals' and req.method == 'GET':
            return handle_list_approvals(req)

        # Approval by ID route
        approval_match = re.match(r'^approvals/([^/]+)$', path)
        if approval_match and req.method == 'GET':
            return handle_get_approval(req, approval_match.group(1))

        # Approval approve route
        approve_match = re.match(r'^approvals/([^/]+)/approve$', path)
        if approve_match and req.method == 'POST':
            return handle_approve(req, approve_match.group(1))

        # Approval deny route
        deny_match = re.match(r'^approvals/([^/]+)/deny$', path)
        if deny_match and req.method == 'POST':
            return handle_deny(req, deny_match.group(1))

        if path == 'quick-actions/available' and req.method == 'GET':
            return handle_list_quick_actions(req)

        if path == 'quick-actions' and req.method == 'POST':
            return handle_execute_quick_action(req)

        # Playbook by ID routes
        playbook_match = re.match(r'^playbooks/([^/]+)$', path)
        if playbook_match:
            playbook_id = playbook_match.group(1)
            if req.method == 'GET':
                return handle_get_playbook(req, playbook_id)
            if req.method == 'PUT':
                return handle_update_playbook(req, playbook_id)
            if req.method == 'DELETE':
                return handle_delete_playbook(req, playbook_id)

        # Playbook versions route
        versions_match = re.match(r'^playbooks/([^/]+)/versions$', path)
        if versions_match and req.method == 'GET':
            return handle_list_playbook_versions(req, versions_match.group(1))

        # Playbook code route
        code_match = re.match(r'^playbooks/([^/]+)/code$', path)
        if code_match and req.method == 'GET':
            return handle_get_playbook_code(req, code_match.group(1))

        # Deploy route
        deploy_match = re.match(r'^playbooks/([^/]+)/deploy$', path)
        if deploy_match and req.method == 'POST':
            return handle_deploy_playbook(req, deploy_match.group(1))

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
