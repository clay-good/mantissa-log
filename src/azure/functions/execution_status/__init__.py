"""Azure Function handler for Execution Status.

Provides endpoints for querying execution status and logs.
Handles listing executions, getting execution details, logs, and cancellation.
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
            json.dumps(execution),
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
                'reason': reason,
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


def handle_get_execution_steps(req: func.HttpRequest, execution_id: str) -> func.HttpResponse:
    """Get step results for a specific execution."""
    cors_headers = get_cors_headers(req)

    try:
        client = _get_cosmos_client()
        database = client.get_database_client(COSMOS_DATABASE)

        # Get execution
        exec_container = database.get_container_client('soar_executions')
        try:
            execution = exec_container.read_item(item=execution_id, partition_key=execution_id)
        except Exception:
            return func.HttpResponse(
                json.dumps({'error': f'Execution not found: {execution_id}'}),
                status_code=404,
                mimetype='application/json',
                headers=cors_headers,
            )

        # Get action logs as steps using parameterized query
        log_container = database.get_container_client('soar_action_log')
        query = "SELECT * FROM c WHERE c.execution_id = @execution_id ORDER BY c.timestamp ASC"
        logs = list(log_container.query_items(
            query,
            parameters=[{"name": "@execution_id", "value": execution_id}],
            max_item_count=500
        ))

        steps = [
            {
                'step_id': log.get('step_id'),
                'action': log.get('action'),
                'status': log.get('status'),
                'timestamp': log.get('timestamp'),
                'details': log.get('details', {}),
                'dry_run': log.get('dry_run', False),
            }
            for log in logs
        ]

        return func.HttpResponse(
            json.dumps({
                'execution_id': execution_id,
                'playbook_id': execution.get('playbook_id'),
                'status': execution.get('status'),
                'steps': steps,
                'count': len(steps),
            }),
            status_code=200,
            mimetype='application/json',
            headers=cors_headers,
        )

    except Exception as e:
        logger.error(f"Error getting execution steps: {e}", exc_info=True)
        return func.HttpResponse(
            json.dumps({'error': str(e)}),
            status_code=500,
            mimetype='application/json',
            headers=cors_headers,
        )


def handle_get_stats(req: func.HttpRequest) -> func.HttpResponse:
    """Get execution statistics."""
    cors_headers = get_cors_headers(req)

    try:
        client = _get_cosmos_client()
        database = client.get_database_client(COSMOS_DATABASE)
        container = database.get_container_client('soar_executions')

        # Get all executions for stats
        query = "SELECT c.status, c.playbook_id FROM c"
        items = list(container.query_items(query, max_item_count=10000))

        stats = {
            'total': len(items),
            'by_status': {},
            'by_playbook': {},
        }

        for item in items:
            status = item.get('status', 'unknown')
            playbook_id = item.get('playbook_id', 'unknown')

            stats['by_status'][status] = stats['by_status'].get(status, 0) + 1
            stats['by_playbook'][playbook_id] = stats['by_playbook'].get(playbook_id, 0) + 1

        return func.HttpResponse(
            json.dumps(stats),
            status_code=200,
            mimetype='application/json',
            headers=cors_headers,
        )

    except Exception as e:
        logger.error(f"Error getting stats: {e}", exc_info=True)
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
            'service': 'execution-status',
            'timestamp': datetime.now(timezone.utc).isoformat(),
        }),
        status_code=200,
        mimetype='application/json',
        headers=cors_headers,
    )


def main(req: func.HttpRequest) -> func.HttpResponse:
    """Main entry point for Execution Status function."""
    cors_headers = get_cors_headers(req)

    if req.method == 'OPTIONS':
        return func.HttpResponse('', status_code=204, headers=cors_headers)

    path = req.route_params.get('path', '')

    # Normalize path
    for prefix in ['api/soar/', 'soar/']:
        if path.startswith(prefix):
            path = path[len(prefix):]
            break

    logger.info(f"Execution Status request: {req.method} /{path}")

    try:
        if path == 'health' and req.method == 'GET':
            return handle_health(req)

        if path == 'executions' and req.method == 'GET':
            return handle_list_executions(req)

        if path == 'executions/stats' and req.method == 'GET':
            return handle_get_stats(req)

        # Match /executions/{id}
        exec_match = re.match(r'^executions/([^/]+)$', path)
        if exec_match and req.method == 'GET':
            return handle_get_execution(req, exec_match.group(1))

        # Match /executions/{id}/logs
        logs_match = re.match(r'^executions/([^/]+)/logs$', path)
        if logs_match and req.method == 'GET':
            return handle_get_execution_logs(req, logs_match.group(1))

        # Match /executions/{id}/steps
        steps_match = re.match(r'^executions/([^/]+)/steps$', path)
        if steps_match and req.method == 'GET':
            return handle_get_execution_steps(req, steps_match.group(1))

        # Match /executions/{id}/cancel
        cancel_match = re.match(r'^executions/([^/]+)/cancel$', path)
        if cancel_match and req.method == 'POST':
            return handle_cancel_execution(req, cancel_match.group(1))

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
