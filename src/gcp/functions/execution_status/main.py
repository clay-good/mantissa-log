"""Execution Status Cloud Function

Provides endpoints for querying execution status and logs.
Handles listing executions, getting execution details, logs, and cancellation.

Environment variables:
- PROJECT_ID: GCP project ID
- EXECUTIONS_COLLECTION: Firestore collection for executions
- ACTION_LOG_COLLECTION: Firestore collection for action logs
"""

import json
import logging
import os
import re
from datetime import datetime, timezone
from typing import Any, Dict, Optional

import functions_framework
from flask import Request
from google.cloud import firestore

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Configuration
PROJECT_ID = os.environ.get('PROJECT_ID', '')
EXECUTIONS_COLLECTION = os.environ.get('EXECUTIONS_COLLECTION', 'soar_executions')
ACTION_LOG_COLLECTION = os.environ.get('ACTION_LOG_COLLECTION', 'soar_action_log')

# Clients
_firestore_client: Optional[firestore.Client] = None


def _get_firestore_client() -> firestore.Client:
    """Get lazily-initialized Firestore client."""
    global _firestore_client
    if _firestore_client is None:
        _firestore_client = firestore.Client(project=PROJECT_ID)
    return _firestore_client


def _cors_headers() -> Dict[str, str]:
    """Return CORS headers."""
    return {
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    }


def _json_response(data: Any, status: int = 200) -> tuple:
    """Create JSON response with CORS headers."""
    return (
        json.dumps(data, default=str),
        status,
        {**_cors_headers(), 'Content-Type': 'application/json'},
    )


def _error_response(message: str, status: int = 400) -> tuple:
    """Create error response."""
    return _json_response({'error': message}, status)


def _get_user_id(request: Request) -> str:
    """Extract user ID from request headers."""
    auth_header = request.headers.get('Authorization', '')
    if auth_header.startswith('Bearer '):
        return 'user@example.com'
    return request.headers.get('X-User-Id', 'anonymous')


def handle_list_executions(request: Request) -> tuple:
    """List executions with optional filtering."""
    params = request.args

    status = params.get('status')
    playbook_id = params.get('playbook_id')
    limit = min(int(params.get('limit', 50)), 100)
    offset = int(params.get('offset', 0))

    db = _get_firestore_client()
    query = db.collection(EXECUTIONS_COLLECTION).order_by(
        'created_at', direction=firestore.Query.DESCENDING
    )

    if status:
        query = query.where('status', '==', status)

    if playbook_id:
        query = query.where('playbook_id', '==', playbook_id)

    # Execute query with pagination
    docs = list(query.limit(limit + offset).stream())

    # Apply offset
    docs = docs[offset:offset + limit]

    executions = []
    for doc in docs:
        execution = doc.to_dict()
        execution['id'] = doc.id
        executions.append(execution)

    return _json_response({
        'executions': executions,
        'count': len(executions),
        'offset': offset,
        'limit': limit,
    })


def handle_get_execution(request: Request, execution_id: str) -> tuple:
    """Get a specific execution by ID."""
    db = _get_firestore_client()
    doc = db.collection(EXECUTIONS_COLLECTION).document(execution_id).get()

    if not doc.exists:
        return _error_response(f"Execution not found: {execution_id}", 404)

    execution = doc.to_dict()
    execution['id'] = doc.id

    return _json_response(execution)


def handle_get_execution_logs(request: Request, execution_id: str) -> tuple:
    """Get logs for a specific execution."""
    params = request.args
    limit = min(int(params.get('limit', 100)), 500)

    db = _get_firestore_client()

    # First verify execution exists
    exec_doc = db.collection(EXECUTIONS_COLLECTION).document(execution_id).get()
    if not exec_doc.exists:
        return _error_response(f"Execution not found: {execution_id}", 404)

    # Get action logs for this execution
    logs_query = (
        db.collection(ACTION_LOG_COLLECTION)
        .where('execution_id', '==', execution_id)
        .order_by('timestamp', direction=firestore.Query.ASCENDING)
        .limit(limit)
    )

    logs = []
    for doc in logs_query.stream():
        log = doc.to_dict()
        log['id'] = doc.id
        logs.append(log)

    return _json_response({
        'execution_id': execution_id,
        'logs': logs,
        'count': len(logs),
    })


def handle_cancel_execution(request: Request, execution_id: str) -> tuple:
    """Cancel a running or pending execution."""
    db = _get_firestore_client()
    doc_ref = db.collection(EXECUTIONS_COLLECTION).document(execution_id)
    doc = doc_ref.get()

    if not doc.exists:
        return _error_response(f"Execution not found: {execution_id}", 404)

    execution = doc.to_dict()
    current_status = execution.get('status')

    # Only cancel if in cancellable state
    cancellable_statuses = ['pending', 'running', 'paused', 'waiting_approval']
    if current_status not in cancellable_statuses:
        return _error_response(
            f"Cannot cancel execution in status: {current_status}", 400
        )

    user_id = _get_user_id(request)
    now = datetime.now(timezone.utc).isoformat()

    try:
        body = request.get_json() or {}
    except Exception:
        body = {}

    reason = body.get('reason', 'Cancelled by user')

    # Update execution status
    doc_ref.update({
        'status': 'cancelled',
        'cancelled_at': now,
        'cancelled_by': user_id,
        'cancelled_reason': reason,
        'updated_at': now,
    })

    logger.info(f"Execution {execution_id} cancelled by {user_id}")

    return _json_response({
        'execution_id': execution_id,
        'status': 'cancelled',
        'cancelled_by': user_id,
        'cancelled_at': now,
        'reason': reason,
    })


def handle_get_execution_steps(request: Request, execution_id: str) -> tuple:
    """Get step results for a specific execution."""
    db = _get_firestore_client()

    exec_doc = db.collection(EXECUTIONS_COLLECTION).document(execution_id).get()
    if not exec_doc.exists:
        return _error_response(f"Execution not found: {execution_id}", 404)

    execution = exec_doc.to_dict()

    # Get step results from action logs
    logs_query = (
        db.collection(ACTION_LOG_COLLECTION)
        .where('execution_id', '==', execution_id)
        .order_by('timestamp', direction=firestore.Query.ASCENDING)
    )

    steps = []
    for doc in logs_query.stream():
        log = doc.to_dict()
        steps.append({
            'step_id': log.get('step_id'),
            'action': log.get('action'),
            'status': log.get('status'),
            'timestamp': log.get('timestamp'),
            'details': log.get('details', {}),
            'dry_run': log.get('dry_run', False),
        })

    return _json_response({
        'execution_id': execution_id,
        'playbook_id': execution.get('playbook_id'),
        'status': execution.get('status'),
        'steps': steps,
        'count': len(steps),
    })


def handle_get_execution_stats(request: Request) -> tuple:
    """Get execution statistics."""
    params = request.args
    days = int(params.get('days', 7))

    db = _get_firestore_client()

    # Get all executions (simplified - in production use aggregation queries)
    executions = list(db.collection(EXECUTIONS_COLLECTION).stream())

    stats = {
        'total': len(executions),
        'by_status': {},
        'by_playbook': {},
    }

    for doc in executions:
        data = doc.to_dict()
        status = data.get('status', 'unknown')
        playbook_id = data.get('playbook_id', 'unknown')

        stats['by_status'][status] = stats['by_status'].get(status, 0) + 1
        stats['by_playbook'][playbook_id] = stats['by_playbook'].get(playbook_id, 0) + 1

    return _json_response(stats)


def handle_health_check(request: Request) -> tuple:
    """Health check endpoint."""
    return _json_response({
        'status': 'healthy',
        'service': 'execution-status',
        'timestamp': datetime.now(timezone.utc).isoformat(),
    })


@functions_framework.http
def execution_status(request: Request) -> tuple:
    """Main entry point for Execution Status function."""
    if request.method == 'OPTIONS':
        return ('', 204, _cors_headers())

    path = request.path
    method = request.method

    # Normalize path
    for prefix in ['/api/soar', '/soar']:
        if path.startswith(prefix):
            path = path[len(prefix):]
            break

    logger.info(f"Execution Status request: {method} {path}")

    try:
        if path == '/health' and method == 'GET':
            return handle_health_check(request)

        if path == '/executions' and method == 'GET':
            return handle_list_executions(request)

        if path == '/executions/stats' and method == 'GET':
            return handle_get_execution_stats(request)

        # Match /executions/{id}
        exec_pattern = r'^/executions/([^/]+)$'
        match = re.match(exec_pattern, path)
        if match and method == 'GET':
            return handle_get_execution(request, match.group(1))

        # Match /executions/{id}/logs
        logs_pattern = r'^/executions/([^/]+)/logs$'
        match = re.match(logs_pattern, path)
        if match and method == 'GET':
            return handle_get_execution_logs(request, match.group(1))

        # Match /executions/{id}/steps
        steps_pattern = r'^/executions/([^/]+)/steps$'
        match = re.match(steps_pattern, path)
        if match and method == 'GET':
            return handle_get_execution_steps(request, match.group(1))

        # Match /executions/{id}/cancel
        cancel_pattern = r'^/executions/([^/]+)/cancel$'
        match = re.match(cancel_pattern, path)
        if match and method == 'POST':
            return handle_cancel_execution(request, match.group(1))

        return _error_response(f"Not found: {method} {path}", 404)

    except Exception as e:
        logger.error(f"Request failed: {e}", exc_info=True)
        return _error_response(f"Internal error: {str(e)}", 500)
