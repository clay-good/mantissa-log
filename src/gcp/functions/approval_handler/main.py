"""Approval Handler Cloud Function

Handles approval requests for SOAR playbook actions.
Provides endpoints for listing, approving, and denying approval requests.

Environment variables:
- PROJECT_ID: GCP project ID
- APPROVALS_COLLECTION: Firestore collection for approvals
- EXECUTIONS_COLLECTION: Firestore collection for executions
- EXECUTOR_FUNCTION: Name of playbook executor function
"""

import json
import logging
import os
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
APPROVALS_COLLECTION = os.environ.get('APPROVALS_COLLECTION', 'soar_approvals')
EXECUTIONS_COLLECTION = os.environ.get('EXECUTIONS_COLLECTION', 'soar_executions')

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


def handle_list_approvals(request: Request) -> tuple:
    """List approval requests with optional filtering."""
    params = request.args

    status = params.get('status', 'pending')
    limit = min(int(params.get('limit', 50)), 100)

    db = _get_firestore_client()
    query = (
        db.collection(APPROVALS_COLLECTION)
        .where('status', '==', status)
        .order_by('created_at', direction=firestore.Query.DESCENDING)
        .limit(limit)
    )

    approvals = []
    for doc in query.stream():
        approval = doc.to_dict()
        approval['id'] = doc.id
        approvals.append(approval)

    return _json_response({
        'approvals': approvals,
        'count': len(approvals),
    })


def handle_get_approval(request: Request, approval_id: str) -> tuple:
    """Get a specific approval request."""
    db = _get_firestore_client()
    doc = db.collection(APPROVALS_COLLECTION).document(approval_id).get()

    if not doc.exists:
        return _error_response(f"Approval not found: {approval_id}", 404)

    approval = doc.to_dict()
    approval['id'] = doc.id

    # Get execution details
    execution_id = approval.get('execution_id')
    if execution_id:
        exec_doc = db.collection(EXECUTIONS_COLLECTION).document(execution_id).get()
        if exec_doc.exists:
            approval['execution'] = exec_doc.to_dict()

    return _json_response(approval)


def handle_approve(request: Request, approval_id: str) -> tuple:
    """Approve an approval request."""
    try:
        body = request.get_json() or {}
    except Exception:
        body = {}

    db = _get_firestore_client()
    doc_ref = db.collection(APPROVALS_COLLECTION).document(approval_id)
    doc = doc_ref.get()

    if not doc.exists:
        return _error_response(f"Approval not found: {approval_id}", 404)

    approval = doc.to_dict()

    if approval.get('status') != 'pending':
        return _error_response(f"Approval is not pending: {approval.get('status')}", 400)

    user_id = _get_user_id(request)
    now = datetime.now(timezone.utc).isoformat()
    notes = body.get('notes', '')

    # Update approval status
    doc_ref.update({
        'status': 'approved',
        'approved_by': user_id,
        'approved_at': now,
        'notes': notes,
    })

    # Update execution to resume
    execution_id = approval.get('execution_id')
    if execution_id:
        db.collection(EXECUTIONS_COLLECTION).document(execution_id).update({
            'approval_status': 'approved',
            'approved_by': user_id,
            'approved_at': now,
        })

    logger.info(f"Approval {approval_id} approved by {user_id}")

    return _json_response({
        'approval_id': approval_id,
        'status': 'approved',
        'approved_by': user_id,
        'approved_at': now,
        'message': 'Approval granted. Execution will resume.',
    })


def handle_deny(request: Request, approval_id: str) -> tuple:
    """Deny an approval request."""
    try:
        body = request.get_json() or {}
    except Exception:
        body = {}

    db = _get_firestore_client()
    doc_ref = db.collection(APPROVALS_COLLECTION).document(approval_id)
    doc = doc_ref.get()

    if not doc.exists:
        return _error_response(f"Approval not found: {approval_id}", 404)

    approval = doc.to_dict()

    if approval.get('status') != 'pending':
        return _error_response(f"Approval is not pending: {approval.get('status')}", 400)

    user_id = _get_user_id(request)
    now = datetime.now(timezone.utc).isoformat()
    reason = body.get('reason', 'No reason provided')

    # Update approval status
    doc_ref.update({
        'status': 'denied',
        'denied_by': user_id,
        'denied_at': now,
        'denial_reason': reason,
    })

    # Update execution to cancelled
    execution_id = approval.get('execution_id')
    if execution_id:
        db.collection(EXECUTIONS_COLLECTION).document(execution_id).update({
            'status': 'cancelled',
            'approval_status': 'denied',
            'denied_by': user_id,
            'denied_at': now,
            'cancelled_reason': f"Approval denied: {reason}",
        })

    logger.info(f"Approval {approval_id} denied by {user_id}: {reason}")

    return _json_response({
        'approval_id': approval_id,
        'status': 'denied',
        'denied_by': user_id,
        'denied_at': now,
        'reason': reason,
        'message': 'Approval denied. Execution has been cancelled.',
    })


def handle_health_check(request: Request) -> tuple:
    """Health check endpoint."""
    return _json_response({
        'status': 'healthy',
        'service': 'approval-handler',
        'timestamp': datetime.now(timezone.utc).isoformat(),
    })


@functions_framework.http
def approval_handler(request: Request) -> tuple:
    """Main entry point for Approval Handler."""
    if request.method == 'OPTIONS':
        return ('', 204, _cors_headers())

    path = request.path
    method = request.method

    # Normalize path
    for prefix in ['/api/soar', '/soar']:
        if path.startswith(prefix):
            path = path[len(prefix):]
            break

    logger.info(f"Approval Handler request: {method} {path}")

    try:
        if path == '/health' and method == 'GET':
            return handle_health_check(request)

        if path == '/approvals' and method == 'GET':
            return handle_list_approvals(request)

        # Match /approvals/{id}
        if path.startswith('/approvals/') and method == 'GET':
            parts = path.split('/')
            if len(parts) == 3:
                return handle_get_approval(request, parts[2])

        # Match /approvals/{id}/approve
        if path.endswith('/approve') and method == 'POST':
            parts = path.split('/')
            if len(parts) == 4 and parts[1] == 'approvals':
                return handle_approve(request, parts[2])

        # Match /approvals/{id}/deny
        if path.endswith('/deny') and method == 'POST':
            parts = path.split('/')
            if len(parts) == 4 and parts[1] == 'approvals':
                return handle_deny(request, parts[2])

        return _error_response(f"Not found: {method} {path}", 404)

    except Exception as e:
        logger.error(f"Request failed: {e}", exc_info=True)
        return _error_response(f"Internal error: {str(e)}", 500)
