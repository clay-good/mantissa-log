"""SOAR API Cloud Function

Handles SOAR (Security Orchestration, Automation and Response) API requests.
Provides endpoints for playbook management, execution, and quick actions.

Environment variables:
- PROJECT_ID: GCP project ID
- PLAYBOOKS_BUCKET: GCS bucket for playbook storage
- FIRESTORE_COLLECTION: Firestore collection for playbook metadata
- EXECUTOR_FUNCTION: Name of the playbook executor function
"""

import json
import logging
import os
import re
import sys
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from uuid import uuid4

import functions_framework
from flask import Request
from google.cloud import firestore
from google.cloud import storage
from google.cloud import functions_v2

# Add shared modules path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../../../shared'))

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Configuration
PROJECT_ID = os.environ.get('PROJECT_ID', '')
PLAYBOOKS_BUCKET = os.environ.get('PLAYBOOKS_BUCKET', 'mantissa-soar-playbooks')
FIRESTORE_COLLECTION = os.environ.get('FIRESTORE_COLLECTION', 'soar_playbooks')
EXECUTOR_FUNCTION = os.environ.get('EXECUTOR_FUNCTION', 'playbook-executor')
REGION = os.environ.get('REGION', 'us-central1')

# Clients (lazy initialization)
_firestore_client: Optional[firestore.Client] = None
_storage_client: Optional[storage.Client] = None


def _get_firestore_client() -> firestore.Client:
    """Get lazily-initialized Firestore client."""
    global _firestore_client
    if _firestore_client is None:
        _firestore_client = firestore.Client(project=PROJECT_ID)
    return _firestore_client


def _get_storage_client() -> storage.Client:
    """Get lazily-initialized Storage client."""
    global _storage_client
    if _storage_client is None:
        _storage_client = storage.Client(project=PROJECT_ID)
    return _storage_client


def _cors_headers() -> Dict[str, str]:
    """Return CORS headers."""
    return {
        'Access-Control-Allow-Origin': '*',
        'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
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
        # In production, decode JWT to get user ID
        # For now, use a placeholder
        return 'user@example.com'
    return request.headers.get('X-User-Id', 'anonymous')


# Playbook Management


def handle_list_playbooks(request: Request) -> tuple:
    """List all playbooks with optional filtering."""
    params = request.args

    # Parse query parameters
    status = params.get('status')
    tag = params.get('tag')
    limit = min(int(params.get('limit', 50)), 100)

    db = _get_firestore_client()
    collection = db.collection(FIRESTORE_COLLECTION)

    # Build query
    query = collection.order_by('updated_at', direction=firestore.Query.DESCENDING)

    if status:
        query = query.where('status', '==', status)

    # Execute query
    docs = query.limit(limit).stream()

    playbooks = []
    for doc in docs:
        playbook = doc.to_dict()
        playbook['id'] = doc.id

        # Filter by tag if specified
        if tag and tag not in playbook.get('tags', []):
            continue

        playbooks.append(playbook)

    return _json_response({
        'playbooks': playbooks,
        'count': len(playbooks),
    })


def handle_create_playbook(request: Request) -> tuple:
    """Create a new playbook."""
    try:
        body = request.get_json()
    except Exception:
        return _error_response('Invalid JSON body')

    # Validate required fields
    name = body.get('name')
    if not name:
        return _error_response('name is required')

    user_id = _get_user_id(request)
    playbook_id = f"pb-{uuid4().hex[:12]}"
    now = datetime.now(timezone.utc).isoformat()

    # Build playbook document
    playbook = {
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

    # Store in Firestore
    db = _get_firestore_client()
    db.collection(FIRESTORE_COLLECTION).document(playbook_id).set(playbook)

    playbook['id'] = playbook_id

    logger.info(f"Created playbook {playbook_id}: {name}")

    return _json_response(playbook, 201)


def handle_get_playbook(request: Request, playbook_id: str) -> tuple:
    """Get a specific playbook by ID."""
    db = _get_firestore_client()
    doc = db.collection(FIRESTORE_COLLECTION).document(playbook_id).get()

    if not doc.exists:
        return _error_response(f"Playbook not found: {playbook_id}", 404)

    playbook = doc.to_dict()
    playbook['id'] = doc.id

    return _json_response(playbook)


def handle_update_playbook(request: Request, playbook_id: str) -> tuple:
    """Update an existing playbook."""
    try:
        body = request.get_json()
    except Exception:
        return _error_response('Invalid JSON body')

    db = _get_firestore_client()
    doc_ref = db.collection(FIRESTORE_COLLECTION).document(playbook_id)
    doc = doc_ref.get()

    if not doc.exists:
        return _error_response(f"Playbook not found: {playbook_id}", 404)

    user_id = _get_user_id(request)
    current = doc.to_dict()

    # Build update
    update = {
        'updated_at': datetime.now(timezone.utc).isoformat(),
        'updated_by': user_id,
    }

    # Allowed fields to update
    for field in ['name', 'description', 'status', 'tags', 'trigger_types', 'steps']:
        if field in body:
            update[field] = body[field]

    # Increment version if steps changed
    if 'steps' in body:
        update['version'] = current.get('version', 0) + 1

    doc_ref.update(update)

    # Get updated document
    updated = doc_ref.get().to_dict()
    updated['id'] = playbook_id

    logger.info(f"Updated playbook {playbook_id}")

    return _json_response(updated)


def handle_delete_playbook(request: Request, playbook_id: str) -> tuple:
    """Delete a playbook."""
    db = _get_firestore_client()
    doc_ref = db.collection(FIRESTORE_COLLECTION).document(playbook_id)
    doc = doc_ref.get()

    if not doc.exists:
        return _error_response(f"Playbook not found: {playbook_id}", 404)

    # Soft delete by setting status
    doc_ref.update({
        'status': 'deleted',
        'deleted_at': datetime.now(timezone.utc).isoformat(),
        'deleted_by': _get_user_id(request),
    })

    logger.info(f"Deleted playbook {playbook_id}")

    return _json_response({'message': f"Playbook {playbook_id} deleted"})


def handle_get_playbook_versions(request: Request, playbook_id: str) -> tuple:
    """Get version history for a playbook."""
    db = _get_firestore_client()

    # Get versions from subcollection
    versions_ref = (
        db.collection(FIRESTORE_COLLECTION)
        .document(playbook_id)
        .collection('versions')
        .order_by('version', direction=firestore.Query.DESCENDING)
    )

    versions = []
    for doc in versions_ref.stream():
        version = doc.to_dict()
        version['id'] = doc.id
        versions.append(version)

    # If no version history, return current version
    if not versions:
        current = db.collection(FIRESTORE_COLLECTION).document(playbook_id).get()
        if current.exists:
            data = current.to_dict()
            versions = [{
                'version': data.get('version', 1),
                'created_at': data.get('created_at'),
                'created_by': data.get('created_by'),
            }]

    return _json_response({
        'playbook_id': playbook_id,
        'versions': versions,
        'count': len(versions),
    })


def handle_get_playbook_code(request: Request, playbook_id: str) -> tuple:
    """Get generated code for a playbook."""
    storage = _get_storage_client()
    bucket = storage.bucket(PLAYBOOKS_BUCKET)

    # Try to get generated code
    blob = bucket.blob(f"generated/{playbook_id}/handler.py")

    if not blob.exists():
        return _error_response(f"Generated code not found for playbook {playbook_id}", 404)

    code = blob.download_as_text()

    return _json_response({
        'playbook_id': playbook_id,
        'code': code,
        'language': 'python',
    })


def handle_deploy_playbook(request: Request, playbook_id: str) -> tuple:
    """Deploy a playbook (activate for execution)."""
    db = _get_firestore_client()
    doc_ref = db.collection(FIRESTORE_COLLECTION).document(playbook_id)
    doc = doc_ref.get()

    if not doc.exists:
        return _error_response(f"Playbook not found: {playbook_id}", 404)

    playbook = doc.to_dict()

    # Validate playbook has steps
    if not playbook.get('steps'):
        return _error_response("Playbook has no steps defined", 400)

    user_id = _get_user_id(request)
    now = datetime.now(timezone.utc).isoformat()

    # Save current version before deploying
    version_data = {
        **playbook,
        'deployed_at': now,
        'deployed_by': user_id,
    }
    doc_ref.collection('versions').document(f"v{playbook.get('version', 1)}").set(version_data)

    # Update status to deployed
    doc_ref.update({
        'status': 'deployed',
        'deployed_at': now,
        'deployed_by': user_id,
    })

    logger.info(f"Deployed playbook {playbook_id}")

    return _json_response({
        'playbook_id': playbook_id,
        'status': 'deployed',
        'deployed_at': now,
        'message': 'Playbook deployed successfully',
    })


def handle_generate_playbook(request: Request) -> tuple:
    """Generate playbook from natural language description."""
    try:
        body = request.get_json()
    except Exception:
        return _error_response('Invalid JSON body')

    description = body.get('description')
    if not description:
        return _error_response('description is required')

    # This would integrate with LLM service
    # For now, return a template
    generated = {
        'name': body.get('name', 'Generated Playbook'),
        'description': description,
        'steps': [
            {
                'id': 'step-1',
                'name': 'Analyze Input',
                'action': 'analyze',
                'parameters': {},
            },
            {
                'id': 'step-2',
                'name': 'Execute Response',
                'action': 'execute',
                'parameters': {},
            },
            {
                'id': 'step-3',
                'name': 'Report Results',
                'action': 'notify',
                'parameters': {},
            },
        ],
        'generated': True,
        'generated_at': datetime.now(timezone.utc).isoformat(),
    }

    return _json_response(generated)


def handle_parse_ir_plan(request: Request) -> tuple:
    """Parse incident response plan into playbook structure."""
    try:
        body = request.get_json()
    except Exception:
        return _error_response('Invalid JSON body')

    ir_plan = body.get('ir_plan') or body.get('plan')
    if not ir_plan:
        return _error_response('ir_plan is required')

    # Parse IR plan (simplified - would use LLM in production)
    lines = ir_plan.strip().split('\n')
    steps = []

    for i, line in enumerate(lines):
        line = line.strip()
        if not line or line.startswith('#'):
            continue

        # Remove list markers
        line = re.sub(r'^[\d\.\-\*]+\s*', '', line)

        if line:
            steps.append({
                'id': f'step-{i+1}',
                'name': line[:50],
                'description': line,
                'action': 'manual',
                'parameters': {},
            })

    return _json_response({
        'steps': steps,
        'count': len(steps),
        'parsed_at': datetime.now(timezone.utc).isoformat(),
    })


# Execution Management


def handle_create_execution(request: Request) -> tuple:
    """Create a new playbook execution."""
    try:
        body = request.get_json()
    except Exception:
        return _error_response('Invalid JSON body')

    playbook_id = body.get('playbook_id')
    if not playbook_id:
        return _error_response('playbook_id is required')

    # Verify playbook exists
    db = _get_firestore_client()
    playbook_doc = db.collection(FIRESTORE_COLLECTION).document(playbook_id).get()

    if not playbook_doc.exists:
        return _error_response(f"Playbook not found: {playbook_id}", 404)

    user_id = _get_user_id(request)
    execution_id = f"exec-{uuid4().hex[:12]}"
    now = datetime.now(timezone.utc).isoformat()

    # Create execution record
    execution = {
        'playbook_id': playbook_id,
        'playbook_name': playbook_doc.to_dict().get('name'),
        'status': 'pending',
        'trigger_type': body.get('trigger_type', 'manual'),
        'trigger_context': body.get('context', {}),
        'parameters': body.get('parameters', {}),
        'dry_run': body.get('dry_run', False),
        'initiated_by': user_id,
        'created_at': now,
        'updated_at': now,
    }

    db.collection('soar_executions').document(execution_id).set(execution)

    # Invoke executor function asynchronously
    # In production, this would trigger the executor Cloud Function
    execution['id'] = execution_id

    logger.info(f"Created execution {execution_id} for playbook {playbook_id}")

    return _json_response(execution, 201)


# ============================================================================
# Execution Handlers (for unified API)
# ============================================================================


def handle_list_executions(request: Request) -> tuple:
    """List executions with optional filtering."""
    params = request.args

    status = params.get('status')
    playbook_id = params.get('playbook_id')
    limit = min(int(params.get('limit', 50)), 100)

    db = _get_firestore_client()
    query = db.collection('soar_executions').order_by(
        'created_at', direction=firestore.Query.DESCENDING
    )

    if status:
        query = query.where('status', '==', status)
    if playbook_id:
        query = query.where('playbook_id', '==', playbook_id)

    docs = query.limit(limit).stream()

    executions = []
    for doc in docs:
        execution = doc.to_dict()
        execution['id'] = doc.id
        executions.append(execution)

    return _json_response({
        'executions': executions,
        'count': len(executions),
    })


def handle_get_execution(request: Request, execution_id: str) -> tuple:
    """Get a specific execution by ID."""
    db = _get_firestore_client()
    doc = db.collection('soar_executions').document(execution_id).get()

    if not doc.exists:
        return _error_response(f"Execution not found: {execution_id}", 404)

    execution = doc.to_dict()
    execution['id'] = doc.id

    return _json_response({'execution': execution})


def handle_get_execution_logs(request: Request, execution_id: str) -> tuple:
    """Get logs for a specific execution."""
    params = request.args
    limit = min(int(params.get('limit', 100)), 500)

    db = _get_firestore_client()

    # Verify execution exists
    exec_doc = db.collection('soar_executions').document(execution_id).get()
    if not exec_doc.exists:
        return _error_response(f"Execution not found: {execution_id}", 404)

    # Get action logs
    logs_query = (
        db.collection('soar_action_log')
        .where('execution_id', '==', execution_id)
        .order_by('timestamp')
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
    try:
        body = request.get_json() or {}
    except Exception:
        body = {}

    db = _get_firestore_client()
    doc_ref = db.collection('soar_executions').document(execution_id)
    doc = doc_ref.get()

    if not doc.exists:
        return _error_response(f"Execution not found: {execution_id}", 404)

    current = doc.to_dict()
    current_status = current.get('status')

    cancellable_statuses = ['pending', 'running', 'paused', 'waiting_approval']
    if current_status not in cancellable_statuses:
        return _error_response(f"Cannot cancel execution in status: {current_status}", 400)

    user_id = _get_user_id(request)
    now = datetime.now(timezone.utc).isoformat()
    reason = body.get('reason', 'Cancelled by user')

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
        'message': 'Execution cancelled successfully',
    })


# ============================================================================
# Approval Handlers (for unified API)
# ============================================================================


def handle_list_approvals(request: Request) -> tuple:
    """List approval requests with optional filtering."""
    params = request.args

    status = params.get('status', 'pending')
    limit = min(int(params.get('limit', 50)), 100)

    db = _get_firestore_client()
    query = (
        db.collection('soar_approvals')
        .where('status', '==', status)
        .order_by('requested_at', direction=firestore.Query.DESCENDING)
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
    doc = db.collection('soar_approvals').document(approval_id).get()

    if not doc.exists:
        return _error_response(f"Approval not found: {approval_id}", 404)

    approval = doc.to_dict()
    approval['id'] = doc.id

    # Get related execution if exists
    execution_id = approval.get('execution_id')
    if execution_id:
        exec_doc = db.collection('soar_executions').document(execution_id).get()
        if exec_doc.exists:
            execution = exec_doc.to_dict()
            execution['id'] = exec_doc.id
            approval['execution'] = execution

    return _json_response({'approval': approval})


def handle_approve(request: Request, approval_id: str) -> tuple:
    """Approve an approval request."""
    try:
        body = request.get_json() or {}
    except Exception:
        body = {}

    db = _get_firestore_client()
    doc_ref = db.collection('soar_approvals').document(approval_id)
    doc = doc_ref.get()

    if not doc.exists:
        return _error_response(f"Approval not found: {approval_id}", 404)

    approval = doc.to_dict()
    if approval.get('status') != 'pending':
        return _error_response(f"Approval is not pending: {approval.get('status')}", 400)

    user_id = _get_user_id(request)
    now = datetime.now(timezone.utc).isoformat()
    notes = body.get('notes', '')

    # Update approval
    doc_ref.update({
        'status': 'approved',
        'approved_by': user_id,
        'approved_at': now,
        'notes': notes,
    })

    # Update related execution
    execution_id = approval.get('execution_id')
    if execution_id:
        db.collection('soar_executions').document(execution_id).update({
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
    doc_ref = db.collection('soar_approvals').document(approval_id)
    doc = doc_ref.get()

    if not doc.exists:
        return _error_response(f"Approval not found: {approval_id}", 404)

    approval = doc.to_dict()
    if approval.get('status') != 'pending':
        return _error_response(f"Approval is not pending: {approval.get('status')}", 400)

    user_id = _get_user_id(request)
    now = datetime.now(timezone.utc).isoformat()
    reason = body.get('reason', 'No reason provided')

    # Update approval
    doc_ref.update({
        'status': 'denied',
        'denied_by': user_id,
        'denied_at': now,
        'denial_reason': reason,
    })

    # Update related execution to cancelled
    execution_id = approval.get('execution_id')
    if execution_id:
        db.collection('soar_executions').document(execution_id).update({
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


# ============================================================================
# Quick Actions
# ============================================================================


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


def handle_list_quick_actions(request: Request) -> tuple:
    """List available quick actions."""
    return _json_response({
        'actions': list(QUICK_ACTIONS.values()),
        'count': len(QUICK_ACTIONS),
    })


def handle_execute_quick_action(request: Request) -> tuple:
    """Execute a quick action."""
    try:
        body = request.get_json()
    except Exception:
        return _error_response('Invalid JSON body')

    action_id = body.get('action_id')
    if not action_id:
        return _error_response('action_id is required')

    if action_id not in QUICK_ACTIONS:
        return _error_response(f"Unknown action: {action_id}", 404)

    action = QUICK_ACTIONS[action_id]
    user_id = _get_user_id(request)
    execution_id = f"qa-{uuid4().hex[:12]}"
    now = datetime.now(timezone.utc).isoformat()

    # Check required parameters
    params = body.get('parameters', {})
    missing = []
    for param in action['parameters']:
        if param.get('required') and param['name'] not in params:
            missing.append(param['name'])
    if missing:
        return _error_response(f"Missing required parameters: {missing}")

    # Create execution record
    db = _get_firestore_client()
    execution = {
        'action_id': action_id,
        'action_name': action['name'],
        'parameters': params,
        'status': 'pending_approval' if action['requires_approval'] else 'executing',
        'initiated_by': user_id,
        'created_at': now,
        'alert_id': body.get('alert_id'),
    }

    db.collection('soar_quick_actions').document(execution_id).set(execution)

    # If requires approval, create approval request
    if action['requires_approval']:
        approval_id = f"apr-{uuid4().hex[:12]}"
        approval = {
            'execution_id': execution_id,
            'action_id': action_id,
            'action_name': action['name'],
            'parameters': params,
            'requested_by': user_id,
            'requested_at': now,
            'status': 'pending',
        }
        db.collection('soar_approvals').document(approval_id).set(approval)
        execution['approval_id'] = approval_id

    execution['id'] = execution_id

    logger.info(f"Quick action {action_id} initiated: {execution_id}")

    return _json_response(execution, 201)


def handle_health_check(request: Request) -> tuple:
    """Health check endpoint."""
    return _json_response({
        'status': 'healthy',
        'service': 'soar-api',
        'timestamp': datetime.now(timezone.utc).isoformat(),
    })


@functions_framework.http
def soar_api(request: Request) -> tuple:
    """Main entry point for SOAR API."""
    # Handle CORS preflight
    if request.method == 'OPTIONS':
        return ('', 204, _cors_headers())

    path = request.path
    method = request.method

    # Normalize path
    for prefix in ['/api/soar', '/soar']:
        if path.startswith(prefix):
            path = path[len(prefix):]
            break

    if not path:
        path = '/'

    logger.info(f"SOAR API request: {method} {path}")

    try:
        # Health check
        if path == '/health' and method == 'GET':
            return handle_health_check(request)

        # Playbooks
        if path == '/playbooks' and method == 'GET':
            return handle_list_playbooks(request)

        if path == '/playbooks' and method == 'POST':
            return handle_create_playbook(request)

        if path == '/playbooks/generate' and method == 'POST':
            return handle_generate_playbook(request)

        if path == '/playbooks/parse-ir-plan' and method == 'POST':
            return handle_parse_ir_plan(request)

        # Playbook by ID routes
        playbook_pattern = r'^/playbooks/([^/]+)$'
        match = re.match(playbook_pattern, path)
        if match:
            playbook_id = match.group(1)
            if method == 'GET':
                return handle_get_playbook(request, playbook_id)
            if method == 'PUT':
                return handle_update_playbook(request, playbook_id)
            if method == 'DELETE':
                return handle_delete_playbook(request, playbook_id)

        # Playbook sub-routes
        versions_pattern = r'^/playbooks/([^/]+)/versions$'
        match = re.match(versions_pattern, path)
        if match and method == 'GET':
            return handle_get_playbook_versions(request, match.group(1))

        code_pattern = r'^/playbooks/([^/]+)/code$'
        match = re.match(code_pattern, path)
        if match and method == 'GET':
            return handle_get_playbook_code(request, match.group(1))

        deploy_pattern = r'^/playbooks/([^/]+)/deploy$'
        match = re.match(deploy_pattern, path)
        if match and method == 'POST':
            return handle_deploy_playbook(request, match.group(1))

        # Execution routes (unified API)
        if path == '/executions' and method == 'GET':
            return handle_list_executions(request)

        if path == '/executions' and method == 'POST':
            return handle_create_execution(request)

        # Execution by ID routes
        exec_pattern = r'^/executions/([^/]+)$'
        match = re.match(exec_pattern, path)
        if match and method == 'GET':
            return handle_get_execution(request, match.group(1))

        # Execution logs route
        logs_pattern = r'^/executions/([^/]+)/logs$'
        match = re.match(logs_pattern, path)
        if match and method == 'GET':
            return handle_get_execution_logs(request, match.group(1))

        # Execution cancel route
        cancel_pattern = r'^/executions/([^/]+)/cancel$'
        match = re.match(cancel_pattern, path)
        if match and method == 'POST':
            return handle_cancel_execution(request, match.group(1))

        # Approval routes (unified API)
        if path == '/approvals' and method == 'GET':
            return handle_list_approvals(request)

        # Approval by ID route
        approval_pattern = r'^/approvals/([^/]+)$'
        match = re.match(approval_pattern, path)
        if match and method == 'GET':
            return handle_get_approval(request, match.group(1))

        # Approval approve route
        approve_pattern = r'^/approvals/([^/]+)/approve$'
        match = re.match(approve_pattern, path)
        if match and method == 'POST':
            return handle_approve(request, match.group(1))

        # Approval deny route
        deny_pattern = r'^/approvals/([^/]+)/deny$'
        match = re.match(deny_pattern, path)
        if match and method == 'POST':
            return handle_deny(request, match.group(1))

        # Quick actions
        if path == '/quick-actions/available' and method == 'GET':
            return handle_list_quick_actions(request)

        if path == '/quick-actions' and method == 'POST':
            return handle_execute_quick_action(request)

        return _error_response(f"Not found: {method} {path}", 404)

    except Exception as e:
        logger.error(f"Request failed: {e}", exc_info=True)
        return _error_response(f"Internal error: {str(e)}", 500)
