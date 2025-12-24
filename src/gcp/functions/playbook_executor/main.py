"""Playbook Executor Cloud Function

Executes SOAR playbooks. Can be triggered by:
- HTTP request (manual execution)
- Pub/Sub message (alert-triggered)
- Cloud Scheduler (scheduled execution)

Environment variables:
- PROJECT_ID: GCP project ID
- FIRESTORE_COLLECTION: Firestore collection for playbook storage
- EXECUTIONS_COLLECTION: Firestore collection for execution tracking
- APPROVALS_COLLECTION: Firestore collection for approval requests
- ACTION_LOG_COLLECTION: Firestore collection for action logging
"""

import json
import logging
import os
import sys
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from uuid import uuid4
from enum import Enum

import functions_framework
from flask import Request
from google.cloud import firestore
from google.cloud import pubsub_v1

# Add shared modules path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../../../shared'))

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Configuration
PROJECT_ID = os.environ.get('PROJECT_ID', '')
FIRESTORE_COLLECTION = os.environ.get('FIRESTORE_COLLECTION', 'soar_playbooks')
EXECUTIONS_COLLECTION = os.environ.get('EXECUTIONS_COLLECTION', 'soar_executions')
APPROVALS_COLLECTION = os.environ.get('APPROVALS_COLLECTION', 'soar_approvals')
ACTION_LOG_COLLECTION = os.environ.get('ACTION_LOG_COLLECTION', 'soar_action_log')
DEFAULT_DRY_RUN = os.environ.get('DEFAULT_DRY_RUN', 'true').lower() == 'true'

# Clients
_firestore_client: Optional[firestore.Client] = None
_pubsub_client: Optional[pubsub_v1.PublisherClient] = None


class ExecutionStatus(str, Enum):
    PENDING = 'pending'
    RUNNING = 'running'
    PAUSED = 'paused'
    WAITING_APPROVAL = 'waiting_approval'
    COMPLETED = 'completed'
    FAILED = 'failed'
    CANCELLED = 'cancelled'


class StepStatus(str, Enum):
    PENDING = 'pending'
    RUNNING = 'running'
    COMPLETED = 'completed'
    FAILED = 'failed'
    SKIPPED = 'skipped'


def _get_firestore_client() -> firestore.Client:
    """Get lazily-initialized Firestore client."""
    global _firestore_client
    if _firestore_client is None:
        _firestore_client = firestore.Client(project=PROJECT_ID)
    return _firestore_client


def _get_pubsub_client() -> pubsub_v1.PublisherClient:
    """Get lazily-initialized Pub/Sub client."""
    global _pubsub_client
    if _pubsub_client is None:
        _pubsub_client = pubsub_v1.PublisherClient()
    return _pubsub_client


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


def log_action(
    execution_id: str,
    step_id: str,
    action: str,
    status: str,
    details: Dict[str, Any],
    dry_run: bool = False,
) -> None:
    """Log an action to the action log."""
    db = _get_firestore_client()
    log_entry = {
        'execution_id': execution_id,
        'step_id': step_id,
        'action': action,
        'status': status,
        'details': details,
        'dry_run': dry_run,
        'timestamp': datetime.now(timezone.utc).isoformat(),
    }
    db.collection(ACTION_LOG_COLLECTION).add(log_entry)


def update_execution_status(
    execution_id: str,
    status: ExecutionStatus,
    current_step: Optional[str] = None,
    error: Optional[str] = None,
) -> None:
    """Update execution status in Firestore."""
    db = _get_firestore_client()
    update = {
        'status': status.value,
        'updated_at': datetime.now(timezone.utc).isoformat(),
    }
    if current_step:
        update['current_step'] = current_step
    if error:
        update['error'] = error
    if status in [ExecutionStatus.COMPLETED, ExecutionStatus.FAILED, ExecutionStatus.CANCELLED]:
        update['completed_at'] = datetime.now(timezone.utc).isoformat()

    db.collection(EXECUTIONS_COLLECTION).document(execution_id).update(update)


def create_approval_request(
    execution_id: str,
    step_id: str,
    step_name: str,
    action: str,
    details: Dict[str, Any],
) -> str:
    """Create an approval request for a step."""
    db = _get_firestore_client()
    approval_id = f"apr-{uuid4().hex[:12]}"
    now = datetime.now(timezone.utc).isoformat()

    approval = {
        'execution_id': execution_id,
        'step_id': step_id,
        'step_name': step_name,
        'action': action,
        'details': details,
        'status': 'pending',
        'created_at': now,
    }

    db.collection(APPROVALS_COLLECTION).document(approval_id).set(approval)

    logger.info(f"Created approval request {approval_id} for execution {execution_id}")
    return approval_id


# Action Executors


def execute_action_notify(params: Dict[str, Any], dry_run: bool) -> Dict[str, Any]:
    """Execute a notification action."""
    if dry_run:
        return {'status': 'dry_run', 'message': 'Would send notification'}

    # In production, integrate with notification service
    return {
        'status': 'completed',
        'message': f"Notification sent to {params.get('recipients', 'default')}",
    }


def execute_action_isolate_host(params: Dict[str, Any], dry_run: bool) -> Dict[str, Any]:
    """Execute host isolation action."""
    host_id = params.get('host_id')
    if not host_id:
        return {'status': 'failed', 'error': 'host_id is required'}

    if dry_run:
        return {'status': 'dry_run', 'message': f'Would isolate host {host_id}'}

    # In production, integrate with EDR/network management
    return {
        'status': 'completed',
        'message': f'Host {host_id} isolated',
        'host_id': host_id,
    }


def execute_action_block_ip(params: Dict[str, Any], dry_run: bool) -> Dict[str, Any]:
    """Execute IP blocking action."""
    ip_address = params.get('ip_address')
    if not ip_address:
        return {'status': 'failed', 'error': 'ip_address is required'}

    if dry_run:
        return {'status': 'dry_run', 'message': f'Would block IP {ip_address}'}

    # In production, integrate with firewall/WAF
    return {
        'status': 'completed',
        'message': f'IP {ip_address} blocked',
        'ip_address': ip_address,
    }


def execute_action_disable_user(params: Dict[str, Any], dry_run: bool) -> Dict[str, Any]:
    """Execute user account disable action."""
    user_id = params.get('user_id')
    if not user_id:
        return {'status': 'failed', 'error': 'user_id is required'}

    if dry_run:
        return {'status': 'dry_run', 'message': f'Would disable user {user_id}'}

    # In production, integrate with IAM
    return {
        'status': 'completed',
        'message': f'User {user_id} disabled',
        'user_id': user_id,
    }


def execute_action_create_ticket(params: Dict[str, Any], dry_run: bool) -> Dict[str, Any]:
    """Execute ticket creation action."""
    if dry_run:
        return {'status': 'dry_run', 'message': 'Would create ticket'}

    # In production, integrate with ticketing system
    ticket_id = f"TKT-{uuid4().hex[:8].upper()}"
    return {
        'status': 'completed',
        'message': f'Ticket {ticket_id} created',
        'ticket_id': ticket_id,
    }


def execute_action_enrich(params: Dict[str, Any], dry_run: bool) -> Dict[str, Any]:
    """Execute data enrichment action."""
    if dry_run:
        return {'status': 'dry_run', 'message': 'Would enrich data'}

    # In production, call threat intelligence APIs
    return {
        'status': 'completed',
        'message': 'Data enriched',
        'enrichment': {
            'source': 'threat_intel',
            'data': params,
        },
    }


ACTION_EXECUTORS = {
    'notify': execute_action_notify,
    'isolate_host': execute_action_isolate_host,
    'block_ip': execute_action_block_ip,
    'disable_user': execute_action_disable_user,
    'create_ticket': execute_action_create_ticket,
    'enrich': execute_action_enrich,
}


# High-risk actions that require approval
HIGH_RISK_ACTIONS = {'isolate_host', 'disable_user', 'block_ip'}


def execute_step(
    execution_id: str,
    step: Dict[str, Any],
    context: Dict[str, Any],
    dry_run: bool,
) -> Dict[str, Any]:
    """Execute a single playbook step."""
    step_id = step.get('id', 'unknown')
    action = step.get('action', 'unknown')
    params = {**step.get('parameters', {}), **context}

    logger.info(f"Executing step {step_id}: action={action}, dry_run={dry_run}")

    # Check if action requires approval (and not in dry_run mode)
    if action in HIGH_RISK_ACTIONS and not dry_run:
        # Create approval request and pause
        approval_id = create_approval_request(
            execution_id=execution_id,
            step_id=step_id,
            step_name=step.get('name', action),
            action=action,
            details=params,
        )
        return {
            'status': StepStatus.PENDING.value,
            'requires_approval': True,
            'approval_id': approval_id,
        }

    # Execute the action
    executor = ACTION_EXECUTORS.get(action)
    if not executor:
        return {
            'status': StepStatus.FAILED.value,
            'error': f'Unknown action: {action}',
        }

    try:
        result = executor(params, dry_run)
        log_action(
            execution_id=execution_id,
            step_id=step_id,
            action=action,
            status=result.get('status', 'unknown'),
            details=result,
            dry_run=dry_run,
        )
        return {
            'status': StepStatus.COMPLETED.value if result.get('status') != 'failed' else StepStatus.FAILED.value,
            'result': result,
        }
    except Exception as e:
        logger.error(f"Step {step_id} failed: {e}")
        return {
            'status': StepStatus.FAILED.value,
            'error': str(e),
        }


def execute_playbook(
    playbook_id: str,
    execution_id: str,
    trigger_context: Dict[str, Any],
    dry_run: bool,
) -> Dict[str, Any]:
    """Execute a playbook."""
    db = _get_firestore_client()

    # Get playbook
    playbook_doc = db.collection(FIRESTORE_COLLECTION).document(playbook_id).get()
    if not playbook_doc.exists:
        raise ValueError(f"Playbook not found: {playbook_id}")

    playbook = playbook_doc.to_dict()
    steps = playbook.get('steps', [])

    if not steps:
        raise ValueError(f"Playbook {playbook_id} has no steps")

    logger.info(f"Executing playbook {playbook_id} with {len(steps)} steps, dry_run={dry_run}")

    # Update execution status to running
    update_execution_status(execution_id, ExecutionStatus.RUNNING)

    # Execute steps
    step_results = []
    execution_context = {**trigger_context}

    for i, step in enumerate(steps):
        step_id = step.get('id', f'step-{i+1}')
        update_execution_status(execution_id, ExecutionStatus.RUNNING, current_step=step_id)

        result = execute_step(execution_id, step, execution_context, dry_run)
        step_results.append({
            'step_id': step_id,
            'step_name': step.get('name', step_id),
            **result,
        })

        # Check if step requires approval - pause execution
        if result.get('requires_approval'):
            update_execution_status(execution_id, ExecutionStatus.WAITING_APPROVAL, current_step=step_id)
            return {
                'execution_id': execution_id,
                'status': ExecutionStatus.WAITING_APPROVAL.value,
                'current_step': step_id,
                'approval_id': result.get('approval_id'),
                'step_results': step_results,
            }

        # Check if step failed - abort execution
        if result.get('status') == StepStatus.FAILED.value:
            update_execution_status(
                execution_id,
                ExecutionStatus.FAILED,
                current_step=step_id,
                error=result.get('error'),
            )
            return {
                'execution_id': execution_id,
                'status': ExecutionStatus.FAILED.value,
                'error': result.get('error'),
                'step_results': step_results,
            }

        # Add step output to context for next steps
        if result.get('result'):
            execution_context[f'{step_id}_output'] = result['result']

    # All steps completed
    update_execution_status(execution_id, ExecutionStatus.COMPLETED)

    return {
        'execution_id': execution_id,
        'status': ExecutionStatus.COMPLETED.value,
        'step_results': step_results,
    }


def handle_execute(request: Request) -> tuple:
    """Handle execution request."""
    try:
        body = request.get_json()
    except Exception:
        return _error_response('Invalid JSON body')

    playbook_id = body.get('playbook_id')
    if not playbook_id:
        return _error_response('playbook_id is required')

    execution_id = body.get('execution_id') or f"exec-{uuid4().hex[:12]}"
    trigger_context = body.get('context', {})
    dry_run = body.get('dry_run', DEFAULT_DRY_RUN)

    # Create execution record if not exists
    db = _get_firestore_client()
    exec_doc = db.collection(EXECUTIONS_COLLECTION).document(execution_id).get()

    if not exec_doc.exists:
        now = datetime.now(timezone.utc).isoformat()
        db.collection(EXECUTIONS_COLLECTION).document(execution_id).set({
            'playbook_id': playbook_id,
            'status': ExecutionStatus.PENDING.value,
            'trigger_context': trigger_context,
            'dry_run': dry_run,
            'created_at': now,
            'updated_at': now,
        })

    try:
        result = execute_playbook(playbook_id, execution_id, trigger_context, dry_run)
        return _json_response(result)
    except ValueError as e:
        return _error_response(str(e), 400)
    except Exception as e:
        logger.error(f"Execution failed: {e}", exc_info=True)
        update_execution_status(execution_id, ExecutionStatus.FAILED, error=str(e))
        return _error_response(f"Execution failed: {str(e)}", 500)


def handle_resume(request: Request) -> tuple:
    """Handle resume execution after approval."""
    try:
        body = request.get_json()
    except Exception:
        return _error_response('Invalid JSON body')

    execution_id = body.get('execution_id')
    if not execution_id:
        return _error_response('execution_id is required')

    approval_granted = body.get('approval_granted', False)
    approver = body.get('approver', 'unknown')

    db = _get_firestore_client()
    exec_doc = db.collection(EXECUTIONS_COLLECTION).document(execution_id).get()

    if not exec_doc.exists:
        return _error_response(f"Execution not found: {execution_id}", 404)

    execution = exec_doc.to_dict()

    if execution.get('status') != ExecutionStatus.WAITING_APPROVAL.value:
        return _error_response(f"Execution is not waiting for approval", 400)

    if not approval_granted:
        update_execution_status(execution_id, ExecutionStatus.CANCELLED)
        return _json_response({
            'execution_id': execution_id,
            'status': ExecutionStatus.CANCELLED.value,
            'message': 'Execution cancelled - approval denied',
        })

    # Continue execution from current step
    playbook_id = execution.get('playbook_id')
    trigger_context = execution.get('trigger_context', {})
    dry_run = execution.get('dry_run', False)

    try:
        result = execute_playbook(playbook_id, execution_id, trigger_context, dry_run)
        return _json_response(result)
    except Exception as e:
        logger.error(f"Resume failed: {e}", exc_info=True)
        return _error_response(f"Resume failed: {str(e)}", 500)


def handle_health_check(request: Request) -> tuple:
    """Health check endpoint."""
    return _json_response({
        'status': 'healthy',
        'service': 'playbook-executor',
        'timestamp': datetime.now(timezone.utc).isoformat(),
    })


@functions_framework.http
def playbook_executor(request: Request) -> tuple:
    """Main entry point for Playbook Executor."""
    if request.method == 'OPTIONS':
        return ('', 204, _cors_headers())

    path = request.path
    method = request.method

    logger.info(f"Playbook Executor request: {method} {path}")

    try:
        if path == '/health' and method == 'GET':
            return handle_health_check(request)

        if path == '/execute' and method == 'POST':
            return handle_execute(request)

        if path == '/resume' and method == 'POST':
            return handle_resume(request)

        return _error_response(f"Not found: {method} {path}", 404)

    except Exception as e:
        logger.error(f"Request failed: {e}", exc_info=True)
        return _error_response(f"Internal error: {str(e)}", 500)


# Pub/Sub entry point for alert-triggered executions
@functions_framework.cloud_event
def playbook_executor_pubsub(cloud_event):
    """Entry point for Pub/Sub triggered executions."""
    import base64

    logger.info(f"Pub/Sub triggered execution: {cloud_event}")

    try:
        data = base64.b64decode(cloud_event.data['message']['data']).decode()
        payload = json.loads(data)

        playbook_id = payload.get('playbook_id')
        if not playbook_id:
            logger.error("No playbook_id in message")
            return

        execution_id = f"exec-{uuid4().hex[:12]}"
        trigger_context = payload.get('context', {})
        dry_run = payload.get('dry_run', DEFAULT_DRY_RUN)

        result = execute_playbook(playbook_id, execution_id, trigger_context, dry_run)
        logger.info(f"Pub/Sub execution complete: {result}")
        return result

    except Exception as e:
        logger.error(f"Pub/Sub execution failed: {e}", exc_info=True)
        raise
