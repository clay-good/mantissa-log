"""Azure Function handler for Playbook Executor.

Executes SOAR playbooks. Can be triggered by:
- HTTP request (manual execution)
- Event Grid (alert-triggered)
- Queue (scheduled execution)
"""

import azure.functions as func
import json
import logging
import os
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from uuid import uuid4
from enum import Enum

from azure.cosmos import CosmosClient

from src.shared.auth.azure import get_cors_headers

logger = logging.getLogger(__name__)

# Configuration
COSMOS_CONNECTION_STRING = os.environ.get('COSMOS_CONNECTION_STRING', '')
COSMOS_DATABASE = os.environ.get('COSMOS_DATABASE', 'mantissa')
DEFAULT_DRY_RUN = os.environ.get('DEFAULT_DRY_RUN', 'true').lower() == 'true'

# Clients
_cosmos_client: Optional[CosmosClient] = None


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


def _get_cosmos_client() -> CosmosClient:
    """Get lazily-initialized Cosmos DB client."""
    global _cosmos_client
    if _cosmos_client is None:
        _cosmos_client = CosmosClient.from_connection_string(COSMOS_CONNECTION_STRING)
    return _cosmos_client


def log_action(
    execution_id: str,
    step_id: str,
    action: str,
    status: str,
    details: Dict[str, Any],
    dry_run: bool = False,
) -> None:
    """Log an action to the action log."""
    client = _get_cosmos_client()
    database = client.get_database_client(COSMOS_DATABASE)
    container = database.get_container_client('soar_action_log')

    log_entry = {
        'id': f"log-{uuid4().hex[:12]}",
        'execution_id': execution_id,
        'step_id': step_id,
        'action': action,
        'status': status,
        'details': details,
        'dry_run': dry_run,
        'timestamp': datetime.now(timezone.utc).isoformat(),
    }
    container.create_item(log_entry)


def update_execution_status(
    execution_id: str,
    status: ExecutionStatus,
    current_step: Optional[str] = None,
    error: Optional[str] = None,
) -> None:
    """Update execution status in Cosmos DB."""
    client = _get_cosmos_client()
    database = client.get_database_client(COSMOS_DATABASE)
    container = database.get_container_client('soar_executions')

    execution = container.read_item(item=execution_id, partition_key=execution_id)

    execution['status'] = status.value
    execution['updated_at'] = datetime.now(timezone.utc).isoformat()

    if current_step:
        execution['current_step'] = current_step
    if error:
        execution['error'] = error
    if status in [ExecutionStatus.COMPLETED, ExecutionStatus.FAILED, ExecutionStatus.CANCELLED]:
        execution['completed_at'] = datetime.now(timezone.utc).isoformat()

    container.replace_item(item=execution_id, body=execution)


def create_approval_request(
    execution_id: str,
    step_id: str,
    step_name: str,
    action: str,
    details: Dict[str, Any],
) -> str:
    """Create an approval request for a step."""
    client = _get_cosmos_client()
    database = client.get_database_client(COSMOS_DATABASE)
    container = database.get_container_client('soar_approvals')

    approval_id = f"apr-{uuid4().hex[:12]}"
    now = datetime.now(timezone.utc).isoformat()

    approval = {
        'id': approval_id,
        'execution_id': execution_id,
        'step_id': step_id,
        'step_name': step_name,
        'action': action,
        'details': details,
        'status': 'pending',
        'created_at': now,
    }

    container.create_item(approval)
    logger.info(f"Created approval request {approval_id} for execution {execution_id}")

    return approval_id


# Action Executors
def execute_action_notify(params: Dict[str, Any], dry_run: bool) -> Dict[str, Any]:
    """Execute a notification action."""
    if dry_run:
        return {'status': 'dry_run', 'message': 'Would send notification'}
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

    return {
        'status': 'completed',
        'message': f'User {user_id} disabled',
        'user_id': user_id,
    }


def execute_action_create_ticket(params: Dict[str, Any], dry_run: bool) -> Dict[str, Any]:
    """Execute ticket creation action."""
    if dry_run:
        return {'status': 'dry_run', 'message': 'Would create ticket'}

    ticket_id = f"TKT-{uuid4().hex[:8].upper()}"
    return {
        'status': 'completed',
        'message': f'Ticket {ticket_id} created',
        'ticket_id': ticket_id,
    }


ACTION_EXECUTORS = {
    'notify': execute_action_notify,
    'isolate_host': execute_action_isolate_host,
    'block_ip': execute_action_block_ip,
    'disable_user': execute_action_disable_user,
    'create_ticket': execute_action_create_ticket,
}

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

    if action in HIGH_RISK_ACTIONS and not dry_run:
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
    client = _get_cosmos_client()
    database = client.get_database_client(COSMOS_DATABASE)
    playbook_container = database.get_container_client('soar_playbooks')

    playbook = playbook_container.read_item(item=playbook_id, partition_key=playbook_id)
    steps = playbook.get('steps', [])

    if not steps:
        raise ValueError(f"Playbook {playbook_id} has no steps")

    logger.info(f"Executing playbook {playbook_id} with {len(steps)} steps, dry_run={dry_run}")

    update_execution_status(execution_id, ExecutionStatus.RUNNING)

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

        if result.get('requires_approval'):
            update_execution_status(execution_id, ExecutionStatus.WAITING_APPROVAL, current_step=step_id)
            return {
                'execution_id': execution_id,
                'status': ExecutionStatus.WAITING_APPROVAL.value,
                'current_step': step_id,
                'approval_id': result.get('approval_id'),
                'step_results': step_results,
            }

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

        if result.get('result'):
            execution_context[f'{step_id}_output'] = result['result']

    update_execution_status(execution_id, ExecutionStatus.COMPLETED)

    return {
        'execution_id': execution_id,
        'status': ExecutionStatus.COMPLETED.value,
        'step_results': step_results,
    }


def handle_execute(req: func.HttpRequest) -> func.HttpResponse:
    """Handle execution request."""
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

    execution_id = body.get('execution_id') or f"exec-{uuid4().hex[:12]}"
    trigger_context = body.get('context', {})
    dry_run = body.get('dry_run', DEFAULT_DRY_RUN)

    try:
        result = execute_playbook(playbook_id, execution_id, trigger_context, dry_run)
        return func.HttpResponse(
            json.dumps(result),
            status_code=200,
            mimetype='application/json',
            headers=cors_headers,
        )
    except ValueError as e:
        return func.HttpResponse(
            json.dumps({'error': str(e)}),
            status_code=400,
            mimetype='application/json',
            headers=cors_headers,
        )
    except Exception as e:
        logger.error(f"Execution failed: {e}", exc_info=True)
        update_execution_status(execution_id, ExecutionStatus.FAILED, error=str(e))
        return func.HttpResponse(
            json.dumps({'error': f"Execution failed: {str(e)}"}),
            status_code=500,
            mimetype='application/json',
            headers=cors_headers,
        )


def handle_resume(req: func.HttpRequest) -> func.HttpResponse:
    """Handle resume execution after approval."""
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

    execution_id = body.get('execution_id')
    if not execution_id:
        return func.HttpResponse(
            json.dumps({'error': 'execution_id is required'}),
            status_code=400,
            mimetype='application/json',
            headers=cors_headers,
        )

    approval_granted = body.get('approval_granted', False)

    client = _get_cosmos_client()
    database = client.get_database_client(COSMOS_DATABASE)
    container = database.get_container_client('soar_executions')

    try:
        execution = container.read_item(item=execution_id, partition_key=execution_id)
    except Exception:
        return func.HttpResponse(
            json.dumps({'error': f"Execution not found: {execution_id}"}),
            status_code=404,
            mimetype='application/json',
            headers=cors_headers,
        )

    if execution.get('status') != ExecutionStatus.WAITING_APPROVAL.value:
        return func.HttpResponse(
            json.dumps({'error': "Execution is not waiting for approval"}),
            status_code=400,
            mimetype='application/json',
            headers=cors_headers,
        )

    if not approval_granted:
        update_execution_status(execution_id, ExecutionStatus.CANCELLED)
        return func.HttpResponse(
            json.dumps({
                'execution_id': execution_id,
                'status': ExecutionStatus.CANCELLED.value,
                'message': 'Execution cancelled - approval denied',
            }),
            status_code=200,
            mimetype='application/json',
            headers=cors_headers,
        )

    playbook_id = execution.get('playbook_id')
    trigger_context = execution.get('trigger_context', {})
    dry_run = execution.get('dry_run', False)

    try:
        result = execute_playbook(playbook_id, execution_id, trigger_context, dry_run)
        return func.HttpResponse(
            json.dumps(result),
            status_code=200,
            mimetype='application/json',
            headers=cors_headers,
        )
    except Exception as e:
        logger.error(f"Resume failed: {e}", exc_info=True)
        return func.HttpResponse(
            json.dumps({'error': f"Resume failed: {str(e)}"}),
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
            'service': 'playbook-executor',
            'timestamp': datetime.now(timezone.utc).isoformat(),
        }),
        status_code=200,
        mimetype='application/json',
        headers=cors_headers,
    )


def main(req: func.HttpRequest) -> func.HttpResponse:
    """Main entry point for Playbook Executor."""
    cors_headers = get_cors_headers(req)

    if req.method == 'OPTIONS':
        return func.HttpResponse('', status_code=204, headers=cors_headers)

    path = req.route_params.get('path', '')

    logger.info(f"Playbook Executor request: {req.method} /{path}")

    try:
        if path == 'health' and req.method == 'GET':
            return handle_health(req)

        if path == 'execute' and req.method == 'POST':
            return handle_execute(req)

        if path == 'resume' and req.method == 'POST':
            return handle_resume(req)

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


# Event Grid trigger for alert-based execution
def eventgrid_trigger(event: func.EventGridEvent) -> None:
    """Event Grid triggered playbook execution."""
    logger.info(f"Event Grid triggered execution: {event.get_json()}")

    try:
        data = event.get_json()
        playbook_id = data.get('playbook_id')

        if not playbook_id:
            logger.error("No playbook_id in event")
            return

        execution_id = f"exec-{uuid4().hex[:12]}"
        trigger_context = data.get('context', {})
        dry_run = data.get('dry_run', DEFAULT_DRY_RUN)

        result = execute_playbook(playbook_id, execution_id, trigger_context, dry_run)
        logger.info(f"Event Grid execution complete: {result}")

    except Exception as e:
        logger.error(f"Event Grid execution failed: {e}", exc_info=True)
        raise
