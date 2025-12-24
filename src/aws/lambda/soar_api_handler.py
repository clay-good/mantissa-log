"""
SOAR API Handler

Lambda function to handle SOAR (Security Orchestration, Automation, and Response)
API requests from the web UI. Provides CRUD operations for playbooks and
playbook execution management.
"""

import json
import logging
import os
import re
import sys
from datetime import datetime, timezone
from decimal import Decimal
from typing import Any, Dict, List, Optional

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
    Playbook,
    PlaybookStore,
    FilePlaybookStore,
    DynamoDBPlaybookStore,
    get_playbook_store,
    get_execution_store,
    get_execution_engine,
    get_approval_service,
    get_action_log,
    IRPlanParser,
    parse_ir_plan,
    PlaybookCodeGenerator,
    generate_playbook_code,
    validate_playbook_code,
    ExecutionStatus,
)

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

# Configuration
PLAYBOOK_STORE_TYPE = os.environ.get('PLAYBOOK_STORE_TYPE', 'dynamodb')
PLAYBOOK_TABLE = os.environ.get('PLAYBOOK_TABLE', 'mantissa-soar-playbooks')
EXECUTION_TABLE = os.environ.get('EXECUTION_TABLE', 'mantissa-soar-executions')
ACTION_LOG_TABLE = os.environ.get('ACTION_LOG_TABLE', 'mantissa-soar-action-log')

# Lazy-initialized stores
_playbook_store: Optional[PlaybookStore] = None
_execution_engine = None


def _get_playbook_store() -> PlaybookStore:
    """Get lazily-initialized playbook store."""
    global _playbook_store
    if _playbook_store is None:
        _playbook_store = get_playbook_store(
            store_type=PLAYBOOK_STORE_TYPE,
            table_name=PLAYBOOK_TABLE,
        )
    return _playbook_store


def _get_execution_engine():
    """Get lazily-initialized execution engine."""
    global _execution_engine
    if _execution_engine is None:
        _execution_engine = get_execution_engine(
            playbook_store=_get_playbook_store(),
            execution_store=get_execution_store(
                store_type='dynamodb',
                table_name=EXECUTION_TABLE,
            ),
            approval_service=get_approval_service(store_type='dynamodb'),
            action_log=get_action_log(
                store_type='dynamodb',
                table_name=ACTION_LOG_TABLE,
            ),
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
    Handle SOAR API requests.

    Routes:
    Playbooks:
    - GET /playbooks - List playbooks
    - GET /playbooks/{id} - Get playbook details
    - POST /playbooks - Create new playbook
    - PUT /playbooks/{id} - Update playbook
    - DELETE /playbooks/{id} - Delete playbook
    - GET /playbooks/{id}/versions - List versions
    - GET /playbooks/{id}/versions/{version} - Get specific version
    - GET /playbooks/{id}/code - Get generated code
    - POST /playbooks/{id}/deploy - Deploy playbook as Lambda
    - POST /playbooks/generate - Generate playbook from NL description
    - POST /playbooks/parse-ir-plan - Parse IR plan text

    Executions:
    - GET /executions - List executions
    - POST /executions - Create/start execution
    - GET /executions/{id} - Get execution details
    - GET /executions/{id}/logs - Get execution logs
    - POST /executions/{id}/cancel - Cancel execution

    Approvals:
    - GET /approvals - List pending approvals
    - GET /approvals/{id} - Get approval details
    - POST /approvals/{id}/approve - Approve action
    - POST /approvals/{id}/deny - Deny action

    Quick Actions:
    - GET /quick-actions/available - List available quick actions
    - POST /quick-actions - Execute quick action
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
        path_params = event.get('pathParameters', {}) or {}

        # Route requests
        # Playbook routes
        if path == '/playbooks' and method == 'GET':
            return handle_list_playbooks(event, user_id, params)
        elif path == '/playbooks' and method == 'POST':
            return handle_create_playbook(event, user_id, body)
        elif path == '/playbooks/generate' and method == 'POST':
            return handle_generate_playbook(event, user_id, body)
        elif path == '/playbooks/parse-ir-plan' and method == 'POST':
            return handle_parse_ir_plan(event, user_id, body)
        elif re.match(r'^/playbooks/[^/]+/versions$', path) and method == 'GET':
            playbook_id = path.split('/')[2]
            return handle_list_versions(event, user_id, playbook_id)
        elif re.match(r'^/playbooks/[^/]+/versions/[^/]+$', path) and method == 'GET':
            parts = path.split('/')
            playbook_id = parts[2]
            version = parts[4]
            return handle_get_version(event, user_id, playbook_id, version)
        elif re.match(r'^/playbooks/[^/]+/deploy$', path) and method == 'POST':
            playbook_id = path.split('/')[2]
            return handle_deploy_playbook(event, user_id, playbook_id, body)
        elif re.match(r'^/playbooks/[^/]+/code$', path) and method == 'GET':
            playbook_id = path.split('/')[2]
            return handle_get_code(event, user_id, playbook_id)
        elif re.match(r'^/playbooks/[^/]+$', path) and method == 'GET':
            playbook_id = path.split('/')[2]
            return handle_get_playbook(event, user_id, playbook_id)
        elif re.match(r'^/playbooks/[^/]+$', path) and method == 'PUT':
            playbook_id = path.split('/')[2]
            return handle_update_playbook(event, user_id, playbook_id, body)
        elif re.match(r'^/playbooks/[^/]+$', path) and method == 'DELETE':
            playbook_id = path.split('/')[2]
            return handle_delete_playbook(event, user_id, playbook_id)

        # Execution routes
        elif path == '/executions' and method == 'GET':
            return handle_list_executions(event, user_id, params)
        elif path == '/executions' and method == 'POST':
            return handle_create_execution(event, user_id, body)
        elif re.match(r'^/executions/[^/]+/logs$', path) and method == 'GET':
            execution_id = path.split('/')[2]
            return handle_get_execution_logs(event, user_id, execution_id)
        elif re.match(r'^/executions/[^/]+/cancel$', path) and method == 'POST':
            execution_id = path.split('/')[2]
            return handle_cancel_execution(event, user_id, execution_id)
        elif re.match(r'^/executions/[^/]+$', path) and method == 'GET':
            execution_id = path.split('/')[2]
            return handle_get_execution(event, user_id, execution_id)

        # Approval routes
        elif path == '/approvals' and method == 'GET':
            return handle_list_approvals(event, user_id, params)
        elif re.match(r'^/approvals/[^/]+/approve$', path) and method == 'POST':
            approval_id = path.split('/')[2]
            return handle_approve_action(event, user_id, approval_id, body)
        elif re.match(r'^/approvals/[^/]+/deny$', path) and method == 'POST':
            approval_id = path.split('/')[2]
            return handle_deny_action(event, user_id, approval_id, body)
        elif re.match(r'^/approvals/[^/]+$', path) and method == 'GET':
            approval_id = path.split('/')[2]
            return handle_get_approval(event, user_id, approval_id)

        # Quick action routes
        elif path == '/quick-actions/available' and method == 'GET':
            return handle_list_quick_actions(event, user_id, params)
        elif path == '/quick-actions' and method == 'POST':
            return handle_execute_quick_action(event, user_id, body)

        else:
            return _error_response(event, 404, 'Not found')

    except Exception as e:
        logger.error(f'Error in SOAR API handler: {e}', exc_info=True)
        return _error_response(event, 500, 'Internal server error')


def handle_list_playbooks(
    event: Dict[str, Any],
    user_id: str,
    params: Dict[str, str]
) -> Dict[str, Any]:
    """
    List playbooks with optional filters.

    Query parameters:
    - enabled: Filter by enabled status (true/false)
    - trigger_type: Filter by trigger type (alert, manual, scheduled, webhook)
    - tags: Filter by tags (comma-separated)
    - search: Search in name and description
    - page: Page number (default 1)
    - page_size: Page size (default 50, max 100)
    """
    store = _get_playbook_store()

    # Parse filters
    filters = {}
    if params.get('enabled') is not None:
        filters['enabled'] = params.get('enabled', '').lower() == 'true'
    if params.get('trigger_type'):
        filters['trigger_type'] = params.get('trigger_type')
    if params.get('tags'):
        filters['tags'] = params.get('tags').split(',')

    # Pagination
    page = int(params.get('page', 1))
    page_size = min(int(params.get('page_size', 50)), 100)

    # Get playbooks
    playbooks = store.list(filters=filters)

    # Search filter (applied in memory)
    search = params.get('search', '').lower()
    if search:
        playbooks = [
            p for p in playbooks
            if search in p.name.lower() or search in p.description.lower()
        ]

    # Sort by modified date descending
    playbooks.sort(key=lambda p: p.modified, reverse=True)

    # Apply pagination
    total = len(playbooks)
    start = (page - 1) * page_size
    end = start + page_size
    playbooks = playbooks[start:end]

    return _success_response(event, {
        'playbooks': [p.to_dict() for p in playbooks],
        'total': total,
        'page': page,
        'page_size': page_size,
        'total_pages': (total + page_size - 1) // page_size,
    })


def handle_get_playbook(
    event: Dict[str, Any],
    user_id: str,
    playbook_id: str
) -> Dict[str, Any]:
    """Get a specific playbook by ID."""
    store = _get_playbook_store()

    playbook = store.get(playbook_id)
    if not playbook:
        return _error_response(event, 404, f'Playbook not found: {playbook_id}')

    return _success_response(event, {
        'playbook': playbook.to_dict(),
    })


def handle_create_playbook(
    event: Dict[str, Any],
    user_id: str,
    body: Dict[str, Any]
) -> Dict[str, Any]:
    """Create a new playbook."""
    store = _get_playbook_store()

    # Validate required fields
    required_fields = ['name', 'steps']
    for field in required_fields:
        if field not in body:
            return _error_response(event, 400, f'Missing required field: {field}')

    # Set defaults
    now = datetime.now(timezone.utc)
    body.setdefault('id', f"pb-{now.strftime('%Y%m%d%H%M%S')}")
    body.setdefault('version', '1.0.0')
    body.setdefault('author', user_id)
    body.setdefault('created', now.isoformat())
    body.setdefault('modified', now.isoformat())
    body.setdefault('enabled', True)
    body.setdefault('description', '')
    body.setdefault('tags', [])
    body.setdefault('trigger', {'trigger_type': 'manual', 'conditions': {}})

    try:
        playbook = Playbook.from_dict(body)
    except Exception as e:
        return _error_response(event, 400, f'Invalid playbook data: {e}')

    # Validate playbook structure
    is_valid, errors = playbook.validate()
    if not is_valid:
        return _error_response(event, 400, f'Invalid playbook: {", ".join(errors)}')

    # Save playbook
    try:
        playbook_id = store.save(playbook)
        logger.info(f'Created playbook: {playbook_id} by user {user_id}')
    except Exception as e:
        logger.error(f'Failed to save playbook: {e}')
        return _error_response(event, 500, f'Failed to save playbook: {e}')

    return _success_response(event, {
        'playbook': playbook.to_dict(),
        'message': 'Playbook created successfully',
    }, status_code=201)


def handle_update_playbook(
    event: Dict[str, Any],
    user_id: str,
    playbook_id: str,
    body: Dict[str, Any]
) -> Dict[str, Any]:
    """Update an existing playbook."""
    store = _get_playbook_store()

    # Get existing playbook
    existing = store.get(playbook_id)
    if not existing:
        return _error_response(event, 404, f'Playbook not found: {playbook_id}')

    # Merge updates
    playbook_data = existing.to_dict()
    for key, value in body.items():
        if key not in ['id', 'created']:  # Don't allow changing ID or created date
            playbook_data[key] = value

    # Update modified timestamp
    playbook_data['modified'] = datetime.now(timezone.utc).isoformat()

    # Increment version if steps changed
    if body.get('steps') and body['steps'] != existing.to_dict().get('steps'):
        old_version = playbook_data.get('version', '1.0.0')
        parts = old_version.split('.')
        parts[-1] = str(int(parts[-1]) + 1)
        playbook_data['version'] = '.'.join(parts)

    try:
        playbook = Playbook.from_dict(playbook_data)
    except Exception as e:
        return _error_response(event, 400, f'Invalid playbook data: {e}')

    # Validate
    is_valid, errors = playbook.validate()
    if not is_valid:
        return _error_response(event, 400, f'Invalid playbook: {", ".join(errors)}')

    # Save
    try:
        store.save(playbook)
        logger.info(f'Updated playbook: {playbook_id} by user {user_id}')
    except Exception as e:
        logger.error(f'Failed to update playbook: {e}')
        return _error_response(event, 500, f'Failed to update playbook: {e}')

    return _success_response(event, {
        'playbook': playbook.to_dict(),
        'message': 'Playbook updated successfully',
    })


def handle_delete_playbook(
    event: Dict[str, Any],
    user_id: str,
    playbook_id: str
) -> Dict[str, Any]:
    """Delete (archive) a playbook."""
    store = _get_playbook_store()

    # Check playbook exists
    playbook = store.get(playbook_id)
    if not playbook:
        return _error_response(event, 404, f'Playbook not found: {playbook_id}')

    # Delete (archive)
    try:
        success = store.delete(playbook_id)
        if success:
            logger.info(f'Deleted playbook: {playbook_id} by user {user_id}')
            return _success_response(event, {
                'message': 'Playbook deleted successfully',
            })
        else:
            return _error_response(event, 500, 'Failed to delete playbook')
    except Exception as e:
        logger.error(f'Failed to delete playbook: {e}')
        return _error_response(event, 500, f'Failed to delete playbook: {e}')


def handle_list_versions(
    event: Dict[str, Any],
    user_id: str,
    playbook_id: str
) -> Dict[str, Any]:
    """List all versions of a playbook."""
    store = _get_playbook_store()

    # Check playbook exists
    playbook = store.get(playbook_id)
    if not playbook:
        return _error_response(event, 404, f'Playbook not found: {playbook_id}')

    try:
        versions = store.list_versions(playbook_id)
        return _success_response(event, {
            'playbook_id': playbook_id,
            'versions': versions,
            'current_version': playbook.version,
        })
    except Exception as e:
        logger.error(f'Failed to list versions: {e}')
        return _error_response(event, 500, f'Failed to list versions: {e}')


def handle_get_version(
    event: Dict[str, Any],
    user_id: str,
    playbook_id: str,
    version: str
) -> Dict[str, Any]:
    """Get a specific version of a playbook."""
    store = _get_playbook_store()

    playbook = store.get_version(playbook_id, version)
    if not playbook:
        return _error_response(event, 404, f'Playbook version not found: {playbook_id}@{version}')

    return _success_response(event, {
        'playbook': playbook.to_dict(),
    })


def handle_deploy_playbook(
    event: Dict[str, Any],
    user_id: str,
    playbook_id: str,
    body: Dict[str, Any]
) -> Dict[str, Any]:
    """Deploy playbook as a Lambda function."""
    store = _get_playbook_store()

    playbook = store.get(playbook_id)
    if not playbook:
        return _error_response(event, 404, f'Playbook not found: {playbook_id}')

    try:
        # Generate Lambda code
        code = generate_playbook_code(playbook)

        # Validate generated code
        is_valid, issues = validate_playbook_code(code)
        if not is_valid:
            return _error_response(event, 400, f'Generated code validation failed: {", ".join(issues)}')

        # Update playbook with generated code
        playbook.lambda_code = code

        # TODO: Actually deploy to Lambda (requires additional infrastructure)
        # For now, just save the code and return it

        store.save(playbook)

        return _success_response(event, {
            'playbook_id': playbook_id,
            'message': 'Playbook code generated successfully',
            'code_preview': code[:1000] + '...' if len(code) > 1000 else code,
            # 'lambda_arn': playbook.lambda_arn,  # Would be set after actual deployment
        })

    except Exception as e:
        logger.error(f'Failed to deploy playbook: {e}')
        return _error_response(event, 500, f'Failed to deploy playbook: {e}')


def handle_get_code(
    event: Dict[str, Any],
    user_id: str,
    playbook_id: str
) -> Dict[str, Any]:
    """Get generated code for a playbook."""
    store = _get_playbook_store()

    playbook = store.get(playbook_id)
    if not playbook:
        return _error_response(event, 404, f'Playbook not found: {playbook_id}')

    try:
        # Generate or retrieve code
        if playbook.lambda_code:
            code = playbook.lambda_code
        else:
            code = generate_playbook_code(playbook)

        return _success_response(event, {
            'playbook_id': playbook_id,
            'code': code,
        })

    except Exception as e:
        logger.error(f'Failed to get playbook code: {e}')
        return _error_response(event, 500, f'Failed to generate code: {e}')


def handle_generate_playbook(
    event: Dict[str, Any],
    user_id: str,
    body: Dict[str, Any]
) -> Dict[str, Any]:
    """Generate a playbook from natural language description."""
    description = body.get('description', '')
    if not description:
        return _error_response(event, 400, 'Description is required')

    # TODO: Implement LLM-based playbook generation
    # For now, return a template playbook
    now = datetime.now(timezone.utc)
    playbook_data = {
        'id': f"pb-generated-{now.strftime('%Y%m%d%H%M%S')}",
        'name': f"Generated Playbook",
        'description': description,
        'version': '1.0.0',
        'author': user_id,
        'created': now.isoformat(),
        'modified': now.isoformat(),
        'enabled': False,  # Disabled by default, needs review
        'tags': ['generated', 'review-required'],
        'trigger': {'trigger_type': 'manual', 'conditions': {}},
        'steps': [
            {
                'id': 'step_1',
                'name': 'Review Required',
                'action_type': 'notify',
                'provider': 'slack',
                'parameters': {
                    'channel': '#security-alerts',
                    'message': 'This playbook was auto-generated and requires review.',
                },
            },
        ],
    }

    return _success_response(event, {
        'playbook': playbook_data,
        'message': 'Playbook generated. Please review and modify before enabling.',
        'generated_from': description,
    })


def handle_parse_ir_plan(
    event: Dict[str, Any],
    user_id: str,
    body: Dict[str, Any]
) -> Dict[str, Any]:
    """Parse an IR plan into a playbook."""
    plan_text = body.get('plan_text', '')
    plan_format = body.get('format', 'markdown')  # markdown or text
    plan_name = body.get('name', 'Parsed IR Plan')

    if not plan_text:
        return _error_response(event, 400, 'Plan text is required')

    try:
        # Parse the IR plan
        playbook = parse_ir_plan(plan_text, plan_name=plan_name)

        # Set author and disable by default
        playbook_dict = playbook.to_dict()
        playbook_dict['author'] = user_id
        playbook_dict['enabled'] = False
        playbook_dict['tags'].append('parsed-ir-plan')
        playbook_dict['tags'].append('review-required')

        return _success_response(event, {
            'playbook': playbook_dict,
            'message': 'IR plan parsed successfully. Please review and modify before enabling.',
            'parsed_from': plan_format,
        })

    except Exception as e:
        logger.error(f'Failed to parse IR plan: {e}')
        return _error_response(event, 400, f'Failed to parse IR plan: {e}')


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


def handle_create_execution(
    event: Dict[str, Any],
    user_id: str,
    body: Dict[str, Any]
) -> Dict[str, Any]:
    """
    Create and start a new playbook execution.

    Request body:
    - playbook_id: ID of the playbook to execute (required)
    - trigger_type: How execution was triggered (manual, alert, scheduled, webhook)
    - alert_id: ID of the triggering alert (if alert-triggered)
    - parameters: Execution parameters (dict)
    - dry_run: If true, validate but don't execute (default: false)
    """
    playbook_id = body.get('playbook_id')
    if not playbook_id:
        return _error_response(event, 400, 'playbook_id is required')

    trigger_type = body.get('trigger_type', 'manual')
    alert_id = body.get('alert_id')
    parameters = body.get('parameters', {})
    dry_run = body.get('dry_run', False)

    # Validate playbook exists and is enabled
    store = _get_playbook_store()
    playbook = store.get(playbook_id)
    if not playbook:
        return _error_response(event, 404, f'Playbook not found: {playbook_id}')

    if not playbook.enabled and not dry_run:
        return _error_response(event, 400, f'Playbook is disabled: {playbook_id}')

    try:
        engine = _get_execution_engine()

        # Create execution context
        context = {
            'user_id': user_id,
            'trigger_type': trigger_type,
            'alert_id': alert_id,
            'parameters': parameters,
        }

        if dry_run:
            # Validate without executing
            is_valid, errors = playbook.validate()
            return _success_response(event, {
                'dry_run': True,
                'valid': is_valid,
                'errors': errors if not is_valid else [],
                'playbook_id': playbook_id,
                'message': 'Dry run validation completed',
            })

        # Start execution
        execution = engine.start_execution(playbook, context)

        logger.info(f'Started execution {execution.id} for playbook {playbook_id} by user {user_id}')

        return _success_response(event, {
            'execution_id': execution.id,
            'playbook_id': playbook_id,
            'status': execution.status.value if hasattr(execution.status, 'value') else str(execution.status),
            'started_at': execution.started_at.isoformat() if execution.started_at else None,
            'message': 'Execution started successfully',
        }, status_code=201)

    except Exception as e:
        logger.error(f'Failed to start execution: {e}', exc_info=True)
        return _error_response(event, 500, f'Failed to start execution: {e}')


# Quick action definitions
QUICK_ACTIONS = {
    'isolate_host': {
        'id': 'isolate_host',
        'name': 'Isolate Host',
        'description': 'Isolate a host from the network',
        'icon': 'shield',
        'requires_approval': True,
        'parameters': [
            {'name': 'hostname', 'type': 'string', 'required': True},
            {'name': 'reason', 'type': 'string', 'required': False},
        ],
    },
    'disable_user': {
        'id': 'disable_user',
        'name': 'Disable User',
        'description': 'Disable a user account in Active Directory',
        'icon': 'user-minus',
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
        'requires_approval': False,
        'parameters': [
            {'name': 'channel', 'type': 'string', 'required': True},
            {'name': 'message', 'type': 'string', 'required': True},
        ],
    },
}


def handle_list_quick_actions(
    event: Dict[str, Any],
    user_id: str,
    params: Dict[str, str]
) -> Dict[str, Any]:
    """
    List available quick actions.

    Query parameters:
    - alert_type: Filter actions relevant to specific alert type
    """
    alert_type = params.get('alert_type')

    # For now, return all quick actions
    # In a production system, you might filter based on user permissions or alert context
    actions = list(QUICK_ACTIONS.values())

    return _success_response(event, {
        'quick_actions': actions,
        'total': len(actions),
    })


def handle_execute_quick_action(
    event: Dict[str, Any],
    user_id: str,
    body: Dict[str, Any]
) -> Dict[str, Any]:
    """
    Execute a quick action.

    Request body:
    - action_id: ID of the quick action to execute (required)
    - alert_id: ID of the related alert (optional)
    - parameters: Action parameters (dict)
    """
    action_id = body.get('action_id')
    if not action_id:
        return _error_response(event, 400, 'action_id is required')

    if action_id not in QUICK_ACTIONS:
        return _error_response(event, 404, f'Quick action not found: {action_id}')

    action_def = QUICK_ACTIONS[action_id]
    alert_id = body.get('alert_id')
    parameters = body.get('parameters', {})

    # Validate required parameters
    for param in action_def['parameters']:
        if param['required'] and param['name'] not in parameters:
            return _error_response(
                event, 400,
                f"Missing required parameter: {param['name']}"
            )

    try:
        # Create a temporary playbook for this quick action
        now = datetime.now(timezone.utc)
        quick_playbook_data = {
            'id': f"quick-{action_id}-{now.strftime('%Y%m%d%H%M%S')}",
            'name': f"Quick Action: {action_def['name']}",
            'description': action_def['description'],
            'version': '1.0.0',
            'author': user_id,
            'created': now.isoformat(),
            'modified': now.isoformat(),
            'enabled': True,
            'tags': ['quick-action', action_id],
            'trigger': {'trigger_type': 'manual', 'conditions': {}},
            'steps': [
                {
                    'id': 'step_1',
                    'name': action_def['name'],
                    'action_type': action_id,
                    'provider': 'internal',
                    'parameters': parameters,
                    'requires_approval': action_def['requires_approval'],
                },
            ],
        }

        playbook = Playbook.from_dict(quick_playbook_data)

        # Execute the quick action
        engine = _get_execution_engine()
        context = {
            'user_id': user_id,
            'trigger_type': 'manual',
            'alert_id': alert_id,
            'parameters': parameters,
            'is_quick_action': True,
        }

        execution = engine.start_execution(playbook, context)

        logger.info(f'Executed quick action {action_id} as execution {execution.id} by user {user_id}')

        return _success_response(event, {
            'execution_id': execution.id,
            'action_id': action_id,
            'status': execution.status.value if hasattr(execution.status, 'value') else str(execution.status),
            'requires_approval': action_def['requires_approval'],
            'message': 'Quick action initiated' + (' (pending approval)' if action_def['requires_approval'] else ''),
        }, status_code=201)

    except Exception as e:
        logger.error(f'Failed to execute quick action: {e}', exc_info=True)
        return _error_response(event, 500, f'Failed to execute quick action: {e}')


def handle_list_executions(
    event: Dict[str, Any],
    user_id: str,
    params: Dict[str, str]
) -> Dict[str, Any]:
    """
    List playbook executions with optional filters.

    Query parameters:
    - playbook_id: Filter by playbook ID
    - status: Filter by status (pending, running, completed, failed, cancelled, waiting_approval)
    - page: Page number (default 1)
    - page_size: Page size (default 50, max 100)
    """
    try:
        engine = _get_execution_engine()
        execution_store = engine.execution_store

        # Parse filters
        filters = {}
        if params.get('playbook_id'):
            filters['playbook_id'] = params.get('playbook_id')
        if params.get('status'):
            filters['status'] = params.get('status')

        # Pagination
        page = int(params.get('page', 1))
        page_size = min(int(params.get('page_size', 50)), 100)

        # Get executions
        executions = execution_store.list(filters=filters)

        # Sort by start time descending
        executions.sort(key=lambda e: e.started_at or datetime.min.replace(tzinfo=timezone.utc), reverse=True)

        # Apply pagination
        total = len(executions)
        start = (page - 1) * page_size
        end = start + page_size
        executions = executions[start:end]

        return _success_response(event, {
            'executions': [e.to_dict() for e in executions],
            'total': total,
            'page': page,
            'page_size': page_size,
            'total_pages': (total + page_size - 1) // page_size,
        })

    except Exception as e:
        logger.error(f'Failed to list executions: {e}', exc_info=True)
        return _error_response(event, 500, f'Failed to list executions: {e}')


def handle_get_execution(
    event: Dict[str, Any],
    user_id: str,
    execution_id: str
) -> Dict[str, Any]:
    """Get a specific execution by ID."""
    try:
        engine = _get_execution_engine()
        execution_store = engine.execution_store

        execution = execution_store.get(execution_id)
        if not execution:
            return _error_response(event, 404, f'Execution not found: {execution_id}')

        return _success_response(event, {
            'execution': execution.to_dict(),
        })

    except Exception as e:
        logger.error(f'Failed to get execution: {e}', exc_info=True)
        return _error_response(event, 500, f'Failed to get execution: {e}')


def handle_get_execution_logs(
    event: Dict[str, Any],
    user_id: str,
    execution_id: str
) -> Dict[str, Any]:
    """Get logs for a specific execution."""
    try:
        engine = _get_execution_engine()
        execution_store = engine.execution_store

        execution = execution_store.get(execution_id)
        if not execution:
            return _error_response(event, 404, f'Execution not found: {execution_id}')

        # Get logs from action log
        action_log = engine.action_log
        logs = action_log.get_logs(execution_id=execution_id)

        return _success_response(event, {
            'execution_id': execution_id,
            'logs': [log.to_dict() if hasattr(log, 'to_dict') else log for log in logs],
        })

    except Exception as e:
        logger.error(f'Failed to get execution logs: {e}', exc_info=True)
        return _error_response(event, 500, f'Failed to get execution logs: {e}')


def handle_cancel_execution(
    event: Dict[str, Any],
    user_id: str,
    execution_id: str
) -> Dict[str, Any]:
    """Cancel a running execution."""
    try:
        engine = _get_execution_engine()
        execution_store = engine.execution_store

        execution = execution_store.get(execution_id)
        if not execution:
            return _error_response(event, 404, f'Execution not found: {execution_id}')

        # Check if execution can be cancelled
        if execution.status in [ExecutionStatus.COMPLETED, ExecutionStatus.FAILED, ExecutionStatus.CANCELLED]:
            return _error_response(event, 400, f'Execution cannot be cancelled (status: {execution.status.value})')

        # Cancel the execution
        engine.cancel_execution(execution_id, cancelled_by=user_id)

        logger.info(f'Cancelled execution {execution_id} by user {user_id}')

        return _success_response(event, {
            'execution_id': execution_id,
            'status': 'cancelled',
            'message': 'Execution cancelled successfully',
        })

    except Exception as e:
        logger.error(f'Failed to cancel execution: {e}', exc_info=True)
        return _error_response(event, 500, f'Failed to cancel execution: {e}')


def handle_list_approvals(
    event: Dict[str, Any],
    user_id: str,
    params: Dict[str, str]
) -> Dict[str, Any]:
    """
    List pending approval requests.

    Query parameters:
    - status: Filter by status (pending, approved, denied)
    - page: Page number (default 1)
    - page_size: Page size (default 50, max 100)
    """
    try:
        engine = _get_execution_engine()
        approval_service = engine.approval_service

        # Parse filters
        status = params.get('status', 'pending')

        # Pagination
        page = int(params.get('page', 1))
        page_size = min(int(params.get('page_size', 50)), 100)

        # Get approvals
        approvals = approval_service.list_pending() if status == 'pending' else approval_service.list_all(status=status)

        # Sort by created time descending
        approvals.sort(key=lambda a: a.created_at if hasattr(a, 'created_at') else datetime.min.replace(tzinfo=timezone.utc), reverse=True)

        # Apply pagination
        total = len(approvals)
        start = (page - 1) * page_size
        end = start + page_size
        approvals = approvals[start:end]

        return _success_response(event, {
            'approvals': [a.to_dict() if hasattr(a, 'to_dict') else a for a in approvals],
            'total': total,
            'page': page,
            'page_size': page_size,
            'total_pages': (total + page_size - 1) // page_size,
        })

    except Exception as e:
        logger.error(f'Failed to list approvals: {e}', exc_info=True)
        return _error_response(event, 500, f'Failed to list approvals: {e}')


def handle_get_approval(
    event: Dict[str, Any],
    user_id: str,
    approval_id: str
) -> Dict[str, Any]:
    """Get a specific approval request by ID."""
    try:
        engine = _get_execution_engine()
        approval_service = engine.approval_service

        approval = approval_service.get(approval_id)
        if not approval:
            return _error_response(event, 404, f'Approval not found: {approval_id}')

        return _success_response(event, {
            'approval': approval.to_dict() if hasattr(approval, 'to_dict') else approval,
        })

    except Exception as e:
        logger.error(f'Failed to get approval: {e}', exc_info=True)
        return _error_response(event, 500, f'Failed to get approval: {e}')


def handle_approve_action(
    event: Dict[str, Any],
    user_id: str,
    approval_id: str,
    body: Dict[str, Any]
) -> Dict[str, Any]:
    """Approve a pending action."""
    try:
        engine = _get_execution_engine()
        approval_service = engine.approval_service

        approval = approval_service.get(approval_id)
        if not approval:
            return _error_response(event, 404, f'Approval not found: {approval_id}')

        # Check if already processed
        if hasattr(approval, 'status') and approval.status != 'pending':
            return _error_response(event, 400, f'Approval already processed (status: {approval.status})')

        # Approve the action
        notes = body.get('notes', '')
        approval_service.approve(approval_id, approved_by=user_id, notes=notes)

        # Resume the execution
        if hasattr(approval, 'execution_id'):
            engine.resume_execution(approval.execution_id, approval_granted=True, approver=user_id)

        logger.info(f'Approved action {approval_id} by user {user_id}')

        return _success_response(event, {
            'approval_id': approval_id,
            'status': 'approved',
            'approved_by': user_id,
            'message': 'Action approved successfully',
        })

    except Exception as e:
        logger.error(f'Failed to approve action: {e}', exc_info=True)
        return _error_response(event, 500, f'Failed to approve action: {e}')


def handle_deny_action(
    event: Dict[str, Any],
    user_id: str,
    approval_id: str,
    body: Dict[str, Any]
) -> Dict[str, Any]:
    """Deny a pending action."""
    try:
        engine = _get_execution_engine()
        approval_service = engine.approval_service

        approval = approval_service.get(approval_id)
        if not approval:
            return _error_response(event, 404, f'Approval not found: {approval_id}')

        # Check if already processed
        if hasattr(approval, 'status') and approval.status != 'pending':
            return _error_response(event, 400, f'Approval already processed (status: {approval.status})')

        # Deny the action
        reason = body.get('reason', 'Denied by user')
        approval_service.deny(approval_id, denied_by=user_id, reason=reason)

        # Resume the execution with denial
        if hasattr(approval, 'execution_id'):
            engine.resume_execution(approval.execution_id, approval_granted=False, approver=user_id)

        logger.info(f'Denied action {approval_id} by user {user_id}')

        return _success_response(event, {
            'approval_id': approval_id,
            'status': 'denied',
            'denied_by': user_id,
            'message': 'Action denied',
        })

    except Exception as e:
        logger.error(f'Failed to deny action: {e}', exc_info=True)
        return _error_response(event, 500, f'Failed to deny action: {e}')
