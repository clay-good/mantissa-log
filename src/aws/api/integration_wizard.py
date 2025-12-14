"""
Integration Setup Wizard API

Provides guided setup workflows for integrations with validation.
"""

import json
import logging
import os
import sys
from pathlib import Path
from typing import Dict, Any

# Add shared utilities to path
sys.path.append(str(Path(__file__).parent.parent.parent / 'shared'))

from integrations.validators import IntegrationValidatorFactory, ValidationResult
from auth import get_authenticated_user_id, AuthenticationError
from auth.cors import get_cors_headers, cors_preflight_response
from utils.lazy_init import aws_clients

logger = logging.getLogger(__name__)


def _get_dynamodb():
    """Get lazily-initialized DynamoDB resource."""
    return aws_clients.dynamodb


def _get_secrets_manager():
    """Get lazily-initialized Secrets Manager client."""
    return aws_clients.secrets_manager


def lambda_handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """
    Lambda handler for integration wizard.

    Routes:
    - POST /api/integrations/validate -> validate_integration()
    - POST /api/integrations/wizard/{type}/save -> save_integration()
    - GET /api/integrations/wizard/{type}/projects -> get_jira_projects()
    """
    try:
        http_method = event.get('httpMethod', 'POST')
        path = event.get('path', '')
        path_params = event.get('pathParameters', {})

        # Handle CORS preflight
        if http_method == 'OPTIONS':
            return cors_preflight_response(event)

        # Authenticate user from JWT
        try:
            user_id = get_authenticated_user_id(event)
        except AuthenticationError:
            return error_response(event, 'Authentication required', 401)

        body = json.loads(event.get('body', '{}'))

        if path.endswith('/validate'):
            return validate_integration(event, body)

        elif path.endswith('/save'):
            integration_type = path_params.get('type')
            return save_integration(event, user_id, integration_type, body)

        elif path.endswith('/projects'):
            return get_jira_projects(event, body)

        else:
            return error_response(event, 'Method not allowed', 405)

    except Exception as e:
        logger.error(f"Error in integration wizard: {str(e)}")
        import traceback
        traceback.print_exc()
        return error_response(event, str(e), 500)


def validate_integration(event: Dict[str, Any], data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Validate integration configuration.

    Request:
    {
        "type": "slack",
        "config": {
            "webhook_url": "https://hooks.slack.com/...",
            "channel": "#alerts"
        }
    }

    Response:
    {
        "success": true,
        "message": "Successfully sent test message to Slack",
        "details": {...}
    }
    """
    integration_type = data.get('type')
    config = data.get('config', {})

    if not integration_type:
        return error_response(event, 'Integration type is required', 400)

    try:
        result = IntegrationValidatorFactory.validate(integration_type, config)

        return success_response(event, {
            'success': result.success,
            'message': result.message,
            'details': result.details,
            'error_code': result.error_code
        })

    except ValueError as e:
        return error_response(event, str(e), 400)


def save_integration(
    event: Dict[str, Any],
    user_id: str,
    integration_type: str,
    data: Dict[str, Any]
) -> Dict[str, Any]:
    """
    Save integration configuration after validation.

    Request:
    {
        "name": "Slack Security Alerts",
        "config": {
            "webhook_url": "https://hooks.slack.com/...",
            "channel": "#security-alerts"
        },
        "severity_filter": ["critical", "high"],
        "enabled": true
    }
    """
    config = data.get('config', {})
    name = data.get('name', f'{integration_type.title()} Integration')
    severity_filter = data.get('severity_filter', [])
    enabled = data.get('enabled', True)

    # Validate before saving
    try:
        validation_result = IntegrationValidatorFactory.validate(integration_type, config)
        if not validation_result.success:
            return error_response(
                event,
                f'Validation failed: {validation_result.message}',
                400
            )
    except ValueError as e:
        return error_response(event, str(e), 400)

    # Store sensitive fields in Secrets Manager
    secret_fields = get_secret_fields(integration_type)
    secrets_data = {}
    config_to_store = config.copy()

    for field in secret_fields:
        if field in config:
            secrets_data[field] = config[field]
            config_to_store[field] = 'STORED_IN_SECRETS_MANAGER'

    # Store secrets
    if secrets_data:
        secret_id = f'mantissa-log/users/{user_id}/integrations/{integration_type}'
        store_secret(secret_id, secrets_data)

    # Store integration in DynamoDB
    table = _get_dynamodb().Table(get_integrations_table_name())

    integration_id = f'{integration_type}-{get_timestamp()}'

    item = {
        'user_id': user_id,
        'integration_id': integration_id,
        'type': integration_type,
        'name': name,
        'config': config_to_store,
        'severity_filter': severity_filter,
        'enabled': enabled,
        'health_status': 'healthy',
        'last_test': validation_result.details.get('timestamp') if validation_result.details else None,
        'created_at': get_timestamp(),
        'updated_at': get_timestamp()
    }

    table.put_item(Item=item)

    return success_response(event, {
        'integration_id': integration_id,
        'message': f'{integration_type.title()} integration saved successfully',
        'integration': item
    })


def get_jira_projects(event: Dict[str, Any], data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Fetch Jira projects for the wizard.

    Request:
    {
        "url": "https://your-domain.atlassian.net",
        "email": "user@example.com",
        "api_token": "token"
    }

    Response:
    {
        "projects": [
            {"key": "PROJ", "name": "Project Name", "id": "10000"},
            ...
        ]
    }
    """
    import requests

    url = data.get('url', '').rstrip('/')
    email = data.get('email')
    api_token = data.get('api_token')

    if not all([url, email, api_token]):
        return error_response(event, 'URL, email, and API token are required', 400)

    try:
        response = requests.get(
            f'{url}/rest/api/3/project',
            auth=(email, api_token),
            timeout=10
        )

        if response.status_code != 200:
            return error_response(
                event,
                'Failed to fetch projects. Check your credentials.',
                400
            )

        projects = response.json()

        simplified_projects = [
            {
                'key': p.get('key'),
                'name': p.get('name'),
                'id': p.get('id')
            }
            for p in projects
        ]

        return success_response(event, {'projects': simplified_projects})

    except requests.exceptions.Timeout:
        return error_response(event, 'Request to Jira timed out', 500)
    except requests.exceptions.RequestException as e:
        return error_response(event, f'Failed to connect to Jira: {str(e)}', 500)


def get_secret_fields(integration_type: str) -> list:
    """Get fields that should be stored in Secrets Manager."""
    secret_fields_map = {
        'slack': ['webhook_url'],
        'jira': ['api_token'],
        'pagerduty': ['integration_key'],
        'webhook': ['headers']  # headers may contain auth tokens
    }
    return secret_fields_map.get(integration_type, [])


def store_secret(secret_id: str, data: Dict[str, Any]) -> None:
    """Store secret in AWS Secrets Manager."""
    sm = _get_secrets_manager()
    try:
        sm.put_secret_value(
            SecretId=secret_id,
            SecretString=json.dumps(data)
        )
    except sm.exceptions.ResourceNotFoundException:
        # Create secret if it doesn't exist
        sm.create_secret(
            Name=secret_id,
            SecretString=json.dumps(data)
        )


def get_integrations_table_name() -> str:
    """Get DynamoDB table name for integrations."""
    import os
    return os.environ.get('INTEGRATIONS_TABLE', 'mantissa-log-integration-settings')


def get_timestamp() -> str:
    """Get current timestamp in ISO format."""
    from datetime import datetime
    return datetime.utcnow().isoformat() + 'Z'


def success_response(event: Dict[str, Any], data: Dict[str, Any]) -> Dict[str, Any]:
    """Return success response with secure CORS headers."""
    return {
        'statusCode': 200,
        'headers': {
            'Content-Type': 'application/json',
            **get_cors_headers(event)
        },
        'body': json.dumps(data)
    }


def error_response(event: Dict[str, Any], message: str, status_code: int) -> Dict[str, Any]:
    """Return error response with secure CORS headers."""
    return {
        'statusCode': status_code,
        'headers': {
            'Content-Type': 'application/json',
            **get_cors_headers(event)
        },
        'body': json.dumps({'error': message})
    }
