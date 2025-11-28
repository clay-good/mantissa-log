"""
Integration API Handler

Lambda function to handle integration configuration API requests.
Manages setup wizards for Slack, Jira, PagerDuty, webhooks, etc.
"""

import json
import os
import sys
from typing import Dict, Any

# Add shared modules to path
sys.path.insert(0, '/opt/python')
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../../shared'))

from integrations.integration_manager import (
    IntegrationManager,
    IntegrationType
)


def lambda_handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """
    Handle integration API requests.

    Routes:
    - GET /integrations - List user's integrations
    - POST /integrations - Create new integration
    - GET /integrations/{id} - Get specific integration
    - PUT /integrations/{id} - Update integration
    - DELETE /integrations/{id} - Delete integration
    - POST /integrations/{id}/test - Test integration
    - GET /integrations/types - Get available integration types
    """
    try:
        path = event.get('path', '')
        method = event.get('httpMethod', 'GET')
        body = json.loads(event.get('body', '{}')) if event.get('body') else {}
        params = event.get('pathParameters') or {}
        query_params = event.get('queryStringParameters') or {}

        # Route to appropriate handler
        if path == '/integrations' and method == 'GET':
            return handle_list_integrations(query_params)
        elif path == '/integrations' and method == 'POST':
            return handle_create_integration(body)
        elif path == '/integrations/types' and method == 'GET':
            return handle_get_integration_types()
        elif path.startswith('/integrations/') and method == 'GET':
            return handle_get_integration(params, query_params)
        elif path.startswith('/integrations/') and '/test' in path and method == 'POST':
            return handle_test_integration(params, query_params)
        elif path.startswith('/integrations/') and method == 'PUT':
            return handle_update_integration(params, body)
        elif path.startswith('/integrations/') and method == 'DELETE':
            return handle_delete_integration(params, query_params)
        else:
            return {
                'statusCode': 404,
                'body': json.dumps({'error': 'Not found'})
            }

    except Exception as e:
        print(f'Error in integration API handler: {e}')
        import traceback
        traceback.print_exc()

        return {
            'statusCode': 500,
            'headers': {
                'Content-Type': 'application/json',
                'Access-Control-Allow-Origin': '*'
            },
            'body': json.dumps({'error': str(e)})
        }


def handle_list_integrations(query_params: Dict[str, str]) -> Dict[str, Any]:
    """
    List user's integrations.

    Query parameters:
    - user_id: User ID
    - type: Optional integration type filter
    """
    user_id = query_params.get('user_id')
    integration_type_str = query_params.get('type')

    if not user_id:
        return {
            'statusCode': 400,
            'body': json.dumps({'error': 'Missing user_id'})
        }

    manager = IntegrationManager()

    integration_type = None
    if integration_type_str:
        try:
            integration_type = IntegrationType(integration_type_str)
        except ValueError:
            return {
                'statusCode': 400,
                'body': json.dumps({'error': f'Invalid integration type: {integration_type_str}'})
            }

    integrations = manager.list_integrations(user_id, integration_type)

    # Convert to JSON-friendly format (without sensitive data)
    integrations_data = []
    for integration in integrations:
        data = integration.to_dict()
        # Remove secret IDs from response
        config = data['config'].copy()
        for key in list(config.keys()):
            if 'secret_id' in key:
                config[key] = '***configured***'
        data['config'] = config
        integrations_data.append(data)

    return {
        'statusCode': 200,
        'headers': {
            'Content-Type': 'application/json',
            'Access-Control-Allow-Origin': '*'
        },
        'body': json.dumps({
            'integrations': integrations_data,
            'total': len(integrations_data)
        })
    }


def handle_create_integration(body: Dict[str, Any]) -> Dict[str, Any]:
    """
    Create new integration.

    Request body:
    {
        "user_id": "user-123",
        "integration_type": "slack",
        "name": "My Slack Integration",
        "config": {...},
        "enabled": true
    }
    """
    user_id = body.get('user_id')
    integration_type_str = body.get('integration_type')
    name = body.get('name')
    config = body.get('config', {})
    enabled = body.get('enabled', True)

    if not all([user_id, integration_type_str, name, config]):
        return {
            'statusCode': 400,
            'body': json.dumps({'error': 'Missing required fields'})
        }

    try:
        integration_type = IntegrationType(integration_type_str)
    except ValueError:
        return {
            'statusCode': 400,
            'body': json.dumps({'error': f'Invalid integration type: {integration_type_str}'})
        }

    manager = IntegrationManager()

    try:
        integration = manager.create_integration(
            user_id=user_id,
            integration_type=integration_type,
            name=name,
            config=config,
            enabled=enabled
        )

        return {
            'statusCode': 201,
            'headers': {
                'Content-Type': 'application/json',
                'Access-Control-Allow-Origin': '*'
            },
            'body': json.dumps({
                'integration': integration.to_dict(),
                'message': 'Integration created successfully'
            })
        }

    except Exception as e:
        print(f'Error creating integration: {e}')
        return {
            'statusCode': 500,
            'headers': {
                'Content-Type': 'application/json',
                'Access-Control-Allow-Origin': '*'
            },
            'body': json.dumps({'error': f'Failed to create integration: {str(e)}'})
        }


def handle_get_integration(params: Dict[str, str], query_params: Dict[str, str]) -> Dict[str, Any]:
    """
    Get specific integration.

    Path parameters:
    - id: Integration ID

    Query parameters:
    - user_id: User ID
    """
    integration_id = params.get('id')
    user_id = query_params.get('user_id')

    if not all([integration_id, user_id]):
        return {
            'statusCode': 400,
            'body': json.dumps({'error': 'Missing integration_id or user_id'})
        }

    manager = IntegrationManager()
    integration = manager.get_integration(integration_id, user_id)

    if not integration:
        return {
            'statusCode': 404,
            'body': json.dumps({'error': 'Integration not found'})
        }

    # Remove sensitive data
    data = integration.to_dict()
    config = data['config'].copy()
    for key in list(config.keys()):
        if 'secret_id' in key:
            config[key] = '***configured***'
    data['config'] = config

    return {
        'statusCode': 200,
        'headers': {
            'Content-Type': 'application/json',
            'Access-Control-Allow-Origin': '*'
        },
        'body': json.dumps({'integration': data})
    }


def handle_update_integration(params: Dict[str, str], body: Dict[str, Any]) -> Dict[str, Any]:
    """
    Update integration.

    Path parameters:
    - id: Integration ID

    Request body:
    {
        "user_id": "user-123",
        "name": "Updated name",
        "config": {...},
        "enabled": false
    }
    """
    integration_id = params.get('id')
    user_id = body.get('user_id')

    if not all([integration_id, user_id]):
        return {
            'statusCode': 400,
            'body': json.dumps({'error': 'Missing integration_id or user_id'})
        }

    manager = IntegrationManager()

    # Build updates dict
    updates = {}
    if 'name' in body:
        updates['name'] = body['name']
    if 'config' in body:
        updates['config'] = body['config']
    if 'enabled' in body:
        updates['enabled'] = body['enabled']

    try:
        integration = manager.update_integration(
            integration_id=integration_id,
            user_id=user_id,
            **updates
        )

        if not integration:
            return {
                'statusCode': 404,
                'body': json.dumps({'error': 'Integration not found'})
            }

        return {
            'statusCode': 200,
            'headers': {
                'Content-Type': 'application/json',
                'Access-Control-Allow-Origin': '*'
            },
            'body': json.dumps({
                'integration': integration.to_dict(),
                'message': 'Integration updated successfully'
            })
        }

    except Exception as e:
        print(f'Error updating integration: {e}')
        return {
            'statusCode': 500,
            'headers': {
                'Content-Type': 'application/json',
                'Access-Control-Allow-Origin': '*'
            },
            'body': json.dumps({'error': f'Failed to update integration: {str(e)}'})
        }


def handle_delete_integration(params: Dict[str, str], query_params: Dict[str, str]) -> Dict[str, Any]:
    """
    Delete integration.

    Path parameters:
    - id: Integration ID

    Query parameters:
    - user_id: User ID
    """
    integration_id = params.get('id')
    user_id = query_params.get('user_id')

    if not all([integration_id, user_id]):
        return {
            'statusCode': 400,
            'body': json.dumps({'error': 'Missing integration_id or user_id'})
        }

    manager = IntegrationManager()
    manager.delete_integration(integration_id, user_id)

    return {
        'statusCode': 200,
        'headers': {
            'Content-Type': 'application/json',
            'Access-Control-Allow-Origin': '*'
        },
        'body': json.dumps({'message': 'Integration deleted successfully'})
    }


def handle_test_integration(params: Dict[str, str], query_params: Dict[str, str]) -> Dict[str, Any]:
    """
    Test integration connection.

    Path parameters:
    - id: Integration ID

    Query parameters:
    - user_id: User ID
    """
    integration_id = params.get('id')
    user_id = query_params.get('user_id')

    if not all([integration_id, user_id]):
        return {
            'statusCode': 400,
            'body': json.dumps({'error': 'Missing integration_id or user_id'})
        }

    manager = IntegrationManager()
    result = manager.test_integration(integration_id, user_id)

    return {
        'statusCode': 200,
        'headers': {
            'Content-Type': 'application/json',
            'Access-Control-Allow-Origin': '*'
        },
        'body': json.dumps(result)
    }


def handle_get_integration_types() -> Dict[str, Any]:
    """
    Get available integration types with descriptions.
    """
    types = [
        {
            'type': 'slack',
            'name': 'Slack',
            'description': 'Send alerts to Slack channels via webhooks',
            'icon': 'message-square',
            'fields': [
                {'name': 'webhook_url', 'label': 'Webhook URL', 'type': 'password', 'required': True},
                {'name': 'channel', 'label': 'Channel', 'type': 'text', 'required': True},
                {'name': 'username', 'label': 'Bot Username', 'type': 'text', 'required': False, 'default': 'Mantissa Log'}
            ]
        },
        {
            'type': 'jira',
            'name': 'Jira',
            'description': 'Create issues in Jira for alerts',
            'icon': 'ticket',
            'fields': [
                {'name': 'url', 'label': 'Jira URL', 'type': 'url', 'required': True, 'placeholder': 'https://your-domain.atlassian.net'},
                {'name': 'username', 'label': 'Username/Email', 'type': 'text', 'required': True},
                {'name': 'api_token', 'label': 'API Token', 'type': 'password', 'required': True},
                {'name': 'project_key', 'label': 'Project Key', 'type': 'text', 'required': True},
                {'name': 'issue_type', 'label': 'Issue Type', 'type': 'text', 'required': True, 'default': 'Bug'}
            ]
        },
        {
            'type': 'pagerduty',
            'name': 'PagerDuty',
            'description': 'Send incidents to PagerDuty',
            'icon': 'alert-circle',
            'fields': [
                {'name': 'integration_key', 'label': 'Integration Key', 'type': 'password', 'required': True}
            ]
        },
        {
            'type': 'email',
            'name': 'Email',
            'description': 'Send alerts via email',
            'icon': 'mail',
            'fields': [
                {'name': 'recipients', 'label': 'Recipients', 'type': 'array', 'required': True}
            ]
        },
        {
            'type': 'webhook',
            'name': 'Custom Webhook',
            'description': 'Send alerts to a custom webhook endpoint',
            'icon': 'link',
            'fields': [
                {'name': 'url', 'label': 'Webhook URL', 'type': 'url', 'required': True},
                {'name': 'method', 'label': 'HTTP Method', 'type': 'select', 'required': True, 'default': 'POST', 'options': ['POST', 'PUT', 'PATCH']},
                {'name': 'auth_type', 'label': 'Authentication', 'type': 'select', 'required': False, 'options': ['none', 'bearer', 'basic']}
            ]
        }
    ]

    return {
        'statusCode': 200,
        'headers': {
            'Content-Type': 'application/json',
            'Access-Control-Allow-Origin': '*'
        },
        'body': json.dumps({'types': types})
    }
