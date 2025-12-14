"""
Redaction API Handler

Lambda function to handle PII/PHI redaction configuration API requests.
"""

import json
import logging
import os
import sys
from typing import Dict, Any

# Add shared modules to path
sys.path.insert(0, '/opt/python')
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../../shared'))

from redaction.redaction_manager import RedactionManager
from redaction.redactor import RedactionType, IntegrationRedactionConfig

# Import authentication and CORS utilities
from auth import (
    get_authenticated_user_id,
    AuthenticationError,
    AuthorizationError,
)
from auth.cors import get_cors_headers, cors_preflight_response

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)


def lambda_handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """
    Handle redaction configuration API requests.

    Routes:
    - GET /redaction/config - Get user's redaction configurations
    - GET /redaction/config/{integration_id} - Get integration config
    - POST /redaction/config - Save redaction configuration
    - DELETE /redaction/config/{integration_id} - Delete configuration
    - GET /redaction/audit - Get redaction audit trail
    - GET /redaction/stats - Get redaction statistics
    - POST /redaction/test - Test redaction on sample data
    """
    # Handle CORS preflight
    method = event.get('httpMethod', 'GET')
    if method == 'OPTIONS':
        return cors_preflight_response(event)

    try:
        # Authenticate user from Cognito JWT claims
        try:
            user_id = get_authenticated_user_id(event)
        except AuthenticationError:
            return {
                'statusCode': 401,
                'headers': {
                    'Content-Type': 'application/json',
                    **get_cors_headers(event)
                },
                'body': json.dumps({'error': 'Authentication required'})
            }

        path = event.get('path', '')
        body = json.loads(event.get('body', '{}')) if event.get('body') else {}
        params = event.get('pathParameters') or {}

        # Route to appropriate handler (pass authenticated user_id)
        if path == '/redaction/config' and method == 'GET':
            return handle_get_configs(event, user_id)
        elif path == '/redaction/config' and method == 'POST':
            return handle_save_config(event, user_id, body)
        elif path.startswith('/redaction/config/') and method == 'GET':
            return handle_get_integration_config(event, user_id, params)
        elif path.startswith('/redaction/config/') and method == 'DELETE':
            return handle_delete_config(event, user_id, params)
        elif path == '/redaction/audit' and method == 'GET':
            return handle_get_audit_trail(event, user_id)
        elif path == '/redaction/stats' and method == 'GET':
            return handle_get_statistics(event, user_id)
        elif path == '/redaction/test' and method == 'POST':
            return handle_test_redaction(event, body)
        else:
            return {
                'statusCode': 404,
                'headers': {
                    'Content-Type': 'application/json',
                    **get_cors_headers(event)
                },
                'body': json.dumps({'error': 'Not found'})
            }

    except Exception as e:
        logger.error(f'Error in redaction API handler: {e}', exc_info=True)

        return {
            'statusCode': 500,
            'headers': {
                'Content-Type': 'application/json',
                **get_cors_headers(event)
            },
            'body': json.dumps({'error': 'Internal server error'})
        }


def handle_get_configs(event: Dict[str, Any], user_id: str) -> Dict[str, Any]:
    """
    Get user's redaction configurations.

    Note: user_id is extracted from authenticated JWT.
    """
    manager = RedactionManager()
    configs = manager.get_user_configs(user_id)

    configs_data = [config.to_dict() for config in configs]

    return {
        'statusCode': 200,
        'headers': {
            'Content-Type': 'application/json',
            **get_cors_headers(event)
        },
        'body': json.dumps({
            'configs': configs_data,
            'total': len(configs_data)
        })
    }


def handle_get_integration_config(
    event: Dict[str, Any],
    user_id: str,
    params: Dict[str, str]
) -> Dict[str, Any]:
    """
    Get redaction configuration for a specific integration.

    Path parameters:
    - integration_id: Integration ID

    Note: user_id is extracted from authenticated JWT.
    """
    integration_id = params.get('integration_id')

    if not integration_id:
        return {
            'statusCode': 400,
            'headers': {
                'Content-Type': 'application/json',
                **get_cors_headers(event)
            },
            'body': json.dumps({'error': 'Missing integration_id'})
        }

    manager = RedactionManager()
    config = manager.get_integration_config(user_id, integration_id)

    if not config:
        return {
            'statusCode': 404,
            'headers': {
                'Content-Type': 'application/json',
                **get_cors_headers(event)
            },
            'body': json.dumps({'error': 'Configuration not found'})
        }

    return {
        'statusCode': 200,
        'headers': {
            'Content-Type': 'application/json',
            **get_cors_headers(event)
        },
        'body': json.dumps({'config': config.to_dict()})
    }


def handle_save_config(event: Dict[str, Any], user_id: str, body: Dict[str, Any]) -> Dict[str, Any]:
    """
    Save redaction configuration.

    Request body:
    {
        "integration_id": "int-abc",
        "integration_type": "slack",
        "enabled": true,
        "enabled_patterns": ["email", "phone", "ssn"],
        "custom_patterns": {"api_key": "api[_-]?key[:\\s=]+[a-zA-Z0-9]+"},
        "preserve_fields": ["alert_id", "severity"]
    }

    Note: user_id is extracted from authenticated JWT, not request body.
    """
    integration_id = body.get('integration_id')
    integration_type = body.get('integration_type')

    if not all([integration_id, integration_type]):
        return {
            'statusCode': 400,
            'headers': {
                'Content-Type': 'application/json',
                **get_cors_headers(event)
            },
            'body': json.dumps({'error': 'Missing required fields'})
        }

    try:
        # Parse enabled patterns
        enabled_patterns = set()
        for pattern_str in body.get('enabled_patterns', []):
            try:
                enabled_patterns.add(RedactionType(pattern_str))
            except ValueError:
                pass

        # Create config
        config = IntegrationRedactionConfig(
            integration_id=integration_id,
            integration_type=integration_type,
            enabled=body.get('enabled', True),
            enabled_patterns=enabled_patterns,
            custom_patterns=body.get('custom_patterns', {}),
            preserve_fields=set(body.get('preserve_fields', []))
        )

        manager = RedactionManager()
        manager.save_integration_config(user_id, config)

        return {
            'statusCode': 200,
            'headers': {
                'Content-Type': 'application/json',
                **get_cors_headers(event)
            },
            'body': json.dumps({
                'config': config.to_dict(),
                'message': 'Configuration saved successfully'
            })
        }

    except Exception as e:
        logger.error(f'Error saving redaction config: {e}', exc_info=True)
        return {
            'statusCode': 500,
            'headers': {
                'Content-Type': 'application/json',
                **get_cors_headers(event)
            },
            'body': json.dumps({'error': 'Failed to save configuration'})
        }


def handle_delete_config(
    event: Dict[str, Any],
    user_id: str,
    params: Dict[str, str]
) -> Dict[str, Any]:
    """
    Delete redaction configuration.

    Path parameters:
    - integration_id: Integration ID

    Note: user_id is extracted from authenticated JWT.
    """
    integration_id = params.get('integration_id')

    if not integration_id:
        return {
            'statusCode': 400,
            'headers': {
                'Content-Type': 'application/json',
                **get_cors_headers(event)
            },
            'body': json.dumps({'error': 'Missing integration_id'})
        }

    manager = RedactionManager()
    manager.delete_integration_config(user_id, integration_id)

    return {
        'statusCode': 200,
        'headers': {
            'Content-Type': 'application/json',
            **get_cors_headers(event)
        },
        'body': json.dumps({'message': 'Configuration deleted successfully'})
    }


def handle_get_audit_trail(event: Dict[str, Any], user_id: str) -> Dict[str, Any]:
    """
    Get redaction audit trail.

    Query parameters:
    - integration_id: Optional integration filter
    - limit: Maximum records (default 100)

    Note: user_id is extracted from authenticated JWT.
    """
    query_params = event.get('queryStringParameters') or {}
    integration_id = query_params.get('integration_id')
    limit = int(query_params.get('limit', 100))

    manager = RedactionManager()
    audit_trail = manager.get_redaction_audit_trail(
        user_id=user_id,
        integration_id=integration_id,
        limit=limit
    )

    return {
        'statusCode': 200,
        'headers': {
            'Content-Type': 'application/json',
            **get_cors_headers(event)
        },
        'body': json.dumps({
            'audit_trail': audit_trail,
            'total': len(audit_trail)
        })
    }


def handle_get_statistics(event: Dict[str, Any], user_id: str) -> Dict[str, Any]:
    """
    Get redaction statistics.

    Query parameters:
    - days: Number of days to look back (default 30)

    Note: user_id is extracted from authenticated JWT.
    """
    query_params = event.get('queryStringParameters') or {}
    days = int(query_params.get('days', 30))

    manager = RedactionManager()
    stats = manager.get_redaction_statistics(user_id, days)

    return {
        'statusCode': 200,
        'headers': {
            'Content-Type': 'application/json',
            **get_cors_headers(event)
        },
        'body': json.dumps({'statistics': stats})
    }


def handle_test_redaction(event: Dict[str, Any], body: Dict[str, Any]) -> Dict[str, Any]:
    """
    Test redaction on sample data.

    Request body:
    {
        "sample_data": {
            "email": "test@example.com",
            "message": "Contact at 555-1234"
        },
        "enabled_patterns": ["email", "phone"]
    }
    """
    sample_data = body.get('sample_data')

    if not sample_data:
        return {
            'statusCode': 400,
            'headers': {
                'Content-Type': 'application/json',
                **get_cors_headers(event)
            },
            'body': json.dumps({'error': 'Missing sample_data'})
        }

    from redaction.redactor import Redactor, DEFAULT_PATTERNS

    # Create redactor with specified patterns
    patterns = {}
    enabled_pattern_names = body.get('enabled_patterns', [])

    for pattern_type, pattern in DEFAULT_PATTERNS.items():
        if pattern_type.value in enabled_pattern_names:
            patterns[pattern_type] = pattern

    redactor = Redactor(patterns)

    # Redact the sample data
    redacted_data = redactor.redact_dict(sample_data)

    # Get summary
    summary = redactor.get_redaction_summary(sample_data)

    return {
        'statusCode': 200,
        'headers': {
            'Content-Type': 'application/json',
            **get_cors_headers(event)
        },
        'body': json.dumps({
            'original': sample_data,
            'redacted': redacted_data,
            'summary': summary
        })
    }
