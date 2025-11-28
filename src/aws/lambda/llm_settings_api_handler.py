"""
LLM Settings API Handler

Lambda function to handle LLM configuration and settings API requests.
Manages user preferences for LLM providers, API keys, and model selection.
"""

import json
import os
import sys
from typing import Dict, Any

# Add shared modules to path
sys.path.insert(0, '/opt/python')
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../../shared'))

from llm.provider_manager import (
    LLMProviderManager,
    LLMProvider,
    UserLLMSettings,
    ProviderConfig
)


def lambda_handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """
    Handle LLM settings API requests.

    Routes:
    - GET /llm/settings - Get user's LLM settings
    - POST /llm/settings - Save user's LLM settings
    - POST /llm/test-connection - Test provider connection
    - GET /llm/models - Get available models
    - GET /llm/usage - Get usage statistics
    """
    try:
        path = event.get('path', '')
        method = event.get('httpMethod', 'GET')
        body = json.loads(event.get('body', '{}')) if event.get('body') else {}
        params = event.get('queryStringParameters') or {}

        # Route to appropriate handler
        if path == '/llm/settings' and method == 'GET':
            return handle_get_settings(params)
        elif path == '/llm/settings' and method == 'POST':
            return handle_save_settings(body)
        elif path == '/llm/test-connection' and method == 'POST':
            return handle_test_connection(body)
        elif path == '/llm/models' and method == 'GET':
            return handle_get_models(params)
        elif path == '/llm/usage' and method == 'GET':
            return handle_get_usage(params)
        else:
            return {
                'statusCode': 404,
                'body': json.dumps({'error': 'Not found'})
            }

    except Exception as e:
        print(f'Error in LLM settings API handler: {e}')
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


def handle_get_settings(params: Dict[str, str]) -> Dict[str, Any]:
    """
    Get user's LLM settings.

    Query parameters:
    - user_id: User ID
    """
    user_id = params.get('user_id')

    if not user_id:
        return {
            'statusCode': 400,
            'body': json.dumps({'error': 'Missing user_id'})
        }

    manager = LLMProviderManager()
    settings = manager.get_user_settings(user_id)

    # Convert settings to JSON-friendly format
    if settings:
        settings_data = {
            'user_id': settings.user_id,
            'providers': {},
            'preferences': {
                'queryModel': settings.query_model,
                'detectionModel': settings.detection_model,
                'maxTokens': settings.max_tokens,
                'temperature': settings.temperature
            }
        }

        # Add provider configurations (without exposing actual API keys)
        for provider_name, config in settings.providers.items():
            settings_data['providers'][provider_name] = {
                'enabled': config.enabled,
                'model': config.model_id,
                'region': config.region,
                'hasApiKey': bool(config.api_key_secret_id)
            }
    else:
        # Return default settings if none exist
        settings_data = {
            'user_id': user_id,
            'providers': {
                'anthropic': {'enabled': False, 'model': 'claude-3-5-sonnet-20241022', 'hasApiKey': False},
                'openai': {'enabled': False, 'model': 'gpt-4-turbo-preview', 'hasApiKey': False},
                'google': {'enabled': False, 'model': 'gemini-1.5-pro', 'hasApiKey': False},
                'bedrock': {'enabled': False, 'model': 'anthropic.claude-3-5-sonnet-20241022-v2:0', 'region': 'us-east-1', 'hasApiKey': False}
            },
            'preferences': {
                'queryModel': 'claude-3-5-sonnet-20241022',
                'detectionModel': 'claude-3-5-sonnet-20241022',
                'maxTokens': 2000,
                'temperature': 0.0
            }
        }

    return {
        'statusCode': 200,
        'headers': {
            'Content-Type': 'application/json',
            'Access-Control-Allow-Origin': '*'
        },
        'body': json.dumps({'settings': settings_data})
    }


def handle_save_settings(body: Dict[str, Any]) -> Dict[str, Any]:
    """
    Save user's LLM settings.

    Request body:
    {
        "user_id": "user-123",
        "settings": {
            "providers": {
                "anthropic": {
                    "enabled": true,
                    "apiKey": "sk-ant-...",
                    "model": "claude-3-5-sonnet-20241022"
                },
                ...
            },
            "preferences": {
                "queryModel": "claude-3-5-sonnet-20241022",
                "detectionModel": "claude-3-5-sonnet-20241022",
                "maxTokens": 2000,
                "temperature": 0.0
            }
        }
    }
    """
    user_id = body.get('user_id')
    settings_data = body.get('settings')

    if not all([user_id, settings_data]):
        return {
            'statusCode': 400,
            'body': json.dumps({'error': 'Missing required fields'})
        }

    manager = LLMProviderManager()

    try:
        # Build provider configurations
        provider_configs = {}

        for provider_name, provider_data in settings_data.get('providers', {}).items():
            if not provider_data.get('enabled'):
                continue

            try:
                provider_enum = LLMProvider(provider_name)
            except ValueError:
                continue

            # Store API key if provided
            api_key = provider_data.get('apiKey', '')
            api_key_secret_id = None

            if api_key and provider_enum != LLMProvider.AWS_BEDROCK:
                api_key_secret_id = manager.store_api_key(
                    user_id=user_id,
                    provider=provider_enum,
                    api_key=api_key
                )

            # Create provider config
            config = ProviderConfig(
                provider=provider_enum,
                enabled=True,
                model_id=provider_data.get('model', ''),
                api_key_secret_id=api_key_secret_id,
                region=provider_data.get('region')
            )

            provider_configs[provider_enum] = config

        # Create user settings
        preferences = settings_data.get('preferences', {})

        user_settings = UserLLMSettings(
            user_id=user_id,
            providers=provider_configs,
            query_model=preferences.get('queryModel', 'claude-3-5-sonnet-20241022'),
            detection_model=preferences.get('detectionModel', 'claude-3-5-sonnet-20241022'),
            max_tokens=preferences.get('maxTokens', 2000),
            temperature=preferences.get('temperature', 0.0)
        )

        # Save settings
        manager.save_user_settings(user_settings)

        return {
            'statusCode': 200,
            'headers': {
                'Content-Type': 'application/json',
                'Access-Control-Allow-Origin': '*'
            },
            'body': json.dumps({
                'message': 'Settings saved successfully',
                'user_id': user_id
            })
        }

    except Exception as e:
        print(f'Error saving settings: {e}')
        import traceback
        traceback.print_exc()

        return {
            'statusCode': 500,
            'headers': {
                'Content-Type': 'application/json',
                'Access-Control-Allow-Origin': '*'
            },
            'body': json.dumps({
                'error': f'Failed to save settings: {str(e)}'
            })
        }


def handle_test_connection(body: Dict[str, Any]) -> Dict[str, Any]:
    """
    Test connection to an LLM provider.

    Request body:
    {
        "user_id": "user-123",
        "provider": "anthropic",
        "api_key": "sk-ant-...",  # Optional, uses stored key if not provided
        "model": "claude-3-5-sonnet-20241022",
        "region": "us-east-1"  # For Bedrock only
    }
    """
    user_id = body.get('user_id')
    provider_name = body.get('provider')
    api_key = body.get('api_key')
    model_id = body.get('model')
    region = body.get('region')

    if not all([user_id, provider_name]):
        return {
            'statusCode': 400,
            'body': json.dumps({'error': 'Missing required fields'})
        }

    try:
        provider_enum = LLMProvider(provider_name)
    except ValueError:
        return {
            'statusCode': 400,
            'body': json.dumps({'error': f'Invalid provider: {provider_name}'})
        }

    manager = LLMProviderManager()

    try:
        # Test connection
        result = manager.test_provider_connection(
            provider=provider_enum,
            api_key=api_key,
            model_id=model_id,
            region=region
        )

        return {
            'statusCode': 200,
            'headers': {
                'Content-Type': 'application/json',
                'Access-Control-Allow-Origin': '*'
            },
            'body': json.dumps(result)
        }

    except Exception as e:
        print(f'Error testing connection: {e}')
        import traceback
        traceback.print_exc()

        return {
            'statusCode': 500,
            'headers': {
                'Content-Type': 'application/json',
                'Access-Control-Allow-Origin': '*'
            },
            'body': json.dumps({
                'success': False,
                'error': str(e),
                'message': 'Connection test failed'
            })
        }


def handle_get_models(params: Dict[str, str]) -> Dict[str, Any]:
    """
    Get available models for all providers or a specific provider.

    Query parameters:
    - provider: Optional provider filter
    """
    provider_filter = params.get('provider')

    manager = LLMProviderManager()

    try:
        if provider_filter:
            try:
                provider_enum = LLMProvider(provider_filter)
                models = manager.get_available_models(provider_enum)
            except ValueError:
                return {
                    'statusCode': 400,
                    'body': json.dumps({'error': f'Invalid provider: {provider_filter}'})
                }
        else:
            # Get all models
            models = {}
            for provider in LLMProvider:
                models[provider.value] = [
                    {
                        'id': model.model_id,
                        'name': model.display_name,
                        'provider': model.provider.value,
                        'inputCost': model.pricing.input_per_1m_tokens,
                        'outputCost': model.pricing.output_per_1m_tokens,
                        'maxTokens': model.max_tokens,
                        'bestFor': model.best_for
                    }
                    for model in manager.get_available_models(provider)
                ]

        return {
            'statusCode': 200,
            'headers': {
                'Content-Type': 'application/json',
                'Access-Control-Allow-Origin': '*'
            },
            'body': json.dumps({'models': models})
        }

    except Exception as e:
        print(f'Error getting models: {e}')

        return {
            'statusCode': 500,
            'headers': {
                'Content-Type': 'application/json',
                'Access-Control-Allow-Origin': '*'
            },
            'body': json.dumps({'error': str(e)})
        }


def handle_get_usage(params: Dict[str, str]) -> Dict[str, Any]:
    """
    Get LLM usage statistics for a user.

    Query parameters:
    - user_id: User ID
    - days: Number of days to look back (default 30)
    """
    user_id = params.get('user_id')
    days = int(params.get('days', 30))

    if not user_id:
        return {
            'statusCode': 400,
            'body': json.dumps({'error': 'Missing user_id'})
        }

    manager = LLMProviderManager()

    try:
        usage_stats = manager.get_usage_stats(user_id, days)

        return {
            'statusCode': 200,
            'headers': {
                'Content-Type': 'application/json',
                'Access-Control-Allow-Origin': '*'
            },
            'body': json.dumps({'usage': usage_stats})
        }

    except Exception as e:
        print(f'Error getting usage: {e}')

        return {
            'statusCode': 500,
            'headers': {
                'Content-Type': 'application/json',
                'Access-Control-Allow-Origin': '*'
            },
            'body': json.dumps({'error': str(e)})
        }
