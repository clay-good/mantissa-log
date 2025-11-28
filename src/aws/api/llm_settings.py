"""
LLM Settings API

Manages user LLM provider configurations and API keys.
"""

import json
import os
import sys
from pathlib import Path
from typing import Dict, Any, Optional

import boto3
from botocore.exceptions import ClientError

# Add shared utilities to path
sys.path.append(str(Path(__file__).parent.parent.parent / 'shared'))


def lambda_handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """
    Lambda handler for LLM settings management.
    
    Routes:
    - GET /api/llm-settings/{userId}
    - PUT /api/llm-settings/{userId}
    - POST /api/llm-settings/{userId}/test
    """
    try:
        http_method = event.get('httpMethod', 'GET')
        path = event.get('path', '')
        path_params = event.get('pathParameters', {})
        user_id = path_params.get('userId')
        
        if not user_id:
            return error_response('userId is required', 400)
        
        if http_method == 'GET':
            return get_llm_settings(user_id)
        elif http_method == 'PUT':
            body = json.loads(event.get('body', '{}'))
            return update_llm_settings(user_id, body)
        elif http_method == 'POST' and path.endswith('/test'):
            body = json.loads(event.get('body', '{}'))
            return test_llm_connection(user_id, body)
        else:
            return error_response('Method not allowed', 405)
            
    except Exception as e:
        print(f"Error in LLM settings API: {str(e)}")
        import traceback
        traceback.print_exc()
        return error_response(str(e), 500)


def get_llm_settings(user_id: str) -> Dict[str, Any]:
    """Get user's LLM settings (without API keys)."""
    dynamodb = boto3.resource('dynamodb')
    table = dynamodb.Table(get_settings_table_name())
    
    try:
        response = table.get_item(
            Key={
                'user_id': user_id,
                'setting_type': 'llm_preferences'
            }
        )
        
        if 'Item' not in response:
            # Return defaults
            return success_response({
                'preferences': get_default_preferences(),
                'hasApiKeys': {}
            })
        
        settings = response['Item']
        preferences = settings.get('preferences', get_default_preferences())
        
        # Check which API keys are configured
        has_api_keys = {}
        for provider in ['anthropic', 'openai', 'google', 'bedrock']:
            has_api_keys[provider] = check_api_key_exists(user_id, provider)
        
        return success_response({
            'preferences': preferences,
            'hasApiKeys': has_api_keys
        })
        
    except ClientError as e:
        print(f"DynamoDB error: {str(e)}")
        return error_response('Failed to retrieve settings', 500)


def update_llm_settings(user_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
    """Update user's LLM settings."""
    preferences = data.get('preferences', {})
    api_keys = data.get('apiKeys', {})
    
    # Validate preferences
    if not validate_preferences(preferences):
        return error_response('Invalid preferences', 400)
    
    # Store preferences in DynamoDB
    dynamodb = boto3.resource('dynamodb')
    table = dynamodb.Table(get_settings_table_name())
    
    try:
        table.put_item(
            Item={
                'user_id': user_id,
                'setting_type': 'llm_preferences',
                'preferences': preferences,
                'updated_at': get_timestamp()
            }
        )
    except ClientError as e:
        print(f"DynamoDB error: {str(e)}")
        return error_response('Failed to save preferences', 500)
    
    # Store API keys in AWS Secrets Manager
    for provider, api_key in api_keys.items():
        if api_key and api_key.strip():
            store_api_key(user_id, provider, api_key)
    
    return success_response({
        'message': 'Settings updated successfully',
        'preferences': preferences
    })


def test_llm_connection(user_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
    """Test connection to LLM provider."""
    provider = data.get('provider')
    
    if not provider:
        return error_response('provider is required', 400)
    
    if provider not in ['anthropic', 'openai', 'google', 'bedrock']:
        return error_response('Invalid provider', 400)
    
    # Get API key
    api_key = get_api_key(user_id, provider)
    
    if not api_key and provider != 'bedrock':
        return error_response(f'No API key configured for {provider}', 400)
    
    # Test connection
    try:
        if provider == 'anthropic':
            result = test_anthropic(api_key)
        elif provider == 'openai':
            result = test_openai(api_key)
        elif provider == 'google':
            result = test_google(api_key)
        elif provider == 'bedrock':
            result = test_bedrock()
        else:
            return error_response('Provider not supported', 400)
        
        return success_response({
            'success': True,
            'provider': provider,
            'message': result.get('message', 'Connection successful'),
            'model': result.get('model'),
            'latency_ms': result.get('latency_ms')
        })
        
    except Exception as e:
        return success_response({
            'success': False,
            'provider': provider,
            'error': str(e)
        })


def test_anthropic(api_key: str) -> Dict[str, Any]:
    """Test Anthropic API connection."""
    import anthropic
    import time
    
    client = anthropic.Anthropic(api_key=api_key)
    
    start = time.time()
    response = client.messages.create(
        model="claude-3-5-sonnet-20241022",
        max_tokens=10,
        messages=[{"role": "user", "content": "Hi"}]
    )
    latency = (time.time() - start) * 1000
    
    return {
        'message': 'Connection successful',
        'model': response.model,
        'latency_ms': round(latency, 2)
    }


def test_openai(api_key: str) -> Dict[str, Any]:
    """Test OpenAI API connection."""
    import openai
    import time
    
    client = openai.OpenAI(api_key=api_key)
    
    start = time.time()
    response = client.chat.completions.create(
        model="gpt-4",
        max_tokens=10,
        messages=[{"role": "user", "content": "Hi"}]
    )
    latency = (time.time() - start) * 1000
    
    return {
        'message': 'Connection successful',
        'model': response.model,
        'latency_ms': round(latency, 2)
    }


def test_google(api_key: str) -> Dict[str, Any]:
    """Test Google Gemini API connection."""
    import google.generativeai as genai
    import time
    
    genai.configure(api_key=api_key)
    model = genai.GenerativeModel('gemini-pro')
    
    start = time.time()
    response = model.generate_content(
        "Hi",
        generation_config={'max_output_tokens': 10}
    )
    latency = (time.time() - start) * 1000
    
    return {
        'message': 'Connection successful',
        'model': 'gemini-pro',
        'latency_ms': round(latency, 2)
    }


def test_bedrock() -> Dict[str, Any]:
    """Test AWS Bedrock connection."""
    import time
    
    bedrock = boto3.client('bedrock-runtime')
    
    start = time.time()
    response = bedrock.invoke_model(
        modelId='anthropic.claude-3-5-sonnet-20241022-v2:0',
        body=json.dumps({
            'anthropic_version': 'bedrock-2023-05-31',
            'max_tokens': 10,
            'messages': [{'role': 'user', 'content': 'Hi'}]
        })
    )
    latency = (time.time() - start) * 1000
    
    return {
        'message': 'Connection successful',
        'model': 'claude-3-5-sonnet (Bedrock)',
        'latency_ms': round(latency, 2)
    }


def store_api_key(user_id: str, provider: str, api_key: str) -> None:
    """Store API key in AWS Secrets Manager."""
    secrets = boto3.client('secretsmanager')
    secret_name = f"mantissa-log/users/{user_id}/llm/{provider}"
    
    try:
        secrets.put_secret_value(
            SecretId=secret_name,
            SecretString=api_key
        )
    except secrets.exceptions.ResourceNotFoundException:
        # Create secret if it doesn't exist
        secrets.create_secret(
            Name=secret_name,
            SecretString=api_key,
            Tags=[
                {'Key': 'User', 'Value': user_id},
                {'Key': 'Provider', 'Value': provider}
            ]
        )


def get_api_key(user_id: str, provider: str) -> Optional[str]:
    """Retrieve API key from AWS Secrets Manager."""
    secrets = boto3.client('secretsmanager')
    secret_name = f"mantissa-log/users/{user_id}/llm/{provider}"
    
    try:
        response = secrets.get_secret_value(SecretId=secret_name)
        return response['SecretString']
    except secrets.exceptions.ResourceNotFoundException:
        return None
    except Exception as e:
        print(f"Error retrieving secret: {str(e)}")
        return None


def check_api_key_exists(user_id: str, provider: str) -> bool:
    """Check if API key exists for provider."""
    secrets = boto3.client('secretsmanager')
    secret_name = f"mantissa-log/users/{user_id}/llm/{provider}"
    
    try:
        secrets.describe_secret(SecretId=secret_name)
        return True
    except secrets.exceptions.ResourceNotFoundException:
        return False
    except Exception:
        return False


def validate_preferences(preferences: Dict[str, Any]) -> bool:
    """Validate LLM preferences."""
    required_fields = ['defaultProvider', 'queryModel', 'detectionModel']
    
    for field in required_fields:
        if field not in preferences:
            return False
    
    valid_providers = ['anthropic', 'openai', 'google', 'bedrock']
    if preferences['defaultProvider'] not in valid_providers:
        return False
    
    return True


def get_default_preferences() -> Dict[str, Any]:
    """Get default LLM preferences."""
    return {
        'defaultProvider': 'bedrock',
        'queryModel': 'claude-3-5-sonnet-20241022',
        'detectionModel': 'claude-3-5-sonnet-20241022',
        'maxTokens': 2000,
        'temperature': 0.0,
        'enableCaching': True,
        'trackUsage': True
    }


def get_settings_table_name() -> str:
    """Get DynamoDB table name for user settings."""
    return os.environ.get('USER_SETTINGS_TABLE', 'mantissa-log-user-settings')


def get_timestamp() -> str:
    """Get current timestamp in ISO format."""
    from datetime import datetime
    return datetime.utcnow().isoformat() + 'Z'


def success_response(data: Dict[str, Any]) -> Dict[str, Any]:
    """Return success response."""
    return {
        'statusCode': 200,
        'headers': {
            'Content-Type': 'application/json',
            'Access-Control-Allow-Origin': '*'
        },
        'body': json.dumps(data)
    }


def error_response(message: str, status_code: int) -> Dict[str, Any]:
    """Return error response."""
    return {
        'statusCode': status_code,
        'headers': {
            'Content-Type': 'application/json',
            'Access-Control-Allow-Origin': '*'
        },
        'body': json.dumps({'error': message})
    }
