"""
Settings API for Mantissa Log

Handles LLM configuration, integration settings, and user preferences.
Stores sensitive data (API keys) in AWS Secrets Manager.
"""

import json
import logging
import os
import sys
from pathlib import Path
from datetime import datetime
from typing import Dict, Any

# Add shared modules to path
sys.path.append(str(Path(__file__).parent.parent.parent / 'shared'))

from auth import get_authenticated_user_id, AuthenticationError
from auth.cors import get_cors_headers, cors_preflight_response
from utils.lazy_init import aws_clients

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

USER_SETTINGS_TABLE = os.environ.get('USER_SETTINGS_TABLE', 'mantissa_user_settings')


def _get_dynamodb():
    """Get lazily-initialized DynamoDB resource."""
    return aws_clients.dynamodb


def _get_secrets_manager():
    """Get lazily-initialized Secrets Manager client."""
    return aws_clients.secrets_manager


class SettingsAPI:
    """API handler for user settings and configuration"""

    def __init__(self):
        self._table = None

    @property
    def table(self):
        """Get lazily-initialized DynamoDB table."""
        if self._table is None:
            self._table = _get_dynamodb().Table(USER_SETTINGS_TABLE)
        return self._table

    def lambda_handler(self, event: Dict[str, Any], context: Any) -> Dict[str, Any]:
        """Main Lambda handler for settings endpoints"""

        http_method = event.get('httpMethod')
        path = event.get('path', '')

        # Handle CORS preflight
        if http_method == 'OPTIONS':
            return cors_preflight_response(event)

        try:
            # Authenticate user from Cognito JWT claims
            try:
                user_id = get_authenticated_user_id(event)
            except AuthenticationError:
                return self._error_response(event, 'Authentication required', 401)

            if '/api/settings/llm/test' in path:
                if http_method == 'POST':
                    return self.test_llm_connection(event, user_id)

            elif '/api/settings/llm' in path:
                if http_method == 'GET':
                    return self.get_llm_settings(event, user_id)
                elif http_method == 'PUT':
                    return self.update_llm_settings(event, user_id)

            elif '/api/settings/integrations/test' in path:
                if http_method == 'POST':
                    return self.test_integration(event, user_id)

            elif '/api/settings/integrations' in path:
                if http_method == 'GET':
                    return self.get_integration_settings(event, user_id)
                elif http_method == 'PUT':
                    return self.update_integration_settings(event, user_id)

            else:
                return {
                    'statusCode': 404,
                    'body': json.dumps({'error': 'Endpoint not found'}),
                    'headers': {'Content-Type': 'application/json', **get_cors_headers(event)}
                }

        except Exception as e:
            logger.error(f"Error in settings API: {e}", exc_info=True)
            return self._error_response(event, 'Internal server error', 500)

    def get_llm_settings(self, event: Dict[str, Any], user_id: str) -> Dict[str, Any]:
        """Get LLM configuration for a user (user_id from authenticated JWT)"""

        try:
            response = self.table.get_item(
                Key={'user_id': user_id, 'setting_type': 'llm_config'}
            )

            config = response.get('Item', {}).get('config', {})

            # Don't return actual API keys, just indicate if they're set
            if 'providers' in config:
                for provider_id, provider_config in config['providers'].items():
                    if 'apiKey' in provider_config and provider_config['apiKey']:
                        provider_config['apiKey'] = '********'

            return {
                'statusCode': 200,
                'body': json.dumps({'config': config}),
                'headers': {'Content-Type': 'application/json', **get_cors_headers(event)}
            }

        except Exception as e:
            logger.error(f"Error getting LLM settings: {e}", exc_info=True)
            return self._error_response(event, 'Failed to get settings', 500)

    def update_llm_settings(self, event: Dict[str, Any], user_id: str) -> Dict[str, Any]:
        """Update LLM configuration for a user (user_id from authenticated JWT)"""

        try:
            body = json.loads(event.get('body', '{}'))
            config = body.get('config', {})
            # user_id comes from authenticated JWT, not request body

            # Store API keys in Secrets Manager
            secret_references = {}
            if 'providers' in config:
                for provider_id, provider_config in config['providers'].items():
                    if 'apiKey' in provider_config and provider_config['apiKey']:
                        # Don't store if it's the masked placeholder
                        if provider_config['apiKey'] != '********':
                            secret_name = f"mantissa-log/{user_id}/llm/{provider_id}"

                            # Store in Secrets Manager
                            sm = _get_secrets_manager()
                            try:
                                sm.create_secret(
                                    Name=secret_name,
                                    SecretString=provider_config['apiKey']
                                )
                            except sm.exceptions.ResourceExistsException:
                                # Secret exists, update it
                                sm.update_secret(
                                    SecretId=secret_name,
                                    SecretString=provider_config['apiKey']
                                )

                            # Store reference instead of actual key
                            secret_references[provider_id] = secret_name
                            provider_config['apiKeySecretId'] = secret_name
                            del provider_config['apiKey']

            # Store configuration in DynamoDB
            self.table.put_item(
                Item={
                    'user_id': user_id,
                    'setting_type': 'llm_config',
                    'config': config,
                    'secret_references': secret_references,
                    'updated_at': datetime.utcnow().isoformat()
                }
            )

            return {
                'statusCode': 200,
                'body': json.dumps({
                    'message': 'LLM configuration updated successfully',
                    'config': config
                }),
                'headers': {'Content-Type': 'application/json', **get_cors_headers(event)}
            }

        except Exception as e:
            logger.error(f"Error updating LLM settings: {e}", exc_info=True)
            return self._error_response(event, 'Failed to update settings', 500)

    def test_llm_connection(self, event: Dict[str, Any], user_id: str) -> Dict[str, Any]:
        """Test connection to an LLM provider (user_id from authenticated JWT)"""

        try:
            body = json.loads(event.get('body', '{}'))
            provider = body.get('provider')
            model = body.get('model')
            api_key = body.get('api_key')
            region = body.get('region')

            if not provider:
                return self._error_response(event, 'provider is required', 400)

            # Test connection based on provider
            if provider == 'anthropic':
                result = self._test_anthropic(api_key, model)
            elif provider == 'openai':
                result = self._test_openai(api_key, model)
            elif provider == 'google':
                result = self._test_google(api_key, model)
            elif provider == 'bedrock':
                result = self._test_bedrock(region, model)
            else:
                return self._error_response(event, f'Unknown provider: {provider}', 400)

            return {
                'statusCode': 200 if result['success'] else 400,
                'body': json.dumps(result),
                'headers': {'Content-Type': 'application/json', **get_cors_headers(event)}
            }

        except Exception as e:
            logger.error(f"Error testing LLM connection: {e}", exc_info=True)
            return self._error_response(event, 'Failed to test connection', 500)

    def get_integration_settings(self, event: Dict[str, Any], user_id: str) -> Dict[str, Any]:
        """Get integration configuration for a user (user_id from authenticated JWT)"""

        try:
            response = self.table.get_item(
                Key={'user_id': user_id, 'setting_type': 'integrations'}
            )

            integrations = response.get('Item', {}).get('integrations', {})

            # Mask sensitive fields
            for integration_type, integration_config in integrations.items():
                if 'config' in integration_config:
                    config = integration_config['config']
                    sensitive_fields = ['api_token', 'webhook_url', 'integration_key',
                                       'smtp_password', 'password']
                    for field in sensitive_fields:
                        if field in config and config[field]:
                            config[field] = '********'

            return {
                'statusCode': 200,
                'body': json.dumps({'integrations': integrations}),
                'headers': {'Content-Type': 'application/json', **get_cors_headers(event)}
            }

        except Exception as e:
            logger.error(f"Error getting integration settings: {e}", exc_info=True)
            return self._error_response(event, 'Failed to get integrations', 500)

    def update_integration_settings(self, event: Dict[str, Any], user_id: str) -> Dict[str, Any]:
        """Update integration configuration for a user (user_id from authenticated JWT)"""

        try:
            body = json.loads(event.get('body', '{}'))
            integrations = body.get('integrations', {})
            # user_id comes from authenticated JWT, not request body

            # Store sensitive fields in Secrets Manager
            secret_references = {}
            for integration_type, integration_config in integrations.items():
                if 'config' in integration_config:
                    config = integration_config['config']

                    # Identify sensitive fields
                    sensitive_map = {
                        'slack': ['webhook_url'],
                        'jira': ['api_token'],
                        'pagerduty': ['integration_key'],
                        'email': ['smtp_password'],
                        'webhook': ['auth_token']
                    }

                    sensitive_fields = sensitive_map.get(integration_type, [])

                    for field in sensitive_fields:
                        if field in config and config[field] and config[field] != '********':
                            secret_name = f"mantissa-log/{user_id}/integration/{integration_type}/{field}"

                            # Store in Secrets Manager
                            sm = _get_secrets_manager()
                            try:
                                sm.create_secret(
                                    Name=secret_name,
                                    SecretString=config[field]
                                )
                            except sm.exceptions.ResourceExistsException:
                                sm.update_secret(
                                    SecretId=secret_name,
                                    SecretString=config[field]
                                )

                            # Store reference
                            if integration_type not in secret_references:
                                secret_references[integration_type] = {}
                            secret_references[integration_type][field] = secret_name
                            config[f'{field}_secret_id'] = secret_name
                            del config[field]

            # Store configuration in DynamoDB
            self.table.put_item(
                Item={
                    'user_id': user_id,
                    'setting_type': 'integrations',
                    'integrations': integrations,
                    'secret_references': secret_references,
                    'updated_at': datetime.utcnow().isoformat()
                }
            )

            return {
                'statusCode': 200,
                'body': json.dumps({
                    'message': 'Integration settings updated successfully',
                    'integrations': integrations
                }),
                'headers': {'Content-Type': 'application/json', **get_cors_headers(event)}
            }

        except Exception as e:
            logger.error(f"Error updating integration settings: {e}", exc_info=True)
            return self._error_response(event, 'Failed to update integrations', 500)

    def test_integration(self, event: Dict[str, Any], user_id: str) -> Dict[str, Any]:
        """Test an integration configuration (user_id from authenticated JWT)"""

        try:
            body = json.loads(event.get('body', '{}'))
            integration_type = body.get('type')
            config = body.get('config', {})

            if not integration_type:
                return self._error_response(event, 'type is required', 400)

            # Test integration based on type
            if integration_type == 'slack':
                result = self._test_slack(config)
            elif integration_type == 'jira':
                result = self._test_jira(config)
            elif integration_type == 'pagerduty':
                result = self._test_pagerduty(config)
            elif integration_type == 'email':
                result = self._test_email(config)
            elif integration_type == 'webhook':
                result = self._test_webhook(config)
            else:
                return self._error_response(event, f'Unknown integration type: {integration_type}', 400)

            return {
                'statusCode': 200 if result['success'] else 400,
                'body': json.dumps(result),
                'headers': {'Content-Type': 'application/json', **get_cors_headers(event)}
            }

        except Exception as e:
            logger.error(f"Error testing integration: {e}", exc_info=True)
            return self._error_response(event, 'Failed to test integration', 500)

    # LLM Test Methods

    def _test_anthropic(self, api_key: str, model: str) -> Dict[str, Any]:
        """Test Anthropic API connection"""
        import anthropic

        try:
            client = anthropic.Anthropic(api_key=api_key)
            response = client.messages.create(
                model=model,
                max_tokens=10,
                messages=[{"role": "user", "content": "Test"}]
            )
            return {'success': True, 'message': 'Anthropic API connection successful'}
        except Exception as e:
            return {'success': False, 'message': f'Anthropic API error: {str(e)}'}

    def _test_openai(self, api_key: str, model: str) -> Dict[str, Any]:
        """Test OpenAI API connection"""
        import openai

        try:
            client = openai.OpenAI(api_key=api_key)
            response = client.chat.completions.create(
                model=model,
                max_tokens=10,
                messages=[{"role": "user", "content": "Test"}]
            )
            return {'success': True, 'message': 'OpenAI API connection successful'}
        except Exception as e:
            return {'success': False, 'message': f'OpenAI API error: {str(e)}'}

    def _test_google(self, api_key: str, model: str) -> Dict[str, Any]:
        """Test Google Gemini API connection"""
        import google.generativeai as genai

        try:
            genai.configure(api_key=api_key)
            model_instance = genai.GenerativeModel(model)
            response = model_instance.generate_content("Test")
            return {'success': True, 'message': 'Google Gemini API connection successful'}
        except Exception as e:
            return {'success': False, 'message': f'Google API error: {str(e)}'}

    def _test_bedrock(self, region: str, model: str) -> Dict[str, Any]:
        """Test AWS Bedrock connection"""

        try:
            bedrock = boto3.client('bedrock-runtime', region_name=region)
            response = bedrock.invoke_model(
                modelId=model,
                body=json.dumps({
                    "anthropic_version": "bedrock-2023-05-31",
                    "max_tokens": 10,
                    "messages": [{"role": "user", "content": "Test"}]
                })
            )
            return {'success': True, 'message': 'AWS Bedrock connection successful'}
        except Exception as e:
            return {'success': False, 'message': f'Bedrock error: {str(e)}'}

    # Integration Test Methods

    def _test_slack(self, config: Dict[str, Any]) -> Dict[str, Any]:
        """Test Slack webhook"""
        import requests

        webhook_url = config.get('webhook_url')
        if not webhook_url:
            return {'success': False, 'message': 'Webhook URL is required'}

        try:
            response = requests.post(
                webhook_url,
                json={'text': 'Mantissa Log test message'},
                timeout=10
            )
            if response.status_code == 200:
                return {'success': True, 'message': 'Slack test message sent successfully'}
            else:
                return {'success': False, 'message': f'Slack returned status {response.status_code}'}
        except Exception as e:
            return {'success': False, 'message': f'Slack error: {str(e)}'}

    def _test_jira(self, config: Dict[str, Any]) -> Dict[str, Any]:
        """Test Jira connection"""
        import requests
        from requests.auth import HTTPBasicAuth

        url = config.get('url')
        email = config.get('email')
        api_token = config.get('api_token')

        if not all([url, email, api_token]):
            return {'success': False, 'message': 'URL, email, and API token are required'}

        try:
            response = requests.get(
                f"{url}/rest/api/3/myself",
                auth=HTTPBasicAuth(email, api_token),
                timeout=10
            )
            if response.status_code == 200:
                return {'success': True, 'message': 'Jira connection successful'}
            else:
                return {'success': False, 'message': f'Jira returned status {response.status_code}'}
        except Exception as e:
            return {'success': False, 'message': f'Jira error: {str(e)}'}

    def _test_pagerduty(self, config: Dict[str, Any]) -> Dict[str, Any]:
        """Test PagerDuty integration"""
        import requests

        integration_key = config.get('integration_key')
        if not integration_key:
            return {'success': False, 'message': 'Integration key is required'}

        try:
            response = requests.post(
                'https://events.pagerduty.com/v2/enqueue',
                json={
                    'routing_key': integration_key,
                    'event_action': 'trigger',
                    'payload': {
                        'summary': 'Mantissa Log test alert',
                        'severity': 'info',
                        'source': 'mantissa-log'
                    }
                },
                timeout=10
            )
            if response.status_code == 202:
                return {'success': True, 'message': 'PagerDuty test alert sent successfully'}
            else:
                return {'success': False, 'message': f'PagerDuty returned status {response.status_code}'}
        except Exception as e:
            return {'success': False, 'message': f'PagerDuty error: {str(e)}'}

    def _test_email(self, config: Dict[str, Any]) -> Dict[str, Any]:
        """Test email SMTP configuration"""
        import smtplib
        from email.mime.text import MIMEText

        smtp_host = config.get('smtp_host')
        smtp_port = config.get('smtp_port')
        smtp_user = config.get('smtp_user')
        smtp_password = config.get('smtp_password')
        from_email = config.get('from_email')

        if not all([smtp_host, smtp_port, smtp_user, smtp_password, from_email]):
            return {'success': False, 'message': 'All SMTP fields are required'}

        try:
            msg = MIMEText('Mantissa Log test email')
            msg['Subject'] = 'Mantissa Log Test'
            msg['From'] = from_email
            msg['To'] = from_email

            with smtplib.SMTP(smtp_host, int(smtp_port)) as server:
                server.starttls()
                server.login(smtp_user, smtp_password)
                server.send_message(msg)

            return {'success': True, 'message': 'Email test successful'}
        except Exception as e:
            return {'success': False, 'message': f'Email error: {str(e)}'}

    def _test_webhook(self, config: Dict[str, Any]) -> Dict[str, Any]:
        """Test custom webhook"""
        import requests

        url = config.get('url')
        method = config.get('method', 'POST')

        if not url:
            return {'success': False, 'message': 'Webhook URL is required'}

        try:
            headers = {}
            if config.get('headers'):
                headers = json.loads(config['headers'])

            response = requests.request(
                method=method,
                url=url,
                json={'test': True, 'source': 'mantissa-log'},
                headers=headers,
                timeout=10
            )

            if 200 <= response.status_code < 300:
                return {'success': True, 'message': f'Webhook test successful (status {response.status_code})'}
            else:
                return {'success': False, 'message': f'Webhook returned status {response.status_code}'}
        except Exception as e:
            return {'success': False, 'message': f'Webhook error: {str(e)}'}

    def _error_response(self, event: Dict[str, Any], message: str, status_code: int = 400) -> Dict[str, Any]:
        """Standard error response with secure CORS headers"""
        return {
            'statusCode': status_code,
            'body': json.dumps({'error': message}),
            'headers': {'Content-Type': 'application/json', **get_cors_headers(event)}
        }


# Lambda handler
api = SettingsAPI()

def lambda_handler(event, context):
    """Lambda entry point"""
    return api.lambda_handler(event, context)
