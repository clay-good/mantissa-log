"""
Settings API for Mantissa Log

Handles LLM configuration, integration settings, and user preferences.
Stores sensitive data (API keys) in AWS Secrets Manager.
"""

import json
import boto3
import os
from datetime import datetime
from typing import Dict, Any

dynamodb = boto3.resource('dynamodb')
secrets_manager = boto3.client('secretsmanager')

USER_SETTINGS_TABLE = os.environ.get('USER_SETTINGS_TABLE', 'mantissa_user_settings')


class SettingsAPI:
    """API handler for user settings and configuration"""

    def __init__(self):
        self.table = dynamodb.Table(USER_SETTINGS_TABLE)

    def lambda_handler(self, event: Dict[str, Any], context: Any) -> Dict[str, Any]:
        """Main Lambda handler for settings endpoints"""

        http_method = event.get('httpMethod')
        path = event.get('path', '')

        try:
            if '/api/settings/llm/test' in path:
                if http_method == 'POST':
                    return self.test_llm_connection(event)

            elif '/api/settings/llm' in path:
                if http_method == 'GET':
                    return self.get_llm_settings(event)
                elif http_method == 'PUT':
                    return self.update_llm_settings(event)

            elif '/api/settings/integrations/test' in path:
                if http_method == 'POST':
                    return self.test_integration(event)

            elif '/api/settings/integrations' in path:
                if http_method == 'GET':
                    return self.get_integration_settings(event)
                elif http_method == 'PUT':
                    return self.update_integration_settings(event)

            else:
                return {
                    'statusCode': 404,
                    'body': json.dumps({'error': 'Endpoint not found'}),
                    'headers': self._cors_headers()
                }

        except Exception as e:
            print(f"Error in settings API: {e}")
            return {
                'statusCode': 500,
                'body': json.dumps({'error': str(e)}),
                'headers': self._cors_headers()
            }

    def get_llm_settings(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """Get LLM configuration for a user"""

        params = event.get('queryStringParameters', {}) or {}
        user_id = params.get('user_id')

        if not user_id:
            return self._error_response('user_id is required', 400)

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
                'headers': self._cors_headers()
            }

        except Exception as e:
            print(f"Error getting LLM settings: {e}")
            return self._error_response(str(e), 500)

    def update_llm_settings(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """Update LLM configuration for a user"""

        try:
            body = json.loads(event.get('body', '{}'))
            user_id = body.get('user_id')
            config = body.get('config', {})

            if not user_id:
                return self._error_response('user_id is required', 400)

            # Store API keys in Secrets Manager
            secret_references = {}
            if 'providers' in config:
                for provider_id, provider_config in config['providers'].items():
                    if 'apiKey' in provider_config and provider_config['apiKey']:
                        # Don't store if it's the masked placeholder
                        if provider_config['apiKey'] != '********':
                            secret_name = f"mantissa-log/{user_id}/llm/{provider_id}"

                            # Store in Secrets Manager
                            try:
                                secrets_manager.create_secret(
                                    Name=secret_name,
                                    SecretString=provider_config['apiKey']
                                )
                            except secrets_manager.exceptions.ResourceExistsException:
                                # Secret exists, update it
                                secrets_manager.update_secret(
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
                'headers': self._cors_headers()
            }

        except Exception as e:
            print(f"Error updating LLM settings: {e}")
            return self._error_response(str(e), 500)

    def test_llm_connection(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """Test connection to an LLM provider"""

        try:
            body = json.loads(event.get('body', '{}'))
            provider = body.get('provider')
            model = body.get('model')
            api_key = body.get('api_key')
            region = body.get('region')

            if not provider:
                return self._error_response('provider is required', 400)

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
                return self._error_response(f'Unknown provider: {provider}', 400)

            return {
                'statusCode': 200 if result['success'] else 400,
                'body': json.dumps(result),
                'headers': self._cors_headers()
            }

        except Exception as e:
            print(f"Error testing LLM connection: {e}")
            return self._error_response(str(e), 500)

    def get_integration_settings(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """Get integration configuration for a user"""

        params = event.get('queryStringParameters', {}) or {}
        user_id = params.get('user_id')

        if not user_id:
            return self._error_response('user_id is required', 400)

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
                'headers': self._cors_headers()
            }

        except Exception as e:
            print(f"Error getting integration settings: {e}")
            return self._error_response(str(e), 500)

    def update_integration_settings(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """Update integration configuration for a user"""

        try:
            body = json.loads(event.get('body', '{}'))
            user_id = body.get('user_id')
            integrations = body.get('integrations', {})

            if not user_id:
                return self._error_response('user_id is required', 400)

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
                            try:
                                secrets_manager.create_secret(
                                    Name=secret_name,
                                    SecretString=config[field]
                                )
                            except secrets_manager.exceptions.ResourceExistsException:
                                secrets_manager.update_secret(
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
                'headers': self._cors_headers()
            }

        except Exception as e:
            print(f"Error updating integration settings: {e}")
            return self._error_response(str(e), 500)

    def test_integration(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """Test an integration configuration"""

        try:
            body = json.loads(event.get('body', '{}'))
            integration_type = body.get('type')
            config = body.get('config', {})

            if not integration_type:
                return self._error_response('type is required', 400)

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
                return self._error_response(f'Unknown integration type: {integration_type}', 400)

            return {
                'statusCode': 200 if result['success'] else 400,
                'body': json.dumps(result),
                'headers': self._cors_headers()
            }

        except Exception as e:
            print(f"Error testing integration: {e}")
            return self._error_response(str(e), 500)

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

    def _cors_headers(self) -> Dict[str, str]:
        """CORS headers for API responses"""
        return {
            'Content-Type': 'application/json',
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Headers': 'Content-Type',
            'Access-Control-Allow-Methods': 'GET,POST,PUT,DELETE,OPTIONS'
        }

    def _error_response(self, message: str, status_code: int = 400) -> Dict[str, Any]:
        """Standard error response"""
        return {
            'statusCode': status_code,
            'body': json.dumps({'error': message}),
            'headers': self._cors_headers()
        }


# Lambda handler
api = SettingsAPI()

def lambda_handler(event, context):
    """Lambda entry point"""
    return api.lambda_handler(event, context)
