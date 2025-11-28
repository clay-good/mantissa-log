"""
Integration Validators

Validates and tests integration configurations before saving.
"""

import json
import requests
from typing import Dict, Any, Optional, Tuple
from dataclasses import dataclass


@dataclass
class ValidationResult:
    """Result of integration validation."""
    success: bool
    message: str
    details: Optional[Dict[str, Any]] = None
    error_code: Optional[str] = None


class IntegrationValidator:
    """Base class for integration validators."""
    
    def validate(self, config: Dict[str, Any]) -> ValidationResult:
        """Validate integration configuration."""
        raise NotImplementedError


class SlackValidator(IntegrationValidator):
    """Validates Slack webhook integrations."""
    
    def validate(self, config: Dict[str, Any]) -> ValidationResult:
        """
        Validate Slack webhook configuration.
        
        Args:
            config: {
                'webhook_url': 'https://hooks.slack.com/services/...',
                'channel': '#channel-name',
                'username': 'Mantissa Log' (optional),
                'icon_emoji': ':robot_face:' (optional)
            }
        """
        webhook_url = config.get('webhook_url', '').strip()
        channel = config.get('channel', '').strip()
        
        # Validate webhook URL format
        if not webhook_url:
            return ValidationResult(
                success=False,
                message='Webhook URL is required',
                error_code='MISSING_WEBHOOK_URL'
            )
        
        if not webhook_url.startswith('https://hooks.slack.com/'):
            return ValidationResult(
                success=False,
                message='Invalid Slack webhook URL format',
                error_code='INVALID_WEBHOOK_URL'
            )
        
        # Validate channel format
        if channel and not channel.startswith('#'):
            return ValidationResult(
                success=False,
                message='Channel must start with #',
                error_code='INVALID_CHANNEL'
            )
        
        # Test the webhook
        return self._test_webhook(config)
    
    def _test_webhook(self, config: Dict[str, Any]) -> ValidationResult:
        """Send test message to Slack webhook."""
        webhook_url = config['webhook_url']
        
        payload = {
            'text': 'Test message from Mantissa Log',
            'username': config.get('username', 'Mantissa Log'),
            'icon_emoji': config.get('icon_emoji', ':shield:')
        }
        
        if config.get('channel'):
            payload['channel'] = config['channel']
        
        try:
            response = requests.post(
                webhook_url,
                json=payload,
                timeout=10
            )
            
            if response.status_code == 200 and response.text == 'ok':
                return ValidationResult(
                    success=True,
                    message='Successfully sent test message to Slack',
                    details={'response': 'ok'}
                )
            else:
                return ValidationResult(
                    success=False,
                    message=f'Slack returned error: {response.text}',
                    error_code='WEBHOOK_ERROR',
                    details={'status_code': response.status_code, 'response': response.text}
                )
                
        except requests.exceptions.Timeout:
            return ValidationResult(
                success=False,
                message='Request to Slack timed out',
                error_code='TIMEOUT'
            )
        except requests.exceptions.RequestException as e:
            return ValidationResult(
                success=False,
                message=f'Failed to connect to Slack: {str(e)}',
                error_code='CONNECTION_ERROR'
            )


class JiraValidator(IntegrationValidator):
    """Validates Jira API integrations."""
    
    def validate(self, config: Dict[str, Any]) -> ValidationResult:
        """
        Validate Jira API configuration.
        
        Args:
            config: {
                'url': 'https://your-domain.atlassian.net',
                'email': 'user@example.com',
                'api_token': 'your-api-token',
                'project_key': 'PROJ',
                'issue_type': 'Bug'
            }
        """
        url = config.get('url', '').strip()
        email = config.get('email', '').strip()
        api_token = config.get('api_token', '').strip()
        project_key = config.get('project_key', '').strip()
        
        # Validate required fields
        if not url:
            return ValidationResult(
                success=False,
                message='Jira URL is required',
                error_code='MISSING_URL'
            )
        
        if not email:
            return ValidationResult(
                success=False,
                message='Email is required',
                error_code='MISSING_EMAIL'
            )
        
        if not api_token:
            return ValidationResult(
                success=False,
                message='API token is required',
                error_code='MISSING_API_TOKEN'
            )
        
        if not project_key:
            return ValidationResult(
                success=False,
                message='Project key is required',
                error_code='MISSING_PROJECT_KEY'
            )
        
        # Test authentication and project access
        return self._test_connection(config)
    
    def _test_connection(self, config: Dict[str, Any]) -> ValidationResult:
        """Test Jira connection and project access."""
        url = config['url'].rstrip('/')
        email = config['email']
        api_token = config['api_token']
        project_key = config['project_key']
        
        # Test authentication
        try:
            auth_response = requests.get(
                f'{url}/rest/api/3/myself',
                auth=(email, api_token),
                timeout=10
            )
            
            if auth_response.status_code != 200:
                return ValidationResult(
                    success=False,
                    message='Authentication failed. Check your email and API token.',
                    error_code='AUTH_FAILED',
                    details={'status_code': auth_response.status_code}
                )
            
            # Test project access
            project_response = requests.get(
                f'{url}/rest/api/3/project/{project_key}',
                auth=(email, api_token),
                timeout=10
            )
            
            if project_response.status_code == 404:
                return ValidationResult(
                    success=False,
                    message=f'Project {project_key} not found',
                    error_code='PROJECT_NOT_FOUND'
                )
            elif project_response.status_code != 200:
                return ValidationResult(
                    success=False,
                    message=f'Failed to access project: {project_response.text}',
                    error_code='PROJECT_ACCESS_ERROR'
                )
            
            project_data = project_response.json()
            
            return ValidationResult(
                success=True,
                message=f'Successfully connected to Jira project: {project_data.get("name")}',
                details={
                    'project_name': project_data.get('name'),
                    'project_key': project_data.get('key')
                }
            )
            
        except requests.exceptions.Timeout:
            return ValidationResult(
                success=False,
                message='Request to Jira timed out',
                error_code='TIMEOUT'
            )
        except requests.exceptions.RequestException as e:
            return ValidationResult(
                success=False,
                message=f'Failed to connect to Jira: {str(e)}',
                error_code='CONNECTION_ERROR'
            )


class PagerDutyValidator(IntegrationValidator):
    """Validates PagerDuty integration key."""
    
    def validate(self, config: Dict[str, Any]) -> ValidationResult:
        """
        Validate PagerDuty configuration.
        
        Args:
            config: {
                'integration_key': 'your-integration-key',
                'severity': 'critical' (critical, error, warning, info)
            }
        """
        integration_key = config.get('integration_key', '').strip()
        
        if not integration_key:
            return ValidationResult(
                success=False,
                message='Integration key is required',
                error_code='MISSING_INTEGRATION_KEY'
            )
        
        # Test the integration key
        return self._test_integration_key(config)
    
    def _test_integration_key(self, config: Dict[str, Any]) -> ValidationResult:
        """Send test event to PagerDuty."""
        integration_key = config['integration_key']
        
        payload = {
            'routing_key': integration_key,
            'event_action': 'trigger',
            'payload': {
                'summary': 'Test alert from Mantissa Log',
                'source': 'mantissa-log-test',
                'severity': 'info',
                'custom_details': {
                    'message': 'This is a test alert to validate the PagerDuty integration'
                }
            }
        }
        
        try:
            response = requests.post(
                'https://events.pagerduty.com/v2/enqueue',
                json=payload,
                timeout=10
            )
            
            if response.status_code == 202:
                data = response.json()
                return ValidationResult(
                    success=True,
                    message='Successfully sent test alert to PagerDuty',
                    details={
                        'dedup_key': data.get('dedup_key'),
                        'status': data.get('status')
                    }
                )
            else:
                return ValidationResult(
                    success=False,
                    message=f'PagerDuty returned error: {response.text}',
                    error_code='PAGERDUTY_ERROR',
                    details={'status_code': response.status_code}
                )
                
        except requests.exceptions.Timeout:
            return ValidationResult(
                success=False,
                message='Request to PagerDuty timed out',
                error_code='TIMEOUT'
            )
        except requests.exceptions.RequestException as e:
            return ValidationResult(
                success=False,
                message=f'Failed to connect to PagerDuty: {str(e)}',
                error_code='CONNECTION_ERROR'
            )


class WebhookValidator(IntegrationValidator):
    """Validates custom webhook integrations."""
    
    def validate(self, config: Dict[str, Any]) -> ValidationResult:
        """
        Validate custom webhook configuration.
        
        Args:
            config: {
                'url': 'https://example.com/webhook',
                'method': 'POST',
                'headers': {'Authorization': 'Bearer token'},
                'payload_template': '{"alert": "{{summary}}"}' (optional)
            }
        """
        url = config.get('url', '').strip()
        method = config.get('method', 'POST').upper()
        
        if not url:
            return ValidationResult(
                success=False,
                message='Webhook URL is required',
                error_code='MISSING_URL'
            )
        
        if not url.startswith('https://'):
            return ValidationResult(
                success=False,
                message='Webhook URL must use HTTPS',
                error_code='INVALID_URL_SCHEME'
            )
        
        if method not in ['POST', 'PUT']:
            return ValidationResult(
                success=False,
                message='Method must be POST or PUT',
                error_code='INVALID_METHOD'
            )
        
        # Test the webhook
        return self._test_webhook(config)
    
    def _test_webhook(self, config: Dict[str, Any]) -> ValidationResult:
        """Send test request to webhook."""
        url = config['url']
        method = config.get('method', 'POST')
        headers = config.get('headers', {})
        
        # Default test payload
        test_payload = {
            'test': True,
            'message': 'Test webhook from Mantissa Log',
            'source': 'mantissa-log'
        }
        
        try:
            if method == 'POST':
                response = requests.post(url, json=test_payload, headers=headers, timeout=10)
            else:
                response = requests.put(url, json=test_payload, headers=headers, timeout=10)
            
            if 200 <= response.status_code < 300:
                return ValidationResult(
                    success=True,
                    message=f'Successfully sent test request to webhook (status: {response.status_code})',
                    details={'status_code': response.status_code}
                )
            else:
                return ValidationResult(
                    success=False,
                    message=f'Webhook returned error status: {response.status_code}',
                    error_code='WEBHOOK_ERROR',
                    details={'status_code': response.status_code, 'response': response.text[:500]}
                )
                
        except requests.exceptions.Timeout:
            return ValidationResult(
                success=False,
                message='Request to webhook timed out',
                error_code='TIMEOUT'
            )
        except requests.exceptions.RequestException as e:
            return ValidationResult(
                success=False,
                message=f'Failed to connect to webhook: {str(e)}',
                error_code='CONNECTION_ERROR'
            )


class IntegrationValidatorFactory:
    """Factory for creating integration validators."""
    
    VALIDATORS = {
        'slack': SlackValidator,
        'jira': JiraValidator,
        'pagerduty': PagerDutyValidator,
        'webhook': WebhookValidator
    }
    
    @classmethod
    def get_validator(cls, integration_type: str) -> IntegrationValidator:
        """Get validator for integration type."""
        validator_class = cls.VALIDATORS.get(integration_type.lower())
        if not validator_class:
            raise ValueError(f"Unknown integration type: {integration_type}")
        return validator_class()
    
    @classmethod
    def validate(cls, integration_type: str, config: Dict[str, Any]) -> ValidationResult:
        """Validate integration configuration."""
        validator = cls.get_validator(integration_type)
        return validator.validate(config)
