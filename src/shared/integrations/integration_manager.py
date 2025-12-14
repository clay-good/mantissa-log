"""
Integration Manager

Manages third-party integrations for alert routing (Slack, Jira, PagerDuty, etc.).
Handles configuration storage, validation, and connection testing.
"""

import os
import json
import boto3
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, asdict
from datetime import datetime
from enum import Enum
import logging

logger = logging.getLogger(__name__)


class IntegrationType(Enum):
    """Supported integration types."""
    SLACK = "slack"
    JIRA = "jira"
    PAGERDUTY = "pagerduty"
    EMAIL = "email"
    WEBHOOK = "webhook"


class SeverityLevel(Enum):
    """Alert severity levels."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class SlackConfig:
    """Slack integration configuration."""
    webhook_url: str
    channel: str
    username: Optional[str] = "Mantissa Log"
    icon_emoji: Optional[str] = None
    mention_users: List[str] = None  # Users to @mention for critical alerts
    severity_filter: List[str] = None  # Which severities to send to Slack
    message_template: Optional[str] = None

    def __post_init__(self):
        if self.mention_users is None:
            self.mention_users = []
        if self.severity_filter is None:
            self.severity_filter = ['critical', 'high', 'medium', 'low', 'info']


@dataclass
class JiraConfig:
    """Jira integration configuration."""
    url: str
    username: str
    api_token_secret_id: str  # Reference to Secrets Manager
    project_key: str
    issue_type: str  # Bug, Task, Story, etc.
    priority_mapping: Dict[str, str]  # Map severity to Jira priority
    custom_fields: Optional[Dict[str, str]] = None
    summary_template: Optional[str] = None
    description_template: Optional[str] = None

    def __post_init__(self):
        if self.priority_mapping is None:
            self.priority_mapping = {
                'critical': 'Highest',
                'high': 'High',
                'medium': 'Medium',
                'low': 'Low',
                'info': 'Lowest'
            }
        if self.custom_fields is None:
            self.custom_fields = {}


@dataclass
class PagerDutyConfig:
    """PagerDuty integration configuration."""
    integration_key: str
    severity_filter: List[str] = None  # Which severities trigger PagerDuty
    dedup_key_template: Optional[str] = None
    custom_details: Optional[Dict[str, str]] = None

    def __post_init__(self):
        if self.severity_filter is None:
            self.severity_filter = ['critical', 'high']
        if self.custom_details is None:
            self.custom_details = {}


@dataclass
class EmailConfig:
    """Email integration configuration."""
    recipients: List[str]
    subject_template: Optional[str] = None
    body_template: Optional[str] = None
    severity_filter: List[str] = None

    def __post_init__(self):
        if self.severity_filter is None:
            self.severity_filter = ['critical', 'high', 'medium', 'low', 'info']


@dataclass
class WebhookConfig:
    """Custom webhook integration configuration."""
    url: str
    method: str = "POST"  # POST, PUT, PATCH
    headers: Optional[Dict[str, str]] = None
    auth_type: Optional[str] = None  # None, 'basic', 'bearer', 'custom'
    auth_secret_id: Optional[str] = None  # Reference to Secrets Manager
    payload_template: Optional[str] = None
    retry_config: Optional[Dict[str, Any]] = None

    def __post_init__(self):
        if self.headers is None:
            self.headers = {'Content-Type': 'application/json'}
        if self.retry_config is None:
            self.retry_config = {
                'max_retries': 3,
                'backoff_multiplier': 2,
                'initial_delay_seconds': 1
            }


@dataclass
class IntegrationConfig:
    """Complete integration configuration."""
    integration_id: str
    user_id: str
    integration_type: IntegrationType
    name: str  # User-friendly name
    enabled: bool
    config: Dict[str, Any]  # Type-specific configuration
    created_at: str
    updated_at: str
    last_test_at: Optional[str] = None
    last_test_status: Optional[str] = None  # 'success', 'failed'
    metadata: Optional[Dict[str, Any]] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for storage."""
        return {
            'integration_id': self.integration_id,
            'user_id': self.user_id,
            'integration_type': self.integration_type.value,
            'name': self.name,
            'enabled': self.enabled,
            'config': self.config,
            'created_at': self.created_at,
            'updated_at': self.updated_at,
            'last_test_at': self.last_test_at,
            'last_test_status': self.last_test_status,
            'metadata': self.metadata or {}
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'IntegrationConfig':
        """Create from dictionary."""
        return cls(
            integration_id=data['integration_id'],
            user_id=data['user_id'],
            integration_type=IntegrationType(data['integration_type']),
            name=data['name'],
            enabled=data['enabled'],
            config=data['config'],
            created_at=data['created_at'],
            updated_at=data['updated_at'],
            last_test_at=data.get('last_test_at'),
            last_test_status=data.get('last_test_status'),
            metadata=data.get('metadata', {})
        )


class IntegrationManager:
    """
    Manages third-party integrations for alert routing.

    Features:
    - CRUD operations for integration configurations
    - Secure credential storage in AWS Secrets Manager
    - Integration testing and validation
    - Health status tracking
    """

    def __init__(self, table_name: Optional[str] = None):
        """
        Initialize integration manager.

        Args:
            table_name: DynamoDB table for integration storage
        """
        self.table_name = table_name or os.environ.get(
            'INTEGRATIONS_TABLE',
            'mantissa-log-integrations'
        )

        self.dynamodb = boto3.resource('dynamodb')
        self.table = self.dynamodb.Table(self.table_name)

        self.secrets_client = boto3.client('secretsmanager')

    def create_integration(
        self,
        user_id: str,
        integration_type: IntegrationType,
        name: str,
        config: Dict[str, Any],
        enabled: bool = True
    ) -> IntegrationConfig:
        """
        Create a new integration configuration.

        Args:
            user_id: User ID
            integration_type: Type of integration
            name: User-friendly name
            config: Integration-specific configuration
            enabled: Whether integration is enabled

        Returns:
            IntegrationConfig
        """
        import uuid

        integration_id = f"int-{uuid.uuid4().hex[:12]}"
        timestamp = datetime.utcnow().isoformat() + 'Z'

        # Store sensitive credentials in Secrets Manager
        config = self._store_sensitive_data(
            user_id=user_id,
            integration_id=integration_id,
            integration_type=integration_type,
            config=config
        )

        integration = IntegrationConfig(
            integration_id=integration_id,
            user_id=user_id,
            integration_type=integration_type,
            name=name,
            enabled=enabled,
            config=config,
            created_at=timestamp,
            updated_at=timestamp
        )

        # Save to DynamoDB
        self._save_integration(integration)

        return integration

    def get_integration(
        self,
        integration_id: str,
        user_id: str
    ) -> Optional[IntegrationConfig]:
        """
        Get integration configuration.

        Args:
            integration_id: Integration ID
            user_id: User ID

        Returns:
            IntegrationConfig or None
        """
        try:
            response = self.table.get_item(
                Key={
                    'pk': f'user#{user_id}',
                    'sk': f'integration#{integration_id}'
                }
            )

            if 'Item' not in response:
                return None

            return IntegrationConfig.from_dict(response['Item'])

        except Exception as e:
            logger.error(f'Error retrieving integration: {e}')
            return None

    def list_integrations(
        self,
        user_id: str,
        integration_type: Optional[IntegrationType] = None
    ) -> List[IntegrationConfig]:
        """
        List user's integrations.

        Args:
            user_id: User ID
            integration_type: Optional filter by type

        Returns:
            List of IntegrationConfig
        """
        from boto3.dynamodb.conditions import Key

        try:
            response = self.table.query(
                KeyConditionExpression=
                    Key('pk').eq(f'user#{user_id}') &
                    Key('sk').begins_with('integration#')
            )

            integrations = [
                IntegrationConfig.from_dict(item)
                for item in response.get('Items', [])
            ]

            # Filter by type if specified
            if integration_type:
                integrations = [
                    i for i in integrations
                    if i.integration_type == integration_type
                ]

            return integrations

        except Exception as e:
            logger.error(f'Error listing integrations: {e}')
            return []

    def update_integration(
        self,
        integration_id: str,
        user_id: str,
        **updates
    ) -> Optional[IntegrationConfig]:
        """
        Update integration configuration.

        Args:
            integration_id: Integration ID
            user_id: User ID
            **updates: Fields to update

        Returns:
            Updated IntegrationConfig or None
        """
        integration = self.get_integration(integration_id, user_id)

        if not integration:
            return None

        # Update fields
        if 'name' in updates:
            integration.name = updates['name']
        if 'enabled' in updates:
            integration.enabled = updates['enabled']
        if 'config' in updates:
            # Store sensitive data if present
            config = self._store_sensitive_data(
                user_id=user_id,
                integration_id=integration_id,
                integration_type=integration.integration_type,
                config=updates['config']
            )
            integration.config = config

        integration.updated_at = datetime.utcnow().isoformat() + 'Z'

        # Save
        self._save_integration(integration)

        return integration

    def delete_integration(self, integration_id: str, user_id: str):
        """
        Delete integration configuration.

        Args:
            integration_id: Integration ID
            user_id: User ID
        """
        # Get integration to find secret IDs
        integration = self.get_integration(integration_id, user_id)

        if integration:
            # Delete secrets from Secrets Manager
            self._delete_sensitive_data(integration)

        # Delete from DynamoDB
        try:
            self.table.delete_item(
                Key={
                    'pk': f'user#{user_id}',
                    'sk': f'integration#{integration_id}'
                }
            )
        except Exception as e:
            logger.error(f'Error deleting integration: {e}')

    def test_integration(
        self,
        integration_id: str,
        user_id: str
    ) -> Dict[str, Any]:
        """
        Test integration connection.

        Args:
            integration_id: Integration ID
            user_id: User ID

        Returns:
            Test result dictionary
        """
        integration = self.get_integration(integration_id, user_id)

        if not integration:
            return {
                'success': False,
                'error': 'Integration not found'
            }

        # Retrieve sensitive data for testing
        config = self._retrieve_sensitive_data(integration)

        # Test based on integration type
        try:
            if integration.integration_type == IntegrationType.SLACK:
                result = self._test_slack(config)
            elif integration.integration_type == IntegrationType.JIRA:
                result = self._test_jira(config)
            elif integration.integration_type == IntegrationType.PAGERDUTY:
                result = self._test_pagerduty(config)
            elif integration.integration_type == IntegrationType.WEBHOOK:
                result = self._test_webhook(config)
            else:
                result = {
                    'success': False,
                    'error': f'Testing not implemented for {integration.integration_type.value}'
                }

            # Update last test timestamp and status
            integration.last_test_at = datetime.utcnow().isoformat() + 'Z'
            integration.last_test_status = 'success' if result['success'] else 'failed'
            self._save_integration(integration)

            return result

        except Exception as e:
            logger.error(f'Error testing integration: {e}')
            return {
                'success': False,
                'error': str(e)
            }

    def _save_integration(self, integration: IntegrationConfig):
        """Save integration to DynamoDB."""
        try:
            item = integration.to_dict()
            item['pk'] = f'user#{integration.user_id}'
            item['sk'] = f'integration#{integration.integration_id}'

            self.table.put_item(Item=item)

        except Exception as e:
            logger.error(f'Error saving integration: {e}')
            raise

    def _store_sensitive_data(
        self,
        user_id: str,
        integration_id: str,
        integration_type: IntegrationType,
        config: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Store sensitive data in Secrets Manager and return config with secret IDs.

        Args:
            user_id: User ID
            integration_id: Integration ID
            integration_type: Integration type
            config: Configuration dict

        Returns:
            Config dict with sensitive data replaced by secret IDs
        """
        config_copy = config.copy()

        if integration_type == IntegrationType.SLACK:
            # Store webhook URL
            if 'webhook_url' in config:
                secret_id = self._store_secret(
                    user_id, integration_id, 'webhook_url', config['webhook_url']
                )
                config_copy['webhook_url_secret_id'] = secret_id
                del config_copy['webhook_url']

        elif integration_type == IntegrationType.JIRA:
            # Store API token
            if 'api_token' in config:
                secret_id = self._store_secret(
                    user_id, integration_id, 'api_token', config['api_token']
                )
                config_copy['api_token_secret_id'] = secret_id
                del config_copy['api_token']

        elif integration_type == IntegrationType.PAGERDUTY:
            # Store integration key
            if 'integration_key' in config:
                secret_id = self._store_secret(
                    user_id, integration_id, 'integration_key', config['integration_key']
                )
                config_copy['integration_key_secret_id'] = secret_id
                del config_copy['integration_key']

        elif integration_type == IntegrationType.WEBHOOK:
            # Store auth credentials if present
            if 'auth_value' in config:
                secret_id = self._store_secret(
                    user_id, integration_id, 'auth_value', config['auth_value']
                )
                config_copy['auth_secret_id'] = secret_id
                del config_copy['auth_value']

        return config_copy

    def _retrieve_sensitive_data(self, integration: IntegrationConfig) -> Dict[str, Any]:
        """
        Retrieve sensitive data from Secrets Manager.

        Args:
            integration: Integration configuration

        Returns:
            Config with sensitive data retrieved
        """
        config = integration.config.copy()

        # Retrieve secrets based on integration type
        if integration.integration_type == IntegrationType.SLACK:
            if 'webhook_url_secret_id' in config:
                config['webhook_url'] = self._retrieve_secret(config['webhook_url_secret_id'])

        elif integration.integration_type == IntegrationType.JIRA:
            if 'api_token_secret_id' in config:
                config['api_token'] = self._retrieve_secret(config['api_token_secret_id'])

        elif integration.integration_type == IntegrationType.PAGERDUTY:
            if 'integration_key_secret_id' in config:
                config['integration_key'] = self._retrieve_secret(config['integration_key_secret_id'])

        elif integration.integration_type == IntegrationType.WEBHOOK:
            if 'auth_secret_id' in config:
                config['auth_value'] = self._retrieve_secret(config['auth_secret_id'])

        return config

    def _delete_sensitive_data(self, integration: IntegrationConfig):
        """Delete sensitive data from Secrets Manager."""
        config = integration.config

        secret_ids = []
        if 'webhook_url_secret_id' in config:
            secret_ids.append(config['webhook_url_secret_id'])
        if 'api_token_secret_id' in config:
            secret_ids.append(config['api_token_secret_id'])
        if 'integration_key_secret_id' in config:
            secret_ids.append(config['integration_key_secret_id'])
        if 'auth_secret_id' in config:
            secret_ids.append(config['auth_secret_id'])

        for secret_id in secret_ids:
            try:
                self.secrets_client.delete_secret(
                    SecretId=secret_id,
                    ForceDeleteWithoutRecovery=True
                )
            except Exception as e:
                logger.warning(f'Error deleting secret {secret_id}: {e}')

    def _store_secret(
        self,
        user_id: str,
        integration_id: str,
        key_name: str,
        value: str
    ) -> str:
        """Store secret in Secrets Manager."""
        secret_name = f'mantissa-log/{user_id}/{integration_id}/{key_name}'

        try:
            response = self.secrets_client.create_secret(
                Name=secret_name,
                Description=f'{key_name} for integration {integration_id}',
                SecretString=value,
                Tags=[
                    {'Key': 'user_id', 'Value': user_id},
                    {'Key': 'integration_id', 'Value': integration_id}
                ]
            )
            return response['ARN']

        except self.secrets_client.exceptions.ResourceExistsException:
            # Update existing secret
            response = self.secrets_client.update_secret(
                SecretId=secret_name,
                SecretString=value
            )
            return response['ARN']

    def _retrieve_secret(self, secret_id: str) -> str:
        """Retrieve secret from Secrets Manager."""
        try:
            response = self.secrets_client.get_secret_value(SecretId=secret_id)
            return response['SecretString']
        except Exception as e:
            logger.error(f'Error retrieving secret: {e}')
            return ''

    def _test_slack(self, config: Dict[str, Any]) -> Dict[str, Any]:
        """Test Slack webhook."""
        import requests

        try:
            response = requests.post(
                config['webhook_url'],
                json={
                    'text': 'Test message from Mantissa Log integration setup',
                    'username': config.get('username', 'Mantissa Log'),
                    'channel': config.get('channel', '')
                },
                timeout=10
            )

            if response.status_code == 200:
                return {
                    'success': True,
                    'message': 'Successfully sent test message to Slack'
                }
            else:
                return {
                    'success': False,
                    'error': f'Slack returned status code {response.status_code}'
                }

        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }

    def _test_jira(self, config: Dict[str, Any]) -> Dict[str, Any]:
        """Test Jira connection."""
        import requests
        from requests.auth import HTTPBasicAuth

        try:
            # Test by fetching project info
            url = f"{config['url']}/rest/api/3/project/{config['project_key']}"

            response = requests.get(
                url,
                auth=HTTPBasicAuth(config['username'], config['api_token']),
                timeout=10
            )

            if response.status_code == 200:
                return {
                    'success': True,
                    'message': f"Successfully connected to Jira project {config['project_key']}"
                }
            else:
                return {
                    'success': False,
                    'error': f'Jira returned status code {response.status_code}'
                }

        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }

    def _test_pagerduty(self, config: Dict[str, Any]) -> Dict[str, Any]:
        """Test PagerDuty connection."""
        import requests

        try:
            # Send test event to PagerDuty
            response = requests.post(
                'https://events.pagerduty.com/v2/enqueue',
                json={
                    'routing_key': config['integration_key'],
                    'event_action': 'trigger',
                    'payload': {
                        'summary': 'Test from Mantissa Log integration setup',
                        'severity': 'info',
                        'source': 'mantissa-log-test'
                    }
                },
                timeout=10
            )

            if response.status_code == 202:
                return {
                    'success': True,
                    'message': 'Successfully sent test event to PagerDuty'
                }
            else:
                return {
                    'success': False,
                    'error': f'PagerDuty returned status code {response.status_code}'
                }

        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }

    def _test_webhook(self, config: Dict[str, Any]) -> Dict[str, Any]:
        """Test custom webhook."""
        import requests

        try:
            headers = config.get('headers', {})

            # Add auth if configured
            auth = None
            if config.get('auth_type') == 'bearer' and 'auth_value' in config:
                headers['Authorization'] = f"Bearer {config['auth_value']}"
            elif config.get('auth_type') == 'basic' and 'auth_value' in config:
                # Assuming auth_value is base64 encoded
                headers['Authorization'] = f"Basic {config['auth_value']}"

            # Test payload
            payload = {'test': True, 'message': 'Test from Mantissa Log'}

            response = requests.request(
                method=config.get('method', 'POST'),
                url=config['url'],
                json=payload,
                headers=headers,
                auth=auth,
                timeout=10
            )

            if 200 <= response.status_code < 300:
                return {
                    'success': True,
                    'message': f'Successfully called webhook (status {response.status_code})'
                }
            else:
                return {
                    'success': False,
                    'error': f'Webhook returned status code {response.status_code}'
                }

        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }
