"""
Redacted Integration Sender

Applies PII/PHI redaction to integration payloads before sending to external systems.
This is the integration point between the redaction module and integration validators.
"""

import os
import json
from typing import Dict, Any, Optional
from datetime import datetime
import boto3
import logging

from ..redaction.pii_redactor import create_redactor, PIIRedactor

logger = logging.getLogger(__name__)


class RedactedIntegrationSender:
    """
    Handles sending redacted payloads to integrations.

    Workflow:
    1. Load user's redaction configuration
    2. Apply redaction to payload
    3. Log redaction audit trail
    4. Send redacted payload to integration
    """

    def __init__(self, user_id: str, dynamodb_table: Optional[str] = None):
        """
        Initialize redacted sender.

        Args:
            user_id: User ID for configuration lookup
            dynamodb_table: Optional DynamoDB table name for settings
        """
        self.user_id = user_id
        self.dynamodb = boto3.resource('dynamodb')
        self.table_name = dynamodb_table or os.environ.get(
            'USER_SETTINGS_TABLE',
            'mantissa-log-user-settings'
        )
        self.table = self.dynamodb.Table(self.table_name)
        self.redactor: Optional[PIIRedactor] = None
        self._load_redaction_config()

    def _load_redaction_config(self):
        """Load user's redaction configuration from DynamoDB."""
        try:
            response = self.table.get_item(
                Key={'user_id': self.user_id, 'setting_type': 'redaction'}
            )

            if 'Item' in response:
                config = response['Item'].get('config', {})

                # Only create redactor if redaction is enabled
                if config.get('enabled', True):
                    self.redactor = create_redactor(config)
            else:
                # Default: redaction enabled with standard patterns
                self.redactor = create_redactor()

        except Exception as e:
            logger.error(f'Error loading redaction config for user {self.user_id}: {e}')
            # Fail-safe: create redactor with defaults
            self.redactor = create_redactor()

    def prepare_payload(
        self,
        integration_type: str,
        payload: Dict[str, Any],
        skip_redaction: bool = False
    ) -> Dict[str, Any]:
        """
        Prepare integration payload with redaction applied.

        Args:
            integration_type: Type of integration (slack, jira, pagerduty, etc.)
            payload: Original payload to send
            skip_redaction: If True, skip redaction (for testing)

        Returns:
            Redacted payload ready to send
        """
        if skip_redaction or self.redactor is None:
            return payload

        # Apply redaction based on integration type
        redacted_payload = self.redactor.redact_integration_payload(
            integration_type,
            payload
        )

        return redacted_payload

    def send_alert(
        self,
        integration_type: str,
        alert_data: Dict[str, Any],
        integration_config: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Send alert with PII/PHI redaction applied.

        Args:
            integration_type: Type of integration
            alert_data: Alert data to send
            integration_config: Integration configuration

        Returns:
            Response from integration with redaction metadata
        """
        # Build payload based on integration type
        payload = self._build_payload(integration_type, alert_data, integration_config)

        # Apply redaction
        redacted_payload = self.prepare_payload(integration_type, payload)

        # Send to integration (delegate to appropriate sender)
        response = self._send_to_integration(
            integration_type,
            redacted_payload,
            integration_config
        )

        # Log redaction audit trail
        if self.redactor:
            self._log_redaction_audit(
                integration_type,
                alert_data.get('rule_id'),
                alert_data.get('alert_id'),
                self.redactor.get_redaction_summary()
            )

        return response

    def _build_payload(
        self,
        integration_type: str,
        alert_data: Dict[str, Any],
        config: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Build integration-specific payload from alert data."""

        if integration_type == 'slack':
            return {
                'text': f"*[{alert_data['severity'].upper()}]* {alert_data['rule_name']}",
                'blocks': [
                    {
                        'type': 'section',
                        'text': {
                            'type': 'mrkdwn',
                            'text': f"*{alert_data['rule_name']}*\n{alert_data.get('description', '')}"
                        }
                    },
                    {
                        'type': 'section',
                        'fields': [
                            {
                                'type': 'mrkdwn',
                                'text': f"*Severity:*\n{alert_data['severity']}"
                            },
                            {
                                'type': 'mrkdwn',
                                'text': f"*Timestamp:*\n{alert_data['timestamp']}"
                            },
                            {
                                'type': 'mrkdwn',
                                'text': f"*Result Count:*\n{alert_data.get('result_count', 0)}"
                            }
                        ]
                    },
                    {
                        'type': 'section',
                        'text': {
                            'type': 'mrkdwn',
                            'text': f"*Details:*\n```{json.dumps(alert_data.get('details', {}), indent=2)}```"
                        }
                    }
                ],
                'channel': config.get('channel')
            }

        elif integration_type == 'jira':
            return {
                'fields': {
                    'project': {'key': config['project_key']},
                    'summary': f"[{alert_data['severity'].upper()}] {alert_data['rule_name']}",
                    'description': (
                        f"*Alert Details*\n\n"
                        f"Rule: {alert_data['rule_name']}\n"
                        f"Severity: {alert_data['severity']}\n"
                        f"Timestamp: {alert_data['timestamp']}\n"
                        f"Result Count: {alert_data.get('result_count', 0)}\n\n"
                        f"*Description:*\n{alert_data.get('description', '')}\n\n"
                        f"*Details:*\n{{{code:json}}}{json.dumps(alert_data.get('details', {}), indent=2)}{{{code}}}"
                    ),
                    'issuetype': {'name': config.get('issue_type', 'Bug')},
                    'priority': {'name': config.get('priority_map', {}).get(alert_data['severity'], 'Medium')}
                }
            }

        elif integration_type == 'pagerduty':
            return {
                'routing_key': config['integration_key'],
                'event_action': 'trigger',
                'payload': {
                    'summary': f"[{alert_data['severity'].upper()}] {alert_data['rule_name']}",
                    'severity': config.get('urgency_map', {}).get(
                        alert_data['severity'],
                        'high' if alert_data['severity'] in ['critical', 'high'] else 'low'
                    ),
                    'source': 'Mantissa Log',
                    'timestamp': alert_data['timestamp'],
                    'custom_details': {
                        'rule_name': alert_data['rule_name'],
                        'description': alert_data.get('description', ''),
                        'result_count': alert_data.get('result_count', 0),
                        'details': alert_data.get('details', {})
                    }
                }
            }

        elif integration_type == 'email':
            return {
                'subject': f"[{alert_data['severity'].upper()}] Security Alert: {alert_data['rule_name']}",
                'body': (
                    f"Security Alert Detected\n\n"
                    f"Rule: {alert_data['rule_name']}\n"
                    f"Severity: {alert_data['severity']}\n"
                    f"Timestamp: {alert_data['timestamp']}\n"
                    f"Result Count: {alert_data.get('result_count', 0)}\n\n"
                    f"Description:\n{alert_data.get('description', '')}\n\n"
                    f"Details:\n{json.dumps(alert_data.get('details', {}), indent=2)}"
                ),
                'to': config.get('recipients', []),
                'cc': config.get('cc_recipients', [])
            }

        elif integration_type == 'webhook':
            # Use configured payload template
            template = config.get('payload_template', 'default')

            if template == 'default':
                return {
                    'severity': alert_data['severity'],
                    'rule_name': alert_data['rule_name'],
                    'timestamp': alert_data['timestamp'],
                    'description': alert_data.get('description', ''),
                    'result_count': alert_data.get('result_count', 0),
                    'details': alert_data.get('details', {})
                }
            elif template == 'minimal':
                return {
                    'alert': alert_data['rule_name'],
                    'level': alert_data['severity'],
                    'time': alert_data['timestamp']
                }
            else:
                # Custom template - return full data for now
                return alert_data

        else:
            # Unknown integration type - return generic payload
            return alert_data

    def _send_to_integration(
        self,
        integration_type: str,
        payload: Dict[str, Any],
        config: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Send payload to integration using the appropriate handler.

        Args:
            integration_type: Type of integration (slack, jira, pagerduty, email, webhook)
            payload: Redacted payload to send
            config: Integration configuration

        Returns:
            Dict with success status and details
        """
        try:
            handler = self._get_handler(integration_type, config)
            if not handler:
                return {
                    'success': False,
                    'message': f'Unknown integration type: {integration_type}',
                    'redacted': self.redactor is not None
                }

            # Create an Alert-like object from payload for the handler
            from ..detection.alert_generator import Alert

            alert = Alert(
                id=payload.get('alert_id', 'unknown'),
                rule_id=payload.get('rule_id', ''),
                rule_name=payload.get('rule_name', ''),
                severity=payload.get('severity', 'medium'),
                title=payload.get('title', payload.get('rule_name', 'Alert')),
                description=payload.get('description', ''),
                timestamp=payload.get('timestamp', datetime.utcnow().isoformat()),
                source_data=payload.get('source_data', {}),
                matched_conditions=payload.get('matched_conditions', [])
            )

            # Send via handler
            success = handler.send(alert)

            return {
                'success': success,
                'message': f'Alert sent to {integration_type}' if success else f'Failed to send to {integration_type}',
                'redacted': self.redactor is not None,
                'integration_type': integration_type
            }

        except Exception as e:
            logger.error(f'Error sending to {integration_type}: {e}')
            return {
                'success': False,
                'message': str(e),
                'redacted': self.redactor is not None,
                'error': str(e)
            }

    def _get_handler(self, integration_type: str, config: Dict[str, Any]):
        """
        Get the appropriate handler for an integration type.

        Args:
            integration_type: Type of integration
            config: Integration configuration

        Returns:
            Handler instance or None if unknown type
        """
        integration_type_lower = integration_type.lower()

        try:
            if integration_type_lower == 'slack':
                from ..alerting.handlers.slack import SlackHandler
                return SlackHandler(
                    webhook_url=config.get('webhook_url'),
                    channel=config.get('channel'),
                    username=config.get('username', 'Mantissa Log'),
                    icon_emoji=config.get('icon_emoji', ':shield:')
                )

            elif integration_type_lower == 'jira':
                from ..alerting.handlers.jira import JiraHandler
                return JiraHandler(
                    server_url=config.get('server_url') or config.get('url'),
                    username=config.get('username') or config.get('email'),
                    api_token=config.get('api_token') or config.get('token'),
                    project_key=config.get('project_key') or config.get('project'),
                    issue_type=config.get('issue_type', 'Task')
                )

            elif integration_type_lower == 'pagerduty':
                from ..alerting.handlers.pagerduty import PagerDutyHandler
                return PagerDutyHandler(
                    routing_key=config.get('routing_key') or config.get('integration_key'),
                    severity_mapping=config.get('severity_mapping')
                )

            elif integration_type_lower == 'email':
                from ..alerting.handlers.email import EmailHandler
                return EmailHandler(
                    smtp_host=config.get('smtp_host', 'localhost'),
                    smtp_port=config.get('smtp_port', 587),
                    sender_email=config.get('sender_email') or config.get('from'),
                    recipients=config.get('recipients') or config.get('to', []),
                    username=config.get('username'),
                    password=config.get('password'),
                    use_tls=config.get('use_tls', True)
                )

            elif integration_type_lower == 'webhook':
                from ..alerting.handlers.webhook import WebhookHandler
                return WebhookHandler(
                    url=config.get('url') or config.get('webhook_url'),
                    headers=config.get('headers', {}),
                    method=config.get('method', 'POST'),
                    timeout=config.get('timeout', 30)
                )

            else:
                logger.warning(f'Unknown integration type: {integration_type}')
                return None

        except ImportError as e:
            logger.error(f'Failed to import handler for {integration_type}: {e}')
            return None
        except Exception as e:
            logger.error(f'Failed to create handler for {integration_type}: {e}')
            return None

    def _log_redaction_audit(
        self,
        integration_type: str,
        rule_id: Optional[str],
        alert_id: Optional[str],
        summary: Dict[str, Any]
    ):
        """Log redaction audit trail to DynamoDB."""
        try:
            audit_table_name = os.environ.get(
                'REDACTION_AUDIT_TABLE',
                'mantissa-log-redaction-audit'
            )
            audit_table = self.dynamodb.Table(audit_table_name)

            audit_table.put_item(Item={
                'user_id': self.user_id,
                'timestamp': datetime.utcnow().isoformat() + 'Z',
                'integration_type': integration_type,
                'rule_id': rule_id or 'unknown',
                'alert_id': alert_id or 'unknown',
                'redaction_summary': summary,
                'ttl': int(datetime.utcnow().timestamp()) + (90 * 24 * 60 * 60)  # 90 days
            })
        except Exception as e:
            # Don't fail the alert if audit logging fails
            logger.warning(f'Failed to log redaction audit: {e}')


def send_redacted_alert(
    user_id: str,
    integration_type: str,
    alert_data: Dict[str, Any],
    integration_config: Dict[str, Any]
) -> Dict[str, Any]:
    """
    Convenience function to send an alert with redaction.

    Args:
        user_id: User ID
        integration_type: Integration type (slack, jira, etc.)
        alert_data: Alert data
        integration_config: Integration configuration

    Returns:
        Response from integration
    """
    sender = RedactedIntegrationSender(user_id)
    return sender.send_alert(integration_type, alert_data, integration_config)
