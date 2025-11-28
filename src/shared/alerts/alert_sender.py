"""
Alert Sender with PII/PHI Redaction

Sends alerts to configured integrations with automatic PII/PHI redaction.
Integrates the redaction system with alert routing.
"""

import json
from typing import Dict, Any, List
from datetime import datetime

from redaction.redaction_manager import RedactionManager, ensure_redacted_alert


def send_alert_to_integrations(
    user_id: str,
    alert_id: str,
    alert_payload: Dict[str, Any],
    integrations: List[str],
    severity: str = 'medium'
) -> Dict[str, Any]:
    """
    Send alert to multiple integrations with automatic redaction.

    Args:
        user_id: User ID
        alert_id: Alert ID
        alert_payload: Alert payload (unredacted)
        integrations: List of integration IDs to send to
        severity: Alert severity

    Returns:
        Dictionary with send results per integration
    """
    results = {}

    for integration_id in integrations:
        result = send_alert_to_integration(
            user_id=user_id,
            alert_id=alert_id,
            integration_id=integration_id,
            alert_payload=alert_payload,
            severity=severity
        )
        results[integration_id] = result

    return results


def send_alert_to_integration(
    user_id: str,
    alert_id: str,
    integration_id: str,
    alert_payload: Dict[str, Any],
    severity: str = 'medium',
    integration_type: str = None
) -> Dict[str, Any]:
    """
    Send alert to a single integration with automatic redaction.

    Args:
        user_id: User ID
        alert_id: Alert ID
        integration_id: Integration ID
        alert_payload: Alert payload (unredacted)
        severity: Alert severity
        integration_type: Integration type (slack, jira, etc.)

    Returns:
        Send result dictionary
    """
    try:
        # Get integration config if not provided
        if not integration_type:
            from integrations.integration_manager import IntegrationManager
            manager = IntegrationManager()
            integration = manager.get_integration(integration_id, user_id)

            if not integration:
                return {
                    'success': False,
                    'error': f'Integration {integration_id} not found'
                }

            integration_type = integration.integration_type.value
            integration_config = integration.config
        else:
            integration_config = {}

        # Apply redaction to payload
        redacted_payload = ensure_redacted_alert(
            user_id=user_id,
            integration_id=integration_id,
            integration_type=integration_type,
            alert_payload=alert_payload.copy(),
            alert_id=alert_id
        )

        # Send based on integration type
        if integration_type == 'slack':
            result = send_to_slack(integration_config, redacted_payload, severity)
        elif integration_type == 'jira':
            result = send_to_jira(integration_config, redacted_payload, severity)
        elif integration_type == 'pagerduty':
            result = send_to_pagerduty(integration_config, redacted_payload, severity)
        elif integration_type == 'webhook':
            result = send_to_webhook(integration_config, redacted_payload)
        elif integration_type == 'email':
            result = send_to_email(integration_config, redacted_payload, severity)
        else:
            result = {
                'success': False,
                'error': f'Unsupported integration type: {integration_type}'
            }

        return result

    except Exception as e:
        print(f'Error sending alert to {integration_id}: {e}')
        return {
            'success': False,
            'error': str(e)
        }


def send_to_slack(config: Dict[str, Any], payload: Dict[str, Any], severity: str) -> Dict[str, Any]:
    """Send alert to Slack."""
    import requests

    try:
        # Check severity filter
        severity_filter = config.get('severity_filter', [])
        if severity_filter and severity not in severity_filter:
            return {
                'success': True,
                'skipped': True,
                'reason': f'Severity {severity} not in filter'
            }

        # Get webhook URL from config or Secrets Manager
        webhook_url = config.get('webhook_url')
        if not webhook_url and 'webhook_url_secret_id' in config:
            from integrations.integration_manager import IntegrationManager
            manager = IntegrationManager()
            webhook_url = manager._retrieve_secret(config['webhook_url_secret_id'])

        # Build Slack message
        message = {
            'text': format_slack_message(payload, severity),
            'username': config.get('username', 'Mantissa Log'),
            'channel': config.get('channel', '')
        }

        # Add mentions for critical alerts
        if severity == 'critical' and config.get('mention_users'):
            mentions = ' '.join(config['mention_users'])
            message['text'] = f"{mentions}\n{message['text']}"

        # Send to Slack
        response = requests.post(webhook_url, json=message, timeout=10)

        if response.status_code == 200:
            return {'success': True}
        else:
            return {
                'success': False,
                'error': f'Slack returned status {response.status_code}'
            }

    except Exception as e:
        return {'success': False, 'error': str(e)}


def send_to_jira(config: Dict[str, Any], payload: Dict[str, Any], severity: str) -> Dict[str, Any]:
    """Send alert to Jira."""
    import requests
    from requests.auth import HTTPBasicAuth

    try:
        # Get credentials
        api_token = config.get('api_token')
        if not api_token and 'api_token_secret_id' in config:
            from integrations.integration_manager import IntegrationManager
            manager = IntegrationManager()
            api_token = manager._retrieve_secret(config['api_token_secret_id'])

        # Map severity to priority
        priority_mapping = config.get('priority_mapping', {})
        priority = priority_mapping.get(severity, 'Medium')

        # Create Jira issue
        issue_data = {
            'fields': {
                'project': {'key': config['project_key']},
                'summary': format_jira_summary(payload),
                'description': format_jira_description(payload),
                'issuetype': {'name': config.get('issue_type', 'Bug')},
                'priority': {'name': priority}
            }
        }

        # Add custom fields if configured
        if config.get('custom_fields'):
            issue_data['fields'].update(config['custom_fields'])

        url = f"{config['url']}/rest/api/3/issue"

        response = requests.post(
            url,
            json=issue_data,
            auth=HTTPBasicAuth(config['username'], api_token),
            headers={'Content-Type': 'application/json'},
            timeout=10
        )

        if response.status_code == 201:
            issue_key = response.json().get('key')
            return {
                'success': True,
                'issue_key': issue_key,
                'issue_url': f"{config['url']}/browse/{issue_key}"
            }
        else:
            return {
                'success': False,
                'error': f'Jira returned status {response.status_code}: {response.text}'
            }

    except Exception as e:
        return {'success': False, 'error': str(e)}


def send_to_pagerduty(config: Dict[str, Any], payload: Dict[str, Any], severity: str) -> Dict[str, Any]:
    """Send alert to PagerDuty."""
    import requests

    try:
        # Check severity filter
        severity_filter = config.get('severity_filter', ['critical', 'high'])
        if severity not in severity_filter:
            return {
                'success': True,
                'skipped': True,
                'reason': f'Severity {severity} not in filter'
            }

        # Get integration key
        integration_key = config.get('integration_key')
        if not integration_key and 'integration_key_secret_id' in config:
            from integrations.integration_manager import IntegrationManager
            manager = IntegrationManager()
            integration_key = manager._retrieve_secret(config['integration_key_secret_id'])

        # Map severity to PagerDuty severity
        pd_severity_map = {
            'critical': 'critical',
            'high': 'error',
            'medium': 'warning',
            'low': 'warning',
            'info': 'info'
        }

        # Create PagerDuty event
        event = {
            'routing_key': integration_key,
            'event_action': 'trigger',
            'payload': {
                'summary': format_pagerduty_summary(payload),
                'severity': pd_severity_map.get(severity, 'warning'),
                'source': 'mantissa-log',
                'custom_details': payload
            }
        }

        # Add dedup key if configured
        if config.get('dedup_key_template'):
            event['dedup_key'] = config['dedup_key_template'].format(**payload)

        response = requests.post(
            'https://events.pagerduty.com/v2/enqueue',
            json=event,
            timeout=10
        )

        if response.status_code == 202:
            return {
                'success': True,
                'dedup_key': response.json().get('dedup_key')
            }
        else:
            return {
                'success': False,
                'error': f'PagerDuty returned status {response.status_code}'
            }

    except Exception as e:
        return {'success': False, 'error': str(e)}


def send_to_webhook(config: Dict[str, Any], payload: Dict[str, Any]) -> Dict[str, Any]:
    """Send alert to custom webhook."""
    import requests

    try:
        headers = config.get('headers', {})

        # Add auth if configured
        if config.get('auth_type') == 'bearer' and 'auth_secret_id' in config:
            from integrations.integration_manager import IntegrationManager
            manager = IntegrationManager()
            token = manager._retrieve_secret(config['auth_secret_id'])
            headers['Authorization'] = f'Bearer {token}'

        response = requests.request(
            method=config.get('method', 'POST'),
            url=config['url'],
            json=payload,
            headers=headers,
            timeout=10
        )

        if 200 <= response.status_code < 300:
            return {'success': True}
        else:
            return {
                'success': False,
                'error': f'Webhook returned status {response.status_code}'
            }

    except Exception as e:
        return {'success': False, 'error': str(e)}


def send_to_email(config: Dict[str, Any], payload: Dict[str, Any], severity: str) -> Dict[str, Any]:
    """Send alert via email."""
    import boto3

    try:
        # Check severity filter
        severity_filter = config.get('severity_filter', [])
        if severity_filter and severity not in severity_filter:
            return {
                'success': True,
                'skipped': True,
                'reason': f'Severity {severity} not in filter'
            }

        # Use AWS SES
        ses = boto3.client('ses')

        subject = config.get('subject_template', 'Alert: {alert_id}').format(**payload)
        body = config.get('body_template', format_email_body(payload))

        response = ses.send_email(
            Source='alerts@mantissalog.com',  # Configure as needed
            Destination={'ToAddresses': config['recipients']},
            Message={
                'Subject': {'Data': subject},
                'Body': {'Text': {'Data': body}}
            }
        )

        return {'success': True, 'message_id': response['MessageId']}

    except Exception as e:
        return {'success': False, 'error': str(e)}


# Formatting functions

def format_slack_message(payload: Dict[str, Any], severity: str) -> str:
    """Format payload for Slack."""
    return f"""*Alert: {payload.get('detection_name', 'Detection')}*
Severity: {severity.upper()}
Time: {payload.get('timestamp', datetime.utcnow().isoformat())}
Event Count: {payload.get('event_count', 'N/A')}

{payload.get('description', 'No description provided')}

Alert ID: `{payload.get('alert_id', 'N/A')}`
"""


def format_jira_summary(payload: Dict[str, Any]) -> str:
    """Format summary for Jira."""
    return f"Security Alert: {payload.get('detection_name', 'Detection Triggered')}"


def format_jira_description(payload: Dict[str, Any]) -> str:
    """Format description for Jira."""
    return f"""h3. Alert Details

* *Alert ID:* {payload.get('alert_id', 'N/A')}
* *Detection:* {payload.get('detection_name', 'N/A')}
* *Severity:* {payload.get('severity', 'N/A')}
* *Timestamp:* {payload.get('timestamp', 'N/A')}
* *Event Count:* {payload.get('event_count', 'N/A')}

h3. Description

{payload.get('description', 'No description provided')}

h3. Raw Data

{{code:json}}
{json.dumps(payload, indent=2)}
{{code}}
"""


def format_pagerduty_summary(payload: Dict[str, Any]) -> str:
    """Format summary for PagerDuty."""
    return f"{payload.get('detection_name', 'Security Alert')}: {payload.get('event_count', 'N/A')} events"


def format_email_body(payload: Dict[str, Any]) -> str:
    """Format body for email."""
    return f"""Security Alert

Detection: {payload.get('detection_name', 'N/A')}
Severity: {payload.get('severity', 'N/A')}
Timestamp: {payload.get('timestamp', 'N/A')}
Event Count: {payload.get('event_count', 'N/A')}

Description:
{payload.get('description', 'No description provided')}

Alert ID: {payload.get('alert_id', 'N/A')}

---
This is an automated alert from Mantissa Log.
"""
