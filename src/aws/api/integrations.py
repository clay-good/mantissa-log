"""
Integrations API

Manages alert integrations (Slack, Jira, PagerDuty, Email, Webhooks).
"""

import json
import logging
import sys
from pathlib import Path
from datetime import datetime
from typing import Dict, Any, List
import requests

# Add shared modules to path
sys.path.append(str(Path(__file__).parent.parent.parent / 'shared'))

from auth import get_authenticated_user_id, AuthenticationError
from auth.cors import get_cors_headers, cors_preflight_response
from utils.lazy_init import aws_clients

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)


def _get_dynamodb():
    """Get lazily-initialized DynamoDB resource."""
    return aws_clients.dynamodb


def _get_secrets_manager():
    """Get lazily-initialized Secrets Manager client."""
    return aws_clients.secrets_manager


def lambda_handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """
    Lambda handler for integration management.

    Routes:
    - GET /integrations -> list_integrations()
    - GET /integrations/{id} -> get_integration(id)
    - POST /integrations -> create_or_update_integration()
    - POST /integrations/{id}/test -> test_integration(id)
    - DELETE /integrations/{id} -> delete_integration(id)
    """
    # Handle CORS preflight
    http_method = event.get('httpMethod', 'GET')
    if http_method == 'OPTIONS':
        return cors_preflight_response(event)

    try:
        # Authenticate user from Cognito JWT claims
        try:
            user_id = get_authenticated_user_id(event)
        except AuthenticationError:
            return error_response(event, 'Authentication required', 401)

        path = event.get('path', '')
        path_parameters = event.get('pathParameters') or {}

        if http_method == 'GET' and path == '/integrations':
            return list_integrations(event, user_id)

        elif http_method == 'GET' and '/integrations/' in path:
            integration_id = path_parameters.get('id')
            return get_integration(event, user_id, integration_id)

        elif http_method == 'POST' and path == '/integrations':
            body = json.loads(event.get('body', '{}'))
            return create_or_update_integration(event, user_id, body)

        elif http_method == 'POST' and '/test' in path:
            integration_id = path_parameters.get('id')
            return test_integration(event, user_id, integration_id)

        elif http_method == 'DELETE':
            integration_id = path_parameters.get('id')
            return delete_integration(event, user_id, integration_id)

        else:
            return error_response(event, 'Method not allowed', 405)

    except Exception as e:
        logger.error(f"Error handling integration request: {str(e)}", exc_info=True)
        return error_response(event, 'Internal server error', 500)


def list_integrations(event: Dict[str, Any], user_id: str) -> Dict[str, Any]:
    """List all integrations for a user."""
    table_name = get_integrations_table_name()
    table = _get_dynamodb().Table(table_name)

    response = table.query(
        KeyConditionExpression='user_id = :user_id',
        ExpressionAttributeValues={':user_id': user_id}
    )

    integrations = response.get('Items', [])

    # Add default integrations if none exist
    if not integrations:
        integrations = get_default_integrations(user_id)

    return success_response(event, {'integrations': integrations})


def get_integration(event: Dict[str, Any], user_id: str, integration_id: str) -> Dict[str, Any]:
    """Get a specific integration."""
    table_name = get_integrations_table_name()
    table = _get_dynamodb().Table(table_name)

    response = table.get_item(
        Key={'user_id': user_id, 'integration_id': integration_id}
    )

    if 'Item' not in response:
        return error_response(event, 'Integration not found', 404)

    return success_response(event, response['Item'])


def create_or_update_integration(event: Dict[str, Any], user_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
    """Create or update an integration."""
    table_name = get_integrations_table_name()
    table = _get_dynamodb().Table(table_name)

    integration_id = data.get('integration_id')
    integration_type = data.get('integration_type')
    config = data.get('config', {})

    if not integration_id or not integration_type:
        return error_response(event, 'integration_id and integration_type are required', 400)

    # Store secrets in Secrets Manager
    secret_arn = None
    if 'secrets' in data:
        secret_arn = store_integration_secrets(
            user_id,
            integration_id,
            data['secrets']
        )

    # Create integration item
    item = {
        'user_id': user_id,
        'integration_id': integration_id,
        'integration_type': integration_type,
        'enabled': data.get('enabled', True),
        'config': config,
        'status': 'configured',
        'created_at': datetime.utcnow().isoformat(),
        'updated_at': datetime.utcnow().isoformat()
    }

    if secret_arn:
        item['secret_arn'] = secret_arn

    table.put_item(Item=item)

    return success_response(event, {
        'message': 'Integration saved successfully',
        'integration': item
    })


def test_integration(event: Dict[str, Any], user_id: str, integration_id: str) -> Dict[str, Any]:
    """Test an integration connection."""
    # Get integration config
    integration = get_integration(event, user_id, integration_id)

    if integration.get('statusCode') != 200:
        return integration

    integration_data = json.loads(integration['body'])
    integration_type = integration_data.get('integration_type')

    # Test based on type
    test_result = {
        'success': False,
        'message': 'Test not implemented for this integration type'
    }

    if integration_type == 'slack':
        test_result = test_slack_integration(integration_data)
    elif integration_type == 'jira':
        test_result = test_jira_integration(integration_data)
    elif integration_type == 'pagerduty':
        test_result = test_pagerduty_integration(integration_data)
    elif integration_type == 'email':
        test_result = test_email_integration(integration_data)
    elif integration_type == 'servicenow':
        test_result = test_servicenow_integration(integration_data)
    elif integration_type == 'teams':
        test_result = test_teams_integration(integration_data)
    elif integration_type == 'webhook':
        test_result = test_webhook_integration(integration_data)

    # Update last test timestamp
    table_name = get_integrations_table_name()
    table = _get_dynamodb().Table(table_name)

    table.update_item(
        Key={'user_id': user_id, 'integration_id': integration_id},
        UpdateExpression='SET last_test = :timestamp, last_test_status = :status',
        ExpressionAttributeValues={
            ':timestamp': datetime.utcnow().isoformat(),
            ':status': 'success' if test_result['success'] else 'error'
        }
    )

    return success_response(event, test_result)


def delete_integration(event: Dict[str, Any], user_id: str, integration_id: str) -> Dict[str, Any]:
    """Delete an integration."""
    table_name = get_integrations_table_name()
    table = _get_dynamodb().Table(table_name)

    # Get integration to find secret ARN
    response = table.get_item(
        Key={'user_id': user_id, 'integration_id': integration_id}
    )

    if 'Item' in response and 'secret_arn' in response['Item']:
        # Delete secret
        try:
            _get_secrets_manager().delete_secret(
                SecretId=response['Item']['secret_arn'],
                ForceDeleteWithoutRecovery=True
            )
        except Exception as e:
            logger.error(f"Error deleting secret: {str(e)}")

    # Delete integration
    table.delete_item(
        Key={'user_id': user_id, 'integration_id': integration_id}
    )

    return success_response(event, {'message': 'Integration deleted successfully'})


def test_slack_integration(integration: Dict[str, Any]) -> Dict[str, Any]:
    """Test Slack webhook integration."""
    webhook_url = get_secret_value(integration.get('secret_arn'))

    if not webhook_url:
        return {'success': False, 'message': 'Webhook URL not configured'}

    try:
        response = requests.post(
            webhook_url,
            json={'text': 'Mantissa Log integration test - this is a test alert'},
            timeout=10
        )

        if response.status_code == 200:
            return {'success': True, 'message': 'Slack test message sent successfully'}
        else:
            return {'success': False, 'message': f'Slack returned status {response.status_code}'}

    except Exception as e:
        return {'success': False, 'message': f'Error testing Slack: {str(e)}'}


def test_jira_integration(integration: Dict[str, Any]) -> Dict[str, Any]:
    """Test Jira API integration by verifying credentials and project access."""
    import base64

    url = integration.get('url', '').rstrip('/')
    email = integration.get('email', '')
    api_token = integration.get('api_token', '')
    project_key = integration.get('project_key', '')

    if not all([url, email, api_token, project_key]):
        return {'success': False, 'message': 'Missing required Jira configuration (url, email, api_token, project_key)'}

    try:
        # Create auth header
        auth_string = f"{email}:{api_token}"
        encoded = base64.b64encode(auth_string.encode()).decode()
        headers = {
            "Authorization": f"Basic {encoded}",
            "Content-Type": "application/json",
            "Accept": "application/json"
        }

        # Test authentication by calling /myself endpoint
        response = requests.get(
            f"{url}/rest/api/3/myself",
            headers=headers,
            timeout=10
        )

        if response.status_code == 401:
            return {'success': False, 'message': 'Invalid Jira credentials'}
        elif response.status_code != 200:
            return {'success': False, 'message': f'Jira API returned status {response.status_code}'}

        user_info = response.json()

        # Verify project access
        project_response = requests.get(
            f"{url}/rest/api/3/project/{project_key}",
            headers=headers,
            timeout=10
        )

        if project_response.status_code == 404:
            return {'success': False, 'message': f'Project {project_key} not found'}
        elif project_response.status_code != 200:
            return {'success': False, 'message': f'Cannot access project {project_key}'}

        project_info = project_response.json()
        return {
            'success': True,
            'message': f'Connected as {user_info.get("displayName", email)} with access to project {project_info.get("name", project_key)}'
        }

    except requests.exceptions.Timeout:
        return {'success': False, 'message': 'Connection to Jira timed out'}
    except requests.exceptions.ConnectionError:
        return {'success': False, 'message': f'Cannot connect to Jira at {url}'}
    except Exception as e:
        return {'success': False, 'message': f'Error testing Jira: {str(e)}'}


def test_pagerduty_integration(integration: Dict[str, Any]) -> Dict[str, Any]:
    """Test PagerDuty integration by validating the routing key."""
    routing_key = integration.get('routing_key', '')

    if not routing_key:
        return {'success': False, 'message': 'Missing PagerDuty routing key'}

    try:
        # Send a test event to PagerDuty Events API v2
        payload = {
            "routing_key": routing_key,
            "event_action": "trigger",
            "dedup_key": "mantissa-log-integration-test",
            "payload": {
                "summary": "Mantissa Log integration test - this is a test alert (will auto-resolve)",
                "severity": "info",
                "source": "mantissa-log",
                "custom_details": {
                    "test": True,
                    "message": "This alert was generated to test the PagerDuty integration"
                }
            }
        }

        response = requests.post(
            "https://events.pagerduty.com/v2/enqueue",
            json=payload,
            timeout=10
        )

        if response.status_code == 202:
            result = response.json()
            dedup_key = result.get("dedup_key", "")

            # Immediately resolve the test alert
            resolve_payload = {
                "routing_key": routing_key,
                "event_action": "resolve",
                "dedup_key": dedup_key or "mantissa-log-integration-test"
            }
            requests.post(
                "https://events.pagerduty.com/v2/enqueue",
                json=resolve_payload,
                timeout=10
            )

            return {
                'success': True,
                'message': 'PagerDuty integration verified (test alert sent and resolved)'
            }
        elif response.status_code == 400:
            return {'success': False, 'message': 'Invalid PagerDuty routing key'}
        else:
            return {'success': False, 'message': f'PagerDuty returned status {response.status_code}'}

    except requests.exceptions.Timeout:
        return {'success': False, 'message': 'Connection to PagerDuty timed out'}
    except Exception as e:
        return {'success': False, 'message': f'Error testing PagerDuty: {str(e)}'}


def test_email_integration(integration: Dict[str, Any]) -> Dict[str, Any]:
    """Test email integration by sending a test email via SES."""
    ses = boto3.client('ses', region_name=integration.get('region', 'us-east-1'))

    to_address = integration.get('to_address', '')
    from_address = integration.get('from_address', '')

    if not to_address:
        return {'success': False, 'message': 'Missing recipient email address (to_address)'}

    if not from_address:
        return {'success': False, 'message': 'Missing sender email address (from_address)'}

    try:
        # Verify sender identity is configured
        identities = ses.list_verified_email_addresses()
        verified_emails = identities.get('VerifiedEmailAddresses', [])

        # Check domain verification if exact email not verified
        domain = from_address.split('@')[-1] if '@' in from_address else ''
        domains = ses.list_identities(IdentityType='Domain').get('Identities', [])

        if from_address not in verified_emails and domain not in domains:
            return {
                'success': False,
                'message': f'Sender {from_address} is not verified in SES. Verify the email or domain first.'
            }

        # Send test email
        response = ses.send_email(
            Source=from_address,
            Destination={
                'ToAddresses': [to_address]
            },
            Message={
                'Subject': {
                    'Data': 'Mantissa Log - Integration Test',
                    'Charset': 'UTF-8'
                },
                'Body': {
                    'Text': {
                        'Data': 'This is a test email from Mantissa Log to verify your email integration is working correctly.\n\nIf you received this message, your email alerting is configured properly.',
                        'Charset': 'UTF-8'
                    }
                }
            }
        )

        message_id = response.get('MessageId', '')
        return {
            'success': True,
            'message': f'Test email sent successfully (MessageId: {message_id})'
        }

    except ses.exceptions.MessageRejected as e:
        return {'success': False, 'message': f'Email rejected: {str(e)}'}
    except ses.exceptions.MailFromDomainNotVerifiedException:
        return {'success': False, 'message': f'Domain for {from_address} is not verified in SES'}
    except Exception as e:
        return {'success': False, 'message': f'Error sending test email: {str(e)}'}


def test_servicenow_integration(integration: Dict[str, Any]) -> Dict[str, Any]:
    """Test ServiceNow integration by validating credentials and creating a test incident."""
    instance_url = integration.get('instance_url', '').rstrip('/')
    username = integration.get('username', '')
    password = integration.get('password', '')
    client_id = integration.get('client_id', '')
    client_secret = integration.get('client_secret', '')

    if not instance_url:
        return {'success': False, 'message': 'Missing ServiceNow instance URL'}

    # Support both basic auth and OAuth
    use_oauth = bool(client_id and client_secret)

    try:
        headers = {'Content-Type': 'application/json', 'Accept': 'application/json'}

        if use_oauth:
            # Get OAuth token
            token_url = f"{instance_url}/oauth_token.do"
            token_data = {
                'grant_type': 'password',
                'client_id': client_id,
                'client_secret': client_secret,
                'username': username,
                'password': password
            }
            token_response = requests.post(token_url, data=token_data, timeout=10)

            if token_response.status_code != 200:
                return {'success': False, 'message': 'Failed to obtain OAuth token from ServiceNow'}

            access_token = token_response.json().get('access_token')
            headers['Authorization'] = f'Bearer {access_token}'
        else:
            # Basic auth
            if not username or not password:
                return {'success': False, 'message': 'Missing ServiceNow username or password'}
            auth = (username, password)

        # Test connection by querying sys_user table
        test_url = f"{instance_url}/api/now/table/sys_user?sysparm_limit=1"

        if use_oauth:
            response = requests.get(test_url, headers=headers, timeout=10)
        else:
            response = requests.get(test_url, headers=headers, auth=auth, timeout=10)

        if response.status_code == 401:
            return {'success': False, 'message': 'Invalid ServiceNow credentials'}
        elif response.status_code == 403:
            return {'success': False, 'message': 'Access denied - check user permissions'}
        elif response.status_code != 200:
            return {'success': False, 'message': f'ServiceNow returned status {response.status_code}'}

        # Verify incident table access
        incident_url = f"{instance_url}/api/now/table/incident?sysparm_limit=1"
        if use_oauth:
            incident_response = requests.get(incident_url, headers=headers, timeout=10)
        else:
            incident_response = requests.get(incident_url, headers=headers, auth=auth, timeout=10)

        if incident_response.status_code != 200:
            return {
                'success': False,
                'message': 'Cannot access incident table - check ITIL role permissions'
            }

        return {
            'success': True,
            'message': f'Connected to ServiceNow instance at {instance_url} with incident table access'
        }

    except requests.exceptions.Timeout:
        return {'success': False, 'message': 'Connection to ServiceNow timed out'}
    except requests.exceptions.ConnectionError:
        return {'success': False, 'message': f'Cannot connect to ServiceNow at {instance_url}'}
    except Exception as e:
        return {'success': False, 'message': f'Error testing ServiceNow: {str(e)}'}


def test_teams_integration(integration: Dict[str, Any]) -> Dict[str, Any]:
    """Test Microsoft Teams integration by sending a test message to the webhook."""
    webhook_url = integration.get('webhook_url', '')

    if not webhook_url:
        return {'success': False, 'message': 'Missing Teams webhook URL'}

    # Validate webhook URL format
    if not webhook_url.startswith('https://') or 'webhook.office.com' not in webhook_url:
        return {
            'success': False,
            'message': 'Invalid Teams webhook URL format. URL should be from webhook.office.com'
        }

    try:
        # Send adaptive card test message
        card_payload = {
            "@type": "MessageCard",
            "@context": "http://schema.org/extensions",
            "themeColor": "0076D7",
            "summary": "Mantissa Log Integration Test",
            "sections": [{
                "activityTitle": "🔔 Mantissa Log Integration Test",
                "facts": [
                    {"name": "Status", "value": "✅ Connection Successful"},
                    {"name": "Test Time", "value": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")},
                    {"name": "Message", "value": "Your Microsoft Teams integration is working correctly."}
                ],
                "markdown": True
            }]
        }

        response = requests.post(
            webhook_url,
            json=card_payload,
            headers={'Content-Type': 'application/json'},
            timeout=10
        )

        # Teams webhooks return 200 with "1" on success
        if response.status_code == 200:
            return {
                'success': True,
                'message': 'Test message sent to Teams channel successfully'
            }
        elif response.status_code == 400:
            return {'success': False, 'message': 'Invalid webhook payload format'}
        elif response.status_code == 404:
            return {'success': False, 'message': 'Webhook URL not found - it may have been deleted'}
        elif response.status_code == 429:
            return {'success': False, 'message': 'Rate limited by Teams - try again later'}
        else:
            return {'success': False, 'message': f'Teams webhook returned status {response.status_code}'}

    except requests.exceptions.Timeout:
        return {'success': False, 'message': 'Connection to Teams webhook timed out'}
    except requests.exceptions.ConnectionError:
        return {'success': False, 'message': 'Cannot connect to Teams webhook URL'}
    except Exception as e:
        return {'success': False, 'message': f'Error testing Teams: {str(e)}'}


def test_webhook_integration(integration: Dict[str, Any]) -> Dict[str, Any]:
    """Test generic webhook integration by sending a test payload."""
    webhook_url = integration.get('webhook_url', '')
    method = integration.get('method', 'POST').upper()
    headers = integration.get('headers', {})
    auth_type = integration.get('auth_type', 'none')
    auth_token = integration.get('auth_token', '')
    auth_username = integration.get('auth_username', '')
    auth_password = integration.get('auth_password', '')

    if not webhook_url:
        return {'success': False, 'message': 'Missing webhook URL'}

    # Validate URL
    if not webhook_url.startswith(('http://', 'https://')):
        return {'success': False, 'message': 'Invalid webhook URL - must start with http:// or https://'}

    try:
        # Build request headers
        request_headers = {
            'Content-Type': 'application/json',
            'User-Agent': 'Mantissa-Log/1.0',
            **headers
        }

        # Add authentication
        auth = None
        if auth_type == 'bearer' and auth_token:
            request_headers['Authorization'] = f'Bearer {auth_token}'
        elif auth_type == 'api_key' and auth_token:
            # Support both header and query param API keys
            api_key_header = integration.get('api_key_header', 'X-API-Key')
            request_headers[api_key_header] = auth_token
        elif auth_type == 'basic' and auth_username and auth_password:
            auth = (auth_username, auth_password)

        # Build test payload
        test_payload = {
            "test": True,
            "source": "mantissa-log",
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "message": "This is a test webhook from Mantissa Log to verify your integration.",
            "alert": {
                "rule_name": "Integration Test",
                "severity": "info",
                "description": "Test alert payload for webhook verification"
            }
        }

        # Send request based on method
        if method == 'POST':
            response = requests.post(
                webhook_url,
                json=test_payload,
                headers=request_headers,
                auth=auth,
                timeout=15
            )
        elif method == 'PUT':
            response = requests.put(
                webhook_url,
                json=test_payload,
                headers=request_headers,
                auth=auth,
                timeout=15
            )
        elif method == 'GET':
            # For GET, send params instead of body
            response = requests.get(
                webhook_url,
                params={'test': 'true', 'source': 'mantissa-log'},
                headers=request_headers,
                auth=auth,
                timeout=15
            )
        else:
            return {'success': False, 'message': f'Unsupported HTTP method: {method}'}

        # Check response
        if response.status_code >= 200 and response.status_code < 300:
            response_preview = response.text[:200] if response.text else '(empty response)'
            return {
                'success': True,
                'message': f'Webhook returned {response.status_code}. Response: {response_preview}'
            }
        elif response.status_code == 401:
            return {'success': False, 'message': 'Authentication failed - check credentials'}
        elif response.status_code == 403:
            return {'success': False, 'message': 'Access forbidden - check permissions'}
        elif response.status_code == 404:
            return {'success': False, 'message': 'Webhook endpoint not found'}
        elif response.status_code >= 500:
            return {'success': False, 'message': f'Webhook server error (status {response.status_code})'}
        else:
            return {'success': False, 'message': f'Webhook returned status {response.status_code}'}

    except requests.exceptions.Timeout:
        return {'success': False, 'message': 'Webhook request timed out (15s)'}
    except requests.exceptions.SSLError:
        return {'success': False, 'message': 'SSL certificate verification failed'}
    except requests.exceptions.ConnectionError as e:
        return {'success': False, 'message': f'Cannot connect to webhook URL: {str(e)[:100]}'}
    except Exception as e:
        return {'success': False, 'message': f'Error testing webhook: {str(e)}'}


def store_integration_secrets(user_id: str, integration_id: str, secrets: Dict[str, Any]) -> str:
    """Store integration secrets in Secrets Manager."""
    secret_name = f"mantissa-log/{user_id}/{integration_id}"
    sm = _get_secrets_manager()

    try:
        response = sm.create_secret(
            Name=secret_name,
            SecretString=json.dumps(secrets)
        )
        return response['ARN']

    except sm.exceptions.ResourceExistsException:
        # Update existing secret
        response = sm.update_secret(
            SecretId=secret_name,
            SecretString=json.dumps(secrets)
        )
        return response['ARN']


def get_secret_value(secret_arn: str) -> str:
    """Retrieve secret value from Secrets Manager."""
    if not secret_arn:
        return None

    try:
        response = _get_secrets_manager().get_secret_value(SecretId=secret_arn)
        return response['SecretString']
    except Exception as e:
        logger.error(f"Error retrieving secret: {str(e)}")
        return None


def get_default_integrations(user_id: str) -> List[Dict[str, Any]]:
    """Return default integration templates."""
    return [
        {
            'user_id': user_id,
            'integration_id': 'slack',
            'integration_type': 'slack',
            'name': 'Slack',
            'description': 'Send alerts to Slack channels',
            'configured': False,
            'status': 'not_configured'
        },
        {
            'user_id': user_id,
            'integration_id': 'email',
            'integration_type': 'email',
            'name': 'Email',
            'description': 'Send alerts via email',
            'configured': False,
            'status': 'not_configured'
        },
        {
            'user_id': user_id,
            'integration_id': 'jira',
            'integration_type': 'jira',
            'name': 'Jira',
            'description': 'Create Jira tickets for security findings',
            'configured': False,
            'status': 'not_configured'
        },
        {
            'user_id': user_id,
            'integration_id': 'pagerduty',
            'integration_type': 'pagerduty',
            'name': 'PagerDuty',
            'description': 'Trigger PagerDuty incidents',
            'configured': False,
            'status': 'not_configured'
        },
        {
            'user_id': user_id,
            'integration_id': 'servicenow',
            'integration_type': 'servicenow',
            'name': 'ServiceNow',
            'description': 'Create ServiceNow incidents',
            'configured': False,
            'status': 'not_configured'
        },
        {
            'user_id': user_id,
            'integration_id': 'teams',
            'integration_type': 'teams',
            'name': 'Microsoft Teams',
            'description': 'Send alerts to Teams channels',
            'configured': False,
            'status': 'not_configured'
        },
        {
            'user_id': user_id,
            'integration_id': 'webhook',
            'integration_type': 'webhook',
            'name': 'Custom Webhook',
            'description': 'Send alerts to any HTTP endpoint',
            'configured': False,
            'status': 'not_configured'
        }
    ]


def get_integrations_table_name() -> str:
    """Get the DynamoDB table name for integrations."""
    import os
    return os.environ.get('INTEGRATION_SETTINGS_TABLE', 'mantissa-log-integration-settings')


def success_response(event: Dict[str, Any], data: Dict[str, Any]) -> Dict[str, Any]:
    """Return a success response with secure CORS headers."""
    return {
        'statusCode': 200,
        'headers': {
            'Content-Type': 'application/json',
            **get_cors_headers(event)
        },
        'body': json.dumps(data)
    }


def error_response(event: Dict[str, Any], message: str, status_code: int) -> Dict[str, Any]:
    """Return an error response with secure CORS headers."""
    return {
        'statusCode': status_code,
        'headers': {
            'Content-Type': 'application/json',
            **get_cors_headers(event)
        },
        'body': json.dumps({'error': message})
    }
