"""
Integrations API

Manages alert integrations (Slack, Jira, PagerDuty, Email, Webhooks).
"""

import json
import boto3
from datetime import datetime
from typing import Dict, Any, List
import requests


dynamodb = boto3.resource('dynamodb')
secretsmanager = boto3.client('secretsmanager')


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
    try:
        http_method = event.get('httpMethod', 'GET')
        path = event.get('path', '')
        path_parameters = event.get('pathParameters') or {}

        user_id = get_user_id_from_event(event)

        if http_method == 'GET' and path == '/integrations':
            return list_integrations(user_id)

        elif http_method == 'GET' and '/integrations/' in path:
            integration_id = path_parameters.get('id')
            return get_integration(user_id, integration_id)

        elif http_method == 'POST' and path == '/integrations':
            body = json.loads(event.get('body', '{}'))
            return create_or_update_integration(user_id, body)

        elif http_method == 'POST' and '/test' in path:
            integration_id = path_parameters.get('id')
            return test_integration(user_id, integration_id)

        elif http_method == 'DELETE':
            integration_id = path_parameters.get('id')
            return delete_integration(user_id, integration_id)

        else:
            return error_response('Method not allowed', 405)

    except Exception as e:
        print(f"Error handling integration request: {str(e)}")
        return error_response(str(e), 500)


def list_integrations(user_id: str) -> Dict[str, Any]:
    """List all integrations for a user."""
    table_name = get_integrations_table_name()
    table = dynamodb.Table(table_name)

    response = table.query(
        KeyConditionExpression='user_id = :user_id',
        ExpressionAttributeValues={':user_id': user_id}
    )

    integrations = response.get('Items', [])

    # Add default integrations if none exist
    if not integrations:
        integrations = get_default_integrations(user_id)

    return success_response({'integrations': integrations})


def get_integration(user_id: str, integration_id: str) -> Dict[str, Any]:
    """Get a specific integration."""
    table_name = get_integrations_table_name()
    table = dynamodb.Table(table_name)

    response = table.get_item(
        Key={'user_id': user_id, 'integration_id': integration_id}
    )

    if 'Item' not in response:
        return error_response('Integration not found', 404)

    return success_response(response['Item'])


def create_or_update_integration(user_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
    """Create or update an integration."""
    table_name = get_integrations_table_name()
    table = dynamodb.Table(table_name)

    integration_id = data.get('integration_id')
    integration_type = data.get('integration_type')
    config = data.get('config', {})

    if not integration_id or not integration_type:
        return error_response('integration_id and integration_type are required', 400)

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

    return success_response({
        'message': 'Integration saved successfully',
        'integration': item
    })


def test_integration(user_id: str, integration_id: str) -> Dict[str, Any]:
    """Test an integration connection."""
    # Get integration config
    integration = get_integration(user_id, integration_id)

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

    # Update last test timestamp
    table_name = get_integrations_table_name()
    table = dynamodb.Table(table_name)

    table.update_item(
        Key={'user_id': user_id, 'integration_id': integration_id},
        UpdateExpression='SET last_test = :timestamp, last_test_status = :status',
        ExpressionAttributeValues={
            ':timestamp': datetime.utcnow().isoformat(),
            ':status': 'success' if test_result['success'] else 'error'
        }
    )

    return success_response(test_result)


def delete_integration(user_id: str, integration_id: str) -> Dict[str, Any]:
    """Delete an integration."""
    table_name = get_integrations_table_name()
    table = dynamodb.Table(table_name)

    # Get integration to find secret ARN
    response = table.get_item(
        Key={'user_id': user_id, 'integration_id': integration_id}
    )

    if 'Item' in response and 'secret_arn' in response['Item']:
        # Delete secret
        try:
            secretsmanager.delete_secret(
                SecretId=response['Item']['secret_arn'],
                ForceDeleteWithoutRecovery=True
            )
        except Exception as e:
            print(f"Error deleting secret: {str(e)}")

    # Delete integration
    table.delete_item(
        Key={'user_id': user_id, 'integration_id': integration_id}
    )

    return success_response({'message': 'Integration deleted successfully'})


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


def store_integration_secrets(user_id: str, integration_id: str, secrets: Dict[str, Any]) -> str:
    """Store integration secrets in Secrets Manager."""
    secret_name = f"mantissa-log/{user_id}/{integration_id}"

    try:
        response = secretsmanager.create_secret(
            Name=secret_name,
            SecretString=json.dumps(secrets)
        )
        return response['ARN']

    except secretsmanager.exceptions.ResourceExistsException:
        # Update existing secret
        response = secretsmanager.update_secret(
            SecretId=secret_name,
            SecretString=json.dumps(secrets)
        )
        return response['ARN']


def get_secret_value(secret_arn: str) -> str:
    """Retrieve secret value from Secrets Manager."""
    if not secret_arn:
        return None

    try:
        response = secretsmanager.get_secret_value(SecretId=secret_arn)
        return response['SecretString']
    except Exception as e:
        print(f"Error retrieving secret: {str(e)}")
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
        }
    ]


def get_user_id_from_event(event: Dict[str, Any]) -> str:
    """Extract user ID from Cognito claims in the event."""
    request_context = event.get('requestContext', {})
    authorizer = request_context.get('authorizer', {})
    claims = authorizer.get('claims', {})

    # Get user ID from Cognito sub claim
    user_id = claims.get('sub') or claims.get('cognito:username', 'default-user')
    return user_id


def get_integrations_table_name() -> str:
    """Get the DynamoDB table name for integrations."""
    import os
    return os.environ.get('INTEGRATION_SETTINGS_TABLE', 'mantissa-log-integration-settings')


def success_response(data: Dict[str, Any]) -> Dict[str, Any]:
    """Return a success response."""
    return {
        'statusCode': 200,
        'headers': {
            'Content-Type': 'application/json',
            'Access-Control-Allow-Origin': '*'
        },
        'body': json.dumps(data)
    }


def error_response(message: str, status_code: int) -> Dict[str, Any]:
    """Return an error response."""
    return {
        'statusCode': status_code,
        'headers': {
            'Content-Type': 'application/json',
            'Access-Control-Allow-Origin': '*'
        },
        'body': json.dumps({'error': message})
    }
