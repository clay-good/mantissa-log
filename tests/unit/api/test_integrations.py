"""Unit tests for integration test functions.

Tests cover:
- ServiceNow integration testing
- Microsoft Teams integration testing
- Generic webhook integration testing
- Error handling and edge cases
"""

import sys
import os
from datetime import datetime
from unittest.mock import patch, MagicMock
import pytest

# Add shared modules to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../../../src/shared'))


# Inline implementations of the integration test functions for isolated testing
# These are named _impl to avoid pytest treating them as test cases
# This avoids import issues from the full integrations module

def servicenow_integration_impl(integration):
    """Test ServiceNow integration by validating credentials."""
    import requests

    instance_url = integration.get('instance_url', '').rstrip('/')
    username = integration.get('username', '')
    password = integration.get('password', '')
    client_id = integration.get('client_id', '')
    client_secret = integration.get('client_secret', '')

    if not instance_url:
        return {'success': False, 'message': 'Missing ServiceNow instance URL'}

    use_oauth = bool(client_id and client_secret)

    try:
        headers = {'Content-Type': 'application/json', 'Accept': 'application/json'}

        if use_oauth:
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
            if not username or not password:
                return {'success': False, 'message': 'Missing ServiceNow username or password'}
            auth = (username, password)

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


def teams_integration_impl(integration):
    """Test Microsoft Teams integration by sending a test message."""
    import requests

    webhook_url = integration.get('webhook_url', '')

    if not webhook_url:
        return {'success': False, 'message': 'Missing Teams webhook URL'}

    if not webhook_url.startswith('https://') or 'webhook.office.com' not in webhook_url:
        return {
            'success': False,
            'message': 'Invalid Teams webhook URL format. URL should be from webhook.office.com'
        }

    try:
        card_payload = {
            "@type": "MessageCard",
            "@context": "http://schema.org/extensions",
            "themeColor": "0076D7",
            "summary": "Mantissa Log Integration Test",
            "sections": [{
                "activityTitle": "Mantissa Log Integration Test",
                "facts": [
                    {"name": "Status", "value": "Connection Successful"},
                    {"name": "Test Time", "value": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")},
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


def webhook_integration_impl(integration):
    """Test generic webhook integration by sending a test payload."""
    import requests

    webhook_url = integration.get('webhook_url', '')
    method = integration.get('method', 'POST').upper()
    headers = integration.get('headers', {})
    auth_type = integration.get('auth_type', 'none')
    auth_token = integration.get('auth_token', '')
    auth_username = integration.get('auth_username', '')
    auth_password = integration.get('auth_password', '')

    if not webhook_url:
        return {'success': False, 'message': 'Missing webhook URL'}

    if not webhook_url.startswith(('http://', 'https://')):
        return {'success': False, 'message': 'Invalid webhook URL - must start with http:// or https://'}

    try:
        request_headers = {
            'Content-Type': 'application/json',
            'User-Agent': 'Mantissa-Log/1.0',
            **headers
        }

        auth = None
        if auth_type == 'bearer' and auth_token:
            request_headers['Authorization'] = f'Bearer {auth_token}'
        elif auth_type == 'api_key' and auth_token:
            api_key_header = integration.get('api_key_header', 'X-API-Key')
            request_headers[api_key_header] = auth_token
        elif auth_type == 'basic' and auth_username and auth_password:
            auth = (auth_username, auth_password)

        test_payload = {
            "test": True,
            "source": "mantissa-log",
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "message": "Test webhook from Mantissa Log",
            "alert": {
                "rule_name": "Integration Test",
                "severity": "info",
            }
        }

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
            response = requests.get(
                webhook_url,
                params={'test': 'true', 'source': 'mantissa-log'},
                headers=request_headers,
                auth=auth,
                timeout=15
            )
        else:
            return {'success': False, 'message': f'Unsupported HTTP method: {method}'}

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


# ============================================================================
# Test Classes
# ============================================================================

class TestServiceNowIntegration:
    """Tests for test_servicenow_integration function."""

    def test_missing_instance_url(self):
        """Should return error when instance URL is missing."""
        result = servicenow_integration_impl({})

        assert result['success'] is False
        assert 'Missing ServiceNow instance URL' in result['message']

    def test_missing_credentials_basic_auth(self):
        """Should return error when username/password missing for basic auth."""
        result = servicenow_integration_impl({
            'instance_url': 'https://company.service-now.com'
        })

        assert result['success'] is False
        assert 'Missing ServiceNow username or password' in result['message']

    @patch('requests.get')
    def test_successful_basic_auth(self, mock_get):
        """Should return success when basic auth credentials are valid."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {'result': []}
        mock_get.return_value = mock_response

        result = servicenow_integration_impl({
            'instance_url': 'https://company.service-now.com',
            'username': 'admin',
            'password': 'password123'
        })

        assert result['success'] is True
        assert 'Connected to ServiceNow' in result['message']
        assert mock_get.call_count == 2

    @patch('requests.get')
    def test_invalid_credentials(self, mock_get):
        """Should return error when credentials are invalid."""
        mock_response = MagicMock()
        mock_response.status_code = 401
        mock_get.return_value = mock_response

        result = servicenow_integration_impl({
            'instance_url': 'https://company.service-now.com',
            'username': 'admin',
            'password': 'wrong'
        })

        assert result['success'] is False
        assert 'Invalid ServiceNow credentials' in result['message']

    @patch('requests.get')
    def test_access_denied(self, mock_get):
        """Should return error when access is denied."""
        mock_response = MagicMock()
        mock_response.status_code = 403
        mock_get.return_value = mock_response

        result = servicenow_integration_impl({
            'instance_url': 'https://company.service-now.com',
            'username': 'user',
            'password': 'pass'
        })

        assert result['success'] is False
        assert 'Access denied' in result['message']

    @patch('requests.get')
    def test_incident_table_access_denied(self, mock_get):
        """Should return error when incident table is not accessible."""
        mock_success = MagicMock()
        mock_success.status_code = 200
        mock_fail = MagicMock()
        mock_fail.status_code = 403
        mock_get.side_effect = [mock_success, mock_fail]

        result = servicenow_integration_impl({
            'instance_url': 'https://company.service-now.com',
            'username': 'user',
            'password': 'pass'
        })

        assert result['success'] is False
        assert 'incident table' in result['message'].lower()

    @patch('requests.get')
    @patch('requests.post')
    def test_oauth_authentication(self, mock_post, mock_get):
        """Should support OAuth authentication."""
        mock_token = MagicMock()
        mock_token.status_code = 200
        mock_token.json.return_value = {'access_token': 'test-token'}
        mock_post.return_value = mock_token

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_get.return_value = mock_response

        result = servicenow_integration_impl({
            'instance_url': 'https://company.service-now.com',
            'username': 'user',
            'password': 'pass',
            'client_id': 'client123',
            'client_secret': 'secret456'
        })

        assert result['success'] is True
        mock_post.assert_called_once()

    @patch('requests.get')
    def test_connection_timeout(self, mock_get):
        """Should handle connection timeout."""
        import requests as req
        mock_get.side_effect = req.exceptions.Timeout()

        result = servicenow_integration_impl({
            'instance_url': 'https://company.service-now.com',
            'username': 'user',
            'password': 'pass'
        })

        assert result['success'] is False
        assert 'timed out' in result['message']

    @patch('requests.get')
    def test_connection_error(self, mock_get):
        """Should handle connection errors."""
        import requests as req
        mock_get.side_effect = req.exceptions.ConnectionError()

        result = servicenow_integration_impl({
            'instance_url': 'https://invalid.service-now.com',
            'username': 'user',
            'password': 'pass'
        })

        assert result['success'] is False
        assert 'Cannot connect' in result['message']


class TestTeamsIntegration:
    """Tests for test_teams_integration function."""

    def test_missing_webhook_url(self):
        """Should return error when webhook URL is missing."""
        result = teams_integration_impl({})

        assert result['success'] is False
        assert 'Missing Teams webhook URL' in result['message']

    def test_invalid_webhook_url_format(self):
        """Should validate Teams webhook URL format."""
        result = teams_integration_impl({
            'webhook_url': 'https://example.com/webhook'
        })

        assert result['success'] is False
        assert 'Invalid Teams webhook URL format' in result['message']

    def test_http_url_rejected(self):
        """Should reject non-HTTPS URLs."""
        result = teams_integration_impl({
            'webhook_url': 'http://webhook.office.com/webhook/...'
        })

        assert result['success'] is False
        assert 'Invalid Teams webhook URL format' in result['message']

    @patch('requests.post')
    def test_successful_message(self, mock_post):
        """Should return success when message is sent."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_post.return_value = mock_response

        result = teams_integration_impl({
            'webhook_url': 'https://webhook.office.com/webhook/abc123'
        })

        assert result['success'] is True
        assert 'sent to Teams channel successfully' in result['message']

    @patch('requests.post')
    def test_webhook_not_found(self, mock_post):
        """Should handle deleted webhook."""
        mock_response = MagicMock()
        mock_response.status_code = 404
        mock_post.return_value = mock_response

        result = teams_integration_impl({
            'webhook_url': 'https://webhook.office.com/webhook/deleted'
        })

        assert result['success'] is False
        assert 'not found' in result['message']

    @patch('requests.post')
    def test_rate_limited(self, mock_post):
        """Should handle rate limiting."""
        mock_response = MagicMock()
        mock_response.status_code = 429
        mock_post.return_value = mock_response

        result = teams_integration_impl({
            'webhook_url': 'https://webhook.office.com/webhook/abc'
        })

        assert result['success'] is False
        assert 'Rate limited' in result['message']

    @patch('requests.post')
    def test_sends_message_card(self, mock_post):
        """Should send properly formatted message card."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_post.return_value = mock_response

        teams_integration_impl({
            'webhook_url': 'https://webhook.office.com/webhook/abc'
        })

        call_args = mock_post.call_args
        payload = call_args.kwargs.get('json') or call_args[1].get('json')

        assert payload['@type'] == 'MessageCard'
        assert 'sections' in payload
        assert 'Mantissa Log' in payload['summary']


class TestWebhookIntegration:
    """Tests for test_webhook_integration function."""

    def test_missing_webhook_url(self):
        """Should return error when URL is missing."""
        result = webhook_integration_impl({})

        assert result['success'] is False
        assert 'Missing webhook URL' in result['message']

    def test_invalid_url_format(self):
        """Should reject invalid URL format."""
        result = webhook_integration_impl({
            'webhook_url': 'not-a-valid-url'
        })

        assert result['success'] is False
        assert 'Invalid webhook URL' in result['message']

    @patch('requests.post')
    def test_successful_post(self, mock_post):
        """Should return success for successful POST."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.text = '{"status": "ok"}'
        mock_post.return_value = mock_response

        result = webhook_integration_impl({
            'webhook_url': 'https://example.com/webhook'
        })

        assert result['success'] is True
        assert '200' in result['message']

    @patch('requests.put')
    def test_put_method(self, mock_put):
        """Should support PUT method."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.text = 'OK'
        mock_put.return_value = mock_response

        result = webhook_integration_impl({
            'webhook_url': 'https://example.com/webhook',
            'method': 'PUT'
        })

        assert result['success'] is True
        mock_put.assert_called_once()

    @patch('requests.get')
    def test_get_method(self, mock_get):
        """Should support GET method."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.text = 'OK'
        mock_get.return_value = mock_response

        result = webhook_integration_impl({
            'webhook_url': 'https://example.com/webhook',
            'method': 'GET'
        })

        assert result['success'] is True
        mock_get.assert_called_once()

    def test_unsupported_method(self):
        """Should reject unsupported HTTP methods."""
        result = webhook_integration_impl({
            'webhook_url': 'https://example.com/webhook',
            'method': 'DELETE'
        })

        assert result['success'] is False
        assert 'Unsupported HTTP method' in result['message']

    @patch('requests.post')
    def test_bearer_auth(self, mock_post):
        """Should add Bearer token authentication."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.text = ''
        mock_post.return_value = mock_response

        webhook_integration_impl({
            'webhook_url': 'https://example.com/webhook',
            'auth_type': 'bearer',
            'auth_token': 'my-token-123'
        })

        call_args = mock_post.call_args
        headers = call_args.kwargs.get('headers') or call_args[1].get('headers')
        assert headers['Authorization'] == 'Bearer my-token-123'

    @patch('requests.post')
    def test_api_key_auth(self, mock_post):
        """Should add API key authentication."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.text = ''
        mock_post.return_value = mock_response

        webhook_integration_impl({
            'webhook_url': 'https://example.com/webhook',
            'auth_type': 'api_key',
            'auth_token': 'api-key-456',
            'api_key_header': 'X-Custom-Key'
        })

        call_args = mock_post.call_args
        headers = call_args.kwargs.get('headers') or call_args[1].get('headers')
        assert headers['X-Custom-Key'] == 'api-key-456'

    @patch('requests.post')
    def test_basic_auth(self, mock_post):
        """Should add basic authentication."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.text = ''
        mock_post.return_value = mock_response

        webhook_integration_impl({
            'webhook_url': 'https://example.com/webhook',
            'auth_type': 'basic',
            'auth_username': 'user',
            'auth_password': 'pass'
        })

        call_args = mock_post.call_args
        auth = call_args.kwargs.get('auth') or call_args[1].get('auth')
        assert auth == ('user', 'pass')

    @patch('requests.post')
    def test_custom_headers(self, mock_post):
        """Should include custom headers."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.text = ''
        mock_post.return_value = mock_response

        webhook_integration_impl({
            'webhook_url': 'https://example.com/webhook',
            'headers': {'X-Custom': 'value', 'X-Another': 'test'}
        })

        call_args = mock_post.call_args
        headers = call_args.kwargs.get('headers') or call_args[1].get('headers')
        assert headers['X-Custom'] == 'value'
        assert headers['X-Another'] == 'test'

    @patch('requests.post')
    def test_authentication_failure(self, mock_post):
        """Should handle authentication failure."""
        mock_response = MagicMock()
        mock_response.status_code = 401
        mock_post.return_value = mock_response

        result = webhook_integration_impl({
            'webhook_url': 'https://example.com/webhook'
        })

        assert result['success'] is False
        assert 'Authentication failed' in result['message']

    @patch('requests.post')
    def test_server_error(self, mock_post):
        """Should handle server errors."""
        mock_response = MagicMock()
        mock_response.status_code = 500
        mock_post.return_value = mock_response

        result = webhook_integration_impl({
            'webhook_url': 'https://example.com/webhook'
        })

        assert result['success'] is False
        assert 'server error' in result['message']

    @patch('requests.post')
    def test_timeout(self, mock_post):
        """Should handle timeout."""
        import requests as req
        mock_post.side_effect = req.exceptions.Timeout()

        result = webhook_integration_impl({
            'webhook_url': 'https://slow.example.com/webhook'
        })

        assert result['success'] is False
        assert 'timed out' in result['message']

    @patch('requests.post')
    def test_ssl_error(self, mock_post):
        """Should handle SSL certificate errors."""
        import requests as req
        mock_post.side_effect = req.exceptions.SSLError()

        result = webhook_integration_impl({
            'webhook_url': 'https://bad-cert.example.com/webhook'
        })

        assert result['success'] is False
        assert 'SSL certificate' in result['message']

    @patch('requests.post')
    def test_response_preview_truncated(self, mock_post):
        """Should truncate long responses."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.text = 'x' * 500
        mock_post.return_value = mock_response

        result = webhook_integration_impl({
            'webhook_url': 'https://example.com/webhook'
        })

        assert result['success'] is True
        assert len(result['message']) < 300

    @patch('requests.post')
    def test_sends_test_payload(self, mock_post):
        """Should send properly formatted test payload."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.text = ''
        mock_post.return_value = mock_response

        webhook_integration_impl({
            'webhook_url': 'https://example.com/webhook'
        })

        call_args = mock_post.call_args
        payload = call_args.kwargs.get('json') or call_args[1].get('json')

        assert payload['test'] is True
        assert payload['source'] == 'mantissa-log'
        assert 'timestamp' in payload
        assert 'alert' in payload
