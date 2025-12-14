"""Unit tests for Alerts API handler.

Tests cover:
- List alerts with filtering
- Get single alert
- Acknowledge alert
- Resolve alert
- Bulk operations
- Statistics
- Timeline
- Related alerts
"""

import json
import sys
import os
import importlib
from datetime import datetime, timezone, timedelta
from unittest.mock import patch, MagicMock
from decimal import Decimal
import pytest

# Add shared modules to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../../../src/shared'))


# Sample alert data
def make_alert(
    alert_id: str = 'alert-123',
    rule_id: str = 'rule-001',
    severity: str = 'high',
    status: str = 'new',
    timestamp: str = None
):
    """Create a sample alert."""
    if timestamp is None:
        timestamp = datetime.now(timezone.utc).isoformat()
    return {
        'id': alert_id,
        'rule_id': rule_id,
        'rule_name': 'Test Rule',
        'severity': severity,
        'status': status,
        'title': 'Test Alert',
        'description': 'This is a test alert',
        'timestamp': timestamp,
        'tags': ['test'],
        'metadata': {'result_count': 5}
    }


# Mock DynamoDB table
class MockTable:
    """Mock DynamoDB table for testing."""

    def __init__(self, items=None):
        self.items = items or []
        self._last_key = None

    def scan(self, **kwargs):
        """Mock scan operation."""
        filtered = self.items
        filter_expr = kwargs.get('FilterExpression', '')

        # Very basic filter simulation
        if ':severity' in str(kwargs.get('ExpressionAttributeValues', {})):
            severity = kwargs['ExpressionAttributeValues'].get(':severity')
            if severity:
                filtered = [i for i in filtered if i.get('severity') == severity]

        if ':status' in str(kwargs.get('ExpressionAttributeValues', {})):
            status = kwargs['ExpressionAttributeValues'].get(':status')
            if status:
                filtered = [i for i in filtered if i.get('status') == status]

        return {'Items': filtered}

    def get_item(self, **kwargs):
        """Mock get_item operation."""
        key_id = kwargs.get('Key', {}).get('id')
        for item in self.items:
            if item.get('id') == key_id:
                return {'Item': item}
        return {}

    def update_item(self, **kwargs):
        """Mock update_item operation."""
        key_id = kwargs.get('Key', {}).get('id')
        for item in self.items:
            if item.get('id') == key_id:
                # Simulate update
                if 'acknowledged' in str(kwargs.get('UpdateExpression', '')):
                    item['status'] = 'acknowledged'
                elif 'resolved' in str(kwargs.get('UpdateExpression', '')):
                    item['status'] = 'resolved'
                return {'Attributes': item}
        # Simulate ConditionalCheckFailedException
        raise MockConditionalCheckFailedException()


class MockConditionalCheckFailedException(Exception):
    """Mock exception for conditional check failures."""
    pass


class MockDynamoDB:
    """Mock DynamoDB resource."""

    def __init__(self, table):
        self._table = table
        self.meta = MagicMock()
        self.meta.client.exceptions.ConditionalCheckFailedException = MockConditionalCheckFailedException

    def Table(self, name):
        return self._table


# Test fixtures
@pytest.fixture
def handler_module():
    """Load handler module with mocked dependencies."""
    # Save original modules if they exist
    original_auth = sys.modules.get('auth')
    original_auth_cors = sys.modules.get('auth.cors')

    try:
        # Mock auth module before loading
        mock_auth = MagicMock()
        mock_auth.get_authenticated_user_id = MagicMock(return_value='test-user')
        mock_auth.AuthenticationError = Exception
        mock_cors = MagicMock()
        mock_cors.get_cors_headers = MagicMock(return_value={'Access-Control-Allow-Origin': '*'})
        mock_cors.cors_preflight_response = MagicMock(return_value={
            'statusCode': 200,
            'headers': {'Access-Control-Allow-Origin': '*'},
            'body': ''
        })

        sys.modules['auth'] = mock_auth
        sys.modules['auth.cors'] = mock_cors

        # Load the handler module dynamically (avoiding 'lambda' keyword issues)
        spec = importlib.util.spec_from_file_location(
            "alerts_api_handler",
            os.path.join(os.path.dirname(__file__), '../../../src/aws/lambda/alerts_api_handler.py')
        )
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)

        yield module
    finally:
        # Restore original modules
        if original_auth is not None:
            sys.modules['auth'] = original_auth
        elif 'auth' in sys.modules:
            del sys.modules['auth']

        if original_auth_cors is not None:
            sys.modules['auth.cors'] = original_auth_cors
        elif 'auth.cors' in sys.modules:
            del sys.modules['auth.cors']


@pytest.fixture
def sample_alerts():
    """Create sample alerts."""
    now = datetime.now(timezone.utc)
    return [
        make_alert('alert-1', 'rule-001', 'critical', 'new', (now - timedelta(hours=1)).isoformat()),
        make_alert('alert-2', 'rule-001', 'high', 'acknowledged', (now - timedelta(hours=2)).isoformat()),
        make_alert('alert-3', 'rule-002', 'medium', 'resolved', (now - timedelta(hours=3)).isoformat()),
        make_alert('alert-4', 'rule-003', 'low', 'new', (now - timedelta(hours=4)).isoformat()),
        make_alert('alert-5', 'rule-001', 'high', 'new', (now - timedelta(hours=5)).isoformat()),
    ]


class TestListAlerts:
    """Tests for list alerts endpoint."""

    def test_list_all_alerts(self, handler_module, sample_alerts):
        """Should return all alerts."""
        mock_table = MockTable(sample_alerts)
        handler_module._alerts_table = mock_table

        event = {'httpMethod': 'GET'}
        result = handler_module.handle_list_alerts(event, 'test-user', {})

        assert result['statusCode'] == 200
        body = json.loads(result['body'])
        assert body['total'] == 5
        assert len(body['alerts']) == 5

    def test_filter_by_severity(self, handler_module, sample_alerts):
        """Should filter alerts by severity."""
        mock_table = MockTable(sample_alerts)
        handler_module._alerts_table = mock_table

        event = {'httpMethod': 'GET'}
        result = handler_module.handle_list_alerts(event, 'test-user', {'severity': 'high'})

        assert result['statusCode'] == 200
        body = json.loads(result['body'])
        assert body['total'] == 2
        for alert in body['alerts']:
            assert alert['severity'] == 'high'

    def test_filter_by_status(self, handler_module, sample_alerts):
        """Should filter alerts by status."""
        mock_table = MockTable(sample_alerts)
        handler_module._alerts_table = mock_table

        event = {'httpMethod': 'GET'}
        result = handler_module.handle_list_alerts(event, 'test-user', {'status': 'new'})

        assert result['statusCode'] == 200
        body = json.loads(result['body'])
        assert body['total'] == 3
        for alert in body['alerts']:
            assert alert['status'] == 'new'

    def test_pagination(self, handler_module, sample_alerts):
        """Should paginate results."""
        mock_table = MockTable(sample_alerts)
        handler_module._alerts_table = mock_table

        event = {'httpMethod': 'GET'}
        result = handler_module.handle_list_alerts(event, 'test-user', {'page': '1', 'page_size': '2'})

        assert result['statusCode'] == 200
        body = json.loads(result['body'])
        assert body['total'] == 5
        assert len(body['alerts']) == 2
        assert body['page'] == 1
        assert body['page_size'] == 2
        assert body['total_pages'] == 3


class TestGetAlert:
    """Tests for get single alert endpoint."""

    def test_get_existing_alert(self, handler_module, sample_alerts):
        """Should return alert when found."""
        mock_table = MockTable(sample_alerts)
        handler_module._alerts_table = mock_table

        event = {'httpMethod': 'GET'}
        result = handler_module.handle_get_alert(event, 'test-user', 'alert-1')

        assert result['statusCode'] == 200
        body = json.loads(result['body'])
        assert body['alert']['id'] == 'alert-1'

    def test_get_nonexistent_alert(self, handler_module):
        """Should return 404 for nonexistent alert."""
        mock_table = MockTable([])
        handler_module._alerts_table = mock_table

        event = {'httpMethod': 'GET'}
        result = handler_module.handle_get_alert(event, 'test-user', 'nonexistent')

        assert result['statusCode'] == 404


class TestAcknowledgeAlert:
    """Tests for acknowledge alert endpoint."""

    def test_acknowledge_existing_alert(self, handler_module, sample_alerts):
        """Should acknowledge existing alert."""
        mock_table = MockTable(sample_alerts)
        mock_dynamodb = MockDynamoDB(mock_table)
        handler_module._dynamodb = mock_dynamodb
        handler_module._alerts_table = mock_table

        event = {'httpMethod': 'POST'}
        result = handler_module.handle_acknowledge_alert(event, 'test-user', 'alert-1')

        assert result['statusCode'] == 200
        body = json.loads(result['body'])
        assert body['alert']['status'] == 'acknowledged'
        assert body['message'] == 'Alert acknowledged'

    def test_acknowledge_nonexistent_alert(self, handler_module):
        """Should return 404 for nonexistent alert."""
        mock_table = MockTable([])
        mock_dynamodb = MockDynamoDB(mock_table)
        handler_module._dynamodb = mock_dynamodb
        handler_module._alerts_table = mock_table

        event = {'httpMethod': 'POST'}
        result = handler_module.handle_acknowledge_alert(event, 'test-user', 'nonexistent')

        assert result['statusCode'] == 404


class TestResolveAlert:
    """Tests for resolve alert endpoint."""

    def test_resolve_with_notes(self, handler_module, sample_alerts):
        """Should resolve alert with resolution notes."""
        mock_table = MockTable(sample_alerts)
        mock_dynamodb = MockDynamoDB(mock_table)
        handler_module._dynamodb = mock_dynamodb
        handler_module._alerts_table = mock_table

        event = {'httpMethod': 'POST'}
        result = handler_module.handle_resolve_alert(
            event, 'test-user', 'alert-1',
            {'resolution': 'False positive - expected behavior'}
        )

        assert result['statusCode'] == 200
        body = json.loads(result['body'])
        assert body['alert']['status'] == 'resolved'
        assert body['message'] == 'Alert resolved'

    def test_resolve_without_notes(self, handler_module, sample_alerts):
        """Should resolve alert without resolution notes."""
        mock_table = MockTable(sample_alerts)
        mock_dynamodb = MockDynamoDB(mock_table)
        handler_module._dynamodb = mock_dynamodb
        handler_module._alerts_table = mock_table

        event = {'httpMethod': 'POST'}
        result = handler_module.handle_resolve_alert(event, 'test-user', 'alert-1', {})

        assert result['statusCode'] == 200


class TestBulkOperations:
    """Tests for bulk operations."""

    def test_bulk_acknowledge(self, handler_module, sample_alerts):
        """Should acknowledge multiple alerts."""
        mock_table = MockTable(sample_alerts)
        mock_dynamodb = MockDynamoDB(mock_table)
        handler_module._dynamodb = mock_dynamodb
        handler_module._alerts_table = mock_table

        event = {'httpMethod': 'POST'}
        result = handler_module.handle_bulk_acknowledge(
            event, 'test-user',
            {'alert_ids': ['alert-1', 'alert-4', 'alert-5']}
        )

        assert result['statusCode'] == 200
        body = json.loads(result['body'])
        assert body['acknowledged'] == 3
        assert body['failed'] == 0

    def test_bulk_acknowledge_empty_list(self, handler_module):
        """Should reject empty alert list."""
        mock_table = MockTable([])
        handler_module._alerts_table = mock_table

        event = {'httpMethod': 'POST'}
        result = handler_module.handle_bulk_acknowledge(event, 'test-user', {'alert_ids': []})

        assert result['statusCode'] == 400

    def test_bulk_acknowledge_limit(self, handler_module):
        """Should reject more than 100 alerts."""
        mock_table = MockTable([])
        handler_module._alerts_table = mock_table

        event = {'httpMethod': 'POST'}
        result = handler_module.handle_bulk_acknowledge(
            event, 'test-user',
            {'alert_ids': [f'alert-{i}' for i in range(101)]}
        )

        assert result['statusCode'] == 400

    def test_bulk_resolve(self, handler_module, sample_alerts):
        """Should resolve multiple alerts."""
        mock_table = MockTable(sample_alerts)
        mock_dynamodb = MockDynamoDB(mock_table)
        handler_module._dynamodb = mock_dynamodb
        handler_module._alerts_table = mock_table

        event = {'httpMethod': 'POST'}
        result = handler_module.handle_bulk_resolve(
            event, 'test-user',
            {'alert_ids': ['alert-1', 'alert-2'], 'resolution': 'Bulk resolved'}
        )

        assert result['statusCode'] == 200
        body = json.loads(result['body'])
        assert body['resolved'] == 2


class TestAlertStats:
    """Tests for alert statistics endpoint."""

    def test_get_stats(self, handler_module, sample_alerts):
        """Should return alert statistics."""
        mock_table = MockTable(sample_alerts)
        handler_module._alerts_table = mock_table

        event = {'httpMethod': 'GET'}
        result = handler_module.handle_alert_stats(event, 'test-user', {})

        assert result['statusCode'] == 200
        body = json.loads(result['body'])
        assert 'stats' in body
        assert body['stats']['total'] == 5
        assert 'by_severity' in body['stats']
        assert 'by_status' in body['stats']

    def test_stats_by_severity(self, handler_module, sample_alerts):
        """Should count alerts by severity."""
        mock_table = MockTable(sample_alerts)
        handler_module._alerts_table = mock_table

        event = {'httpMethod': 'GET'}
        result = handler_module.handle_alert_stats(event, 'test-user', {})

        body = json.loads(result['body'])
        assert body['stats']['by_severity']['critical'] == 1
        assert body['stats']['by_severity']['high'] == 2
        assert body['stats']['by_severity']['medium'] == 1
        assert body['stats']['by_severity']['low'] == 1


class TestAlertTimeline:
    """Tests for alert timeline endpoint."""

    def test_get_timeline(self, handler_module, sample_alerts):
        """Should return alert timeline data."""
        mock_table = MockTable(sample_alerts)
        handler_module._alerts_table = mock_table

        now = datetime.now(timezone.utc)
        start = (now - timedelta(days=1)).isoformat()
        end = now.isoformat()

        event = {'httpMethod': 'GET'}
        result = handler_module.handle_alert_timeline(
            event, 'test-user',
            {'start_time': start, 'end_time': end, 'interval': '6h'}
        )

        assert result['statusCode'] == 200
        body = json.loads(result['body'])
        assert 'timeline' in body
        assert isinstance(body['timeline'], list)


class TestRelatedAlerts:
    """Tests for related alerts endpoint."""

    def test_find_related_by_rule(self, handler_module, sample_alerts):
        """Should find related alerts by rule ID."""
        mock_table = MockTable(sample_alerts)
        handler_module._alerts_table = mock_table

        event = {'httpMethod': 'GET'}
        result = handler_module.handle_related_alerts(event, 'test-user', 'alert-1')

        assert result['statusCode'] == 200
        body = json.loads(result['body'])
        assert 'related_alerts' in body
        assert body['count'] >= 0

    def test_related_nonexistent_alert(self, handler_module):
        """Should return 404 for nonexistent source alert."""
        mock_table = MockTable([])
        handler_module._alerts_table = mock_table

        event = {'httpMethod': 'GET'}
        result = handler_module.handle_related_alerts(event, 'test-user', 'nonexistent')

        assert result['statusCode'] == 404


class TestLambdaHandler:
    """Tests for main lambda handler routing."""

    def test_cors_preflight(self, handler_module):
        """Should handle CORS preflight requests."""
        event = {'httpMethod': 'OPTIONS', 'path': '/alerts'}
        result = handler_module.lambda_handler(event, None)

        assert result['statusCode'] == 200

    def test_authentication_required(self, handler_module):
        """Should require authentication."""
        # Override auth mock to raise error
        handler_module.get_authenticated_user_id = MagicMock(
            side_effect=handler_module.AuthenticationError('Not authenticated')
        )
        handler_module._alerts_table = MockTable([])

        event = {'httpMethod': 'GET', 'path': '/alerts'}
        result = handler_module.lambda_handler(event, None)

        assert result['statusCode'] == 401

    def test_route_list_alerts(self, handler_module):
        """Should route to list alerts handler."""
        handler_module._alerts_table = MockTable([])
        handler_module.get_authenticated_user_id = MagicMock(return_value='user')

        event = {'httpMethod': 'GET', 'path': '/alerts', 'queryStringParameters': {}}
        result = handler_module.lambda_handler(event, None)

        assert result['statusCode'] == 200

    def test_route_get_alert(self, handler_module, sample_alerts):
        """Should route to get alert handler."""
        handler_module._alerts_table = MockTable(sample_alerts)
        handler_module.get_authenticated_user_id = MagicMock(return_value='user')

        event = {'httpMethod': 'GET', 'path': '/alerts/alert-1'}
        result = handler_module.lambda_handler(event, None)

        assert result['statusCode'] == 200

    def test_route_not_found(self, handler_module):
        """Should return 404 for unknown routes."""
        handler_module._alerts_table = MockTable([])
        handler_module.get_authenticated_user_id = MagicMock(return_value='user')

        event = {'httpMethod': 'GET', 'path': '/unknown'}
        result = handler_module.lambda_handler(event, None)

        assert result['statusCode'] == 404


class TestDecimalEncoder:
    """Tests for Decimal JSON encoder."""

    def test_encodes_decimal(self, handler_module):
        """Should encode Decimal values as floats."""
        data = {'value': Decimal('123.45')}
        result = json.dumps(data, cls=handler_module.DecimalEncoder)
        parsed = json.loads(result)

        assert parsed['value'] == 123.45
        assert isinstance(parsed['value'], float)
