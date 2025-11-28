"""
Mantissa Log - Unit Test Configuration

Pytest fixtures specific to unit tests.
"""

import pytest
from unittest.mock import Mock, MagicMock


@pytest.fixture
def mock_bedrock_client():
    """Mock AWS Bedrock client for LLM operations"""
    client = Mock()
    client.invoke_model.return_value = {
        'body': MagicMock(read=lambda: b'{"completion": "SELECT * FROM cloudtrail LIMIT 10"}')
    }
    return client


@pytest.fixture
def mock_anthropic_client():
    """Mock Anthropic API client"""
    client = Mock()
    client.messages.create.return_value = Mock(
        content=[Mock(text='SELECT * FROM cloudtrail LIMIT 10')]
    )
    return client


@pytest.fixture
def isolated_test_db():
    """Isolated test database"""
    # For unit tests, use in-memory or mock database
    return {
        'tables': {},
        'data': {}
    }


@pytest.fixture
def sample_query_context():
    """Sample query context for testing"""
    return {
        'session_id': 'test-session-123',
        'user_id': 'test-user',
        'history': [],
        'schema': {
            'cloudtrail': {
                'columns': ['eventname', 'eventtime', 'useridentity', 'sourceipaddress']
            }
        }
    }
