"""
Mantissa Log - Root Test Configuration

Pytest fixtures and configuration for all tests.
"""

import pytest
import boto3
import json
from pathlib import Path
from moto import mock_s3, mock_athena, mock_glue, mock_dynamodb
from typing import Dict, Any

# Test data directory
FIXTURES_DIR = Path(__file__).parent / 'fixtures'


@pytest.fixture
def sample_cloudtrail_event() -> Dict[str, Any]:
    """Load sample CloudTrail event"""
    with open(FIXTURES_DIR / 'sample_logs' / 'cloudtrail' / 'console_login_success.json') as f:
        return json.load(f)


@pytest.fixture
def sample_cloudtrail_failure() -> Dict[str, Any]:
    """Load sample CloudTrail failure event"""
    with open(FIXTURES_DIR / 'sample_logs' / 'cloudtrail' / 'console_login_failure.json') as f:
        return json.load(f)


@pytest.fixture
def sample_api_call() -> Dict[str, Any]:
    """Load sample API call event"""
    with open(FIXTURES_DIR / 'sample_logs' / 'cloudtrail' / 'api_call.json') as f:
        return json.load(f)


@pytest.fixture
def sample_vpc_flow_accept() -> str:
    """Load sample VPC Flow Log ACCEPT record"""
    with open(FIXTURES_DIR / 'sample_logs' / 'vpc_flow' / 'accept_record.txt') as f:
        return f.read()


@pytest.fixture
def sample_vpc_flow_reject() -> str:
    """Load sample VPC Flow Log REJECT record"""
    with open(FIXTURES_DIR / 'sample_logs' / 'vpc_flow' / 'reject_record.txt') as f:
        return f.read()


@pytest.fixture
def sample_guardduty_finding() -> Dict[str, Any]:
    """Load sample GuardDuty finding"""
    with open(FIXTURES_DIR / 'sample_logs' / 'guardduty' / 'high_severity.json') as f:
        return json.load(f)


@pytest.fixture
def sample_detection_rule() -> Dict[str, Any]:
    """Load sample detection rule"""
    import yaml
    with open(FIXTURES_DIR / 'rules' / 'sample_rule.yaml') as f:
        return yaml.safe_load(f)


@pytest.fixture
def mock_aws_credentials(monkeypatch):
    """Mock AWS credentials for testing"""
    monkeypatch.setenv('AWS_ACCESS_KEY_ID', 'testing')
    monkeypatch.setenv('AWS_SECRET_ACCESS_KEY', 'testing')
    monkeypatch.setenv('AWS_SECURITY_TOKEN', 'testing')
    monkeypatch.setenv('AWS_SESSION_TOKEN', 'testing')
    monkeypatch.setenv('AWS_DEFAULT_REGION', 'us-east-1')


@pytest.fixture
def s3_client(mock_aws_credentials):
    """Mock S3 client"""
    with mock_s3():
        yield boto3.client('s3', region_name='us-east-1')


@pytest.fixture
def athena_client(mock_aws_credentials):
    """Mock Athena client"""
    with mock_athena():
        yield boto3.client('athena', region_name='us-east-1')


@pytest.fixture
def glue_client(mock_aws_credentials):
    """Mock Glue client"""
    with mock_glue():
        yield boto3.client('glue', region_name='us-east-1')


@pytest.fixture
def dynamodb_client(mock_aws_credentials):
    """Mock DynamoDB client"""
    with mock_dynamodb():
        yield boto3.client('dynamodb', region_name='us-east-1')


@pytest.fixture
def test_bucket(s3_client):
    """Create test S3 bucket"""
    bucket_name = 'test-mantissa-log-bucket'
    s3_client.create_bucket(Bucket=bucket_name)
    return bucket_name


@pytest.fixture
def mock_llm_response():
    """Mock LLM API response"""
    return {
        'sql': 'SELECT * FROM cloudtrail WHERE eventname = \'ConsoleLogin\' LIMIT 10',
        'explanation': 'This query retrieves console login events from CloudTrail',
        'warnings': []
    }
