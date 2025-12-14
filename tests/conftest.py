"""
Mantissa Log - Root Test Configuration

Pytest fixtures and configuration for all tests.
"""

import sys
from pathlib import Path

# Add src directory to Python path for imports
ROOT_DIR = Path(__file__).parent.parent
SRC_DIR = ROOT_DIR / 'src'
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

import pytest
import boto3
import json
from moto import mock_aws
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
    with mock_aws():
        yield boto3.client('s3', region_name='us-east-1')


@pytest.fixture
def athena_client(mock_aws_credentials):
    """Mock Athena client"""
    with mock_aws():
        yield boto3.client('athena', region_name='us-east-1')


@pytest.fixture
def glue_client(mock_aws_credentials):
    """Mock Glue client"""
    with mock_aws():
        yield boto3.client('glue', region_name='us-east-1')


@pytest.fixture
def dynamodb_client(mock_aws_credentials):
    """Mock DynamoDB client"""
    with mock_aws():
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


@pytest.fixture
def sample_executor_configs():
    """Load sample executor configurations"""
    configs = {}

    config_files = {
        'aws': FIXTURES_DIR / 'sample_configs' / 'aws_executor_config.json',
        'gcp': FIXTURES_DIR / 'sample_configs' / 'gcp_executor_config.json',
        'azure': FIXTURES_DIR / 'sample_configs' / 'azure_executor_config.json'
    }

    for provider, config_path in config_files.items():
        if config_path.exists():
            with open(config_path) as f:
                configs[provider] = json.load(f)

    return configs


@pytest.fixture
def sample_sigma_rules_path():
    """Get path to sample Sigma rules"""
    return FIXTURES_DIR / 'sample_sigma_rules'


@pytest.fixture
def sample_query_results():
    """Load sample query result fixtures"""
    results = {}

    result_files = {
        'brute_force': FIXTURES_DIR / 'sample_query_results' / 'athena_brute_force_results.json',
        'privilege_escalation': FIXTURES_DIR / 'sample_query_results' / 'privilege_escalation_results.json'
    }

    for result_type, result_path in result_files.items():
        if result_path.exists():
            with open(result_path) as f:
                results[result_type] = json.load(f)

    return results


@pytest.fixture
def temp_rules_directory(tmp_path):
    """Create temporary directory for test rules"""
    rules_dir = tmp_path / "test_rules"
    rules_dir.mkdir()
    return rules_dir
