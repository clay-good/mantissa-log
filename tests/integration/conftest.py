"""
Mantissa Log - Integration Test Configuration

Pytest fixtures for integration tests with mocked AWS services.
"""

import pytest
import boto3
from moto import mock_aws
from typing import Dict, Any


@pytest.fixture(scope='function')
def aws_integration_env(mock_aws_credentials):
    """Set up full AWS integration environment with moto"""
    with mock_aws():
        yield {
            's3': boto3.client('s3', region_name='us-east-1'),
            'athena': boto3.client('athena', region_name='us-east-1'),
            'glue': boto3.client('glue', region_name='us-east-1'),
            'dynamodb': boto3.client('dynamodb', region_name='us-east-1'),
            'lambda': boto3.client('lambda', region_name='us-east-1'),
        }


@pytest.fixture
def test_glue_database(aws_integration_env):
    """Create test Glue database"""
    glue = aws_integration_env['glue']
    database_name = 'test_mantissa_log'

    glue.create_database(
        DatabaseInput={
            'Name': database_name,
            'Description': 'Test database for Mantissa Log'
        }
    )

    return database_name


@pytest.fixture
def test_glue_tables(aws_integration_env, test_glue_database):
    """Create test Glue tables"""
    glue = aws_integration_env['glue']

    # CloudTrail table
    glue.create_table(
        DatabaseName=test_glue_database,
        TableInput={
            'Name': 'cloudtrail',
            'StorageDescriptor': {
                'Columns': [
                    {'Name': 'eventname', 'Type': 'string'},
                    {'Name': 'eventtime', 'Type': 'timestamp'},
                    {'Name': 'useridentity', 'Type': 'struct<type:string,principalid:string>'},
                    {'Name': 'sourceipaddress', 'Type': 'string'},
                    {'Name': 'errorcode', 'Type': 'string'},
                ],
                'Location': 's3://test-bucket/cloudtrail/',
                'InputFormat': 'org.apache.hadoop.mapred.TextInputFormat',
                'OutputFormat': 'org.apache.hadoop.hive.ql.io.HiveIgnoreKeyTextOutputFormat',
                'SerdeInfo': {
                    'SerializationLibrary': 'org.openx.data.jsonserde.JsonSerDe',
                },
            },
            'PartitionKeys': [
                {'Name': 'year', 'Type': 'string'},
                {'Name': 'month', 'Type': 'string'},
                {'Name': 'day', 'Type': 'string'},
            ],
        }
    )

    # VPC Flow Logs table
    glue.create_table(
        DatabaseName=test_glue_database,
        TableInput={
            'Name': 'vpc_flow_logs',
            'StorageDescriptor': {
                'Columns': [
                    {'Name': 'version', 'Type': 'int'},
                    {'Name': 'account_id', 'Type': 'string'},
                    {'Name': 'interface_id', 'Type': 'string'},
                    {'Name': 'srcaddr', 'Type': 'string'},
                    {'Name': 'dstaddr', 'Type': 'string'},
                    {'Name': 'srcport', 'Type': 'int'},
                    {'Name': 'dstport', 'Type': 'int'},
                    {'Name': 'protocol', 'Type': 'int'},
                    {'Name': 'packets', 'Type': 'bigint'},
                    {'Name': 'bytes', 'Type': 'bigint'},
                    {'Name': 'start_time', 'Type': 'bigint'},
                    {'Name': 'end_time', 'Type': 'bigint'},
                    {'Name': 'action', 'Type': 'string'},
                    {'Name': 'log_status', 'Type': 'string'},
                ],
                'Location': 's3://test-bucket/vpc-flow-logs/',
                'InputFormat': 'org.apache.hadoop.mapred.TextInputFormat',
                'OutputFormat': 'org.apache.hadoop.hive.ql.io.HiveIgnoreKeyTextOutputFormat',
                'SerdeInfo': {
                    'SerializationLibrary': 'org.apache.hadoop.hive.serde2.lazy.LazySimpleSerDe',
                    'Parameters': {
                        'field.delim': ' ',
                        'serialization.format': ' ',
                    },
                },
            },
        }
    )

    return ['cloudtrail', 'vpc_flow_logs']


@pytest.fixture
def test_dynamodb_tables(aws_integration_env):
    """Create test DynamoDB tables"""
    dynamodb = aws_integration_env['dynamodb']

    # Detection state table
    dynamodb.create_table(
        TableName='test-detection-state',
        KeySchema=[
            {'AttributeName': 'rule_id', 'KeyType': 'HASH'},
        ],
        AttributeDefinitions=[
            {'AttributeName': 'rule_id', 'AttributeType': 'S'},
        ],
        BillingMode='PAY_PER_REQUEST',
    )

    # Query sessions table
    dynamodb.create_table(
        TableName='test-query-sessions',
        KeySchema=[
            {'AttributeName': 'session_id', 'KeyType': 'HASH'},
        ],
        AttributeDefinitions=[
            {'AttributeName': 'session_id', 'AttributeType': 'S'},
        ],
        BillingMode='PAY_PER_REQUEST',
    )

    return {
        'detection_state': 'test-detection-state',
        'query_sessions': 'test-query-sessions',
    }


@pytest.fixture
def test_s3_buckets(aws_integration_env):
    """Create test S3 buckets"""
    s3 = aws_integration_env['s3']

    buckets = {
        'logs': 'test-mantissa-logs',
        'rules': 'test-mantissa-rules',
        'query_results': 'test-mantissa-query-results',
    }

    for bucket in buckets.values():
        s3.create_bucket(Bucket=bucket)

    return buckets


@pytest.fixture
def sample_logs_in_s3(aws_integration_env, test_s3_buckets, sample_cloudtrail_event):
    """Upload sample logs to S3"""
    s3 = aws_integration_env['s3']
    import json

    # Upload CloudTrail event
    s3.put_object(
        Bucket=test_s3_buckets['logs'],
        Key='cloudtrail/2024/11/27/test-event.json',
        Body=json.dumps(sample_cloudtrail_event)
    )

    return test_s3_buckets['logs']
