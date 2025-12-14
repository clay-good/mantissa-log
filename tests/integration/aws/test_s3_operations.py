"""
Integration tests for S3 operations
"""

import pytest
import json


@pytest.mark.integration
@pytest.mark.aws
def test_log_storage(aws_integration_env, test_s3_buckets, sample_cloudtrail_event):
    """Test storing logs in S3"""
    s3 = aws_integration_env['s3']

    # Upload log file
    key = 'cloudtrail/2024/11/27/event1.json'
    s3.put_object(
        Bucket=test_s3_buckets['logs'],
        Key=key,
        Body=json.dumps(sample_cloudtrail_event)
    )

    # Verify file exists
    response = s3.head_object(Bucket=test_s3_buckets['logs'], Key=key)
    assert response['ContentLength'] > 0


@pytest.mark.integration
@pytest.mark.aws
def test_rule_storage(aws_integration_env, test_s3_buckets, sample_detection_rule):
    """Test storing rules in S3"""
    s3 = aws_integration_env['s3']
    import yaml

    # Upload rule file
    key = 'rules/test_rule.yaml'
    s3.put_object(
        Bucket=test_s3_buckets['rules'],
        Key=key,
        Body=yaml.dump(sample_detection_rule)
    )

    # Retrieve and verify
    response = s3.get_object(Bucket=test_s3_buckets['rules'], Key=key)
    content = response['Body'].read().decode('utf-8')
    rule = yaml.safe_load(content)

    assert rule['name'] == sample_detection_rule['name']
    assert rule['severity'] == sample_detection_rule['severity']


@pytest.mark.integration
@pytest.mark.aws
def test_lifecycle_policy(aws_integration_env, test_s3_buckets):
    """Test S3 lifecycle policy application"""
    s3 = aws_integration_env['s3']

    # Set lifecycle policy
    lifecycle_config = {
        'Rules': [
            {
                'ID': 'archive-old-logs',  # AWS uses 'ID' not 'Id'
                'Status': 'Enabled',
                'Filter': {'Prefix': 'cloudtrail/'},  # Use Filter instead of Prefix
                'Transitions': [
                    {
                        'Days': 90,
                        'StorageClass': 'GLACIER'
                    }
                ],
                'Expiration': {
                    'Days': 365
                }
            }
        ]
    }

    s3.put_bucket_lifecycle_configuration(
        Bucket=test_s3_buckets['logs'],
        LifecycleConfiguration=lifecycle_config
    )

    # Verify lifecycle policy
    response = s3.get_bucket_lifecycle_configuration(Bucket=test_s3_buckets['logs'])
    assert len(response['Rules']) == 1
    assert response['Rules'][0]['ID'] == 'archive-old-logs'


@pytest.mark.integration
@pytest.mark.aws
def test_list_logs_by_prefix(sample_logs_in_s3, aws_integration_env):
    """Test listing logs by prefix"""
    s3 = aws_integration_env['s3']

    # List objects with prefix
    response = s3.list_objects_v2(
        Bucket=sample_logs_in_s3,
        Prefix='cloudtrail/2024/11/'
    )

    assert 'Contents' in response
    assert len(response['Contents']) > 0
