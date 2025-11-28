"""
Integration tests for AWS Glue catalog operations
"""

import pytest


@pytest.mark.integration
@pytest.mark.aws
def test_database_creation(aws_integration_env):
    """Test Glue database creation"""
    glue = aws_integration_env['glue']

    database_name = 'test_integration_db'

    # Create database
    glue.create_database(
        DatabaseInput={
            'Name': database_name,
            'Description': 'Test database'
        }
    )

    # Verify database exists
    response = glue.get_database(Name=database_name)
    assert response['Database']['Name'] == database_name


@pytest.mark.integration
@pytest.mark.aws
def test_table_creation(test_glue_database, aws_integration_env):
    """Test Glue table creation"""
    glue = aws_integration_env['glue']

    table_name = 'test_table'

    # Create table
    glue.create_table(
        DatabaseName=test_glue_database,
        TableInput={
            'Name': table_name,
            'StorageDescriptor': {
                'Columns': [
                    {'Name': 'id', 'Type': 'string'},
                    {'Name': 'timestamp', 'Type': 'timestamp'},
                ],
                'Location': 's3://test-bucket/data/',
                'InputFormat': 'org.apache.hadoop.mapred.TextInputFormat',
                'OutputFormat': 'org.apache.hadoop.hive.ql.io.HiveIgnoreKeyTextOutputFormat',
                'SerdeInfo': {
                    'SerializationLibrary': 'org.openx.data.jsonserde.JsonSerDe',
                },
            },
        }
    )

    # Verify table exists
    response = glue.get_table(DatabaseName=test_glue_database, Name=table_name)
    assert response['Table']['Name'] == table_name


@pytest.mark.integration
@pytest.mark.aws
def test_partition_management(test_glue_database, aws_integration_env):
    """Test partition creation and management"""
    glue = aws_integration_env['glue']

    table_name = 'partitioned_table'

    # Create partitioned table
    glue.create_table(
        DatabaseName=test_glue_database,
        TableInput={
            'Name': table_name,
            'StorageDescriptor': {
                'Columns': [
                    {'Name': 'event', 'Type': 'string'},
                ],
                'Location': 's3://test-bucket/partitioned/',
                'InputFormat': 'org.apache.hadoop.mapred.TextInputFormat',
                'OutputFormat': 'org.apache.hadoop.hive.ql.io.HiveIgnoreKeyTextOutputFormat',
                'SerdeInfo': {
                    'SerializationLibrary': 'org.openx.data.jsonserde.JsonSerDe',
                },
            },
            'PartitionKeys': [
                {'Name': 'year', 'Type': 'string'},
                {'Name': 'month', 'Type': 'string'},
            ],
        }
    )

    # Create partition
    glue.create_partition(
        DatabaseName=test_glue_database,
        TableName=table_name,
        PartitionInput={
            'Values': ['2024', '11'],
            'StorageDescriptor': {
                'Columns': [
                    {'Name': 'event', 'Type': 'string'},
                ],
                'Location': 's3://test-bucket/partitioned/year=2024/month=11/',
                'InputFormat': 'org.apache.hadoop.mapred.TextInputFormat',
                'OutputFormat': 'org.apache.hadoop.hive.ql.io.HiveIgnoreKeyTextOutputFormat',
                'SerdeInfo': {
                    'SerializationLibrary': 'org.openx.data.jsonserde.JsonSerDe',
                },
            },
        }
    )

    # Verify partition exists
    partitions = glue.get_partitions(DatabaseName=test_glue_database, TableName=table_name)
    assert len(partitions['Partitions']) == 1
    assert partitions['Partitions'][0]['Values'] == ['2024', '11']


@pytest.mark.integration
@pytest.mark.aws
def test_schema_verification(test_glue_tables, test_glue_database, aws_integration_env):
    """Test that created tables have correct schema"""
    glue = aws_integration_env['glue']

    # Verify CloudTrail table schema
    cloudtrail_table = glue.get_table(DatabaseName=test_glue_database, Name='cloudtrail')

    columns = cloudtrail_table['Table']['StorageDescriptor']['Columns']
    column_names = [col['Name'] for col in columns]

    assert 'eventname' in column_names
    assert 'eventtime' in column_names
    assert 'useridentity' in column_names
    assert 'sourceipaddress' in column_names
