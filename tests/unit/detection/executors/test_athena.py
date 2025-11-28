"""Tests for Athena query executor."""

import pytest
from unittest.mock import Mock, MagicMock, patch
from datetime import datetime
from src.shared.detection.executors.athena import AthenaQueryExecutor
from src.shared.detection.executors.base import (
    QueryResult,
    QueryMetrics,
    QueryExecutionError,
    QueryValidationError,
    QueryTimeoutError
)


class TestAthenaQueryExecutorInit:
    """Tests for AthenaQueryExecutor initialization."""

    def test_init_with_defaults(self):
        """Test initialization with default parameters."""
        executor = AthenaQueryExecutor(
            database='test_db',
            output_location='s3://test-bucket/results/'
        )

        assert executor.database == 'test_db'
        assert executor.output_location == 's3://test-bucket/results/'
        assert executor.region == 'us-east-1'
        assert executor.workgroup == 'primary'
        assert executor.client is None

    def test_init_with_custom_values(self):
        """Test initialization with custom parameters."""
        executor = AthenaQueryExecutor(
            database='custom_db',
            output_location='s3://custom-bucket/output/',
            region='us-west-2',
            workgroup='custom-workgroup'
        )

        assert executor.database == 'custom_db'
        assert executor.output_location == 's3://custom-bucket/output/'
        assert executor.region == 'us-west-2'
        assert executor.workgroup == 'custom-workgroup'


class TestAthenaQueryValidation:
    """Tests for query validation."""

    def test_validate_select_query(self):
        """Test validation of valid SELECT query."""
        executor = AthenaQueryExecutor(
            database='test_db',
            output_location='s3://test-bucket/results/'
        )

        valid_queries = [
            "SELECT * FROM cloudtrail",
            "SELECT eventname, sourceipaddress FROM cloudtrail WHERE eventtime > '2024-01-01'",
            "SELECT COUNT(*) as count FROM cloudtrail GROUP BY eventname"
        ]

        for query in valid_queries:
            assert executor.validate_query(query) is True

    def test_reject_non_select_query(self):
        """Test rejection of non-SELECT queries."""
        executor = AthenaQueryExecutor(
            database='test_db',
            output_location='s3://test-bucket/results/'
        )

        invalid_queries = [
            "INSERT INTO cloudtrail VALUES (1, 'test')",
            "UPDATE cloudtrail SET field = 'value'",
            "CREATE TABLE test (id INT)"
        ]

        for query in invalid_queries:
            assert executor.validate_query(query) is False

    def test_reject_dangerous_keywords(self):
        """Test rejection of queries with dangerous keywords."""
        executor = AthenaQueryExecutor(
            database='test_db',
            output_location='s3://test-bucket/results/'
        )

        dangerous_queries = [
            "SELECT * FROM cloudtrail; DROP TABLE cloudtrail;",
            "SELECT * FROM cloudtrail WHERE 1=1; DELETE FROM cloudtrail;",
            "SELECT * FROM cloudtrail UNION ALL EXEC sp_executesql 'DROP DATABASE'"
        ]

        for query in dangerous_queries:
            assert executor.validate_query(query) is False


class TestAthenaQueryExecution:
    """Tests for query execution."""

    @patch('boto3.client')
    def test_execute_query_success(self, mock_boto_client):
        """Test successful query execution."""
        # Setup mock
        mock_client = MagicMock()
        mock_boto_client.return_value = mock_client

        # Mock start_query_execution
        mock_client.start_query_execution.return_value = {
            'QueryExecutionId': 'query-123'
        }

        # Mock get_query_execution (query succeeds)
        mock_client.get_query_execution.return_value = {
            'QueryExecution': {
                'Status': {
                    'State': 'SUCCEEDED'
                },
                'Statistics': {
                    'DataScannedInBytes': 1024 * 1024,  # 1 MB
                    'EngineExecutionTimeInMillis': 500
                }
            }
        }

        # Mock paginated results
        mock_paginator = MagicMock()
        mock_client.get_paginator.return_value = mock_paginator
        mock_paginator.paginate.return_value = [
            {
                'ResultSet': {
                    'Rows': [
                        {
                            'Data': [
                                {'VarCharValue': 'eventname'},
                                {'VarCharValue': 'sourceipaddress'}
                            ]
                        },
                        {
                            'Data': [
                                {'VarCharValue': 'ConsoleLogin'},
                                {'VarCharValue': '1.2.3.4'}
                            ]
                        }
                    ]
                }
            }
        ]

        executor = AthenaQueryExecutor(
            database='test_db',
            output_location='s3://test-bucket/results/'
        )

        result = executor.execute_query("SELECT eventname, sourceipaddress FROM cloudtrail")

        assert isinstance(result, QueryResult)
        assert result.row_count == 1
        assert len(result.data) == 1
        assert result.data[0]['eventname'] == 'ConsoleLogin'
        assert result.data[0]['sourceipaddress'] == '1.2.3.4'
        assert result.bytes_scanned == 1024 * 1024
        assert result.query_id == 'query-123'

    @patch('boto3.client')
    def test_execute_query_validation_error(self, mock_boto_client):
        """Test query execution with validation error."""
        executor = AthenaQueryExecutor(
            database='test_db',
            output_location='s3://test-bucket/results/'
        )

        with pytest.raises(QueryValidationError):
            executor.execute_query("DROP TABLE cloudtrail")

    @patch('boto3.client')
    def test_execute_query_timeout(self, mock_boto_client):
        """Test query execution timeout."""
        mock_client = MagicMock()
        mock_boto_client.return_value = mock_client

        # Mock start_query_execution
        mock_client.start_query_execution.return_value = {
            'QueryExecutionId': 'query-456'
        }

        # Mock get_query_execution (never succeeds)
        mock_client.get_query_execution.return_value = {
            'QueryExecution': {
                'Status': {
                    'State': 'RUNNING'
                },
                'Statistics': {}
            }
        }

        executor = AthenaQueryExecutor(
            database='test_db',
            output_location='s3://test-bucket/results/'
        )

        with pytest.raises(QueryTimeoutError):
            executor.execute_query(
                "SELECT * FROM cloudtrail",
                timeout_seconds=1
            )

    @patch('boto3.client')
    def test_execute_query_failed(self, mock_boto_client):
        """Test query execution failure."""
        mock_client = MagicMock()
        mock_boto_client.return_value = mock_client

        # Mock start_query_execution
        mock_client.start_query_execution.return_value = {
            'QueryExecutionId': 'query-789'
        }

        # Mock get_query_execution (query fails)
        mock_client.get_query_execution.return_value = {
            'QueryExecution': {
                'Status': {
                    'State': 'FAILED',
                    'StateChangeReason': 'Table not found'
                },
                'Statistics': {}
            }
        }

        executor = AthenaQueryExecutor(
            database='test_db',
            output_location='s3://test-bucket/results/'
        )

        with pytest.raises(QueryExecutionError) as exc_info:
            executor.execute_query("SELECT * FROM invalid_table")

        assert 'FAILED' in str(exc_info.value)


class TestAthenaCostEstimation:
    """Tests for cost estimation."""

    def test_get_query_cost_estimate(self):
        """Test query cost estimation."""
        executor = AthenaQueryExecutor(
            database='test_db',
            output_location='s3://test-bucket/results/'
        )

        # Simple estimation: 1GB = $0.005
        cost = executor.get_query_cost_estimate("SELECT * FROM cloudtrail")

        assert isinstance(cost, float)
        assert cost > 0


class TestAthenaTableSchema:
    """Tests for table schema retrieval."""

    @patch('boto3.client')
    def test_get_table_schema(self, mock_boto_client):
        """Test retrieving table schema."""
        mock_client = MagicMock()
        mock_boto_client.return_value = mock_client

        mock_client.get_table_metadata.return_value = {
            'TableMetadata': {
                'Columns': [
                    {'Name': 'eventname', 'Type': 'string'},
                    {'Name': 'eventtime', 'Type': 'timestamp'},
                    {'Name': 'sourceipaddress', 'Type': 'string'}
                ]
            }
        }

        executor = AthenaQueryExecutor(
            database='test_db',
            output_location='s3://test-bucket/results/'
        )

        schema = executor.get_table_schema('test_db', 'cloudtrail')

        assert schema == {
            'eventname': 'string',
            'eventtime': 'timestamp',
            'sourceipaddress': 'string'
        }


class TestAthenaConnection:
    """Tests for connection testing."""

    @patch('boto3.client')
    def test_connection_success(self, mock_boto_client):
        """Test successful connection test."""
        mock_client = MagicMock()
        mock_boto_client.return_value = mock_client

        mock_client.start_query_execution.return_value = {
            'QueryExecutionId': 'test-query-id'
        }

        executor = AthenaQueryExecutor(
            database='test_db',
            output_location='s3://test-bucket/results/'
        )

        result = executor.test_connection()

        assert result is True

    @patch('boto3.client')
    def test_connection_failure(self, mock_boto_client):
        """Test connection failure."""
        mock_client = MagicMock()
        mock_boto_client.return_value = mock_client

        mock_client.start_query_execution.side_effect = Exception("Connection failed")

        executor = AthenaQueryExecutor(
            database='test_db',
            output_location='s3://test-bucket/results/'
        )

        result = executor.test_connection()

        assert result is False
