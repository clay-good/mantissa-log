"""Tests for BigQuery executor."""

import pytest
from unittest.mock import Mock, MagicMock, patch
from datetime import datetime
from src.shared.detection.executors.bigquery import BigQueryExecutor
from src.shared.detection.executors.base import (
    QueryResult,
    QueryMetrics,
    QueryExecutionError,
    QueryValidationError,
    QueryTimeoutError
)


class TestBigQueryExecutorInit:
    """Tests for BigQueryExecutor initialization."""

    def test_init_with_defaults(self):
        """Test initialization with default parameters."""
        executor = BigQueryExecutor(
            project_id='test-project',
            dataset='test_dataset'
        )

        assert executor.project_id == 'test-project'
        assert executor.dataset == 'test_dataset'
        assert executor.location == 'US'
        assert executor.client is None

    def test_init_with_custom_location(self):
        """Test initialization with custom location."""
        executor = BigQueryExecutor(
            project_id='test-project',
            dataset='test_dataset',
            location='EU'
        )

        assert executor.location == 'EU'


class TestBigQueryValidation:
    """Tests for query validation."""

    def test_validate_select_query(self):
        """Test validation of valid SELECT query."""
        executor = BigQueryExecutor(
            project_id='test-project',
            dataset='test_dataset'
        )

        valid_queries = [
            "SELECT * FROM cloudtrail",
            "SELECT eventname, sourceipaddress FROM cloudtrail WHERE eventtime > TIMESTAMP('2024-01-01')",
            "SELECT COUNT(*) as count FROM cloudtrail GROUP BY eventname"
        ]

        for query in valid_queries:
            assert executor.validate_query(query) is True

    def test_reject_dangerous_keywords(self):
        """Test rejection of queries with dangerous keywords."""
        executor = BigQueryExecutor(
            project_id='test-project',
            dataset='test_dataset'
        )

        dangerous_queries = [
            "DROP TABLE cloudtrail",
            "DELETE FROM cloudtrail",
            "INSERT INTO cloudtrail VALUES (1, 'test')",
            "UPDATE cloudtrail SET field = 'value'",
            "CREATE TABLE test (id INT64)"
        ]

        for query in dangerous_queries:
            assert executor.validate_query(query) is False


class TestBigQueryExecution:
    """Tests for query execution."""

    @patch('google.cloud.bigquery.Client')
    def test_execute_query_success(self, mock_bigquery_client):
        """Test successful query execution."""
        # Setup mock
        mock_client = MagicMock()
        mock_bigquery_client.return_value = mock_client

        # Mock query job
        mock_job = MagicMock()
        mock_job.job_id = 'job-123'
        mock_job.total_bytes_processed = 1024 * 1024  # 1 MB
        mock_client.query.return_value = mock_job

        # Mock results
        mock_row = MagicMock()
        mock_row.items.return_value = [
            ('eventname', 'ConsoleLogin'),
            ('sourceipaddress', '1.2.3.4')
        ]
        mock_job.result.return_value = [mock_row]

        executor = BigQueryExecutor(
            project_id='test-project',
            dataset='test_dataset'
        )

        with patch.object(executor, '_get_client', return_value=mock_client):
            result = executor.execute_query("SELECT eventname, sourceipaddress FROM cloudtrail")

        assert isinstance(result, QueryResult)
        assert result.row_count == 1
        assert len(result.data) == 1
        assert result.data[0]['eventname'] == 'ConsoleLogin'
        assert result.bytes_scanned == 1024 * 1024
        assert result.query_id == 'job-123'

    @patch('google.cloud.bigquery.Client')
    def test_execute_query_validation_error(self, mock_bigquery_client):
        """Test query execution with validation error."""
        executor = BigQueryExecutor(
            project_id='test-project',
            dataset='test_dataset'
        )

        with pytest.raises(QueryValidationError):
            executor.execute_query("DROP TABLE cloudtrail")

    @patch('google.cloud.bigquery.Client')
    def test_execute_query_timeout(self, mock_bigquery_client):
        """Test query execution timeout."""
        mock_client = MagicMock()
        mock_bigquery_client.return_value = mock_client

        mock_job = MagicMock()
        mock_client.query.return_value = mock_job

        # Mock timeout exception
        mock_job.result.side_effect = Exception("timeout exceeded")

        executor = BigQueryExecutor(
            project_id='test-project',
            dataset='test_dataset'
        )

        with patch.object(executor, '_get_client', return_value=mock_client):
            with pytest.raises(QueryTimeoutError):
                executor.execute_query("SELECT * FROM cloudtrail", timeout_seconds=1)

    @patch('google.cloud.bigquery.Client')
    def test_execute_query_with_max_results(self, mock_bigquery_client):
        """Test query execution with max results limit."""
        mock_client = MagicMock()
        mock_bigquery_client.return_value = mock_client

        mock_job = MagicMock()
        mock_job.job_id = 'job-456'
        mock_job.total_bytes_processed = 2048
        mock_client.query.return_value = mock_job

        # Mock multiple rows
        mock_rows = []
        for i in range(5):
            mock_row = MagicMock()
            mock_row.items.return_value = [('id', i), ('name', f'test{i}')]
            mock_rows.append(mock_row)

        mock_job.result.return_value = mock_rows

        executor = BigQueryExecutor(
            project_id='test-project',
            dataset='test_dataset'
        )

        with patch.object(executor, '_get_client', return_value=mock_client):
            result = executor.execute_query("SELECT * FROM test", max_results=5)

        assert result.row_count == 5


class TestBigQueryCostEstimation:
    """Tests for cost estimation."""

    @patch('google.cloud.bigquery.Client')
    def test_get_query_cost_estimate(self, mock_bigquery_client):
        """Test query cost estimation using dry run."""
        mock_client = MagicMock()
        mock_bigquery_client.return_value = mock_client

        # Mock dry run query
        mock_job = MagicMock()
        mock_job.total_bytes_processed = 5 * (1024 ** 3)  # 5 GB
        mock_client.query.return_value = mock_job

        executor = BigQueryExecutor(
            project_id='test-project',
            dataset='test_dataset'
        )

        with patch.object(executor, '_get_client', return_value=mock_client):
            cost = executor.get_query_cost_estimate("SELECT * FROM large_table")

        # 5 GB / 1 TB * $5 = $0.025
        expected_cost = (5 * (1024 ** 3) / (1024 ** 4)) * 5.0
        assert cost == pytest.approx(expected_cost, rel=1e-6)

    @patch('google.cloud.bigquery.Client')
    def test_get_query_cost_estimate_fallback(self, mock_bigquery_client):
        """Test cost estimation fallback on error."""
        mock_client = MagicMock()
        mock_bigquery_client.return_value = mock_client

        # Mock dry run failure
        mock_client.query.side_effect = Exception("Dry run failed")

        executor = BigQueryExecutor(
            project_id='test-project',
            dataset='test_dataset'
        )

        with patch.object(executor, '_get_client', return_value=mock_client):
            cost = executor.get_query_cost_estimate("SELECT * FROM test")

        # Should return fallback estimate
        assert cost == 0.01


class TestBigQueryMetrics:
    """Tests for query metrics retrieval."""

    @patch('google.cloud.bigquery.Client')
    def test_get_query_metrics(self, mock_bigquery_client):
        """Test retrieving query metrics."""
        mock_client = MagicMock()
        mock_bigquery_client.return_value = mock_client

        # Mock job retrieval
        mock_job = MagicMock()
        mock_job.job_id = 'job-123'
        mock_job.query = 'SELECT * FROM test'
        mock_job.state = 'DONE'
        mock_job.started = datetime(2024, 1, 1, 12, 0, 0)
        mock_job.ended = datetime(2024, 1, 1, 12, 0, 5)
        mock_job.total_bytes_processed = 1024 * 1024
        mock_job.total_rows = 100
        mock_job.errors = None

        mock_client.get_job.return_value = mock_job

        executor = BigQueryExecutor(
            project_id='test-project',
            dataset='test_dataset'
        )

        with patch.object(executor, '_get_client', return_value=mock_client):
            metrics = executor.get_query_metrics('job-123')

        assert isinstance(metrics, QueryMetrics)
        assert metrics.query_id == 'job-123'
        assert metrics.query == 'SELECT * FROM test'
        assert metrics.status == 'DONE'
        assert metrics.bytes_scanned == 1024 * 1024
        assert metrics.rows_returned == 100


class TestBigQueryTableSchema:
    """Tests for table schema retrieval."""

    @patch('google.cloud.bigquery.Client')
    def test_get_table_schema(self, mock_bigquery_client):
        """Test retrieving table schema."""
        mock_client = MagicMock()
        mock_bigquery_client.return_value = mock_client

        # Mock table metadata
        mock_field1 = MagicMock()
        mock_field1.name = 'eventname'
        mock_field1.field_type = 'STRING'

        mock_field2 = MagicMock()
        mock_field2.name = 'eventtime'
        mock_field2.field_type = 'TIMESTAMP'

        mock_table = MagicMock()
        mock_table.schema = [mock_field1, mock_field2]

        mock_client.get_table.return_value = mock_table

        executor = BigQueryExecutor(
            project_id='test-project',
            dataset='test_dataset'
        )

        with patch.object(executor, '_get_client', return_value=mock_client):
            schema = executor.get_table_schema('test_dataset', 'cloudtrail')

        assert schema == {
            'eventname': 'STRING',
            'eventtime': 'TIMESTAMP'
        }


class TestBigQueryConnection:
    """Tests for connection testing."""

    @patch('google.cloud.bigquery.Client')
    def test_connection_success(self, mock_bigquery_client):
        """Test successful connection test."""
        mock_client = MagicMock()
        mock_bigquery_client.return_value = mock_client

        # Mock successful dry run
        mock_client.query.return_value = MagicMock()

        executor = BigQueryExecutor(
            project_id='test-project',
            dataset='test_dataset'
        )

        with patch.object(executor, '_get_client', return_value=mock_client):
            result = executor.test_connection()

        assert result is True

    @patch('google.cloud.bigquery.Client')
    def test_connection_failure(self, mock_bigquery_client):
        """Test connection failure."""
        mock_client = MagicMock()
        mock_bigquery_client.return_value = mock_client

        # Mock connection failure
        mock_client.query.side_effect = Exception("Connection failed")

        executor = BigQueryExecutor(
            project_id='test-project',
            dataset='test_dataset'
        )

        with patch.object(executor, '_get_client', return_value=mock_client):
            result = executor.test_connection()

        assert result is False


class TestBigQueryCancelQuery:
    """Tests for query cancellation."""

    @patch('google.cloud.bigquery.Client')
    def test_cancel_query_success(self, mock_bigquery_client):
        """Test successful query cancellation."""
        mock_client = MagicMock()
        mock_bigquery_client.return_value = mock_client

        mock_job = MagicMock()
        mock_client.get_job.return_value = mock_job

        executor = BigQueryExecutor(
            project_id='test-project',
            dataset='test_dataset'
        )

        with patch.object(executor, '_get_client', return_value=mock_client):
            result = executor.cancel_query('job-123')

        assert result is True
        mock_job.cancel.assert_called_once()

    @patch('google.cloud.bigquery.Client')
    def test_cancel_query_failure(self, mock_bigquery_client):
        """Test query cancellation failure."""
        mock_client = MagicMock()
        mock_bigquery_client.return_value = mock_client

        mock_client.get_job.side_effect = Exception("Job not found")

        executor = BigQueryExecutor(
            project_id='test-project',
            dataset='test_dataset'
        )

        with patch.object(executor, '_get_client', return_value=mock_client):
            result = executor.cancel_query('invalid-job-id')

        assert result is False
