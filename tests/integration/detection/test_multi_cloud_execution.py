"""Integration tests for multi-cloud query execution.

These tests verify that the same Sigma rule can be executed on different
cloud providers (AWS Athena, GCP BigQuery, Azure Synapse).
"""

import pytest
from unittest.mock import Mock, MagicMock, patch
from datetime import datetime, timedelta
from src.shared.detection.executors.athena import AthenaQueryExecutor
from src.shared.detection.executors.config import (
    CloudProvider,
    CloudProviderConfig,
    AWSConfig,
    GCPConfig,
    AzureConfig,
    create_executor_from_config
)
from src.shared.detection.engine import DetectionEngine
from src.shared.detection.rule import RuleLoader

# Optional imports - skip tests if not available
try:
    import google.cloud.bigquery
    from src.shared.detection.executors.bigquery import BigQueryExecutor
    HAS_BIGQUERY = True
except ImportError:
    HAS_BIGQUERY = False
    BigQueryExecutor = None

try:
    import pyodbc
    from src.shared.detection.executors.synapse import SynapseExecutor
    HAS_SYNAPSE = True
except ImportError:
    HAS_SYNAPSE = False
    SynapseExecutor = None


pytestmark = pytest.mark.integration


class TestMultiCloudQueryExecution:
    """Test query execution across multiple cloud providers."""

    @patch('boto3.client')
    def test_athena_query_execution(self, mock_boto_client):
        """Test query execution on AWS Athena."""
        # Setup mock
        mock_client = MagicMock()
        mock_boto_client.return_value = mock_client

        mock_client.start_query_execution.return_value = {
            'QueryExecutionId': 'query-123'
        }

        mock_client.get_query_execution.return_value = {
            'QueryExecution': {
                'Status': {'State': 'SUCCEEDED'},
                'Statistics': {'DataScannedInBytes': 1024}
            }
        }

        mock_paginator = MagicMock()
        mock_client.get_paginator.return_value = mock_paginator
        mock_paginator.paginate.return_value = [
            {
                'ResultSet': {
                    'Rows': [
                        {'Data': [{'VarCharValue': 'eventname'}]},
                        {'Data': [{'VarCharValue': 'ConsoleLogin'}]}
                    ]
                }
            }
        ]

        executor = AthenaQueryExecutor(
            database='test_db',
            output_location='s3://bucket/results/'
        )

        result = executor.execute_query("SELECT eventname FROM cloudtrail")

        assert result.row_count == 1
        assert result.data[0]['eventname'] == 'ConsoleLogin'

    @pytest.mark.skipif(not HAS_BIGQUERY, reason="google-cloud-bigquery not installed")
    @patch('google.cloud.bigquery.Client')
    def test_bigquery_query_execution(self, mock_bigquery_client):
        """Test query execution on GCP BigQuery."""
        mock_client = MagicMock()
        mock_bigquery_client.return_value = mock_client

        mock_job = MagicMock()
        mock_job.job_id = 'job-123'
        mock_job.total_bytes_processed = 2048
        mock_client.query.return_value = mock_job

        mock_row = MagicMock()
        mock_row.items.return_value = [('eventname', 'ConsoleLogin')]
        mock_job.result.return_value = [mock_row]

        executor = BigQueryExecutor(
            project_id='test-project',
            dataset='test_dataset'
        )

        with patch.object(executor, '_get_client', return_value=mock_client):
            result = executor.execute_query("SELECT eventname FROM cloudtrail")

        assert result.row_count == 1
        assert result.data[0]['eventname'] == 'ConsoleLogin'

    @pytest.mark.skipif(not HAS_SYNAPSE, reason="pyodbc not installed")
    @patch('pyodbc.connect')
    def test_synapse_query_execution(self, mock_connect):
        """Test query execution on Azure Synapse."""
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_conn.cursor.return_value = mock_cursor
        mock_connect.return_value = mock_conn

        mock_cursor.description = [
            ('eventname', None, None, None, None, None, None)
        ]

        mock_cursor.__iter__ = lambda self: iter([('ConsoleLogin',)])

        executor = SynapseExecutor(
            server='test-synapse.sql.azuresynapse.net',
            database='test_db'
        )

        result = executor.execute_query("SELECT eventname FROM cloudtrail")

        assert result.row_count == 1
        assert result.data[0]['eventname'] == 'ConsoleLogin'


class TestMultiCloudConfigFactory:
    """Test executor creation from configuration."""

    def test_create_aws_executor(self):
        """Test creating AWS executor from config."""
        config = CloudProviderConfig(
            provider=CloudProvider.AWS,
            aws=AWSConfig(
                database='test_db',
                output_location='s3://bucket/results/'
            )
        )

        executor = create_executor_from_config(config)

        assert isinstance(executor, AthenaQueryExecutor)
        assert executor.database == 'test_db'

    @pytest.mark.skipif(not HAS_BIGQUERY, reason="google-cloud-bigquery not installed")
    def test_create_gcp_executor(self):
        """Test creating GCP executor from config."""
        config = CloudProviderConfig(
            provider=CloudProvider.GCP,
            gcp=GCPConfig(
                project_id='test-project',
                dataset='test_dataset'
            )
        )

        executor = create_executor_from_config(config)

        assert isinstance(executor, BigQueryExecutor)
        assert executor.project_id == 'test-project'

    @pytest.mark.skipif(not HAS_SYNAPSE, reason="pyodbc not installed")
    def test_create_azure_executor(self):
        """Test creating Azure executor from config."""
        config = CloudProviderConfig(
            provider=CloudProvider.AZURE,
            azure=AzureConfig(
                server='test-synapse.sql.azuresynapse.net',
                database='test_db'
            )
        )

        executor = create_executor_from_config(config)

        assert isinstance(executor, SynapseExecutor)
        assert executor.server == 'test-synapse.sql.azuresynapse.net'


class TestMultiCloudCostEstimation:
    """Test cost estimation across cloud providers."""

    def test_athena_cost_estimation(self):
        """Test Athena cost estimation."""
        executor = AthenaQueryExecutor(
            database='test_db',
            output_location='s3://bucket/results/'
        )

        cost = executor.get_query_cost_estimate("SELECT * FROM cloudtrail")

        # Should return some positive cost estimate
        assert cost > 0

    @pytest.mark.skipif(not HAS_BIGQUERY, reason="google-cloud-bigquery not installed")
    @patch('google.cloud.bigquery.Client')
    def test_bigquery_cost_estimation(self, mock_bigquery_client):
        """Test BigQuery cost estimation with dry run."""
        mock_client = MagicMock()
        mock_bigquery_client.return_value = mock_client

        mock_job = MagicMock()
        mock_job.total_bytes_processed = 5 * (1024 ** 3)  # 5 GB
        mock_client.query.return_value = mock_job

        executor = BigQueryExecutor(
            project_id='test-project',
            dataset='test_dataset'
        )

        with patch.object(executor, '_get_client', return_value=mock_client):
            cost = executor.get_query_cost_estimate("SELECT * FROM cloudtrail")

        # 5 GB should have measurable cost
        assert cost > 0

    @pytest.mark.skipif(not HAS_SYNAPSE, reason="pyodbc not installed")
    def test_synapse_cost_estimation(self):
        """Test Synapse cost estimation."""
        executor = SynapseExecutor(
            server='test-synapse.sql.azuresynapse.net',
            database='test_db'
        )

        cost = executor.get_query_cost_estimate("SELECT * FROM cloudtrail")

        # Conservative estimate
        assert cost == 0.01


@pytest.mark.skipif(not HAS_BIGQUERY or not HAS_SYNAPSE, reason="google-cloud-bigquery or pyodbc not installed")
class TestMultiCloudValidation:
    """Test query validation across cloud providers."""

    def test_all_providers_reject_dangerous_queries(self):
        """Test that all providers reject dangerous SQL keywords."""
        dangerous_queries = [
            "DROP TABLE cloudtrail",
            "DELETE FROM cloudtrail",
            "UPDATE cloudtrail SET field = 'value'",
            "INSERT INTO cloudtrail VALUES (1, 'test')"
        ]

        # AWS Athena
        athena_executor = AthenaQueryExecutor(
            database='test_db',
            output_location='s3://bucket/results/'
        )

        # GCP BigQuery
        bigquery_executor = BigQueryExecutor(
            project_id='test-project',
            dataset='test_dataset'
        )

        # Azure Synapse
        synapse_executor = SynapseExecutor(
            server='test-synapse.sql.azuresynapse.net',
            database='test_db'
        )

        for query in dangerous_queries:
            assert athena_executor.validate_query(query) is False
            assert bigquery_executor.validate_query(query) is False
            assert synapse_executor.validate_query(query) is False

    def test_all_providers_accept_select_queries(self):
        """Test that all providers accept valid SELECT queries."""
        valid_queries = [
            "SELECT * FROM cloudtrail",
            "SELECT eventname, sourceipaddress FROM cloudtrail WHERE eventtime > '2024-01-01'"
        ]

        athena_executor = AthenaQueryExecutor(
            database='test_db',
            output_location='s3://bucket/results/'
        )

        bigquery_executor = BigQueryExecutor(
            project_id='test-project',
            dataset='test_dataset'
        )

        synapse_executor = SynapseExecutor(
            server='test-synapse.sql.azuresynapse.net',
            database='test_db'
        )

        for query in valid_queries:
            assert athena_executor.validate_query(query) is True
            assert bigquery_executor.validate_query(query) is True
            assert synapse_executor.validate_query(query) is True


class TestMultiCloudConnectionTesting:
    """Test connection testing across cloud providers."""

    @patch('boto3.client')
    def test_athena_connection_test(self, mock_boto_client):
        """Test Athena connection testing."""
        mock_client = MagicMock()
        mock_boto_client.return_value = mock_client

        mock_client.start_query_execution.return_value = {
            'QueryExecutionId': 'test-query'
        }

        executor = AthenaQueryExecutor(
            database='test_db',
            output_location='s3://bucket/results/'
        )

        result = executor.test_connection()

        assert result is True

    @pytest.mark.skipif(not HAS_BIGQUERY, reason="google-cloud-bigquery not installed")
    @patch('google.cloud.bigquery.Client')
    def test_bigquery_connection_test(self, mock_bigquery_client):
        """Test BigQuery connection testing."""
        mock_client = MagicMock()
        mock_bigquery_client.return_value = mock_client

        mock_client.query.return_value = MagicMock()

        executor = BigQueryExecutor(
            project_id='test-project',
            dataset='test_dataset'
        )

        with patch.object(executor, '_get_client', return_value=mock_client):
            result = executor.test_connection()

        assert result is True

    @pytest.mark.skipif(not HAS_SYNAPSE, reason="pyodbc not installed")
    @patch('pyodbc.connect')
    def test_synapse_connection_test(self, mock_connect):
        """Test Synapse connection testing."""
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_conn.cursor.return_value = mock_cursor
        mock_connect.return_value = mock_conn

        executor = SynapseExecutor(
            server='test-synapse.sql.azuresynapse.net',
            database='test_db'
        )

        result = executor.test_connection()

        assert result is True
