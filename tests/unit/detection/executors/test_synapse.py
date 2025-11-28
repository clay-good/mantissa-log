"""Tests for Azure Synapse executor."""

import pytest
from unittest.mock import Mock, MagicMock, patch
from datetime import datetime
from src.shared.detection.executors.synapse import SynapseExecutor
from src.shared.detection.executors.base import (
    QueryResult,
    QueryMetrics,
    QueryExecutionError,
    QueryValidationError,
    QueryTimeoutError
)


class TestSynapseExecutorInit:
    """Tests for SynapseExecutor initialization."""

    def test_init_with_managed_identity(self):
        """Test initialization with managed identity."""
        executor = SynapseExecutor(
            server='test-synapse.sql.azuresynapse.net',
            database='test_db'
        )

        assert executor.server == 'test-synapse.sql.azuresynapse.net'
        assert executor.database == 'test_db'
        assert executor.use_managed_identity is True
        assert executor.username is None
        assert executor.password is None
        assert executor.connection is None

    def test_init_with_sql_auth(self):
        """Test initialization with SQL authentication."""
        executor = SynapseExecutor(
            server='test-synapse.sql.azuresynapse.net',
            database='test_db',
            username='admin',
            password='password123',
            use_managed_identity=False
        )

        assert executor.use_managed_identity is False
        assert executor.username == 'admin'
        assert executor.password == 'password123'


class TestSynapseValidation:
    """Tests for query validation."""

    def test_validate_select_query(self):
        """Test validation of valid SELECT query."""
        executor = SynapseExecutor(
            server='test-synapse.sql.azuresynapse.net',
            database='test_db'
        )

        valid_queries = [
            "SELECT * FROM cloudtrail",
            "SELECT eventname, sourceipaddress FROM cloudtrail WHERE eventtime > '2024-01-01'",
            "SELECT COUNT(*) as count FROM cloudtrail GROUP BY eventname"
        ]

        for query in valid_queries:
            assert executor.validate_query(query) is True

    def test_reject_dangerous_keywords(self):
        """Test rejection of queries with dangerous keywords."""
        executor = SynapseExecutor(
            server='test-synapse.sql.azuresynapse.net',
            database='test_db'
        )

        dangerous_queries = [
            "DROP TABLE cloudtrail",
            "DELETE FROM cloudtrail",
            "INSERT INTO cloudtrail VALUES (1, 'test')",
            "UPDATE cloudtrail SET field = 'value'",
            "CREATE TABLE test (id INT)",
            "EXEC sp_executesql 'DROP DATABASE test'"
        ]

        for query in dangerous_queries:
            assert executor.validate_query(query) is False


class TestSynapseConnection:
    """Tests for connection management."""

    @patch('pyodbc.connect')
    def test_get_connection_managed_identity(self, mock_connect):
        """Test connection with managed identity."""
        mock_conn = MagicMock()
        mock_connect.return_value = mock_conn

        executor = SynapseExecutor(
            server='test-synapse.sql.azuresynapse.net',
            database='test_db',
            use_managed_identity=True
        )

        conn = executor._get_connection()

        assert conn is mock_conn
        # Verify connection string contains managed identity auth
        call_args = mock_connect.call_args[0][0]
        assert 'Authentication=ActiveDirectoryMsi' in call_args

    @patch('pyodbc.connect')
    def test_get_connection_sql_auth(self, mock_connect):
        """Test connection with SQL authentication."""
        mock_conn = MagicMock()
        mock_connect.return_value = mock_conn

        executor = SynapseExecutor(
            server='test-synapse.sql.azuresynapse.net',
            database='test_db',
            username='admin',
            password='password123',
            use_managed_identity=False
        )

        conn = executor._get_connection()

        assert conn is mock_conn
        call_args = mock_connect.call_args[0][0]
        assert 'UID=admin' in call_args
        assert 'PWD=password123' in call_args

    @patch('pyodbc.connect')
    def test_connection_reuse(self, mock_connect):
        """Test connection is reused across calls."""
        mock_conn = MagicMock()
        mock_connect.return_value = mock_conn

        executor = SynapseExecutor(
            server='test-synapse.sql.azuresynapse.net',
            database='test_db'
        )

        conn1 = executor._get_connection()
        conn2 = executor._get_connection()

        assert conn1 is conn2
        # Should only connect once
        assert mock_connect.call_count == 1


class TestSynapseExecution:
    """Tests for query execution."""

    @patch('pyodbc.connect')
    def test_execute_query_success(self, mock_connect):
        """Test successful query execution."""
        # Setup mock connection
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_conn.cursor.return_value = mock_cursor
        mock_connect.return_value = mock_conn

        # Mock cursor description (column names)
        mock_cursor.description = [
            ('eventname', None, None, None, None, None, None),
            ('sourceipaddress', None, None, None, None, None, None)
        ]

        # Mock result rows
        mock_cursor.__iter__ = lambda self: iter([
            ('ConsoleLogin', '1.2.3.4'),
            ('AssumeRole', '5.6.7.8')
        ])

        executor = SynapseExecutor(
            server='test-synapse.sql.azuresynapse.net',
            database='test_db'
        )

        result = executor.execute_query("SELECT eventname, sourceipaddress FROM cloudtrail")

        assert isinstance(result, QueryResult)
        assert result.row_count == 2
        assert len(result.data) == 2
        assert result.data[0]['eventname'] == 'ConsoleLogin'
        assert result.data[0]['sourceipaddress'] == '1.2.3.4'
        assert result.data[1]['eventname'] == 'AssumeRole'

    @patch('pyodbc.connect')
    def test_execute_query_validation_error(self, mock_connect):
        """Test query execution with validation error."""
        executor = SynapseExecutor(
            server='test-synapse.sql.azuresynapse.net',
            database='test_db'
        )

        with pytest.raises(QueryValidationError):
            executor.execute_query("DROP TABLE cloudtrail")

    @patch('pyodbc.connect')
    def test_execute_query_with_max_results(self, mock_connect):
        """Test query execution with max results limit."""
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_conn.cursor.return_value = mock_cursor
        mock_connect.return_value = mock_conn

        mock_cursor.description = [
            ('id', None, None, None, None, None, None)
        ]

        # Mock 10 rows
        mock_cursor.__iter__ = lambda self: iter([(i,) for i in range(10)])

        executor = SynapseExecutor(
            server='test-synapse.sql.azuresynapse.net',
            database='test_db'
        )

        result = executor.execute_query("SELECT id FROM test", max_results=5)

        # Should only return 5 rows
        assert result.row_count == 5

    @patch('pyodbc.connect')
    def test_execute_query_error(self, mock_connect):
        """Test query execution error."""
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_conn.cursor.return_value = mock_cursor
        mock_connect.return_value = mock_conn

        # Mock query execution error
        mock_cursor.execute.side_effect = Exception("Table not found")

        executor = SynapseExecutor(
            server='test-synapse.sql.azuresynapse.net',
            database='test_db'
        )

        with pytest.raises(QueryExecutionError):
            executor.execute_query("SELECT * FROM invalid_table")


class TestSynapseCostEstimation:
    """Tests for cost estimation."""

    def test_get_query_cost_estimate(self):
        """Test query cost estimation."""
        executor = SynapseExecutor(
            server='test-synapse.sql.azuresynapse.net',
            database='test_db'
        )

        # Synapse uses DWU-based pricing, difficult to estimate
        cost = executor.get_query_cost_estimate("SELECT * FROM cloudtrail")

        assert cost == 0.01  # Conservative estimate


class TestSynapseMetrics:
    """Tests for query metrics retrieval."""

    @patch('pyodbc.connect')
    def test_get_query_metrics(self, mock_connect):
        """Test retrieving query metrics from DMV."""
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_conn.cursor.return_value = mock_cursor
        mock_connect.return_value = mock_conn

        # Mock DMV query result
        mock_cursor.fetchone.return_value = (
            'query-123',  # request_id
            'SELECT * FROM test',  # command
            datetime(2024, 1, 1, 12, 0, 0),  # submit_time
            datetime(2024, 1, 1, 12, 0, 1),  # start_time
            datetime(2024, 1, 1, 12, 0, 5),  # end_time
            4000,  # total_elapsed_time (ms)
            'Completed'  # status
        )

        executor = SynapseExecutor(
            server='test-synapse.sql.azuresynapse.net',
            database='test_db'
        )

        metrics = executor.get_query_metrics('query-123')

        assert isinstance(metrics, QueryMetrics)
        assert metrics.query_id == 'query-123'
        assert metrics.query == 'SELECT * FROM test'
        assert metrics.status == 'Completed'
        assert metrics.execution_time_ms == 4000


class TestSynapseTableSchema:
    """Tests for table schema retrieval."""

    @patch('pyodbc.connect')
    def test_get_table_schema_simple(self, mock_connect):
        """Test retrieving table schema for simple table name."""
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_conn.cursor.return_value = mock_cursor
        mock_connect.return_value = mock_conn

        # Mock schema query results
        mock_cursor.__iter__ = lambda self: iter([
            ('eventname', 'varchar'),
            ('eventtime', 'datetime2'),
            ('sourceipaddress', 'varchar')
        ])

        executor = SynapseExecutor(
            server='test-synapse.sql.azuresynapse.net',
            database='test_db'
        )

        schema = executor.get_table_schema('test_db', 'cloudtrail')

        assert schema == {
            'eventname': 'varchar',
            'eventtime': 'datetime2',
            'sourceipaddress': 'varchar'
        }

    @patch('pyodbc.connect')
    def test_get_table_schema_with_schema_prefix(self, mock_connect):
        """Test retrieving table schema with schema.table notation."""
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_conn.cursor.return_value = mock_cursor
        mock_connect.return_value = mock_conn

        mock_cursor.__iter__ = lambda self: iter([
            ('id', 'int'),
            ('name', 'varchar')
        ])

        executor = SynapseExecutor(
            server='test-synapse.sql.azuresynapse.net',
            database='test_db'
        )

        schema = executor.get_table_schema('test_db', 'custom_schema.users')

        # Should parse schema.table correctly
        assert 'id' in schema
        assert 'name' in schema


class TestSynapseConnectionTesting:
    """Tests for connection testing."""

    @patch('pyodbc.connect')
    def test_connection_success(self, mock_connect):
        """Test successful connection test."""
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
        mock_cursor.execute.assert_called_with("SELECT 1")

    @patch('pyodbc.connect')
    def test_connection_failure(self, mock_connect):
        """Test connection failure."""
        mock_connect.side_effect = Exception("Connection failed")

        executor = SynapseExecutor(
            server='test-synapse.sql.azuresynapse.net',
            database='test_db'
        )

        result = executor.test_connection()

        assert result is False


class TestSynapseCancelQuery:
    """Tests for query cancellation."""

    @patch('pyodbc.connect')
    def test_cancel_query_success(self, mock_connect):
        """Test successful query cancellation."""
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_conn.cursor.return_value = mock_cursor
        mock_connect.return_value = mock_conn

        executor = SynapseExecutor(
            server='test-synapse.sql.azuresynapse.net',
            database='test_db'
        )

        result = executor.cancel_query('query-123')

        assert result is True
        mock_cursor.execute.assert_called_with("KILL 'query-123'")

    @patch('pyodbc.connect')
    def test_cancel_query_failure(self, mock_connect):
        """Test query cancellation failure."""
        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_conn.cursor.return_value = mock_cursor
        mock_connect.return_value = mock_conn

        mock_cursor.execute.side_effect = Exception("Query not found")

        executor = SynapseExecutor(
            server='test-synapse.sql.azuresynapse.net',
            database='test_db'
        )

        result = executor.cancel_query('invalid-query')

        assert result is False


class TestSynapseClose:
    """Tests for connection cleanup."""

    @patch('pyodbc.connect')
    def test_close_connection(self, mock_connect):
        """Test closing connection."""
        mock_conn = MagicMock()
        mock_connect.return_value = mock_conn

        executor = SynapseExecutor(
            server='test-synapse.sql.azuresynapse.net',
            database='test_db'
        )

        # Establish connection
        executor._get_connection()
        assert executor.connection is not None

        # Close connection
        executor.close()

        assert executor.connection is None
        mock_conn.close.assert_called_once()

    @patch('pyodbc.connect')
    def test_close_no_connection(self, mock_connect):
        """Test closing when no connection exists."""
        executor = SynapseExecutor(
            server='test-synapse.sql.azuresynapse.net',
            database='test_db'
        )

        # Should not raise error
        executor.close()

        assert executor.connection is None
