"""Tests for base QueryExecutor abstract class."""

import pytest
from datetime import datetime
from src.shared.detection.executors.base import (
    QueryExecutor,
    QueryResult,
    QueryMetrics,
    QueryExecutionError,
    QueryValidationError,
    QueryTimeoutError
)


class TestQueryResult:
    """Tests for QueryResult dataclass."""

    def test_query_result_creation(self):
        """Test creating QueryResult with all fields."""
        result = QueryResult(
            data=[{'col1': 'value1', 'col2': 'value2'}],
            row_count=1,
            bytes_scanned=1024,
            execution_time_ms=500,
            cost_estimate=0.001,
            query_id='query-123'
        )

        assert result.data == [{'col1': 'value1', 'col2': 'value2'}]
        assert result.row_count == 1
        assert result.bytes_scanned == 1024
        assert result.execution_time_ms == 500
        assert result.cost_estimate == 0.001
        assert result.query_id == 'query-123'

    def test_query_result_minimal(self):
        """Test creating QueryResult with minimal fields."""
        result = QueryResult(
            data=[],
            row_count=0
        )

        assert result.data == []
        assert result.row_count == 0
        assert result.bytes_scanned is None
        assert result.execution_time_ms is None
        assert result.cost_estimate is None
        assert result.query_id is None


class TestQueryMetrics:
    """Tests for QueryMetrics dataclass."""

    def test_query_metrics_creation(self):
        """Test creating QueryMetrics with all fields."""
        timestamp = datetime.now()
        metrics = QueryMetrics(
            query_id='query-123',
            query='SELECT * FROM test',
            execution_time_ms=1000,
            bytes_scanned=2048,
            rows_returned=10,
            cost=0.005,
            timestamp=timestamp,
            status='SUCCEEDED',
            error_message=None
        )

        assert metrics.query_id == 'query-123'
        assert metrics.query == 'SELECT * FROM test'
        assert metrics.execution_time_ms == 1000
        assert metrics.bytes_scanned == 2048
        assert metrics.rows_returned == 10
        assert metrics.cost == 0.005
        assert metrics.timestamp == timestamp
        assert metrics.status == 'SUCCEEDED'
        assert metrics.error_message is None

    def test_query_metrics_with_error(self):
        """Test creating QueryMetrics with error."""
        timestamp = datetime.now()
        metrics = QueryMetrics(
            query_id='query-456',
            query='SELECT * FROM invalid_table',
            execution_time_ms=100,
            bytes_scanned=0,
            rows_returned=0,
            cost=0.0,
            timestamp=timestamp,
            status='FAILED',
            error_message='Table not found'
        )

        assert metrics.status == 'FAILED'
        assert metrics.error_message == 'Table not found'


class TestQueryExecutorExceptions:
    """Tests for custom exceptions."""

    def test_query_execution_error(self):
        """Test QueryExecutionError exception."""
        with pytest.raises(QueryExecutionError) as exc_info:
            raise QueryExecutionError("Test execution error")

        assert str(exc_info.value) == "Test execution error"

    def test_query_validation_error(self):
        """Test QueryValidationError exception."""
        with pytest.raises(QueryValidationError) as exc_info:
            raise QueryValidationError("Invalid SQL syntax")

        assert str(exc_info.value) == "Invalid SQL syntax"

    def test_query_timeout_error(self):
        """Test QueryTimeoutError exception."""
        with pytest.raises(QueryTimeoutError) as exc_info:
            raise QueryTimeoutError("Query timed out after 60s")

        assert str(exc_info.value) == "Query timed out after 60s"


class TestQueryExecutorAbstract:
    """Tests for QueryExecutor abstract class."""

    def test_cannot_instantiate_abstract_class(self):
        """Test that QueryExecutor cannot be instantiated directly."""
        with pytest.raises(TypeError):
            QueryExecutor()

    def test_concrete_implementation_required(self):
        """Test that concrete implementations must implement all abstract methods."""

        class IncompleteExecutor(QueryExecutor):
            """Incomplete executor missing some methods."""
            pass

        with pytest.raises(TypeError):
            IncompleteExecutor()


class TestQueryValidation:
    """Tests for common query validation patterns."""

    def test_select_query_validation(self):
        """Test validation logic for SELECT queries."""
        query_upper = "SELECT * FROM table".upper().strip()

        assert query_upper.startswith("SELECT")
        assert "DROP" not in query_upper
        assert "DELETE" not in query_upper

    def test_dangerous_keyword_detection(self):
        """Test detection of dangerous SQL keywords."""
        dangerous = [
            "DROP", "DELETE", "TRUNCATE", "INSERT", "UPDATE",
            "CREATE", "ALTER", "GRANT", "REVOKE", "EXEC"
        ]

        # Valid query
        valid_query = "SELECT * FROM users WHERE id = 1"
        assert not any(keyword in valid_query.upper() for keyword in dangerous)

        # Invalid queries
        invalid_queries = [
            "SELECT * FROM users; DROP TABLE users;",
            "SELECT * FROM users WHERE 1=1; DELETE FROM users;",
            "SELECT * FROM users UNION ALL SELECT * FROM users; TRUNCATE TABLE logs;"
        ]

        for invalid_query in invalid_queries:
            assert any(keyword in invalid_query.upper() for keyword in dangerous)
