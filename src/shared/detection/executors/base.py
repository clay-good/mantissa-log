"""Base query executor interface for multi-cloud abstraction."""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any, Dict, List, Optional
from datetime import datetime


@dataclass
class QueryResult:
    """Result from query execution."""

    data: List[Dict[str, Any]]
    row_count: int
    bytes_scanned: Optional[int] = None
    execution_time_ms: Optional[int] = None
    cost_estimate: Optional[float] = None
    query_id: Optional[str] = None


@dataclass
class QueryMetrics:
    """Metrics for query performance tracking."""

    query_id: str
    query: str
    execution_time_ms: int
    bytes_scanned: int
    rows_returned: int
    cost: float
    timestamp: datetime
    status: str
    error_message: Optional[str] = None


class QueryExecutor(ABC):
    """Abstract base class for cloud-specific query executors."""

    @abstractmethod
    def execute_query(
        self,
        query: str,
        max_results: Optional[int] = None,
        timeout_seconds: Optional[int] = None
    ) -> QueryResult:
        """Execute a query and return results.

        Args:
            query: SQL query to execute
            max_results: Maximum number of results to return
            timeout_seconds: Query timeout in seconds

        Returns:
            QueryResult with data and metadata

        Raises:
            QueryExecutionError: If query execution fails
            QueryTimeoutError: If query exceeds timeout
        """
        pass

    @abstractmethod
    def validate_query(self, query: str) -> bool:
        """Validate query syntax without executing.

        Args:
            query: SQL query to validate

        Returns:
            True if query is valid

        Raises:
            QueryValidationError: If query is invalid
        """
        pass

    @abstractmethod
    def get_query_cost_estimate(self, query: str) -> float:
        """Estimate cost of query execution.

        Args:
            query: SQL query to estimate

        Returns:
            Estimated cost in USD
        """
        pass

    @abstractmethod
    def get_query_metrics(self, query_id: str) -> QueryMetrics:
        """Retrieve metrics for a completed query.

        Args:
            query_id: Unique query identifier

        Returns:
            QueryMetrics with execution details
        """
        pass

    @abstractmethod
    def cancel_query(self, query_id: str) -> bool:
        """Cancel a running query.

        Args:
            query_id: Query to cancel

        Returns:
            True if cancelled successfully
        """
        pass

    @abstractmethod
    def get_table_schema(self, database: str, table: str) -> Dict[str, str]:
        """Get schema for a table.

        Args:
            database: Database name
            table: Table name

        Returns:
            Dictionary mapping column names to data types
        """
        pass

    @abstractmethod
    def test_connection(self) -> bool:
        """Test connection to query service.

        Returns:
            True if connection is successful
        """
        pass


class QueryExecutionError(Exception):
    """Exception raised when query execution fails."""
    pass


class QueryValidationError(Exception):
    """Exception raised when query validation fails."""
    pass


class QueryTimeoutError(Exception):
    """Exception raised when query exceeds timeout."""
    pass
