"""Azure Synapse Analytics query executor implementation."""

import time
from datetime import datetime
from typing import Any, Dict, List, Optional

from .base import (
    QueryExecutor,
    QueryResult,
    QueryMetrics,
    QueryExecutionError,
    QueryValidationError,
    QueryTimeoutError
)


class SynapseExecutor(QueryExecutor):
    """Query executor for Azure Synapse Analytics."""

    def __init__(
        self,
        server: str,
        database: str,
        username: Optional[str] = None,
        password: Optional[str] = None,
        use_managed_identity: bool = True
    ):
        """Initialize Synapse executor.

        Args:
            server: Synapse server name (e.g., 'mysynapse.sql.azuresynapse.net')
            database: Database name
            username: SQL username (if not using managed identity)
            password: SQL password (if not using managed identity)
            use_managed_identity: Use Azure managed identity for authentication
        """
        self.server = server
        self.database = database
        self.username = username
        self.password = password
        self.use_managed_identity = use_managed_identity
        self.connection = None

    def _get_connection(self):
        """Get or create database connection."""
        if self.connection is None:
            try:
                import pyodbc

                if self.use_managed_identity:
                    # Use Azure AD authentication
                    conn_str = (
                        f"Driver={{ODBC Driver 17 for SQL Server}};"
                        f"Server=tcp:{self.server},1433;"
                        f"Database={self.database};"
                        f"Authentication=ActiveDirectoryMsi;"
                        f"Encrypt=yes;"
                        f"TrustServerCertificate=no;"
                    )
                else:
                    # Use SQL authentication
                    conn_str = (
                        f"Driver={{ODBC Driver 17 for SQL Server}};"
                        f"Server=tcp:{self.server},1433;"
                        f"Database={self.database};"
                        f"UID={self.username};"
                        f"PWD={self.password};"
                        f"Encrypt=yes;"
                        f"TrustServerCertificate=no;"
                    )

                self.connection = pyodbc.connect(conn_str, timeout=30)
            except ImportError:
                raise ImportError("pyodbc is required for Synapse executor")
            except Exception as e:
                raise QueryExecutionError(f"Failed to connect to Synapse: {str(e)}")

        return self.connection

    def execute_query(
        self,
        query: str,
        max_results: Optional[int] = None,
        timeout_seconds: Optional[int] = 120
    ) -> QueryResult:
        """Execute query against Synapse."""
        if not self.validate_query(query):
            raise QueryValidationError("Invalid or unsafe query")

        conn = self._get_connection()
        start_time = time.time()

        try:
            cursor = conn.cursor()
            cursor.execute(query)

            # Get column names
            columns = [column[0] for column in cursor.description]

            # Fetch results
            results = []
            rows_fetched = 0

            for row in cursor:
                if max_results and rows_fetched >= max_results:
                    break

                result_dict = {}
                for i, value in enumerate(row):
                    result_dict[columns[i]] = value
                results.append(result_dict)
                rows_fetched += 1

            cursor.close()

            execution_time_ms = int((time.time() - start_time) * 1000)

            # Synapse doesn't provide bytes scanned in the same way
            # Use approximate estimate based on row count
            bytes_scanned = len(results) * 1024  # Rough estimate

            # Synapse pricing varies, use conservative estimate
            cost_estimate = 0.01

            return QueryResult(
                data=results,
                row_count=len(results),
                bytes_scanned=bytes_scanned,
                execution_time_ms=execution_time_ms,
                cost_estimate=cost_estimate,
                query_id=None  # Synapse doesn't provide query ID in this interface
            )

        except Exception as e:
            if "timeout" in str(e).lower():
                raise QueryTimeoutError(f"Query execution timed out")
            raise QueryExecutionError(f"Synapse execution error: {str(e)}")

    def validate_query(self, query: str) -> bool:
        """Validate query syntax."""
        import re

        query_upper = query.upper().strip()

        # Must be SELECT
        if not query_upper.startswith("SELECT"):
            return False

        # No dangerous keywords
        dangerous = [
            "DROP", "DELETE", "TRUNCATE", "INSERT", "UPDATE",
            "CREATE", "ALTER", "GRANT", "REVOKE", "EXEC", "EXECUTE"
        ]

        for keyword in dangerous:
            if re.search(r'\b' + keyword + r'\b', query_upper):
                return False

        return True

    def get_query_cost_estimate(self, query: str) -> float:
        """Estimate cost for Synapse query.

        Note: Synapse uses DWU-based pricing, difficult to estimate per-query.
        Returns conservative estimate.
        """
        return 0.01

    def get_query_metrics(self, query_id: str) -> QueryMetrics:
        """Retrieve metrics for a completed query.

        Note: Synapse query metrics require querying DMVs.
        This is a simplified implementation.
        """
        conn = self._get_connection()

        try:
            cursor = conn.cursor()

            # Query sys.dm_pdw_exec_requests for query stats
            query = """
                SELECT
                    request_id,
                    command,
                    submit_time,
                    start_time,
                    end_time,
                    total_elapsed_time,
                    status
                FROM sys.dm_pdw_exec_requests
                WHERE request_id = ?
            """

            cursor.execute(query, query_id)
            row = cursor.fetchone()

            if not row:
                raise QueryExecutionError(f"Query {query_id} not found")

            return QueryMetrics(
                query_id=row[0],
                query=row[1],
                execution_time_ms=row[5] if row[5] else 0,
                bytes_scanned=0,  # Not available
                rows_returned=0,  # Not available in this query
                cost=0.01,
                timestamp=row[2] or datetime.now(),
                status=row[6],
                error_message=None
            )
        except Exception as e:
            raise QueryExecutionError(f"Failed to get query metrics: {str(e)}")

    def cancel_query(self, query_id: str) -> bool:
        """Cancel a running query."""
        conn = self._get_connection()

        try:
            cursor = conn.cursor()
            cursor.execute(f"KILL '{query_id}'")
            cursor.close()
            return True
        except Exception:
            return False

    def get_table_schema(self, database: str, table: str) -> Dict[str, str]:
        """Get schema for a table."""
        conn = self._get_connection()

        try:
            cursor = conn.cursor()

            # Parse schema and table if provided as schema.table
            if '.' in table:
                schema_name, table_name = table.split('.', 1)
            else:
                schema_name = 'dbo'
                table_name = table

            query = """
                SELECT COLUMN_NAME, DATA_TYPE
                FROM INFORMATION_SCHEMA.COLUMNS
                WHERE TABLE_SCHEMA = ? AND TABLE_NAME = ?
                ORDER BY ORDINAL_POSITION
            """

            cursor.execute(query, schema_name, table_name)

            schema = {}
            for row in cursor:
                schema[row[0]] = row[1]

            cursor.close()
            return schema

        except Exception as e:
            raise QueryExecutionError(f"Failed to get table schema: {str(e)}")

    def test_connection(self) -> bool:
        """Test connection to Synapse."""
        try:
            conn = self._get_connection()
            cursor = conn.cursor()
            cursor.execute("SELECT 1")
            cursor.close()
            return True
        except Exception:
            return False

    def close(self):
        """Close database connection."""
        if self.connection:
            try:
                self.connection.close()
            except Exception:
                pass
            self.connection = None
