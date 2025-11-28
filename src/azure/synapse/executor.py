"""
Azure Synapse Analytics Query Executor

Executes detection queries against Azure Synapse with cost estimation,
result caching, and performance tracking.
"""

import json
import os
from typing import Dict, List, Any, Optional
from datetime import datetime, timezone
import logging
import pyodbc
from azure.identity import DefaultAzureCredential, ClientSecretCredential
from azure.synapse.artifacts import ArtifactsClient
from azure.core.exceptions import AzureError

logger = logging.getLogger()
logger.setLevel(logging.INFO)


class SynapseExecutor:
    """Query executor for Azure Synapse Analytics"""

    def __init__(
        self,
        workspace_name: Optional[str] = None,
        sql_pool_name: Optional[str] = None,
        server_name: Optional[str] = None,
        database_name: Optional[str] = None,
        use_serverless: bool = False
    ):
        """
        Initialize Synapse executor.

        Args:
            workspace_name: Synapse workspace name
            sql_pool_name: Dedicated SQL pool name (if not serverless)
            server_name: SQL server name
            database_name: Database name
            use_serverless: Whether to use serverless SQL pool
        """
        self.workspace_name = workspace_name or os.environ.get('SYNAPSE_WORKSPACE_NAME')
        self.sql_pool_name = sql_pool_name or os.environ.get('SYNAPSE_SQL_POOL_NAME')
        self.server_name = server_name or os.environ.get('SYNAPSE_SERVER_NAME')
        self.database_name = database_name or os.environ.get('SYNAPSE_DATABASE_NAME')
        self.use_serverless = use_serverless

        # Get authentication credentials
        self.credential = DefaultAzureCredential()

        # Build connection string
        self.connection_string = self._build_connection_string()

        # Initialize connection
        self.connection = None

    def _build_connection_string(self) -> str:
        """Build ODBC connection string for Synapse"""
        if self.use_serverless:
            endpoint = f"{self.workspace_name}-ondemand.sql.azuresynapse.net"
        else:
            endpoint = f"{self.server_name}.sql.azuresynapse.net"

        # Get access token for authentication
        token = self.credential.get_token("https://database.windows.net/.default")
        access_token = token.token

        connection_string = (
            f"Driver={{ODBC Driver 18 for SQL Server}};"
            f"Server=tcp:{endpoint},1433;"
            f"Database={self.database_name};"
            f"Encrypt=yes;"
            f"TrustServerCertificate=no;"
            f"Connection Timeout=30;"
        )

        return connection_string

    def _get_connection(self):
        """Get or create database connection"""
        if self.connection is None or not self._is_connection_alive():
            # Get fresh token
            token = self.credential.get_token("https://database.windows.net/.default")

            # Create connection with token
            self.connection = pyodbc.connect(
                self.connection_string,
                attrs_before={
                    1256: token.token.encode('utf-16-le')  # SQL_COPT_SS_ACCESS_TOKEN
                }
            )

        return self.connection

    def _is_connection_alive(self) -> bool:
        """Check if connection is still alive"""
        if self.connection is None:
            return False

        try:
            cursor = self.connection.cursor()
            cursor.execute("SELECT 1")
            cursor.close()
            return True
        except Exception:
            return False

    def execute_query(
        self,
        query: str,
        use_cache: bool = True,
        max_results: Optional[int] = None
    ) -> Dict[str, Any]:
        """
        Execute T-SQL query against Synapse.

        Args:
            query: T-SQL query
            use_cache: Whether to use result set caching
            max_results: Maximum number of results to return

        Returns:
            Dictionary containing results and metadata
        """
        connection = self._get_connection()
        cursor = connection.cursor()

        try:
            # Enable result set caching if requested
            if use_cache:
                cursor.execute("SET RESULT_SET_CACHING ON")

            # Start timing
            start_time = datetime.now(timezone.utc)

            # Execute query
            cursor.execute(query)

            # Fetch results
            columns = [column[0] for column in cursor.description] if cursor.description else []
            rows = []

            if max_results:
                rows = cursor.fetchmany(max_results)
            else:
                rows = cursor.fetchall()

            # Convert to list of dicts
            results = []
            for row in rows:
                row_dict = {}
                for idx, column in enumerate(columns):
                    value = row[idx]
                    # Convert datetime to ISO format
                    if isinstance(value, datetime):
                        value = value.isoformat()
                    row_dict[column] = value
                results.append(row_dict)

            # End timing
            end_time = datetime.now(timezone.utc)
            execution_time_ms = int((end_time - start_time).total_seconds() * 1000)

            # Get query statistics (bytes processed)
            bytes_processed = self._get_query_stats(cursor)

            # Estimate cost (Synapse serverless: ~$5 per TB, dedicated pool: fixed cost)
            cost_estimate = 0.0
            if self.use_serverless and bytes_processed > 0:
                cost_estimate = (bytes_processed / (1024 ** 4)) * 5.0

            cursor.close()

            return {
                'results': results,
                'row_count': len(results),
                'bytes_processed': bytes_processed,
                'cost_estimate': cost_estimate,
                'execution_time_ms': execution_time_ms,
                'query': query,
                'serverless': self.use_serverless
            }

        except pyodbc.ProgrammingError as e:
            logger.error(f"Invalid query: {e}")
            cursor.close()
            raise ValueError(f"Invalid Synapse query: {e}")
        except pyodbc.Error as e:
            logger.error(f"Query execution failed: {e}")
            cursor.close()
            raise
        except Exception as e:
            logger.error(f"Unexpected error: {e}")
            cursor.close()
            raise

    def _get_query_stats(self, cursor) -> int:
        """Get bytes processed from query statistics"""
        try:
            # Query sys.dm_pdw_exec_requests for stats
            stats_query = """
            SELECT TOP 1 total_elapsed_time, data_processed_mb
            FROM sys.dm_pdw_exec_requests
            WHERE status = 'Completed'
            ORDER BY submit_time DESC
            """
            cursor.execute(stats_query)
            row = cursor.fetchone()

            if row and len(row) > 1:
                data_processed_mb = row[1] or 0
                return int(data_processed_mb * 1024 * 1024)  # Convert MB to bytes

            return 0
        except Exception as e:
            logger.warning(f"Failed to get query stats: {e}")
            return 0

    def validate_query(self, query: str) -> Dict[str, Any]:
        """
        Validate T-SQL query syntax without executing.

        Args:
            query: T-SQL query

        Returns:
            Validation result
        """
        connection = self._get_connection()
        cursor = connection.cursor()

        try:
            # Use SET NOEXEC to validate without executing
            cursor.execute("SET NOEXEC ON")
            cursor.execute(query)
            cursor.execute("SET NOEXEC OFF")

            cursor.close()

            return {
                'valid': True,
                'query': query
            }

        except pyodbc.ProgrammingError as e:
            cursor.execute("SET NOEXEC OFF")
            cursor.close()

            return {
                'valid': False,
                'error': str(e),
                'query': query
            }
        except Exception as e:
            cursor.execute("SET NOEXEC OFF")
            cursor.close()

            return {
                'valid': False,
                'error': f"Validation failed: {str(e)}",
                'query': query
            }

    def get_query_cost_estimate(self, query: str) -> float:
        """
        Estimate query cost.

        Args:
            query: T-SQL query

        Returns:
            Estimated cost in USD
        """
        # For dedicated SQL pool, cost is fixed (pool running cost)
        # For serverless, estimate based on data scanned
        if self.use_serverless:
            # Rough estimate: assume 1GB per table scan
            # Real implementation would analyze query plan
            return 0.05  # $0.05 for small query
        else:
            # Dedicated pool has fixed cost
            return 0.0

    def list_tables(self, schema: str = 'dbo') -> List[str]:
        """
        List all tables in the database.

        Args:
            schema: Schema name (default: dbo)

        Returns:
            List of table names
        """
        connection = self._get_connection()
        cursor = connection.cursor()

        try:
            query = f"""
            SELECT TABLE_NAME
            FROM INFORMATION_SCHEMA.TABLES
            WHERE TABLE_SCHEMA = '{schema}'
              AND TABLE_TYPE = 'BASE TABLE'
            ORDER BY TABLE_NAME
            """

            cursor.execute(query)
            tables = [row[0] for row in cursor.fetchall()]
            cursor.close()

            return tables

        except Exception as e:
            logger.error(f"Failed to list tables: {e}")
            cursor.close()
            return []

    def get_table_schema(self, table_name: str, schema: str = 'dbo') -> List[Dict[str, str]]:
        """
        Get schema for a specific table.

        Args:
            table_name: Name of the table
            schema: Schema name (default: dbo)

        Returns:
            List of column definitions
        """
        connection = self._get_connection()
        cursor = connection.cursor()

        try:
            query = f"""
            SELECT
                COLUMN_NAME,
                DATA_TYPE,
                IS_NULLABLE,
                CHARACTER_MAXIMUM_LENGTH
            FROM INFORMATION_SCHEMA.COLUMNS
            WHERE TABLE_SCHEMA = '{schema}'
              AND TABLE_NAME = '{table_name}'
            ORDER BY ORDINAL_POSITION
            """

            cursor.execute(query)

            schema_info = []
            for row in cursor.fetchall():
                schema_info.append({
                    'name': row[0],
                    'type': row[1],
                    'nullable': row[2] == 'YES',
                    'max_length': row[3]
                })

            cursor.close()
            return schema_info

        except Exception as e:
            logger.error(f"Failed to get table schema for {table_name}: {e}")
            cursor.close()
            return []

    def create_table_from_query(
        self,
        destination_table: str,
        query: str,
        schema: str = 'dbo'
    ) -> bool:
        """
        Create a new table from query results (for materialized views).

        Args:
            destination_table: Name of destination table
            query: SQL query
            schema: Schema name

        Returns:
            True if successful
        """
        connection = self._get_connection()
        cursor = connection.cursor()

        try:
            create_query = f"""
            CREATE TABLE [{schema}].[{destination_table}]
            WITH (
                DISTRIBUTION = ROUND_ROBIN,
                CLUSTERED COLUMNSTORE INDEX
            )
            AS
            {query}
            """

            cursor.execute(create_query)
            connection.commit()
            cursor.close()

            logger.info(f"Created table {destination_table} from query")
            return True

        except Exception as e:
            logger.error(f"Failed to create table from query: {e}")
            cursor.close()
            return False

    def delete_table(self, table_name: str, schema: str = 'dbo') -> bool:
        """
        Delete a table.

        Args:
            table_name: Name of table to delete
            schema: Schema name

        Returns:
            True if successful
        """
        connection = self._get_connection()
        cursor = connection.cursor()

        try:
            cursor.execute(f"DROP TABLE IF EXISTS [{schema}].[{table_name}]")
            connection.commit()
            cursor.close()

            logger.info(f"Deleted table {table_name}")
            return True

        except Exception as e:
            logger.error(f"Failed to delete table {table_name}: {e}")
            cursor.close()
            return False

    def close(self):
        """Close the database connection"""
        if self.connection:
            try:
                self.connection.close()
            except Exception as e:
                logger.error(f"Failed to close connection: {e}")
            finally:
                self.connection = None
