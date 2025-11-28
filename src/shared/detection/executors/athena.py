"""AWS Athena query executor implementation."""

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


class AthenaQueryExecutor(QueryExecutor):
    """Query executor for AWS Athena."""

    def __init__(
        self,
        database: str,
        output_location: str,
        region: str = "us-east-1",
        workgroup: str = "primary"
    ):
        """Initialize Athena executor.

        Args:
            database: Athena database name
            output_location: S3 location for query results
            region: AWS region
            workgroup: Athena workgroup name
        """
        self.database = database
        self.output_location = output_location
        self.region = region
        self.workgroup = workgroup
        self.client = None

    def _get_client(self):
        """Get or create Athena client."""
        if self.client is None:
            try:
                import boto3
                self.client = boto3.client('athena', region_name=self.region)
            except ImportError:
                raise ImportError("boto3 is required for Athena executor")
        return self.client

    def execute_query(
        self,
        query: str,
        max_results: Optional[int] = None,
        timeout_seconds: Optional[int] = 120
    ) -> QueryResult:
        """Execute query against Athena."""
        if not self.validate_query(query):
            raise QueryValidationError("Invalid or unsafe query")

        client = self._get_client()
        start_time = time.time()

        # Start query execution
        try:
            response = client.start_query_execution(
                QueryString=query,
                QueryExecutionContext={'Database': self.database},
                ResultConfiguration={'OutputLocation': self.output_location},
                WorkGroup=self.workgroup
            )
        except Exception as e:
            raise QueryExecutionError(f"Failed to start query: {str(e)}")

        query_execution_id = response['QueryExecutionId']

        # Wait for query to complete
        while time.time() - start_time < timeout_seconds:
            try:
                status = client.get_query_execution(QueryExecutionId=query_execution_id)
                state = status['QueryExecution']['Status']['State']

                if state == 'SUCCEEDED':
                    break
                elif state in ['FAILED', 'CANCELLED']:
                    reason = status['QueryExecution']['Status'].get('StateChangeReason', 'Unknown')
                    raise QueryExecutionError(f"Query {state}: {reason}")

                time.sleep(1)
            except QueryExecutionError:
                raise
            except Exception as e:
                raise QueryExecutionError(f"Error checking query status: {str(e)}")
        else:
            self.cancel_query(query_execution_id)
            raise QueryTimeoutError(f"Query execution timed out after {timeout_seconds} seconds")

        # Get query statistics
        execution_time_ms = int((time.time() - start_time) * 1000)
        stats = status['QueryExecution'].get('Statistics', {})
        bytes_scanned = stats.get('DataScannedInBytes', 0)

        # Calculate cost ($5 per TB scanned)
        cost_estimate = (bytes_scanned / (1024 ** 4)) * 5.0

        # Get results
        results = []
        paginator = client.get_paginator('get_query_results')

        try:
            for page in paginator.paginate(
                QueryExecutionId=query_execution_id,
                PaginationConfig={'MaxItems': max_results} if max_results else {}
            ):
                rows = page['ResultSet']['Rows']

                # Get headers from first row
                if not results and rows:
                    headers = [col.get('VarCharValue', '') for col in rows[0]['Data']]
                    rows = rows[1:]
                elif results and rows:
                    headers = [col.get('VarCharValue', '') for col in page['ResultSet']['Rows'][0]['Data']]
                else:
                    continue

                # Parse rows
                for row in rows:
                    result_dict = {}
                    for i, col in enumerate(row['Data']):
                        result_dict[headers[i]] = col.get('VarCharValue')
                    results.append(result_dict)
        except Exception as e:
            raise QueryExecutionError(f"Failed to retrieve results: {str(e)}")

        return QueryResult(
            data=results,
            row_count=len(results),
            bytes_scanned=bytes_scanned,
            execution_time_ms=execution_time_ms,
            cost_estimate=cost_estimate,
            query_id=query_execution_id
        )

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
            "CREATE", "ALTER", "GRANT", "REVOKE", "EXEC"
        ]

        for keyword in dangerous:
            if re.search(r'\b' + keyword + r'\b', query_upper):
                return False

        return True

    def get_query_cost_estimate(self, query: str) -> float:
        """Estimate cost based on expected data scanned."""
        # Simple estimation: assume 1GB per query
        # Real implementation would use EXPLAIN or historical data
        estimated_bytes = 1 * (1024 ** 3)
        return (estimated_bytes / (1024 ** 4)) * 5.0

    def get_query_metrics(self, query_id: str) -> QueryMetrics:
        """Retrieve metrics for a completed query."""
        client = self._get_client()

        try:
            response = client.get_query_execution(QueryExecutionId=query_id)
            execution = response['QueryExecution']
            stats = execution.get('Statistics', {})
            status = execution['Status']

            return QueryMetrics(
                query_id=query_id,
                query=execution['Query'],
                execution_time_ms=stats.get('EngineExecutionTimeInMillis', 0),
                bytes_scanned=stats.get('DataScannedInBytes', 0),
                rows_returned=stats.get('ResultSetMetadataVersion', 0),
                cost=(stats.get('DataScannedInBytes', 0) / (1024 ** 4)) * 5.0,
                timestamp=datetime.fromisoformat(status['SubmissionDateTime'].replace('Z', '+00:00')),
                status=status['State'],
                error_message=status.get('StateChangeReason')
            )
        except Exception as e:
            raise QueryExecutionError(f"Failed to get query metrics: {str(e)}")

    def cancel_query(self, query_id: str) -> bool:
        """Cancel a running query."""
        client = self._get_client()

        try:
            client.stop_query_execution(QueryExecutionId=query_id)
            return True
        except Exception:
            return False

    def get_table_schema(self, database: str, table: str) -> Dict[str, str]:
        """Get schema for a table."""
        client = self._get_client()

        try:
            response = client.get_table_metadata(
                CatalogName='AwsDataCatalog',
                DatabaseName=database,
                TableName=table
            )

            schema = {}
            for column in response['TableMetadata']['Columns']:
                schema[column['Name']] = column['Type']

            return schema
        except Exception as e:
            raise QueryExecutionError(f"Failed to get table schema: {str(e)}")

    def test_connection(self) -> bool:
        """Test connection to Athena."""
        try:
            client = self._get_client()
            # Simple test query
            response = client.start_query_execution(
                QueryString="SELECT 1",
                QueryExecutionContext={'Database': self.database},
                ResultConfiguration={'OutputLocation': self.output_location},
                WorkGroup=self.workgroup
            )
            query_id = response['QueryExecutionId']

            # Wait briefly for completion
            time.sleep(2)

            # Cancel the test query
            self.cancel_query(query_id)

            return True
        except Exception:
            return False
