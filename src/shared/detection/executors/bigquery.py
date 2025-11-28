"""GCP BigQuery query executor implementation."""

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


class BigQueryExecutor(QueryExecutor):
    """Query executor for GCP BigQuery."""

    def __init__(
        self,
        project_id: str,
        dataset: str,
        location: str = "US"
    ):
        """Initialize BigQuery executor.

        Args:
            project_id: GCP project ID
            dataset: BigQuery dataset name
            location: BigQuery location
        """
        self.project_id = project_id
        self.dataset = dataset
        self.location = location
        self.client = None

    def _get_client(self):
        """Get or create BigQuery client."""
        if self.client is None:
            try:
                from google.cloud import bigquery
                self.client = bigquery.Client(project=self.project_id, location=self.location)
            except ImportError:
                raise ImportError("google-cloud-bigquery is required for BigQuery executor")
        return self.client

    def execute_query(
        self,
        query: str,
        max_results: Optional[int] = None,
        timeout_seconds: Optional[int] = 120
    ) -> QueryResult:
        """Execute query against BigQuery."""
        if not self.validate_query(query):
            raise QueryValidationError("Invalid or unsafe query")

        client = self._get_client()
        start_time = time.time()

        try:
            # Configure query job
            from google.cloud import bigquery

            job_config = bigquery.QueryJobConfig(
                default_dataset=f"{self.project_id}.{self.dataset}",
                use_query_cache=True
            )

            if max_results:
                job_config.maximum_rows = max_results

            # Start query
            query_job = client.query(query, job_config=job_config)

            # Wait for completion
            try:
                results_iter = query_job.result(timeout=timeout_seconds)
            except Exception as e:
                if "timeout" in str(e).lower():
                    query_job.cancel()
                    raise QueryTimeoutError(f"Query execution timed out after {timeout_seconds} seconds")
                raise QueryExecutionError(f"Query execution failed: {str(e)}")

            # Get results
            results = []
            for row in results_iter:
                results.append(dict(row.items()))

            # Get statistics
            execution_time_ms = int((time.time() - start_time) * 1000)
            bytes_scanned = query_job.total_bytes_processed or 0

            # BigQuery pricing: $5 per TB on-demand
            cost_estimate = (bytes_scanned / (1024 ** 4)) * 5.0

            return QueryResult(
                data=results,
                row_count=len(results),
                bytes_scanned=bytes_scanned,
                execution_time_ms=execution_time_ms,
                cost_estimate=cost_estimate,
                query_id=query_job.job_id
            )

        except QueryTimeoutError:
            raise
        except QueryValidationError:
            raise
        except Exception as e:
            raise QueryExecutionError(f"BigQuery execution error: {str(e)}")

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
            "CREATE", "ALTER", "GRANT", "REVOKE"
        ]

        for keyword in dangerous:
            if re.search(r'\b' + keyword + r'\b', query_upper):
                return False

        return True

    def get_query_cost_estimate(self, query: str) -> float:
        """Estimate cost using dry run."""
        client = self._get_client()

        try:
            from google.cloud import bigquery

            job_config = bigquery.QueryJobConfig(
                default_dataset=f"{self.project_id}.{self.dataset}",
                dry_run=True,
                use_query_cache=False
            )

            query_job = client.query(query, job_config=job_config)

            # Get bytes that would be processed
            bytes_scanned = query_job.total_bytes_processed or 0

            # Calculate cost
            return (bytes_scanned / (1024 ** 4)) * 5.0

        except Exception:
            # Fallback estimate
            return 0.01

    def get_query_metrics(self, query_id: str) -> QueryMetrics:
        """Retrieve metrics for a completed query."""
        client = self._get_client()

        try:
            job = client.get_job(query_id)

            return QueryMetrics(
                query_id=query_id,
                query=job.query,
                execution_time_ms=int((job.ended - job.started).total_seconds() * 1000) if job.ended and job.started else 0,
                bytes_scanned=job.total_bytes_processed or 0,
                rows_returned=job.total_rows or 0,
                cost=((job.total_bytes_processed or 0) / (1024 ** 4)) * 5.0,
                timestamp=job.started or datetime.now(),
                status=job.state,
                error_message=str(job.errors[0]) if job.errors else None
            )
        except Exception as e:
            raise QueryExecutionError(f"Failed to get query metrics: {str(e)}")

    def cancel_query(self, query_id: str) -> bool:
        """Cancel a running query."""
        client = self._get_client()

        try:
            job = client.get_job(query_id)
            job.cancel()
            return True
        except Exception:
            return False

    def get_table_schema(self, database: str, table: str) -> Dict[str, str]:
        """Get schema for a table."""
        client = self._get_client()

        try:
            table_ref = f"{self.project_id}.{database}.{table}"
            table_obj = client.get_table(table_ref)

            schema = {}
            for field in table_obj.schema:
                schema[field.name] = field.field_type

            return schema
        except Exception as e:
            raise QueryExecutionError(f"Failed to get table schema: {str(e)}")

    def test_connection(self) -> bool:
        """Test connection to BigQuery."""
        try:
            client = self._get_client()

            # Test with a simple query
            from google.cloud import bigquery

            job_config = bigquery.QueryJobConfig(dry_run=True)
            client.query("SELECT 1", job_config=job_config)

            return True
        except Exception:
            return False
