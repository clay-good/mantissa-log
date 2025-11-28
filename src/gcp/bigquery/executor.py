"""
BigQuery Query Executor for GCP

Executes detection queries against Google BigQuery with cost estimation,
result caching, and performance tracking.
"""

import json
import os
from typing import Dict, List, Any, Optional
from datetime import datetime, timezone
import logging
from google.cloud import bigquery
from google.api_core import exceptions as google_exceptions
from google.oauth2 import service_account

logger = logging.getLogger()
logger.setLevel(logging.INFO)


class BigQueryExecutor:
    """Query executor for Google BigQuery"""

    def __init__(
        self,
        project_id: Optional[str] = None,
        dataset_id: Optional[str] = None,
        credentials_path: Optional[str] = None
    ):
        """
        Initialize BigQuery executor.

        Args:
            project_id: GCP project ID (defaults to env var)
            dataset_id: BigQuery dataset ID (defaults to env var)
            credentials_path: Path to service account JSON
        """
        self.project_id = project_id or os.environ.get('GCP_PROJECT_ID')
        self.dataset_id = dataset_id or os.environ.get('BIGQUERY_DATASET')

        # Initialize BigQuery client
        if credentials_path:
            credentials = service_account.Credentials.from_service_account_file(
                credentials_path,
                scopes=["https://www.googleapis.com/auth/bigquery"]
            )
            self.client = bigquery.Client(
                project=self.project_id,
                credentials=credentials
            )
        else:
            # Use default credentials (ADC)
            self.client = bigquery.Client(project=self.project_id)

    def execute_query(
        self,
        query: str,
        use_cache: bool = True,
        max_results: Optional[int] = None
    ) -> Dict[str, Any]:
        """
        Execute SQL query against BigQuery.

        Args:
            query: BigQuery Standard SQL query
            use_cache: Whether to use cached results
            max_results: Maximum number of results to return

        Returns:
            Dictionary containing results and metadata
        """
        job_config = bigquery.QueryJobConfig(
            use_query_cache=use_cache,
            use_legacy_sql=False  # Use Standard SQL
        )

        try:
            # Execute query
            query_job = self.client.query(query, job_config=job_config)

            # Wait for completion
            results = query_job.result(max_results=max_results)

            # Extract results
            rows = []
            for row in results:
                # Convert Row to dict
                row_dict = dict(row.items())
                # Convert datetime objects to ISO format
                for key, value in row_dict.items():
                    if isinstance(value, datetime):
                        row_dict[key] = value.isoformat()
                rows.append(row_dict)

            # Calculate bytes processed
            bytes_processed = query_job.total_bytes_processed or 0
            bytes_billed = query_job.total_bytes_billed or 0

            # Estimate cost ($5 per TB)
            cost_estimate = (bytes_billed / (1024 ** 4)) * 5.0

            return {
                'results': rows,
                'row_count': len(rows),
                'bytes_processed': bytes_processed,
                'bytes_billed': bytes_billed,
                'cost_estimate': cost_estimate,
                'cache_hit': query_job.cache_hit,
                'execution_time_ms': query_job.ended - query_job.started if query_job.ended and query_job.started else 0,
                'job_id': query_job.job_id,
                'query': query
            }

        except google_exceptions.BadRequest as e:
            logger.error(f"Invalid query: {e}")
            raise ValueError(f"Invalid BigQuery query: {e}")
        except google_exceptions.Forbidden as e:
            logger.error(f"Permission denied: {e}")
            raise PermissionError(f"BigQuery access denied: {e}")
        except google_exceptions.NotFound as e:
            logger.error(f"Resource not found: {e}")
            raise ValueError(f"BigQuery resource not found: {e}")
        except Exception as e:
            logger.error(f"Query execution failed: {e}")
            raise

    def validate_query(self, query: str) -> Dict[str, Any]:
        """
        Validate SQL query syntax without executing.

        Args:
            query: BigQuery SQL query

        Returns:
            Validation result with estimated bytes scanned
        """
        job_config = bigquery.QueryJobConfig(
            dry_run=True,
            use_query_cache=False
        )

        try:
            query_job = self.client.query(query, job_config=job_config)

            # Dry run returns estimated bytes
            bytes_estimate = query_job.total_bytes_processed or 0
            cost_estimate = (bytes_estimate / (1024 ** 4)) * 5.0

            return {
                'valid': True,
                'bytes_estimate': bytes_estimate,
                'cost_estimate': cost_estimate,
                'query': query
            }

        except google_exceptions.BadRequest as e:
            return {
                'valid': False,
                'error': str(e),
                'query': query
            }
        except Exception as e:
            return {
                'valid': False,
                'error': f"Validation failed: {str(e)}",
                'query': query
            }

    def get_query_cost_estimate(self, query: str) -> float:
        """
        Estimate query cost without executing.

        Args:
            query: BigQuery SQL query

        Returns:
            Estimated cost in USD
        """
        validation = self.validate_query(query)
        if validation['valid']:
            return validation['cost_estimate']
        else:
            raise ValueError(f"Cannot estimate cost for invalid query: {validation.get('error')}")

    def list_tables(self) -> List[str]:
        """
        List all tables in the configured dataset.

        Returns:
            List of table names
        """
        try:
            dataset_ref = self.client.dataset(self.dataset_id)
            tables = self.client.list_tables(dataset_ref)
            return [table.table_id for table in tables]
        except Exception as e:
            logger.error(f"Failed to list tables: {e}")
            return []

    def get_table_schema(self, table_name: str) -> List[Dict[str, str]]:
        """
        Get schema for a specific table.

        Args:
            table_name: Name of the table

        Returns:
            List of column definitions
        """
        try:
            table_ref = self.client.dataset(self.dataset_id).table(table_name)
            table = self.client.get_table(table_ref)

            schema = []
            for field in table.schema:
                schema.append({
                    'name': field.name,
                    'type': field.field_type,
                    'mode': field.mode,
                    'description': field.description or ''
                })

            return schema
        except Exception as e:
            logger.error(f"Failed to get table schema for {table_name}: {e}")
            return []

    def create_table_from_query(
        self,
        destination_table: str,
        query: str,
        partition_by: Optional[str] = None
    ) -> bool:
        """
        Create a new table from query results (for materialized views).

        Args:
            destination_table: Name of destination table
            query: SQL query
            partition_by: Column to partition by (optional)

        Returns:
            True if successful
        """
        try:
            table_ref = self.client.dataset(self.dataset_id).table(destination_table)

            job_config = bigquery.QueryJobConfig(
                destination=table_ref,
                write_disposition=bigquery.WriteDisposition.WRITE_TRUNCATE
            )

            if partition_by:
                job_config.time_partitioning = bigquery.TimePartitioning(
                    field=partition_by
                )

            query_job = self.client.query(query, job_config=job_config)
            query_job.result()  # Wait for completion

            logger.info(f"Created table {destination_table} from query")
            return True

        except Exception as e:
            logger.error(f"Failed to create table from query: {e}")
            return False

    def delete_table(self, table_name: str) -> bool:
        """
        Delete a table.

        Args:
            table_name: Name of table to delete

        Returns:
            True if successful
        """
        try:
            table_ref = self.client.dataset(self.dataset_id).table(table_name)
            self.client.delete_table(table_ref)
            logger.info(f"Deleted table {table_name}")
            return True
        except Exception as e:
            logger.error(f"Failed to delete table {table_name}: {e}")
            return False

    def get_bytes_scanned_last_30_days(self) -> int:
        """
        Get total bytes scanned in last 30 days for cost tracking.

        Returns:
            Total bytes scanned
        """
        query = f"""
        SELECT SUM(total_bytes_processed) as total_bytes
        FROM `{self.project_id}.region-us.INFORMATION_SCHEMA.JOBS_BY_PROJECT`
        WHERE creation_time > TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL 30 DAY)
          AND job_type = 'QUERY'
          AND state = 'DONE'
        """

        try:
            result = self.execute_query(query, use_cache=False, max_results=1)
            if result['results']:
                return result['results'][0].get('total_bytes', 0)
            return 0
        except Exception as e:
            logger.error(f"Failed to get bytes scanned: {e}")
            return 0

    def close(self):
        """Close the BigQuery client connection"""
        if hasattr(self.client, 'close'):
            self.client.close()
