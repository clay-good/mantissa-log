"""
Query Executor

Executes Athena queries and handles result retrieval.
"""

import json
import logging
import time
import boto3
import sys
from pathlib import Path
from typing import Dict, Any, List, Optional
from datetime import datetime

# Add shared modules to path
sys.path.append(str(Path(__file__).parent.parent.parent / 'shared'))

from auth import get_authenticated_user_id, AuthenticationError
from auth.cors import get_cors_headers, cors_preflight_response
from auth.rate_limiter import get_rate_limiter, RateLimitExceeded, RateLimitConfig, rate_limit_response

logger = logging.getLogger(__name__)

# Use strict rate limits for Athena queries (expensive operation)
_rate_limiter = None

def _get_rate_limiter():
    """Get or create rate limiter singleton."""
    global _rate_limiter
    if _rate_limiter is None:
        config = RateLimitConfig.strict()  # 10/min, 100/hour, 1000/day
        _rate_limiter = get_rate_limiter("aws")
        _rate_limiter.config = config
    return _rate_limiter
logger.setLevel(logging.INFO)


class AthenaQueryExecutor:
    """Executes queries against AWS Athena."""
    
    def __init__(self):
        self.athena = boto3.client('athena')
        self.s3 = boto3.client('s3')
    
    def execute_query(
        self,
        query: str,
        database: str = 'mantissa_log',
        output_location: Optional[str] = None,
        wait: bool = True
    ) -> Dict[str, Any]:
        """
        Execute Athena query and optionally wait for results.
        
        Args:
            query: SQL query to execute
            database: Athena database name
            output_location: S3 location for query results
            wait: Whether to wait for query completion
        
        Returns:
            Query execution result with metadata
        """
        if not output_location:
            output_location = self._get_output_location()
        
        # Start query execution
        response = self.athena.start_query_execution(
            QueryString=query,
            QueryExecutionContext={'Database': database},
            ResultConfiguration={'OutputLocation': output_location}
        )
        
        execution_id = response['QueryExecutionId']
        
        if not wait:
            return {
                'execution_id': execution_id,
                'status': 'RUNNING',
                'output_location': output_location
            }
        
        # Wait for completion
        status = self._wait_for_query(execution_id)
        
        if status['State'] != 'SUCCEEDED':
            return {
                'execution_id': execution_id,
                'status': status['State'],
                'error': status.get('StateChangeReason', 'Query failed')
            }
        
        # Get results
        results = self._get_query_results(execution_id)
        statistics = status.get('Statistics', {})
        
        return {
            'execution_id': execution_id,
            'status': 'SUCCEEDED',
            'results': results,
            'statistics': {
                'data_scanned_bytes': statistics.get('DataScannedInBytes', 0),
                'execution_time_ms': statistics.get('TotalExecutionTimeInMillis', 0),
                'result_count': len(results)
            },
            'output_location': output_location
        }
    
    def _wait_for_query(
        self,
        execution_id: str,
        max_wait: int = 300
    ) -> Dict[str, Any]:
        """Wait for query to complete."""
        start_time = time.time()
        
        while True:
            response = self.athena.get_query_execution(
                QueryExecutionId=execution_id
            )
            
            status = response['QueryExecution']['Status']
            state = status['State']
            
            if state in ['SUCCEEDED', 'FAILED', 'CANCELLED']:
                return status
            
            if time.time() - start_time > max_wait:
                # Cancel long-running query
                self.athena.stop_query_execution(QueryExecutionId=execution_id)
                raise TimeoutError(f'Query exceeded {max_wait}s timeout')
            
            time.sleep(1)
    
    def _get_query_results(
        self,
        execution_id: str,
        max_results: int = 1000
    ) -> List[Dict[str, Any]]:
        """Get query results."""
        paginator = self.athena.get_paginator('get_query_results')
        
        results = []
        columns = []
        
        for page in paginator.paginate(
            QueryExecutionId=execution_id,
            PaginationConfig={'MaxItems': max_results}
        ):
            # Get column names from first row
            if not columns and page['ResultSet']['Rows']:
                first_row = page['ResultSet']['Rows'][0]
                columns = [col['VarCharValue'] for col in first_row['Data']]
                continue
            
            # Process data rows
            for row in page['ResultSet']['Rows']:
                if row['Data']:
                    row_data = {}
                    for i, col in enumerate(columns):
                        value = row['Data'][i].get('VarCharValue')
                        row_data[col] = value
                    results.append(row_data)
        
        return results
    
    def _get_output_location(self) -> str:
        """Get S3 output location for query results."""
        import os
        bucket = os.environ.get('ATHENA_OUTPUT_BUCKET', 'mantissa-log-athena-results')
        return f's3://{bucket}/queries/'


class QueryExecutorAPI:
    """Lambda handler for query execution."""
    
    def __init__(self):
        self.executor = AthenaQueryExecutor()
    
    def lambda_handler(self, event: Dict[str, Any], context: Any) -> Dict[str, Any]:
        """
        Lambda handler for query execution API.

        POST /api/query/execute
        {
            "query": "SELECT * FROM cloudtrail_logs LIMIT 10",
            "database": "mantissa_log",
            "wait": true
        }
        """
        # Handle CORS preflight
        http_method = event.get('httpMethod')
        if http_method == 'OPTIONS':
            return cors_preflight_response(event)

        try:
            # Authenticate user from Cognito JWT claims
            try:
                user_id = get_authenticated_user_id(event)
            except AuthenticationError:
                return self._error_response(event, 'Authentication required', 401)

            # Check rate limit
            try:
                rate_limiter = _get_rate_limiter()
                rate_limiter.check_rate_limit(user_id, "query_execute")
            except RateLimitExceeded as e:
                logger.warning(f"Rate limit exceeded for user {user_id}")
                return rate_limit_response(e.retry_after, get_cors_headers(event))

            body = json.loads(event.get('body', '{}'))

            query = body.get('query')
            database = body.get('database', 'mantissa_log')
            wait = body.get('wait', True)

            if not query:
                return self._error_response(event, 'Query is required', 400)

            result = self.executor.execute_query(
                query=query,
                database=database,
                wait=wait
            )

            return self._success_response(event, result)

        except Exception as e:
            logger.error(f"Error executing query: {str(e)}", exc_info=True)
            return self._error_response(event, 'Internal server error', 500)

    def _success_response(self, event: Dict[str, Any], data: Dict[str, Any]) -> Dict[str, Any]:
        """Return success response with secure CORS headers."""
        return {
            'statusCode': 200,
            'headers': {
                'Content-Type': 'application/json',
                **get_cors_headers(event)
            },
            'body': json.dumps(data)
        }

    def _error_response(self, event: Dict[str, Any], message: str, status_code: int) -> Dict[str, Any]:
        """Return error response with secure CORS headers."""
        return {
            'statusCode': status_code,
            'headers': {
                'Content-Type': 'application/json',
                **get_cors_headers(event)
            },
            'body': json.dumps({'error': message})
        }


# Lambda entry point
def lambda_handler(event, context):
    """Entry point for AWS Lambda."""
    api = QueryExecutorAPI()
    return api.lambda_handler(event, context)
