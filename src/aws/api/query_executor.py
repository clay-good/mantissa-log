"""
Query Executor

Executes Athena queries and handles result retrieval.
"""

import json
import time
import boto3
from typing import Dict, Any, List, Optional
from datetime import datetime


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
        try:
            body = json.loads(event.get('body', '{}'))
            
            query = body.get('query')
            database = body.get('database', 'mantissa_log')
            wait = body.get('wait', True)
            
            if not query:
                return self._error_response('Query is required', 400)
            
            result = self.executor.execute_query(
                query=query,
                database=database,
                wait=wait
            )
            
            return self._success_response(result)
            
        except Exception as e:
            print(f"Error executing query: {str(e)}")
            import traceback
            traceback.print_exc()
            return self._error_response(str(e), 500)
    
    def _success_response(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Return success response."""
        return {
            'statusCode': 200,
            'headers': {
                'Content-Type': 'application/json',
                'Access-Control-Allow-Origin': '*'
            },
            'body': json.dumps(data)
        }
    
    def _error_response(self, message: str, status_code: int) -> Dict[str, Any]:
        """Return error response."""
        return {
            'statusCode': status_code,
            'headers': {
                'Content-Type': 'application/json',
                'Access-Control-Allow-Origin': '*'
            },
            'body': json.dumps({'error': message})
        }


# Lambda entry point
def lambda_handler(event, context):
    """Entry point for AWS Lambda."""
    api = QueryExecutorAPI()
    return api.lambda_handler(event, context)
