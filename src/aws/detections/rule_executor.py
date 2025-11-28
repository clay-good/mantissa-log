"""
Detection Rule Executor

Executes detection rules on schedule and triggers alerts.
"""

import json
import boto3
from typing import Dict, Any, Optional
from datetime import datetime
import sys
from pathlib import Path

# Add shared modules to path
sys.path.append(str(Path(__file__).parent.parent.parent / 'shared'))

from alerts.router import AlertRouter, Alert


class DetectionRuleExecutor:
    """Executes detection rules and triggers alerts."""

    def __init__(self):
        self.athena = boto3.client('athena')
        self.s3 = boto3.client('s3')
        self.dynamodb = boto3.resource('dynamodb')
        self.alert_router = AlertRouter()

    def execute_rule(self, rule_id: str, user_id: str) -> Dict[str, Any]:
        """
        Execute a detection rule.

        Args:
            rule_id: Detection rule ID
            user_id: User who owns the rule

        Returns:
            Execution result
        """
        # Get rule from DynamoDB
        rule = self._get_rule(user_id, rule_id)

        if not rule:
            raise ValueError(f'Rule {rule_id} not found')

        if not rule.get('enabled', True):
            return {
                'rule_id': rule_id,
                'status': 'skipped',
                'reason': 'Rule is disabled'
            }

        # Execute query
        query_result = self._execute_query(rule['query'])

        # Check if alert should be triggered
        should_alert = self._should_trigger_alert(
            query_result,
            rule.get('threshold', {})
        )

        if should_alert:
            # Create and route alert
            alert = self._create_alert(rule, query_result)
            route_result = self.alert_router.route_alert(user_id, alert)

            return {
                'rule_id': rule_id,
                'status': 'alerted',
                'result_count': len(query_result['results']),
                'alert_id': alert.alert_id,
                'routed_to': route_result['routed_to']
            }
        else:
            return {
                'rule_id': rule_id,
                'status': 'executed',
                'result_count': len(query_result['results']),
                'alert_triggered': False
            }

    def _get_rule(self, user_id: str, rule_id: str) -> Optional[Dict[str, Any]]:
        """Get detection rule from DynamoDB."""
        table = self.dynamodb.Table(self._get_table_name('detection-rules'))

        response = table.get_item(
            Key={
                'user_id': user_id,
                'rule_id': rule_id
            }
        )

        return response.get('Item')

    def _execute_query(self, query: str) -> Dict[str, Any]:
        """Execute Athena query."""
        import time

        output_location = self._get_output_location()

        response = self.athena.start_query_execution(
            QueryString=query,
            QueryExecutionContext={'Database': 'mantissa_log'},
            ResultConfiguration={'OutputLocation': output_location}
        )

        execution_id = response['QueryExecutionId']

        # Wait for completion
        while True:
            status_response = self.athena.get_query_execution(
                QueryExecutionId=execution_id
            )

            status = status_response['QueryExecution']['Status']['State']

            if status in ['SUCCEEDED', 'FAILED', 'CANCELLED']:
                break

            time.sleep(1)

        if status != 'SUCCEEDED':
            raise Exception(f'Query failed with status: {status}')

        # Get results
        results = []
        paginator = self.athena.get_paginator('get_query_results')

        for page in paginator.paginate(
            QueryExecutionId=execution_id,
            PaginationConfig={'MaxItems': 1000}
        ):
            for i, row in enumerate(page['ResultSet']['Rows']):
                if i == 0:  # Skip header row
                    continue
                results.append(row)

        statistics = status_response['QueryExecution']['Statistics']

        return {
            'results': results,
            'statistics': {
                'execution_time_ms': statistics.get('TotalExecutionTimeInMillis', 0),
                'data_scanned_bytes': statistics.get('DataScannedInBytes', 0)
            }
        }

    def _should_trigger_alert(
        self,
        query_result: Dict[str, Any],
        threshold: Dict[str, Any]
    ) -> bool:
        """Determine if alert should be triggered based on threshold."""
        result_count = len(query_result.get('results', []))

        threshold_type = threshold.get('type', 'count')
        threshold_value = threshold.get('value', 0)

        if threshold_type == 'count':
            return result_count > threshold_value
        elif threshold_type == 'any':
            return result_count > 0
        else:
            return False

    def _create_alert(
        self,
        rule: Dict[str, Any],
        query_result: Dict[str, Any]
    ) -> Alert:
        """Create alert from rule and query result."""
        import uuid

        alert_id = f"alert-{uuid.uuid4()}"

        return Alert(
            alert_id=alert_id,
            rule_id=rule['rule_id'],
            rule_name=rule['name'],
            severity=rule.get('severity', 'medium'),
            summary=f"{len(query_result['results'])} matches for {rule['name']}",
            description=rule.get('description', ''),
            query=rule['query'],
            result_count=len(query_result['results']),
            results=query_result['results'][:10],
            timestamp=datetime.utcnow().isoformat() + 'Z',
            metadata={
                'execution_time_ms': query_result['statistics']['execution_time_ms'],
                'data_scanned_bytes': query_result['statistics']['data_scanned_bytes']
            }
        )

    def _get_output_location(self) -> str:
        """Get S3 output location."""
        import os
        bucket = os.environ.get('ATHENA_OUTPUT_BUCKET', 'mantissa-log-athena-results')
        return f's3://{bucket}/detections/'

    def _get_table_name(self, table_type: str) -> str:
        """Get DynamoDB table name."""
        import os
        prefix = os.environ.get('TABLE_PREFIX', 'mantissa-log')
        env = os.environ.get('ENVIRONMENT', 'dev')
        return f'{prefix}-{table_type}-{env}'


def lambda_handler(event, context):
    """
    Lambda handler for scheduled detection execution.

    Triggered by EventBridge on schedule.
    Event contains:
    {
        "rule_id": "rule-123",
        "user_id": "user-456"
    }
    """
    try:
        rule_id = event.get('rule_id')
        user_id = event.get('user_id')

        if not rule_id or not user_id:
            raise ValueError('rule_id and user_id are required')

        executor = DetectionRuleExecutor()
        result = executor.execute_rule(rule_id, user_id)

        print(f"Detection execution result: {json.dumps(result)}")

        return {
            'statusCode': 200,
            'body': json.dumps(result)
        }

    except Exception as e:
        print(f"Error executing detection: {str(e)}")
        import traceback
        traceback.print_exc()

        return {
            'statusCode': 500,
            'body': json.dumps({'error': str(e)})
        }
