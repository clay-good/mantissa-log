"""
Dead Letter Queue Handler

Handles alerts that failed to send after all retries, storing them for
manual review, retry, or alerting on integration failures.
"""

import os
import json
from datetime import datetime
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, asdict
from enum import Enum
import boto3


class FailureReason(Enum):
    """Reasons for alert delivery failure."""
    RETRIES_EXHAUSTED = "retries_exhausted"
    CIRCUIT_BREAKER_OPEN = "circuit_breaker_open"
    INVALID_CONFIGURATION = "invalid_configuration"
    INTEGRATION_ERROR = "integration_error"
    TIMEOUT = "timeout"
    RATE_LIMIT = "rate_limit"
    UNKNOWN = "unknown"


@dataclass
class FailedAlert:
    """Represents a failed alert in the DLQ."""
    user_id: str
    alert_id: str
    rule_id: str
    rule_name: str
    integration_type: str
    integration_id: str
    alert_data: Dict[str, Any]
    failure_reason: FailureReason
    error_message: str
    attempt_count: int
    first_attempt: str
    last_attempt: str
    payload: Dict[str, Any]


class DeadLetterQueueHandler:
    """
    Handles failed alerts that couldn't be delivered to integrations.

    Failed alerts are stored in DynamoDB for:
    - Manual review and retry
    - Alerting on integration failures
    - Analysis of failure patterns
    """

    def __init__(self, table_name: Optional[str] = None):
        """
        Initialize DLQ handler.

        Args:
            table_name: DynamoDB table for failed alerts
        """
        self.table_name = table_name or os.environ.get(
            'ALERT_DLQ_TABLE',
            'mantissa-log-alert-dlq'
        )
        self.dynamodb = boto3.resource('dynamodb')
        self.table = self.dynamodb.Table(self.table_name)

    def add_failed_alert(
        self,
        user_id: str,
        alert_id: str,
        rule_id: str,
        rule_name: str,
        integration_type: str,
        integration_id: str,
        alert_data: Dict[str, Any],
        payload: Dict[str, Any],
        failure_reason: FailureReason,
        error_message: str,
        attempt_count: int
    ):
        """
        Add a failed alert to the DLQ.

        Args:
            user_id: User ID
            alert_id: Unique alert ID
            rule_id: Detection rule ID
            rule_name: Detection rule name
            integration_type: Type of integration (slack, jira, etc.)
            integration_id: Specific integration instance ID
            alert_data: Original alert data
            payload: Payload that failed to send
            failure_reason: Reason for failure
            error_message: Error message
            attempt_count: Number of attempts made
        """
        timestamp = datetime.utcnow().isoformat() + 'Z'

        self.table.put_item(Item={
            'pk': f'user#{user_id}',
            'sk': f'failed#{timestamp}#{alert_id}',
            'user_id': user_id,
            'alert_id': alert_id,
            'rule_id': rule_id,
            'rule_name': rule_name,
            'integration_type': integration_type,
            'integration_id': integration_id,
            'alert_data': json.dumps(alert_data),
            'payload': json.dumps(payload),
            'failure_reason': failure_reason.value,
            'error_message': error_message,
            'attempt_count': attempt_count,
            'first_attempt': alert_data.get('timestamp', timestamp),
            'last_attempt': timestamp,
            'status': 'failed',
            'created_at': timestamp,
            'ttl': int(datetime.utcnow().timestamp()) + (90 * 24 * 60 * 60)  # 90 days
        })

    def get_failed_alerts(
        self,
        user_id: str,
        limit: int = 100,
        status: Optional[str] = None
    ) -> List[FailedAlert]:
        """
        Get failed alerts for a user.

        Args:
            user_id: User ID
            limit: Maximum number of alerts to return
            status: Optional status filter (failed, retried, resolved)

        Returns:
            List of failed alerts
        """
        from boto3.dynamodb.conditions import Key

        try:
            query_kwargs = {
                'KeyConditionExpression':
                    Key('pk').eq(f'user#{user_id}') &
                    Key('sk').begins_with('failed#'),
                'Limit': limit,
                'ScanIndexForward': False  # Most recent first
            }

            response = self.table.query(**query_kwargs)

            failed_alerts = []
            for item in response.get('Items', []):
                # Filter by status if specified
                if status and item.get('status') != status:
                    continue

                failed_alert = FailedAlert(
                    user_id=item.get('user_id', ''),
                    alert_id=item.get('alert_id', ''),
                    rule_id=item.get('rule_id', ''),
                    rule_name=item.get('rule_name', ''),
                    integration_type=item.get('integration_type', ''),
                    integration_id=item.get('integration_id', ''),
                    alert_data=json.loads(item.get('alert_data', '{}')),
                    failure_reason=FailureReason(item.get('failure_reason', 'unknown')),
                    error_message=item.get('error_message', ''),
                    attempt_count=int(item.get('attempt_count', 0)),
                    first_attempt=item.get('first_attempt', ''),
                    last_attempt=item.get('last_attempt', ''),
                    payload=json.loads(item.get('payload', '{}'))
                )
                failed_alerts.append(failed_alert)

            return failed_alerts

        except Exception as e:
            print(f'Error fetching failed alerts: {e}')
            return []

    def retry_failed_alert(
        self,
        user_id: str,
        alert_id: str,
        timestamp: str
    ) -> bool:
        """
        Retry sending a failed alert.

        Args:
            user_id: User ID
            alert_id: Alert ID
            timestamp: Timestamp from the failed alert SK

        Returns:
            True if retry succeeded
        """
        pk = f'user#{user_id}'
        sk = f'failed#{timestamp}#{alert_id}'

        try:
            # Get the failed alert
            response = self.table.get_item(
                Key={'pk': pk, 'sk': sk}
            )

            if 'Item' not in response:
                print(f'Failed alert not found: {alert_id}')
                return False

            item = response['Item']

            # Extract data for retry
            integration_type = item.get('integration_type')
            payload = json.loads(item.get('payload', '{}'))

            # TODO: Implement actual retry logic here
            # This would call the integration sender with the saved payload

            # Mark as retried
            self.table.update_item(
                Key={'pk': pk, 'sk': sk},
                UpdateExpression='SET #status = :status, retried_at = :timestamp',
                ExpressionAttributeNames={'#status': 'status'},
                ExpressionAttributeValues={
                    ':status': 'retried',
                    ':timestamp': datetime.utcnow().isoformat() + 'Z'
                }
            )

            return True

        except Exception as e:
            print(f'Error retrying failed alert: {e}')
            return False

    def mark_resolved(
        self,
        user_id: str,
        alert_id: str,
        timestamp: str,
        resolution_note: Optional[str] = None
    ):
        """
        Mark a failed alert as resolved.

        Args:
            user_id: User ID
            alert_id: Alert ID
            timestamp: Timestamp from the failed alert SK
            resolution_note: Optional note about resolution
        """
        pk = f'user#{user_id}'
        sk = f'failed#{timestamp}#{alert_id}'

        try:
            update_expr = 'SET #status = :status, resolved_at = :timestamp'
            expr_values = {
                ':status': 'resolved',
                ':timestamp': datetime.utcnow().isoformat() + 'Z'
            }

            if resolution_note:
                update_expr += ', resolution_note = :note'
                expr_values[':note'] = resolution_note

            self.table.update_item(
                Key={'pk': pk, 'sk': sk},
                UpdateExpression=update_expr,
                ExpressionAttributeNames={'#status': 'status'},
                ExpressionAttributeValues=expr_values
            )

        except Exception as e:
            print(f'Error marking alert resolved: {e}')

    def get_failure_stats(
        self,
        user_id: str,
        hours: int = 24
    ) -> Dict[str, Any]:
        """
        Get statistics on failed alerts.

        Args:
            user_id: User ID
            hours: Hours to look back

        Returns:
            Dictionary with failure statistics
        """
        from datetime import timedelta
        from boto3.dynamodb.conditions import Key

        cutoff_time = (datetime.utcnow() - timedelta(hours=hours)).isoformat() + 'Z'

        try:
            response = self.table.query(
                KeyConditionExpression=
                    Key('pk').eq(f'user#{user_id}') &
                    Key('sk').between(f'failed#{cutoff_time}', f'failed#9999-12-31')
            )

            items = response.get('Items', [])

            # Calculate stats
            total_failures = len(items)
            by_reason = {}
            by_integration = {}
            by_rule = {}

            for item in items:
                # By reason
                reason = item.get('failure_reason', 'unknown')
                by_reason[reason] = by_reason.get(reason, 0) + 1

                # By integration
                integration_type = item.get('integration_type', 'unknown')
                by_integration[integration_type] = by_integration.get(integration_type, 0) + 1

                # By rule
                rule_name = item.get('rule_name', 'unknown')
                by_rule[rule_name] = by_rule.get(rule_name, 0) + 1

            return {
                'total_failures': total_failures,
                'by_reason': by_reason,
                'by_integration': by_integration,
                'by_rule': by_rule,
                'time_window_hours': hours
            }

        except Exception as e:
            print(f'Error calculating failure stats: {e}')
            return {
                'total_failures': 0,
                'by_reason': {},
                'by_integration': {},
                'by_rule': {},
                'time_window_hours': hours
            }

    def cleanup_old_alerts(self, days: int = 90):
        """
        Cleanup failed alerts older than specified days.

        Note: This is handled automatically by DynamoDB TTL,
        but this method can be used for manual cleanup.

        Args:
            days: Delete alerts older than this many days
        """
        from datetime import timedelta
        from boto3.dynamodb.conditions import Attr

        cutoff_time = (datetime.utcnow() - timedelta(days=days)).isoformat() + 'Z'

        try:
            # Scan for old items (not efficient for large tables)
            response = self.table.scan(
                FilterExpression=Attr('created_at').lt(cutoff_time)
            )

            # Delete old items
            with self.table.batch_writer() as batch:
                for item in response.get('Items', []):
                    batch.delete_item(
                        Key={
                            'pk': item['pk'],
                            'sk': item['sk']
                        }
                    )

            print(f"Cleaned up {len(response.get('Items', []))} old failed alerts")

        except Exception as e:
            print(f'Error cleaning up old alerts: {e}')


def log_failed_alert(
    user_id: str,
    alert_id: str,
    rule_id: str,
    rule_name: str,
    integration_type: str,
    integration_id: str,
    alert_data: Dict[str, Any],
    payload: Dict[str, Any],
    failure_reason: FailureReason,
    error_message: str,
    attempt_count: int
):
    """
    Convenience function to log a failed alert.

    Args:
        user_id: User ID
        alert_id: Alert ID
        rule_id: Rule ID
        rule_name: Rule name
        integration_type: Integration type
        integration_id: Integration ID
        alert_data: Alert data
        payload: Failed payload
        failure_reason: Reason for failure
        error_message: Error message
        attempt_count: Number of attempts
    """
    handler = DeadLetterQueueHandler()
    handler.add_failed_alert(
        user_id,
        alert_id,
        rule_id,
        rule_name,
        integration_type,
        integration_id,
        alert_data,
        payload,
        failure_reason,
        error_message,
        attempt_count
    )
