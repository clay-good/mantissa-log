"""
Integration Health Monitoring

Tracks the health status of external integrations (Slack, Jira, PagerDuty, etc.)
by monitoring success/failure rates, response times, and availability.
"""

import os
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
from enum import Enum
from dataclasses import dataclass, asdict
import boto3
from decimal import Decimal


class HealthStatus(Enum):
    """Health status levels for integrations."""
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNHEALTHY = "unhealthy"
    UNKNOWN = "unknown"


@dataclass
class HealthMetrics:
    """Health metrics for an integration."""
    total_requests: int
    successful_requests: int
    failed_requests: int
    success_rate: float
    avg_response_time_ms: float
    last_success: Optional[str]
    last_failure: Optional[str]
    consecutive_failures: int
    status: HealthStatus


class IntegrationHealthMonitor:
    """Monitors and tracks integration health."""

    def __init__(self, table_name: Optional[str] = None):
        """
        Initialize health monitor.

        Args:
            table_name: DynamoDB table for health metrics
        """
        self.table_name = table_name or os.environ.get(
            'INTEGRATION_HEALTH_TABLE',
            'mantissa-log-integration-health'
        )
        self.dynamodb = boto3.resource('dynamodb')
        self.table = self.dynamodb.Table(self.table_name)

    def record_request(
        self,
        user_id: str,
        integration_type: str,
        integration_id: str,
        success: bool,
        response_time_ms: float,
        error_message: Optional[str] = None
    ):
        """
        Record an integration request for health tracking.

        Args:
            user_id: User ID
            integration_type: Type of integration (slack, jira, etc.)
            integration_id: Specific integration instance ID
            success: Whether request succeeded
            response_time_ms: Response time in milliseconds
            error_message: Optional error message if failed
        """
        timestamp = datetime.utcnow().isoformat() + 'Z'

        # Store individual request record
        self.table.put_item(Item={
            'pk': f'user#{user_id}#integration#{integration_id}',
            'sk': f'request#{timestamp}',
            'user_id': user_id,
            'integration_type': integration_type,
            'integration_id': integration_id,
            'timestamp': timestamp,
            'success': success,
            'response_time_ms': Decimal(str(response_time_ms)),
            'error_message': error_message or '',
            'ttl': int(datetime.utcnow().timestamp()) + (30 * 24 * 60 * 60)  # 30 days
        })

        # Update aggregated metrics
        self._update_metrics(
            user_id,
            integration_id,
            integration_type,
            success,
            response_time_ms,
            timestamp,
            error_message
        )

    def _update_metrics(
        self,
        user_id: str,
        integration_id: str,
        integration_type: str,
        success: bool,
        response_time_ms: float,
        timestamp: str,
        error_message: Optional[str]
    ):
        """Update aggregated health metrics."""
        pk = f'user#{user_id}#integration#{integration_id}'
        sk = 'metrics#current'

        try:
            # Get current metrics
            response = self.table.get_item(
                Key={'pk': pk, 'sk': sk}
            )

            if 'Item' in response:
                metrics = response['Item']
                total = int(metrics.get('total_requests', 0)) + 1
                successful = int(metrics.get('successful_requests', 0)) + (1 if success else 0)
                failed = int(metrics.get('failed_requests', 0)) + (0 if success else 1)

                # Calculate rolling average response time
                current_avg = float(metrics.get('avg_response_time_ms', 0))
                new_avg = ((current_avg * (total - 1)) + response_time_ms) / total

                # Track consecutive failures
                if success:
                    consecutive_failures = 0
                    last_success = timestamp
                    last_failure = metrics.get('last_failure')
                else:
                    consecutive_failures = int(metrics.get('consecutive_failures', 0)) + 1
                    last_success = metrics.get('last_success')
                    last_failure = timestamp
            else:
                # First request for this integration
                total = 1
                successful = 1 if success else 0
                failed = 0 if success else 1
                new_avg = response_time_ms
                consecutive_failures = 0 if success else 1
                last_success = timestamp if success else None
                last_failure = timestamp if not success else None

            # Calculate success rate
            success_rate = (successful / total * 100) if total > 0 else 0

            # Determine health status
            status = self._determine_status(
                success_rate,
                consecutive_failures,
                new_avg
            )

            # Update metrics
            self.table.put_item(Item={
                'pk': pk,
                'sk': sk,
                'user_id': user_id,
                'integration_type': integration_type,
                'integration_id': integration_id,
                'total_requests': total,
                'successful_requests': successful,
                'failed_requests': failed,
                'success_rate': Decimal(str(round(success_rate, 2))),
                'avg_response_time_ms': Decimal(str(round(new_avg, 2))),
                'last_success': last_success or '',
                'last_failure': last_failure or '',
                'last_error': error_message or '',
                'consecutive_failures': consecutive_failures,
                'status': status.value,
                'updated_at': timestamp
            })

        except Exception as e:
            print(f'Error updating health metrics: {e}')

    def _determine_status(
        self,
        success_rate: float,
        consecutive_failures: int,
        avg_response_time_ms: float
    ) -> HealthStatus:
        """
        Determine health status based on metrics.

        Args:
            success_rate: Percentage of successful requests
            consecutive_failures: Number of consecutive failures
            avg_response_time_ms: Average response time

        Returns:
            Health status
        """
        # Unhealthy: 3+ consecutive failures OR success rate < 50%
        if consecutive_failures >= 3 or success_rate < 50:
            return HealthStatus.UNHEALTHY

        # Degraded: 1-2 consecutive failures OR success rate 50-90% OR slow responses
        if (consecutive_failures > 0 or
            success_rate < 90 or
            avg_response_time_ms > 5000):
            return HealthStatus.DEGRADED

        # Healthy: Success rate >= 90% AND no recent failures AND good performance
        return HealthStatus.HEALTHY

    def get_health(
        self,
        user_id: str,
        integration_id: str
    ) -> Optional[HealthMetrics]:
        """
        Get current health metrics for an integration.

        Args:
            user_id: User ID
            integration_id: Integration instance ID

        Returns:
            Health metrics or None if not found
        """
        pk = f'user#{user_id}#integration#{integration_id}'
        sk = 'metrics#current'

        try:
            response = self.table.get_item(
                Key={'pk': pk, 'sk': sk}
            )

            if 'Item' not in response:
                return None

            item = response['Item']

            return HealthMetrics(
                total_requests=int(item.get('total_requests', 0)),
                successful_requests=int(item.get('successful_requests', 0)),
                failed_requests=int(item.get('failed_requests', 0)),
                success_rate=float(item.get('success_rate', 0)),
                avg_response_time_ms=float(item.get('avg_response_time_ms', 0)),
                last_success=item.get('last_success') or None,
                last_failure=item.get('last_failure') or None,
                consecutive_failures=int(item.get('consecutive_failures', 0)),
                status=HealthStatus(item.get('status', 'unknown'))
            )

        except Exception as e:
            print(f'Error fetching health metrics: {e}')
            return None

    def get_all_health(self, user_id: str) -> Dict[str, HealthMetrics]:
        """
        Get health metrics for all integrations for a user.

        Args:
            user_id: User ID

        Returns:
            Dictionary mapping integration_id to health metrics
        """
        from boto3.dynamodb.conditions import Key

        try:
            response = self.table.query(
                KeyConditionExpression=
                    Key('pk').begins_with(f'user#{user_id}#integration#') &
                    Key('sk').eq('metrics#current')
            )

            health_map = {}
            for item in response.get('Items', []):
                integration_id = item.get('integration_id')
                if integration_id:
                    health_map[integration_id] = HealthMetrics(
                        total_requests=int(item.get('total_requests', 0)),
                        successful_requests=int(item.get('successful_requests', 0)),
                        failed_requests=int(item.get('failed_requests', 0)),
                        success_rate=float(item.get('success_rate', 0)),
                        avg_response_time_ms=float(item.get('avg_response_time_ms', 0)),
                        last_success=item.get('last_success') or None,
                        last_failure=item.get('last_failure') or None,
                        consecutive_failures=int(item.get('consecutive_failures', 0)),
                        status=HealthStatus(item.get('status', 'unknown'))
                    )

            return health_map

        except Exception as e:
            print(f'Error fetching all health metrics: {e}')
            return {}

    def get_recent_failures(
        self,
        user_id: str,
        integration_id: str,
        hours: int = 24
    ) -> List[Dict[str, Any]]:
        """
        Get recent failures for an integration.

        Args:
            user_id: User ID
            integration_id: Integration instance ID
            hours: Number of hours to look back

        Returns:
            List of recent failure records
        """
        from boto3.dynamodb.conditions import Key

        pk = f'user#{user_id}#integration#{integration_id}'
        cutoff_time = (datetime.utcnow() - timedelta(hours=hours)).isoformat() + 'Z'

        try:
            response = self.table.query(
                KeyConditionExpression=
                    Key('pk').eq(pk) &
                    Key('sk').between(f'request#{cutoff_time}', f'request#9999-12-31')
            )

            failures = []
            for item in response.get('Items', []):
                if not item.get('success', True):
                    failures.append({
                        'timestamp': item.get('timestamp'),
                        'response_time_ms': float(item.get('response_time_ms', 0)),
                        'error_message': item.get('error_message', 'Unknown error')
                    })

            return sorted(failures, key=lambda x: x['timestamp'], reverse=True)

        except Exception as e:
            print(f'Error fetching recent failures: {e}')
            return []

    def reset_metrics(self, user_id: str, integration_id: str):
        """
        Reset health metrics for an integration.

        Args:
            user_id: User ID
            integration_id: Integration instance ID
        """
        pk = f'user#{user_id}#integration#{integration_id}'
        sk = 'metrics#current'

        try:
            self.table.delete_item(
                Key={'pk': pk, 'sk': sk}
            )
        except Exception as e:
            print(f'Error resetting metrics: {e}')


def check_integration_health(
    user_id: str,
    integration_id: str
) -> HealthMetrics:
    """
    Convenience function to check integration health.

    Args:
        user_id: User ID
        integration_id: Integration instance ID

    Returns:
        Health metrics (returns UNKNOWN status if not found)
    """
    monitor = IntegrationHealthMonitor()
    health = monitor.get_health(user_id, integration_id)

    if health is None:
        return HealthMetrics(
            total_requests=0,
            successful_requests=0,
            failed_requests=0,
            success_rate=0.0,
            avg_response_time_ms=0.0,
            last_success=None,
            last_failure=None,
            consecutive_failures=0,
            status=HealthStatus.UNKNOWN
        )

    return health
