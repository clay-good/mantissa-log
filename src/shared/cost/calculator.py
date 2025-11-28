"""
Cost Calculator

Calculates projected costs for detection rules based on query complexity,
execution frequency, and historical performance metrics.
"""

from typing import Dict, Any, Optional
from datetime import datetime, timedelta
import json


class CostCalculator:
    """Calculates projected costs for detections and queries."""

    # AWS Pricing (as of 2024)
    ATHENA_PRICE_PER_TB = 5.00  # $5 per TB scanned
    LAMBDA_PRICE_PER_GB_SECOND = 0.0000166667  # $0.0000166667 per GB-second
    LAMBDA_PRICE_PER_REQUEST = 0.0000002  # $0.20 per 1M requests
    DYNAMODB_WRITE_PRICE_PER_MILLION = 1.25  # $1.25 per million write requests
    DYNAMODB_READ_PRICE_PER_MILLION = 0.25  # $0.25 per million read requests
    SQS_PRICE_PER_MILLION = 0.40  # $0.40 per million requests
    SNS_PRICE_PER_MILLION = 0.50  # $0.50 per million notifications

    def __init__(self):
        pass

    def calculate_detection_cost(
        self,
        query_stats: Dict[str, Any],
        schedule_expression: str,
        estimated_alerts_per_month: int = 10
    ) -> Dict[str, Any]:
        """
        Calculate projected monthly cost for a detection rule.

        Args:
            query_stats: Statistics from test query execution
                {
                    'data_scanned_bytes': int,
                    'execution_time_ms': int,
                    'result_count': int
                }
            schedule_expression: Cron or rate expression (e.g., "rate(5 minutes)")
            estimated_alerts_per_month: Expected number of alerts per month

        Returns:
            Cost breakdown and total
        """
        # Calculate executions per month
        executions_per_month = self._calculate_executions_per_month(
            schedule_expression
        )

        # Calculate Athena query cost
        data_scanned_gb = query_stats.get('data_scanned_bytes', 0) / (1024 ** 3)
        data_scanned_tb = data_scanned_gb / 1024
        athena_cost_per_run = data_scanned_tb * self.ATHENA_PRICE_PER_TB
        athena_monthly_cost = athena_cost_per_run * executions_per_month

        # Calculate Lambda execution cost
        execution_time_seconds = query_stats.get('execution_time_ms', 0) / 1000
        lambda_memory_gb = 0.5  # 512 MB default
        lambda_gb_seconds = execution_time_seconds * lambda_memory_gb
        lambda_compute_cost = lambda_gb_seconds * self.LAMBDA_PRICE_PER_GB_SECOND
        lambda_request_cost = self.LAMBDA_PRICE_PER_REQUEST
        lambda_cost_per_run = lambda_compute_cost + lambda_request_cost
        lambda_monthly_cost = lambda_cost_per_run * executions_per_month

        # Calculate DynamoDB cost
        # Each execution: 1 read (get rule) + 1 write (update last_executed)
        # Each alert: 1 write (alert history)
        dynamodb_reads = executions_per_month
        dynamodb_writes = executions_per_month + estimated_alerts_per_month
        dynamodb_read_cost = (dynamodb_reads / 1_000_000) * self.DYNAMODB_READ_PRICE_PER_MILLION
        dynamodb_write_cost = (dynamodb_writes / 1_000_000) * self.DYNAMODB_WRITE_PRICE_PER_MILLION
        dynamodb_monthly_cost = dynamodb_read_cost + dynamodb_write_cost

        # Calculate Alert Delivery cost
        # SQS messages + integration delivery
        sqs_messages = estimated_alerts_per_month
        sqs_cost = (sqs_messages / 1_000_000) * self.SQS_PRICE_PER_MILLION

        # Integration delivery costs (Slack/Jira/etc are free on their end)
        # We only pay for our Lambda invocations
        alert_lambda_cost = estimated_alerts_per_month * (
            self.LAMBDA_PRICE_PER_REQUEST +
            (0.256 * 1.0 * self.LAMBDA_PRICE_PER_GB_SECOND)  # 256MB, 1s avg
        )

        alert_delivery_cost = sqs_cost + alert_lambda_cost

        # Calculate total
        total_monthly_cost = (
            athena_monthly_cost +
            lambda_monthly_cost +
            dynamodb_monthly_cost +
            alert_delivery_cost
        )

        return {
            'breakdown': {
                'query_execution': {
                    'athena': {
                        'data_scanned_bytes': query_stats.get('data_scanned_bytes', 0),
                        'data_scanned_gb': round(data_scanned_gb, 4),
                        'cost_per_run': round(athena_cost_per_run, 6),
                        'runs_per_month': executions_per_month,
                        'monthly_cost': round(athena_monthly_cost, 2)
                    },
                    'lambda': {
                        'execution_time_ms': query_stats.get('execution_time_ms', 0),
                        'memory_mb': 512,
                        'cost_per_run': round(lambda_cost_per_run, 6),
                        'runs_per_month': executions_per_month,
                        'monthly_cost': round(lambda_monthly_cost, 2)
                    }
                },
                'state_storage': {
                    'dynamodb': {
                        'read_requests': dynamodb_reads,
                        'write_requests': dynamodb_writes,
                        'monthly_cost': round(dynamodb_monthly_cost, 2)
                    }
                },
                'alert_delivery': {
                    'estimated_alerts': estimated_alerts_per_month,
                    'sqs_cost': round(sqs_cost, 2),
                    'lambda_cost': round(alert_lambda_cost, 2),
                    'monthly_cost': round(alert_delivery_cost, 2)
                }
            },
            'total_monthly_cost': round(total_monthly_cost, 2),
            'executions_per_month': executions_per_month,
            'schedule_expression': schedule_expression,
            'cost_per_execution': round(total_monthly_cost / executions_per_month, 6) if executions_per_month > 0 else 0
        }

    def calculate_query_cost(
        self,
        data_scanned_bytes: int,
        execution_time_ms: int
    ) -> Dict[str, Any]:
        """
        Calculate cost for a single ad-hoc query.

        Args:
            data_scanned_bytes: Bytes scanned by Athena
            execution_time_ms: Query execution time in milliseconds

        Returns:
            Cost breakdown
        """
        # Athena cost
        data_scanned_gb = data_scanned_bytes / (1024 ** 3)
        data_scanned_tb = data_scanned_gb / 1024
        athena_cost = data_scanned_tb * self.ATHENA_PRICE_PER_TB

        # Lambda cost
        execution_time_seconds = execution_time_ms / 1000
        lambda_memory_gb = 0.5  # 512 MB
        lambda_gb_seconds = execution_time_seconds * lambda_memory_gb
        lambda_cost = (
            lambda_gb_seconds * self.LAMBDA_PRICE_PER_GB_SECOND +
            self.LAMBDA_PRICE_PER_REQUEST
        )

        total_cost = athena_cost + lambda_cost

        return {
            'athena_cost': round(athena_cost, 6),
            'lambda_cost': round(lambda_cost, 6),
            'total_cost': round(total_cost, 6),
            'data_scanned_bytes': data_scanned_bytes,
            'data_scanned_gb': round(data_scanned_gb, 4),
            'execution_time_ms': execution_time_ms
        }

    def estimate_monthly_cost_range(
        self,
        query_stats: Dict[str, Any],
        schedule_expression: str
    ) -> Dict[str, Any]:
        """
        Estimate cost range based on different alert volumes.

        Args:
            query_stats: Query execution statistics
            schedule_expression: Schedule expression

        Returns:
            Cost estimates for low, medium, high alert volumes
        """
        # Calculate for different alert scenarios
        scenarios = {
            'low': 5,      # 5 alerts/month
            'medium': 20,  # 20 alerts/month
            'high': 100    # 100 alerts/month
        }

        estimates = {}
        for scenario, alert_count in scenarios.items():
            cost = self.calculate_detection_cost(
                query_stats,
                schedule_expression,
                estimated_alerts_per_month=alert_count
            )
            estimates[scenario] = {
                'alerts_per_month': alert_count,
                'total_monthly_cost': cost['total_monthly_cost']
            }

        return {
            'scenarios': estimates,
            'baseline_cost': estimates['low']['total_monthly_cost'],
            'worst_case_cost': estimates['high']['total_monthly_cost']
        }

    def _calculate_executions_per_month(self, schedule_expression: str) -> int:
        """
        Calculate number of executions per month from schedule expression.

        Args:
            schedule_expression: Cron or rate expression

        Returns:
            Number of executions per month
        """
        # Parse rate expressions
        if schedule_expression.startswith('rate('):
            # Extract rate value and unit
            rate_str = schedule_expression[5:-1]  # Remove 'rate(' and ')'
            parts = rate_str.split()

            if len(parts) != 2:
                return 0

            value = int(parts[0])
            unit = parts[1].lower()

            # Calculate executions per month (30 days)
            if unit.startswith('minute'):
                return int((30 * 24 * 60) / value)
            elif unit.startswith('hour'):
                return int((30 * 24) / value)
            elif unit.startswith('day'):
                return int(30 / value)
            elif unit.startswith('week'):
                return int(30 / (value * 7))

        # Parse cron expressions
        elif schedule_expression.startswith('cron('):
            # For cron, we need to estimate based on pattern
            # This is simplified - real implementation would parse cron properly
            cron_str = schedule_expression[5:-1]  # Remove 'cron(' and ')'

            # Common patterns
            if cron_str.startswith('0 * * * *'):  # Every hour
                return 30 * 24
            elif cron_str.startswith('0 0 * * *'):  # Daily
                return 30
            elif cron_str.startswith('0 0 * * 0'):  # Weekly
                return 4
            elif cron_str.startswith('0 0 1 * *'):  # Monthly
                return 1
            else:
                # Default to hourly if unknown
                return 30 * 24

        return 0

    def get_optimization_suggestions(
        self,
        query_stats: Dict[str, Any],
        cost_breakdown: Dict[str, Any]
    ) -> list:
        """
        Suggest optimizations to reduce costs.

        Args:
            query_stats: Query execution statistics
            cost_breakdown: Cost breakdown from calculate_detection_cost

        Returns:
            List of optimization suggestions
        """
        suggestions = []

        # Check data scanned
        data_scanned_gb = query_stats.get('data_scanned_bytes', 0) / (1024 ** 3)
        if data_scanned_gb > 1.0:
            suggestions.append({
                'category': 'data_scanning',
                'severity': 'high',
                'title': 'Large amount of data scanned',
                'description': f'Query scans {data_scanned_gb:.2f} GB per execution',
                'recommendation': 'Add partition filters (e.g., WHERE dt >= DATE_SUB(CURRENT_DATE, 7)) to reduce data scanned'
            })

        # Check execution frequency
        executions = cost_breakdown.get('executions_per_month', 0)
        if executions > 10000:  # More than every 4 minutes
            suggestions.append({
                'category': 'frequency',
                'severity': 'medium',
                'title': 'High execution frequency',
                'description': f'Rule executes {executions} times per month',
                'recommendation': 'Consider reducing frequency if real-time detection is not critical'
            })

        # Check query execution time
        execution_time_ms = query_stats.get('execution_time_ms', 0)
        if execution_time_ms > 5000:  # More than 5 seconds
            suggestions.append({
                'category': 'performance',
                'severity': 'medium',
                'title': 'Slow query execution',
                'description': f'Query takes {execution_time_ms/1000:.2f} seconds to execute',
                'recommendation': 'Optimize query with appropriate filters, partitions, and column selection'
            })

        # Check total cost
        total_cost = cost_breakdown.get('total_monthly_cost', 0)
        if total_cost > 10.00:
            suggestions.append({
                'category': 'cost',
                'severity': 'high',
                'title': 'High monthly cost',
                'description': f'Projected monthly cost is ${total_cost:.2f}',
                'recommendation': 'Consider optimizing query or reducing execution frequency'
            })
        elif total_cost > 5.00:
            suggestions.append({
                'category': 'cost',
                'severity': 'medium',
                'title': 'Moderate monthly cost',
                'description': f'Projected monthly cost is ${total_cost:.2f}',
                'recommendation': 'Monitor actual costs and optimize if needed'
            })

        return suggestions


class CostTracker:
    """Tracks actual costs and compares to projections."""

    def __init__(self, dynamodb_resource):
        self.dynamodb = dynamodb_resource

    def record_execution_cost(
        self,
        user_id: str,
        rule_id: str,
        execution_cost: Dict[str, Any]
    ):
        """
        Record actual cost for a detection execution.

        Args:
            user_id: User ID
            rule_id: Detection rule ID
            execution_cost: Actual execution cost details
        """
        table = self.dynamodb.Table(self._get_table_name('cost-tracking'))

        item = {
            'user_id': user_id,
            'record_id': f"{rule_id}#{datetime.utcnow().isoformat()}",
            'rule_id': rule_id,
            'timestamp': datetime.utcnow().isoformat() + 'Z',
            'data_scanned_bytes': execution_cost.get('data_scanned_bytes', 0),
            'execution_time_ms': execution_cost.get('execution_time_ms', 0),
            'athena_cost': execution_cost.get('athena_cost', 0),
            'lambda_cost': execution_cost.get('lambda_cost', 0),
            'total_cost': execution_cost.get('total_cost', 0)
        }

        table.put_item(Item=item)

    def get_actual_costs(
        self,
        user_id: str,
        rule_id: str,
        days: int = 30
    ) -> Dict[str, Any]:
        """
        Get actual costs for a rule over a time period.

        Args:
            user_id: User ID
            rule_id: Detection rule ID
            days: Number of days to look back

        Returns:
            Actual cost summary
        """
        table = self.dynamodb.Table(self._get_table_name('cost-tracking'))

        cutoff_date = datetime.utcnow() - timedelta(days=days)
        cutoff_str = cutoff_date.isoformat() + 'Z'

        # Query for rule executions
        response = table.query(
            KeyConditionExpression='user_id = :user_id AND begins_with(record_id, :rule_id)',
            FilterExpression='#ts >= :cutoff',
            ExpressionAttributeNames={'#ts': 'timestamp'},
            ExpressionAttributeValues={
                ':user_id': user_id,
                ':rule_id': rule_id,
                ':cutoff': cutoff_str
            }
        )

        items = response.get('Items', [])

        if not items:
            return {
                'rule_id': rule_id,
                'period_days': days,
                'executions': 0,
                'total_cost': 0,
                'avg_cost_per_execution': 0
            }

        # Calculate totals
        total_cost = sum(item.get('total_cost', 0) for item in items)
        total_data_scanned = sum(item.get('data_scanned_bytes', 0) for item in items)
        avg_execution_time = sum(item.get('execution_time_ms', 0) for item in items) / len(items)

        return {
            'rule_id': rule_id,
            'period_days': days,
            'executions': len(items),
            'total_cost': round(total_cost, 2),
            'avg_cost_per_execution': round(total_cost / len(items), 6),
            'total_data_scanned_bytes': total_data_scanned,
            'avg_execution_time_ms': round(avg_execution_time, 2),
            'projected_monthly_cost': round(total_cost * (30 / days), 2)
        }

    def compare_to_projection(
        self,
        user_id: str,
        rule_id: str,
        projected_cost: float,
        days: int = 30
    ) -> Dict[str, Any]:
        """
        Compare actual costs to projections.

        Args:
            user_id: User ID
            rule_id: Detection rule ID
            projected_cost: Projected monthly cost
            days: Number of days to analyze

        Returns:
            Comparison results
        """
        actual = self.get_actual_costs(user_id, rule_id, days)

        variance = actual['projected_monthly_cost'] - projected_cost
        variance_pct = (variance / projected_cost * 100) if projected_cost > 0 else 0

        status = 'on_track'
        if variance_pct > 20:
            status = 'over_budget'
        elif variance_pct < -20:
            status = 'under_budget'

        return {
            'rule_id': rule_id,
            'projected_monthly_cost': projected_cost,
            'actual_monthly_cost': actual['projected_monthly_cost'],
            'variance': round(variance, 2),
            'variance_percent': round(variance_pct, 2),
            'status': status,
            'period_days': days,
            'executions': actual['executions']
        }

    def _get_table_name(self, table_type: str) -> str:
        """Get DynamoDB table name."""
        import os
        prefix = os.environ.get('TABLE_PREFIX', 'mantissa-log')
        env = os.environ.get('ENVIRONMENT', 'dev')
        return f'{prefix}-{table_type}-{env}'
