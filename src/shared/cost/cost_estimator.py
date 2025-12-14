"""
Cost Estimation Engine

Tracks query performance and provides cost projections for detection rules
based on data scanned, execution frequency, and historical metrics.
"""

import os
import json
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, asdict
from decimal import Decimal
import boto3
import logging

logger = logging.getLogger(__name__)


@dataclass
class QueryCostMetrics:
    """Metrics for a single query execution."""
    query_id: str
    user_id: str
    rule_id: Optional[str]
    execution_time_ms: int
    data_scanned_bytes: int
    result_rows: int
    timestamp: str

    @property
    def data_scanned_mb(self) -> float:
        """Convert bytes to megabytes."""
        return self.data_scanned_bytes / (1024 * 1024)

    @property
    def data_scanned_gb(self) -> float:
        """Convert bytes to gigabytes."""
        return self.data_scanned_bytes / (1024 * 1024 * 1024)

    @property
    def athena_cost_usd(self) -> float:
        """Calculate Athena cost: $5 per TB scanned."""
        tb_scanned = self.data_scanned_bytes / (1024 * 1024 * 1024 * 1024)
        return tb_scanned * 5.0


@dataclass
class DetectionCostProjection:
    """Projected monthly cost for a detection rule."""
    rule_id: str
    rule_name: str

    # Query costs
    avg_data_scanned_mb: float
    executions_per_month: int
    athena_cost_monthly_usd: float

    # Lambda costs
    avg_execution_time_ms: int
    lambda_memory_mb: int
    lambda_cost_monthly_usd: float

    # Storage costs
    dynamodb_writes_per_month: int
    dynamodb_cost_monthly_usd: float

    # Alert delivery costs (typically $0 for Slack/Email)
    estimated_alerts_per_month: int
    alert_delivery_cost_usd: float

    # Total
    total_monthly_cost_usd: float

    # Optimization potential
    optimization_potential_usd: float
    optimization_suggestions: List[str]


class CostEstimator:
    """
    Estimates and tracks costs for queries and detection rules.

    Provides cost projections based on:
    - Historical query performance
    - Execution frequency
    - Data growth trends
    - AWS service pricing
    """

    def __init__(
        self,
        metrics_table: Optional[str] = None,
        athena_client: Optional[Any] = None
    ):
        """
        Initialize cost estimator.

        Args:
            metrics_table: DynamoDB table for query metrics
            athena_client: Boto3 Athena client
        """
        self.metrics_table_name = metrics_table or os.environ.get(
            'QUERY_METRICS_TABLE',
            'mantissa-log-query-metrics'
        )

        self.dynamodb = boto3.resource('dynamodb')
        self.metrics_table = self.dynamodb.Table(self.metrics_table_name)
        self.athena = athena_client or boto3.client('athena')

        # AWS Pricing (as of 2024)
        self.PRICING = {
            'athena_per_tb': 5.00,  # $5 per TB scanned
            'lambda_per_gb_second': 0.0000166667,  # $0.0000166667 per GB-second
            'lambda_requests_per_million': 0.20,  # $0.20 per 1M requests
            'dynamodb_write_per_million': 1.25,  # $1.25 per 1M write requests
            'dynamodb_read_per_million': 0.25,  # $0.25 per 1M read requests
            's3_storage_per_gb': 0.023,  # $0.023 per GB per month
            'sns_per_million': 0.50,  # $0.50 per 1M messages
        }

    def record_query_execution(
        self,
        query_id: str,
        user_id: str,
        execution_time_ms: int,
        data_scanned_bytes: int,
        result_rows: int,
        rule_id: Optional[str] = None
    ) -> QueryCostMetrics:
        """
        Record metrics for a query execution.

        Args:
            query_id: Athena query execution ID
            user_id: User who executed query
            execution_time_ms: Query execution time
            data_scanned_bytes: Bytes scanned by Athena
            result_rows: Number of rows returned
            rule_id: Optional detection rule ID

        Returns:
            QueryCostMetrics object
        """
        timestamp = datetime.utcnow().isoformat() + 'Z'

        metrics = QueryCostMetrics(
            query_id=query_id,
            user_id=user_id,
            rule_id=rule_id,
            execution_time_ms=execution_time_ms,
            data_scanned_bytes=data_scanned_bytes,
            result_rows=result_rows,
            timestamp=timestamp
        )

        # Store in DynamoDB
        self.metrics_table.put_item(Item={
            'pk': f'user#{user_id}',
            'sk': f'query#{timestamp}#{query_id}',
            'query_id': query_id,
            'rule_id': rule_id or '',
            'execution_time_ms': execution_time_ms,
            'data_scanned_bytes': data_scanned_bytes,
            'result_rows': result_rows,
            'athena_cost_usd': Decimal(str(metrics.athena_cost_usd)),
            'timestamp': timestamp,
            'ttl': int(datetime.utcnow().timestamp()) + (90 * 24 * 60 * 60)  # 90 days
        })

        return metrics

    def get_query_statistics(
        self,
        query_string: str,
        user_id: str,
        lookback_days: int = 30
    ) -> Dict[str, Any]:
        """
        Get historical statistics for similar queries.

        Args:
            query_string: SQL query to analyze
            user_id: User ID
            lookback_days: Days of history to analyze

        Returns:
            Dictionary with statistics
        """
        from boto3.dynamodb.conditions import Key

        cutoff_time = (
            datetime.utcnow() - timedelta(days=lookback_days)
        ).isoformat() + 'Z'

        try:
            # Query recent executions
            response = self.metrics_table.query(
                KeyConditionExpression=
                    Key('pk').eq(f'user#{user_id}') &
                    Key('sk').between(f'query#{cutoff_time}', f'query#9999-12-31'),
                Limit=1000
            )

            items = response.get('Items', [])

            if not items:
                return {
                    'sample_count': 0,
                    'avg_data_scanned_mb': 0,
                    'avg_execution_time_ms': 0,
                    'avg_cost_usd': 0
                }

            # Calculate statistics
            total_data = sum(int(item.get('data_scanned_bytes', 0)) for item in items)
            total_time = sum(int(item.get('execution_time_ms', 0)) for item in items)
            total_cost = sum(float(item.get('athena_cost_usd', 0)) for item in items)

            count = len(items)

            return {
                'sample_count': count,
                'avg_data_scanned_mb': (total_data / count) / (1024 * 1024),
                'avg_execution_time_ms': total_time / count,
                'avg_cost_usd': total_cost / count,
                'total_cost_period_usd': total_cost,
                'lookback_days': lookback_days
            }

        except Exception as e:
            logger.error(f'Error fetching query statistics: {e}')
            return {
                'sample_count': 0,
                'avg_data_scanned_mb': 0,
                'avg_execution_time_ms': 0,
                'avg_cost_usd': 0
            }

    def estimate_detection_cost(
        self,
        query_string: str,
        user_id: str,
        interval_minutes: int = 5,
        estimated_alerts_per_month: int = 10,
        lambda_memory_mb: int = 512,
        use_historical_data: bool = True
    ) -> DetectionCostProjection:
        """
        Estimate monthly cost for a detection rule.

        Args:
            query_string: SQL query for detection
            user_id: User ID
            interval_minutes: How often rule runs
            estimated_alerts_per_month: Expected alert count
            lambda_memory_mb: Lambda memory allocation
            use_historical_data: Use historical query stats if available

        Returns:
            DetectionCostProjection
        """
        # Calculate executions per month
        executions_per_month = (30 * 24 * 60) // interval_minutes

        # Get historical data or use defaults
        if use_historical_data:
            stats = self.get_query_statistics(query_string, user_id)
            avg_data_scanned_mb = stats['avg_data_scanned_mb']
            avg_execution_time_ms = int(stats['avg_execution_time_ms'])

            # If no historical data, use conservative estimates
            if avg_data_scanned_mb == 0:
                avg_data_scanned_mb = 100  # 100 MB default
                avg_execution_time_ms = 2000  # 2 seconds default
        else:
            # Default estimates for new queries
            avg_data_scanned_mb = 100
            avg_execution_time_ms = 2000

        # 1. Athena query costs
        total_data_scanned_gb = (avg_data_scanned_mb * executions_per_month) / 1024
        total_data_scanned_tb = total_data_scanned_gb / 1024
        athena_cost_monthly = total_data_scanned_tb * self.PRICING['athena_per_tb']

        # 2. Lambda execution costs
        # GB-seconds = (memory_mb / 1024) * (execution_time_ms / 1000) * executions
        gb_seconds = (lambda_memory_mb / 1024) * (avg_execution_time_ms / 1000) * executions_per_month
        lambda_compute_cost = gb_seconds * self.PRICING['lambda_per_gb_second']
        lambda_request_cost = (executions_per_month / 1_000_000) * self.PRICING['lambda_requests_per_million']
        lambda_cost_monthly = lambda_compute_cost + lambda_request_cost

        # 3. DynamoDB costs (state tracking)
        dynamodb_writes = executions_per_month  # One write per execution
        dynamodb_cost_monthly = (dynamodb_writes / 1_000_000) * self.PRICING['dynamodb_write_per_million']

        # 4. Alert delivery costs
        # Slack/Email are typically free via webhooks
        # SNS/SQS have minimal costs
        alert_delivery_cost = (estimated_alerts_per_month / 1_000_000) * self.PRICING['sns_per_million']

        # Total cost
        total_monthly_cost = (
            athena_cost_monthly +
            lambda_cost_monthly +
            dynamodb_cost_monthly +
            alert_delivery_cost
        )

        # Generate optimization suggestions
        optimization_suggestions = []
        optimization_potential = 0.0

        # Suggest partition optimization if scanning > 500 MB
        if avg_data_scanned_mb > 500:
            potential_reduction = avg_data_scanned_mb * 0.7  # 70% reduction possible
            optimization_potential += (
                (potential_reduction * executions_per_month / 1024 / 1024) *
                self.PRICING['athena_per_tb']
            )
            optimization_suggestions.append(
                f'Add partition filters to reduce data scanned from '
                f'{avg_data_scanned_mb:.0f}MB to ~{avg_data_scanned_mb * 0.3:.0f}MB '
                f'(save ~${optimization_potential:.2f}/month)'
            )

        # Suggest reducing frequency if cost > $5/month
        if total_monthly_cost > 5.0 and interval_minutes < 15:
            new_interval = interval_minutes * 3
            new_executions = (30 * 24 * 60) // new_interval
            new_cost = (total_monthly_cost / executions_per_month) * new_executions
            savings = total_monthly_cost - new_cost
            optimization_suggestions.append(
                f'Increase interval from {interval_minutes} to {new_interval} minutes '
                f'(save ${savings:.2f}/month)'
            )

        # Suggest column pruning if execution time > 5 seconds
        if avg_execution_time_ms > 5000:
            optimization_suggestions.append(
                f'Select only needed columns instead of SELECT * '
                f'to reduce execution time from {avg_execution_time_ms/1000:.1f}s'
            )

        return DetectionCostProjection(
            rule_id='',  # Filled in by caller
            rule_name='',  # Filled in by caller
            avg_data_scanned_mb=avg_data_scanned_mb,
            executions_per_month=executions_per_month,
            athena_cost_monthly_usd=athena_cost_monthly,
            avg_execution_time_ms=avg_execution_time_ms,
            lambda_memory_mb=lambda_memory_mb,
            lambda_cost_monthly_usd=lambda_cost_monthly,
            dynamodb_writes_per_month=dynamodb_writes,
            dynamodb_cost_monthly_usd=dynamodb_cost_monthly,
            estimated_alerts_per_month=estimated_alerts_per_month,
            alert_delivery_cost_usd=alert_delivery_cost,
            total_monthly_cost_usd=total_monthly_cost,
            optimization_potential_usd=optimization_potential,
            optimization_suggestions=optimization_suggestions
        )

    def get_user_cost_summary(
        self,
        user_id: str,
        period_days: int = 30
    ) -> Dict[str, Any]:
        """
        Get cost summary for a user over a time period.

        Args:
            user_id: User ID
            period_days: Days to analyze

        Returns:
            Cost summary dictionary
        """
        from boto3.dynamodb.conditions import Key

        cutoff_time = (
            datetime.utcnow() - timedelta(days=period_days)
        ).isoformat() + 'Z'

        try:
            response = self.metrics_table.query(
                KeyConditionExpression=
                    Key('pk').eq(f'user#{user_id}') &
                    Key('sk').between(f'query#{cutoff_time}', f'query#9999-12-31')
            )

            items = response.get('Items', [])

            if not items:
                return {
                    'period_days': period_days,
                    'total_queries': 0,
                    'total_cost_usd': 0,
                    'avg_cost_per_query_usd': 0,
                    'total_data_scanned_gb': 0,
                    'by_rule': {}
                }

            # Aggregate by rule
            by_rule = {}
            total_cost = 0
            total_data = 0

            for item in items:
                rule_id = item.get('rule_id', 'ad_hoc')
                cost = float(item.get('athena_cost_usd', 0))
                data_bytes = int(item.get('data_scanned_bytes', 0))

                if rule_id not in by_rule:
                    by_rule[rule_id] = {
                        'query_count': 0,
                        'total_cost_usd': 0,
                        'total_data_scanned_gb': 0
                    }

                by_rule[rule_id]['query_count'] += 1
                by_rule[rule_id]['total_cost_usd'] += cost
                by_rule[rule_id]['total_data_scanned_gb'] += data_bytes / (1024 * 1024 * 1024)

                total_cost += cost
                total_data += data_bytes

            return {
                'period_days': period_days,
                'total_queries': len(items),
                'total_cost_usd': total_cost,
                'avg_cost_per_query_usd': total_cost / len(items),
                'total_data_scanned_gb': total_data / (1024 * 1024 * 1024),
                'projected_monthly_cost_usd': (total_cost / period_days) * 30,
                'by_rule': by_rule
            }

        except Exception as e:
            logger.error(f'Error generating cost summary: {e}')
            return {
                'period_days': period_days,
                'total_queries': 0,
                'total_cost_usd': 0,
                'error': str(e)
            }

    def optimize_query_for_cost(
        self,
        query_string: str
    ) -> Dict[str, Any]:
        """
        Analyze query and suggest cost optimizations.

        Args:
            query_string: SQL query to optimize

        Returns:
            Dictionary with optimization suggestions
        """
        suggestions = []

        query_upper = query_string.upper()

        # Check for partition filters
        if 'eventdate >=' not in query_upper and 'eventdate =' not in query_upper:
            suggestions.append({
                'severity': 'high',
                'type': 'missing_partition_filter',
                'message': 'Add partition filter on eventdate to reduce data scanned',
                'example': "WHERE eventdate >= CURRENT_DATE - INTERVAL '1' DAY",
                'potential_savings': '70-90% reduction in data scanned'
            })

        # Check for SELECT *
        if 'SELECT *' in query_upper or 'SELECT\n*' in query_string:
            suggestions.append({
                'severity': 'medium',
                'type': 'select_all',
                'message': 'Select only needed columns instead of SELECT *',
                'example': 'SELECT eventtime, eventname, sourceipaddress FROM ...',
                'potential_savings': '30-50% reduction in data scanned'
            })

        # Check for missing LIMIT
        if 'LIMIT' not in query_upper and 'GROUP BY' not in query_upper:
            suggestions.append({
                'severity': 'low',
                'type': 'missing_limit',
                'message': 'Add LIMIT clause to cap result size',
                'example': 'LIMIT 1000',
                'potential_savings': 'Faster execution, no data scan savings'
            })

        # Check for LIKE on both sides
        if query_upper.count('%') >= 4:  # Multiple LIKE patterns
            suggestions.append({
                'severity': 'medium',
                'type': 'multiple_like_patterns',
                'message': 'Multiple LIKE patterns slow queries - consider exact matches',
                'example': "eventname IN ('CreateUser', 'DeleteUser') instead of LIKE '%User%'",
                'potential_savings': 'Faster execution'
            })

        # Check for JOINs without partition filters
        if 'JOIN' in query_upper and query_upper.count('eventdate >=') < 2:
            suggestions.append({
                'severity': 'high',
                'type': 'join_missing_partition',
                'message': 'Add partition filters to both sides of JOIN',
                'example': 'Both tables should have WHERE eventdate >= CURRENT_DATE - INTERVAL ...',
                'potential_savings': '80-95% reduction in data scanned'
            })

        return {
            'query': query_string,
            'total_suggestions': len(suggestions),
            'suggestions': suggestions,
            'estimated_improvement': self._calculate_improvement_estimate(suggestions)
        }

    def _calculate_improvement_estimate(self, suggestions: List[Dict]) -> str:
        """Calculate potential improvement from suggestions."""
        if not suggestions:
            return 'Query is well optimized'

        high_severity = len([s for s in suggestions if s['severity'] == 'high'])
        medium_severity = len([s for s in suggestions if s['severity'] == 'medium'])

        if high_severity >= 2:
            return 'Potential 80-95% cost reduction'
        elif high_severity == 1:
            return 'Potential 50-80% cost reduction'
        elif medium_severity >= 2:
            return 'Potential 30-50% cost reduction'
        else:
            return 'Potential 10-30% cost reduction'


def estimate_query_cost(
    query_string: str,
    user_id: str,
    interval_minutes: int = 5
) -> Dict[str, Any]:
    """
    Convenience function to estimate query cost.

    Args:
        query_string: SQL query
        user_id: User ID
        interval_minutes: Detection interval

    Returns:
        Cost projection dictionary
    """
    estimator = CostEstimator()
    projection = estimator.estimate_detection_cost(
        query_string,
        user_id,
        interval_minutes
    )

    return asdict(projection)


def get_optimization_suggestions(query_string: str) -> List[Dict[str, str]]:
    """
    Convenience function to get query optimization suggestions.

    Args:
        query_string: SQL query

    Returns:
        List of optimization suggestions
    """
    estimator = CostEstimator()
    result = estimator.optimize_query_for_cost(query_string)

    return result['suggestions']
