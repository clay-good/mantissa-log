"""
Cost Projection Calculator

Calculates estimated monthly costs for detection rules based on:
- Athena query costs (data scanned)
- Lambda execution costs
- DynamoDB state storage costs
- Alert delivery costs
"""

from typing import Dict, Any
from dataclasses import dataclass


# AWS Pricing (US East 1, as of 2024)
ATHENA_COST_PER_TB = 5.00  # $5 per TB scanned
LAMBDA_COST_PER_GB_SECOND = 0.0000166667  # $0.0000166667 per GB-second
LAMBDA_COST_PER_REQUEST = 0.0000002  # $0.20 per 1M requests
DYNAMODB_COST_PER_WRITE = 0.00000125  # $1.25 per million writes
SNS_COST_PER_REQUEST = 0.0000005  # $0.50 per million requests


@dataclass
class QueryMetrics:
    """Metrics from a query execution"""
    data_scanned_bytes: int
    execution_time_ms: int
    result_count: int


@dataclass
class ScheduleConfig:
    """Detection rule schedule configuration"""
    interval_minutes: int  # Execution interval in minutes

    @property
    def executions_per_month(self) -> int:
        """Calculate number of executions per month"""
        # 30 days * 24 hours * 60 minutes / interval
        return int((30 * 24 * 60) / self.interval_minutes)


@dataclass
class CostBreakdown:
    """Detailed cost breakdown"""
    query_cost: float
    lambda_cost: float
    storage_cost: float
    alert_cost: float

    @property
    def total_cost(self) -> float:
        """Total estimated monthly cost"""
        return self.query_cost + self.lambda_cost + self.storage_cost + self.alert_cost


class CostCalculator:
    """Calculate projected monthly costs for detection rules"""

    def __init__(self):
        self.athena_cost_per_tb = ATHENA_COST_PER_TB
        self.lambda_cost_per_gb_second = LAMBDA_COST_PER_GB_SECOND
        self.lambda_cost_per_request = LAMBDA_COST_PER_REQUEST
        self.dynamodb_cost_per_write = DYNAMODB_COST_PER_WRITE
        self.sns_cost_per_request = SNS_COST_PER_REQUEST

    def calculate_query_cost(
        self,
        data_scanned_bytes: int,
        executions_per_month: int
    ) -> float:
        """
        Calculate Athena query cost.

        Args:
            data_scanned_bytes: Bytes scanned in a single query execution
            executions_per_month: Number of times query runs per month

        Returns:
            Estimated monthly query cost in dollars
        """
        # Convert bytes to TB
        data_scanned_tb = data_scanned_bytes / (1024 ** 4)

        # Total data scanned per month
        total_tb_per_month = data_scanned_tb * executions_per_month

        # Cost = TB scanned * $5/TB
        return total_tb_per_month * self.athena_cost_per_tb

    def calculate_lambda_cost(
        self,
        execution_time_ms: int,
        memory_mb: int,
        executions_per_month: int
    ) -> float:
        """
        Calculate Lambda execution cost.

        Args:
            execution_time_ms: Execution time in milliseconds
            memory_mb: Allocated memory in MB
            executions_per_month: Number of executions per month

        Returns:
            Estimated monthly Lambda cost in dollars
        """
        # Convert to seconds and GB
        execution_time_seconds = execution_time_ms / 1000
        memory_gb = memory_mb / 1024

        # GB-seconds per execution
        gb_seconds = execution_time_seconds * memory_gb

        # Compute cost
        compute_cost = gb_seconds * executions_per_month * self.lambda_cost_per_gb_second

        # Request cost
        request_cost = executions_per_month * self.lambda_cost_per_request

        return compute_cost + request_cost

    def calculate_storage_cost(
        self,
        executions_per_month: int
    ) -> float:
        """
        Calculate DynamoDB state storage cost.

        Args:
            executions_per_month: Number of executions per month

        Returns:
            Estimated monthly DynamoDB cost in dollars
        """
        # Each execution writes state (1 write per execution)
        total_writes = executions_per_month

        return total_writes * self.dynamodb_cost_per_write

    def calculate_alert_cost(
        self,
        estimated_alerts_per_month: int,
        alert_destinations: list
    ) -> float:
        """
        Calculate alert delivery cost.

        Args:
            estimated_alerts_per_month: Expected number of alerts
            alert_destinations: List of alert types (slack, email, sns, etc.)

        Returns:
            Estimated monthly alert delivery cost in dollars
        """
        cost = 0.0

        for destination in alert_destinations:
            if destination == 'sns':
                # SNS publishing cost
                cost += estimated_alerts_per_month * self.sns_cost_per_request
            elif destination in ['slack', 'email', 'jira', 'pagerduty']:
                # These use Lambda/HTTP which is already counted
                # Minimal additional cost
                cost += 0.0

        return cost

    def calculate_total_cost(
        self,
        query_metrics: QueryMetrics,
        schedule: ScheduleConfig,
        lambda_memory_mb: int = 512,
        estimated_alerts_per_month: int = 10,
        alert_destinations: list = None
    ) -> CostBreakdown:
        """
        Calculate total projected monthly cost.

        Args:
            query_metrics: Metrics from test query execution
            schedule: Detection rule schedule configuration
            lambda_memory_mb: Lambda memory allocation (default 512MB)
            estimated_alerts_per_month: Estimated alerts (default 10)
            alert_destinations: List of alert destinations

        Returns:
            Detailed cost breakdown
        """
        if alert_destinations is None:
            alert_destinations = []

        executions = schedule.executions_per_month

        query_cost = self.calculate_query_cost(
            query_metrics.data_scanned_bytes,
            executions
        )

        lambda_cost = self.calculate_lambda_cost(
            query_metrics.execution_time_ms,
            lambda_memory_mb,
            executions
        )

        storage_cost = self.calculate_storage_cost(executions)

        alert_cost = self.calculate_alert_cost(
            estimated_alerts_per_month,
            alert_destinations
        )

        return CostBreakdown(
            query_cost=query_cost,
            lambda_cost=lambda_cost,
            storage_cost=storage_cost,
            alert_cost=alert_cost
        )

    def format_cost_report(
        self,
        breakdown: CostBreakdown,
        query_metrics: QueryMetrics,
        schedule: ScheduleConfig,
        lambda_memory_mb: int = 512
    ) -> Dict[str, Any]:
        """
        Format cost breakdown as a detailed report.

        Args:
            breakdown: Cost breakdown
            query_metrics: Query metrics
            schedule: Schedule configuration
            lambda_memory_mb: Lambda memory allocation

        Returns:
            Formatted cost report dictionary
        """
        data_scanned_mb = query_metrics.data_scanned_bytes / (1024 ** 2)
        execution_time_sec = query_metrics.execution_time_ms / 1000

        return {
            'total_monthly_cost': round(breakdown.total_cost, 2),
            'breakdown': {
                'query_execution': {
                    'cost': round(breakdown.query_cost, 2),
                    'data_scanned_mb': round(data_scanned_mb, 2),
                    'runs_per_month': schedule.executions_per_month,
                    'description': f'{schedule.executions_per_month:,} executions × {data_scanned_mb:.2f}MB'
                },
                'lambda_execution': {
                    'cost': round(breakdown.lambda_cost, 4),
                    'avg_duration_sec': round(execution_time_sec, 2),
                    'memory_mb': lambda_memory_mb,
                    'executions': schedule.executions_per_month,
                    'description': f'{execution_time_sec:.2f}s @ {lambda_memory_mb}MB'
                },
                'state_storage': {
                    'cost': round(breakdown.storage_cost, 4),
                    'write_requests': schedule.executions_per_month,
                    'description': f'{schedule.executions_per_month:,} DynamoDB writes'
                },
                'alert_delivery': {
                    'cost': round(breakdown.alert_cost, 4),
                    'description': 'Estimated based on alert frequency'
                }
            },
            'notes': [
                'Costs are estimates based on AWS US-East-1 pricing',
                'Actual costs may vary based on data growth and alert frequency',
                'Query optimization can significantly reduce costs'
            ]
        }


def parse_schedule_string(schedule: str) -> ScheduleConfig:
    """
    Parse schedule string (e.g., 'rate(5 minutes)') to ScheduleConfig.

    Args:
        schedule: AWS EventBridge schedule expression

    Returns:
        ScheduleConfig object
    """
    schedule = schedule.lower()

    if 'rate(' in schedule:
        # Extract number and unit
        parts = schedule.replace('rate(', '').replace(')', '').strip().split()

        if len(parts) == 2:
            value = int(parts[0])
            unit = parts[1].rstrip('s')  # Remove trailing 's'

            if unit == 'minute':
                return ScheduleConfig(interval_minutes=value)
            elif unit == 'hour':
                return ScheduleConfig(interval_minutes=value * 60)
            elif unit == 'day':
                return ScheduleConfig(interval_minutes=value * 60 * 24)

    # Default to 5 minutes if parsing fails
    return ScheduleConfig(interval_minutes=5)
