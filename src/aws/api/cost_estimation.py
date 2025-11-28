"""
Cost Estimation API

Provides cost projections for detection rules based on query performance metrics.
"""

import json
import sys
from pathlib import Path
from typing import Dict, Any

# Add shared utilities to path
sys.path.append(str(Path(__file__).parent.parent.parent / 'shared'))

from utils.cost_calculator import (
    CostCalculator,
    QueryMetrics,
    ScheduleConfig,
    parse_schedule_string
)


def lambda_handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """
    Lambda handler for cost estimation.

    Expected input:
    {
        "queryMetrics": {
            "dataScan nedBytes": 262144000,  // 250 MB
            "executionTimeMs": 2300,
            "resultCount": 15
        },
        "schedule": "rate(5 minutes)",
        "lambdaMemoryMb": 512,
        "estimatedAlertsPerMonth": 10,
        "alertDestinations": ["slack", "email"]
    }

    Returns:
    {
        "totalMonthlyCost": 0.14,
        "breakdown": {...},
        "notes": [...]
    }
    """
    try:
        body = json.loads(event.get('body', '{}'))

        # Extract parameters
        query_metrics_data = body.get('queryMetrics', {})
        schedule_str = body.get('schedule', 'rate(5 minutes)')
        lambda_memory = body.get('lambdaMemoryMb', 512)
        estimated_alerts = body.get('estimatedAlertsPerMonth', 10)
        alert_destinations = body.get('alertDestinations', [])

        # Validate required fields
        if not query_metrics_data:
            return error_response('queryMetrics is required', 400)

        # Create QueryMetrics object
        query_metrics = QueryMetrics(
            data_scanned_bytes=query_metrics_data.get('dataScannedBytes', 0),
            execution_time_ms=query_metrics_data.get('executionTimeMs', 1000),
            result_count=query_metrics_data.get('resultCount', 0)
        )

        # Parse schedule
        schedule = parse_schedule_string(schedule_str)

        # Calculate costs
        calculator = CostCalculator()
        breakdown = calculator.calculate_total_cost(
            query_metrics=query_metrics,
            schedule=schedule,
            lambda_memory_mb=lambda_memory,
            estimated_alerts_per_month=estimated_alerts,
            alert_destinations=alert_destinations
        )

        # Format report
        report = calculator.format_cost_report(
            breakdown=breakdown,
            query_metrics=query_metrics,
            schedule=schedule,
            lambda_memory_mb=lambda_memory
        )

        return success_response(report)

    except Exception as e:
        print(f"Error calculating cost estimate: {str(e)}")
        import traceback
        traceback.print_exc()
        return error_response(str(e), 500)


def success_response(data: Dict[str, Any]) -> Dict[str, Any]:
    """Return a success response"""
    return {
        'statusCode': 200,
        'headers': {
            'Content-Type': 'application/json',
            'Access-Control-Allow-Origin': '*'
        },
        'body': json.dumps(data)
    }


def error_response(message: str, status_code: int) -> Dict[str, Any]:
    """Return an error response"""
    return {
        'statusCode': status_code,
        'headers': {
            'Content-Type': 'application/json',
            'Access-Control-Allow-Origin': '*'
        },
        'body': json.dumps({'error': message})
    }
