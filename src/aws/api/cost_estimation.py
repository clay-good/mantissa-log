"""
Cost Estimation API

Provides cost projections for detection rules based on query performance metrics.

.. deprecated::
    This handler is deprecated in favor of `src/aws/api/cost_projection.py`
    which provides additional features including:
    - Cost tracking and actual vs projected comparisons
    - Monthly cost range estimation
    - Optimization suggestions
    - Full cost breakdown by service (Athena, Lambda, DynamoDB, etc.)

    Please migrate to cost_projection.py. This file will be removed in a future release.
"""

import warnings
warnings.warn(
    "cost_estimation.py is deprecated. Use cost_projection.py instead.",
    DeprecationWarning,
    stacklevel=2
)

import json
import logging
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
from auth import get_authenticated_user_id, AuthenticationError
from auth.cors import get_cors_headers, cors_preflight_response

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)


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
    # Handle CORS preflight
    http_method = event.get('httpMethod')
    if http_method == 'OPTIONS':
        return cors_preflight_response(event)

    try:
        # Authenticate user from Cognito JWT claims
        try:
            user_id = get_authenticated_user_id(event)
        except AuthenticationError:
            return error_response(event, 'Authentication required', 401)

        body = json.loads(event.get('body', '{}'))

        # Extract parameters
        query_metrics_data = body.get('queryMetrics', {})
        schedule_str = body.get('schedule', 'rate(5 minutes)')
        lambda_memory = body.get('lambdaMemoryMb', 512)
        estimated_alerts = body.get('estimatedAlertsPerMonth', 10)
        alert_destinations = body.get('alertDestinations', [])

        # Validate required fields
        if not query_metrics_data:
            return error_response(event, 'queryMetrics is required', 400)

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

        return success_response(event, report)

    except Exception as e:
        logger.error(f"Error calculating cost estimate: {str(e)}", exc_info=True)
        return error_response(event, 'Internal server error', 500)


def success_response(event: Dict[str, Any], data: Dict[str, Any]) -> Dict[str, Any]:
    """Return a success response with secure CORS headers."""
    return {
        'statusCode': 200,
        'headers': {
            'Content-Type': 'application/json',
            **get_cors_headers(event)
        },
        'body': json.dumps(data)
    }


def error_response(event: Dict[str, Any], message: str, status_code: int) -> Dict[str, Any]:
    """Return an error response with secure CORS headers."""
    return {
        'statusCode': status_code,
        'headers': {
            'Content-Type': 'application/json',
            **get_cors_headers(event)
        },
        'body': json.dumps({'error': message})
    }
