"""
Cost Estimation API Handler

Lambda function to handle cost estimation API requests from the web UI.
"""

import json
import os
import sys
from typing import Dict, Any

# Add shared modules to path
sys.path.insert(0, '/opt/python')
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../../shared'))

from cost.cost_estimator import CostEstimator, estimate_query_cost, get_optimization_suggestions


def lambda_handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """
    Handle cost estimation API requests.

    Routes:
    - POST /cost/estimate - Full cost projection for detection rule
    - POST /cost/estimate-query - Quick cost estimate for ad-hoc query
    - GET /cost/summary - User cost summary
    - POST /cost/optimize - Get query optimization suggestions
    """
    try:
        path = event.get('path', '')
        method = event.get('httpMethod', 'GET')
        body = json.loads(event.get('body', '{}')) if event.get('body') else {}

        # Route to appropriate handler
        if path == '/cost/estimate' and method == 'POST':
            return handle_estimate_detection(body)
        elif path == '/cost/estimate-query' and method == 'POST':
            return handle_estimate_query(body)
        elif path == '/cost/summary' and method == 'GET':
            return handle_cost_summary(event)
        elif path == '/cost/optimize' and method == 'POST':
            return handle_optimize_query(body)
        else:
            return {
                'statusCode': 404,
                'body': json.dumps({'error': 'Not found'})
            }

    except Exception as e:
        print(f'Error in cost API handler: {e}')
        return {
            'statusCode': 500,
            'body': json.dumps({'error': str(e)})
        }


def handle_estimate_detection(body: Dict[str, Any]) -> Dict[str, Any]:
    """
    Handle full cost projection for detection rule.

    Request body:
    {
        "user_id": "user-123",
        "query": "SELECT ...",
        "interval_minutes": 5,
        "estimated_alerts_per_month": 10,
        "lambda_memory_mb": 512
    }
    """
    user_id = body.get('user_id')
    query = body.get('query')
    interval_minutes = body.get('interval_minutes', 5)
    estimated_alerts = body.get('estimated_alerts_per_month', 10)
    lambda_memory = body.get('lambda_memory_mb', 512)

    if not user_id or not query:
        return {
            'statusCode': 400,
            'body': json.dumps({'error': 'Missing user_id or query'})
        }

    estimator = CostEstimator()

    # Get full projection
    projection = estimator.estimate_detection_cost(
        query_string=query,
        user_id=user_id,
        interval_minutes=interval_minutes,
        estimated_alerts_per_month=estimated_alerts,
        lambda_memory_mb=lambda_memory
    )

    # Convert to dict for JSON serialization
    projection_dict = {
        'rule_id': projection.rule_id,
        'rule_name': projection.rule_name,
        'avg_data_scanned_mb': projection.avg_data_scanned_mb,
        'executions_per_month': projection.executions_per_month,
        'athena_cost_monthly_usd': projection.athena_cost_monthly_usd,
        'avg_execution_time_ms': projection.avg_execution_time_ms,
        'lambda_memory_mb': projection.lambda_memory_mb,
        'lambda_cost_monthly_usd': projection.lambda_cost_monthly_usd,
        'dynamodb_writes_per_month': projection.dynamodb_writes_per_month,
        'dynamodb_cost_monthly_usd': projection.dynamodb_cost_monthly_usd,
        'estimated_alerts_per_month': projection.estimated_alerts_per_month,
        'alert_delivery_cost_usd': projection.alert_delivery_cost_usd,
        'total_monthly_cost_usd': projection.total_monthly_cost_usd,
        'optimization_potential_usd': projection.optimization_potential_usd,
        'optimization_suggestions': projection.optimization_suggestions
    }

    return {
        'statusCode': 200,
        'headers': {
            'Content-Type': 'application/json',
            'Access-Control-Allow-Origin': '*'
        },
        'body': json.dumps({
            'projection': projection_dict,
            'timestamp': estimator._get_timestamp()
        })
    }


def handle_estimate_query(body: Dict[str, Any]) -> Dict[str, Any]:
    """
    Handle quick cost estimate for ad-hoc query.

    Request body:
    {
        "user_id": "user-123",
        "query": "SELECT ..."
    }
    """
    user_id = body.get('user_id')
    query = body.get('query')

    if not user_id or not query:
        return {
            'statusCode': 400,
            'body': json.dumps({'error': 'Missing user_id or query'})
        }

    estimator = CostEstimator()

    # Get historical statistics
    stats = estimator.get_query_statistics(query, user_id, lookback_days=30)

    # If no historical data, use conservative estimate
    if stats['sample_count'] == 0:
        data_scanned_mb = 100  # Conservative estimate
        cost_usd = (data_scanned_mb / 1024 / 1024) * 5.0  # $5 per TB
    else:
        data_scanned_mb = stats['avg_data_scanned_mb']
        cost_usd = stats['avg_cost_usd']

    # Get optimization warnings
    optimization_result = estimator.optimize_query_for_cost(query)

    return {
        'statusCode': 200,
        'headers': {
            'Content-Type': 'application/json',
            'Access-Control-Allow-Origin': '*'
        },
        'body': json.dumps({
            'estimate': {
                'cost_usd': cost_usd,
                'data_scanned_mb': data_scanned_mb,
                'sample_count': stats['sample_count'],
                'warnings': [
                    s['message'] for s in optimization_result['suggestions']
                    if s['severity'] == 'high'
                ]
            }
        })
    }


def handle_cost_summary(event: Dict[str, Any]) -> Dict[str, Any]:
    """
    Handle user cost summary request.

    Query parameters:
    - user_id: User ID
    - period_days: Days to analyze (default 30)
    """
    params = event.get('queryStringParameters', {}) or {}
    user_id = params.get('user_id')
    period_days = int(params.get('period_days', 30))

    if not user_id:
        return {
            'statusCode': 400,
            'body': json.dumps({'error': 'Missing user_id'})
        }

    estimator = CostEstimator()
    summary = estimator.get_user_cost_summary(user_id, period_days)

    return {
        'statusCode': 200,
        'headers': {
            'Content-Type': 'application/json',
            'Access-Control-Allow-Origin': '*'
        },
        'body': json.dumps({
            'summary': summary,
            'timestamp': datetime.utcnow().isoformat() + 'Z'
        })
    }


def handle_optimize_query(body: Dict[str, Any]) -> Dict[str, Any]:
    """
    Handle query optimization suggestions request.

    Request body:
    {
        "query": "SELECT ..."
    }
    """
    query = body.get('query')

    if not query:
        return {
            'statusCode': 400,
            'body': json.dumps({'error': 'Missing query'})
        }

    estimator = CostEstimator()
    result = estimator.optimize_query_for_cost(query)

    return {
        'statusCode': 200,
        'headers': {
            'Content-Type': 'application/json',
            'Access-Control-Allow-Origin': '*'
        },
        'body': json.dumps(result)
    }


# Helper method for timestamp
def _get_timestamp(self):
    """Get current UTC timestamp."""
    from datetime import datetime
    return datetime.utcnow().isoformat() + 'Z'


# Monkey-patch helper onto CostEstimator
CostEstimator._get_timestamp = _get_timestamp
