"""
Detection Metrics API Handler

Lambda function to serve detection rule performance metrics to the web UI.
Provides analytics including alert counts, false positive rates, timing metrics,
and trend analysis.
"""

import json
import logging
import os
import sys
from datetime import datetime, timedelta
from decimal import Decimal
from typing import Dict, Any, List, Optional

# Add shared modules to path
sys.path.insert(0, '/opt/python')
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../../shared'))

from detection.metrics import (
    MetricsCalculator,
    MetricsPeriod,
    RuleMetrics,
    PortfolioMetrics,
    DynamoDBMetricsStore,
)

# Import authentication and CORS utilities
from auth import (
    get_authenticated_user_id,
    AuthenticationError,
    AuthorizationError,
)
from auth.cors import get_cors_headers, cors_preflight_response

# Lazy client imports
from utils.lazy_init import aws_clients

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

# Environment configuration
METRICS_TABLE = os.environ.get('DETECTION_METRICS_TABLE', 'mantissa-detection-metrics')
ALERTS_TABLE = os.environ.get('ALERTS_TABLE', 'mantissa-alerts')
RULES_TABLE = os.environ.get('RULES_TABLE', 'mantissa-detection-rules')


def _get_dynamodb():
    """Get lazily-initialized DynamoDB resource."""
    return aws_clients.dynamodb


class DecimalEncoder(json.JSONEncoder):
    """JSON encoder that handles Decimal types from DynamoDB."""
    def default(self, obj):
        if isinstance(obj, Decimal):
            return float(obj)
        return super().default(obj)


def lambda_handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """
    Handle detection metrics API requests.

    Routes:
    - GET /detection/metrics - Portfolio-level metrics summary
    - GET /detection/metrics/{rule_id} - Single rule metrics
    - GET /detection/metrics/history - Historical metrics time series
    - GET /detection/optimizations - Rule optimization suggestions
    """
    # Handle CORS preflight
    method = event.get('httpMethod', 'GET')
    if method == 'OPTIONS':
        return cors_preflight_response(event)

    try:
        # Authenticate user from Cognito JWT claims
        try:
            user_id = get_authenticated_user_id(event)
        except AuthenticationError:
            return error_response(event, 401, 'Authentication required')

        path = event.get('path', '')
        path_params = event.get('pathParameters') or {}
        query_params = event.get('queryStringParameters') or {}

        # Route to appropriate handler
        if path == '/detection/metrics' and method == 'GET':
            return handle_portfolio_metrics(event, user_id, query_params)
        elif path.startswith('/detection/metrics/history') and method == 'GET':
            return handle_metrics_history(event, user_id, query_params)
        elif path.startswith('/detection/metrics/') and method == 'GET':
            rule_id = path_params.get('rule_id') or path.split('/')[-1]
            return handle_rule_metrics(event, user_id, rule_id, query_params)
        elif path == '/detection/optimizations' and method == 'GET':
            return handle_optimizations(event, user_id, query_params)
        else:
            return error_response(event, 404, 'Not found')

    except Exception as e:
        logger.error(f'Error in detection metrics API: {e}', exc_info=True)
        return error_response(event, 500, 'Internal server error')


def handle_portfolio_metrics(
    event: Dict[str, Any],
    user_id: str,
    params: Dict[str, str]
) -> Dict[str, Any]:
    """
    Get portfolio-level metrics for all detection rules.

    Query params:
    - period: hour, day, week, month (default: week)
    """
    period_str = params.get('period', 'week')
    try:
        period = MetricsPeriod(period_str)
    except ValueError:
        period = MetricsPeriod.WEEK

    # Load rules and alerts from DynamoDB
    rules = _get_user_rules(user_id)
    alerts_by_rule = _get_alerts_by_rule(user_id, period)

    # Calculate metrics
    calculator = MetricsCalculator()
    portfolio = calculator.calculate_portfolio_metrics(rules, alerts_by_rule, period)

    # Calculate per-rule metrics for the response
    rule_metrics = []
    for rule in rules:
        rule_id = rule.get('id', rule.get('rule_id', ''))
        rule_name = rule.get('name', rule.get('title', rule_id))
        alerts = alerts_by_rule.get(rule_id, [])

        metrics = calculator.calculate_rule_metrics(rule_id, rule_name, alerts, period)

        rule_metrics.append({
            'id': rule_id,
            'name': rule_name,
            'enabled': rule.get('enabled', True),
            'severity': rule.get('severity', 'medium'),
            'total_alerts': metrics.total_alerts,
            'fp_rate': round(metrics.false_positive_rate * 100, 1),
            'accuracy': round((1 - metrics.false_positive_rate) * 100, 1),
            'alert_trend': _calculate_trend_direction(metrics.alert_count_trend),
            'last_alert': _get_last_alert_time(alerts),
            'mean_time_to_resolve': metrics.mean_time_to_resolve,
            'unique_entities': metrics.unique_source_ips + metrics.unique_users,
        })

    return success_response(event, {
        'portfolio': portfolio.to_dict(),
        'rules': rule_metrics,
        'period': period.value,
        'generated_at': datetime.utcnow().isoformat() + 'Z'
    })


def handle_rule_metrics(
    event: Dict[str, Any],
    user_id: str,
    rule_id: str,
    params: Dict[str, str]
) -> Dict[str, Any]:
    """
    Get detailed metrics for a single detection rule.

    Query params:
    - period: hour, day, week, month (default: week)
    """
    period_str = params.get('period', 'week')
    try:
        period = MetricsPeriod(period_str)
    except ValueError:
        period = MetricsPeriod.WEEK

    # Verify rule belongs to user
    rule = _get_rule(user_id, rule_id)
    if not rule:
        return error_response(event, 404, 'Rule not found')

    # Get alerts for this rule
    alerts = _get_rule_alerts(user_id, rule_id, period)
    previous_alerts = _get_rule_alerts(user_id, rule_id, period, previous_period=True)

    # Calculate metrics
    calculator = MetricsCalculator()
    metrics = calculator.calculate_rule_metrics(
        rule_id=rule_id,
        rule_name=rule.get('name', rule.get('title', rule_id)),
        alerts=alerts,
        period=period,
        previous_period_alerts=previous_alerts
    )

    return success_response(event, {
        'metrics': metrics.to_dict(),
        'rule': {
            'id': rule_id,
            'name': rule.get('name', rule.get('title', '')),
            'severity': rule.get('severity', 'medium'),
            'enabled': rule.get('enabled', True),
            'query': rule.get('query', ''),
        },
        'generated_at': datetime.utcnow().isoformat() + 'Z'
    })


def handle_metrics_history(
    event: Dict[str, Any],
    user_id: str,
    params: Dict[str, str]
) -> Dict[str, Any]:
    """
    Get historical metrics time series for trend visualization.

    Query params:
    - rule_id: Optional rule ID (if not provided, returns portfolio metrics)
    - period: hour, day, week, month (default: day)
    - limit: Number of data points (default: 30)
    """
    rule_id = params.get('rule_id')
    period_str = params.get('period', 'day')
    limit = min(int(params.get('limit', 30)), 90)

    try:
        period = MetricsPeriod(period_str)
    except ValueError:
        period = MetricsPeriod.DAY

    # Get historical data from metrics store
    store = DynamoDBMetricsStore(METRICS_TABLE)

    if rule_id:
        # Verify rule belongs to user
        rule = _get_rule(user_id, rule_id)
        if not rule:
            return error_response(event, 404, 'Rule not found')

        history = store.get_rule_metrics(rule_id, period, limit)
        data_points = [
            {
                'period_end': m.period_end,
                'total_alerts': m.total_alerts,
                'false_positive_rate': m.false_positive_rate,
                'resolution_rate': m.resolution_rate,
                'mean_time_to_resolve': m.mean_time_to_resolve,
            }
            for m in history
        ]
    else:
        history = store.get_portfolio_metrics(period, limit)
        data_points = [
            {
                'period_end': m.period_end,
                'total_alerts': m.total_alerts,
                'active_rules': m.active_rules,
                'avg_false_positive_rate': m.avg_false_positive_rate,
                'avg_resolution_rate': m.avg_resolution_rate,
            }
            for m in history
        ]

    return success_response(event, {
        'history': data_points,
        'period': period.value,
        'rule_id': rule_id,
        'generated_at': datetime.utcnow().isoformat() + 'Z'
    })


def handle_optimizations(
    event: Dict[str, Any],
    user_id: str,
    params: Dict[str, str]
) -> Dict[str, Any]:
    """
    Get optimization suggestions for rules based on performance metrics.

    Query params:
    - rule_id: Optional specific rule ID
    """
    rule_id = params.get('rule_id')

    if rule_id:
        # Get optimizations for specific rule
        rule = _get_rule(user_id, rule_id)
        if not rule:
            return error_response(event, 404, 'Rule not found')

        alerts = _get_rule_alerts(user_id, rule_id, MetricsPeriod.WEEK)
        optimizations = _generate_optimizations(rule, alerts)

        return success_response(event, {
            'rule_id': rule_id,
            'optimizations': optimizations
        })

    # Get optimizations for all rules needing attention
    rules = _get_user_rules(user_id)
    alerts_by_rule = _get_alerts_by_rule(user_id, MetricsPeriod.WEEK)

    all_optimizations = []
    calculator = MetricsCalculator()

    for rule in rules:
        rid = rule.get('id', rule.get('rule_id', ''))
        alerts = alerts_by_rule.get(rid, [])

        metrics = calculator.calculate_rule_metrics(
            rid,
            rule.get('name', ''),
            alerts,
            MetricsPeriod.WEEK
        )

        # Only suggest optimizations for rules with issues
        if metrics.false_positive_rate > 0.10 or (metrics.total_alerts == 0 and rule.get('enabled', True)):
            optimizations = _generate_optimizations(rule, alerts, metrics)
            if optimizations:
                all_optimizations.append({
                    'rule_id': rid,
                    'rule_name': rule.get('name', rule.get('title', '')),
                    'optimizations': optimizations
                })

    return success_response(event, {
        'rules_with_optimizations': all_optimizations,
        'total_suggestions': sum(len(r['optimizations']) for r in all_optimizations)
    })


# Helper functions

def _get_user_rules(user_id: str) -> List[Dict[str, Any]]:
    """Get all detection rules for a user."""
    try:
        table = _get_dynamodb().Table(RULES_TABLE)
        response = table.query(
            IndexName='user-index',
            KeyConditionExpression='user_id = :uid',
            ExpressionAttributeValues={':uid': user_id}
        )
        return response.get('Items', [])
    except Exception as e:
        logger.error(f'Error fetching rules: {e}')
        return []


def _get_rule(user_id: str, rule_id: str) -> Optional[Dict[str, Any]]:
    """Get a single rule by ID, verifying ownership."""
    try:
        table = _get_dynamodb().Table(RULES_TABLE)
        response = table.get_item(Key={'id': rule_id})
        item = response.get('Item')
        if item and item.get('user_id') == user_id:
            return item
        return None
    except Exception as e:
        logger.error(f'Error fetching rule: {e}')
        return None


def _get_alerts_by_rule(user_id: str, period: MetricsPeriod) -> Dict[str, List[Dict[str, Any]]]:
    """Get alerts grouped by rule for a user and time period."""
    try:
        table = _get_dynamodb().Table(ALERTS_TABLE)
        start_time = _get_period_start(period)

        response = table.query(
            IndexName='user-timestamp-index',
            KeyConditionExpression='user_id = :uid AND #ts >= :start',
            ExpressionAttributeNames={'#ts': 'timestamp'},
            ExpressionAttributeValues={
                ':uid': user_id,
                ':start': start_time.isoformat() + 'Z'
            }
        )

        alerts_by_rule: Dict[str, List[Dict[str, Any]]] = {}
        for alert in response.get('Items', []):
            rule_id = alert.get('rule_id', 'unknown')
            if rule_id not in alerts_by_rule:
                alerts_by_rule[rule_id] = []
            alerts_by_rule[rule_id].append(alert)

        return alerts_by_rule
    except Exception as e:
        logger.error(f'Error fetching alerts: {e}')
        return {}


def _get_rule_alerts(
    user_id: str,
    rule_id: str,
    period: MetricsPeriod,
    previous_period: bool = False
) -> List[Dict[str, Any]]:
    """Get alerts for a specific rule."""
    try:
        table = _get_dynamodb().Table(ALERTS_TABLE)

        if previous_period:
            end_time = _get_period_start(period)
            start_time = _get_previous_period_start(period)
        else:
            start_time = _get_period_start(period)
            end_time = datetime.utcnow()

        response = table.query(
            IndexName='rule-timestamp-index',
            KeyConditionExpression='rule_id = :rid AND #ts BETWEEN :start AND :end',
            FilterExpression='user_id = :uid',
            ExpressionAttributeNames={'#ts': 'timestamp'},
            ExpressionAttributeValues={
                ':rid': rule_id,
                ':uid': user_id,
                ':start': start_time.isoformat() + 'Z',
                ':end': end_time.isoformat() + 'Z'
            }
        )

        return response.get('Items', [])
    except Exception as e:
        logger.error(f'Error fetching rule alerts: {e}')
        return []


def _get_period_start(period: MetricsPeriod) -> datetime:
    """Get the start datetime for a period."""
    now = datetime.utcnow()
    if period == MetricsPeriod.HOUR:
        return now - timedelta(hours=1)
    elif period == MetricsPeriod.DAY:
        return now - timedelta(days=1)
    elif period == MetricsPeriod.WEEK:
        return now - timedelta(days=7)
    else:  # MONTH
        return now - timedelta(days=30)


def _get_previous_period_start(period: MetricsPeriod) -> datetime:
    """Get the start of the previous period."""
    start = _get_period_start(period)
    if period == MetricsPeriod.HOUR:
        return start - timedelta(hours=1)
    elif period == MetricsPeriod.DAY:
        return start - timedelta(days=1)
    elif period == MetricsPeriod.WEEK:
        return start - timedelta(days=7)
    else:
        return start - timedelta(days=30)


def _calculate_trend_direction(trend_percentage: float) -> str:
    """Convert trend percentage to direction string."""
    if trend_percentage > 5:
        return 'up'
    elif trend_percentage < -5:
        return 'down'
    return 'stable'


def _get_last_alert_time(alerts: List[Dict[str, Any]]) -> Optional[str]:
    """Get the most recent alert timestamp."""
    if not alerts:
        return None
    sorted_alerts = sorted(
        alerts,
        key=lambda a: a.get('timestamp', ''),
        reverse=True
    )
    return sorted_alerts[0].get('timestamp') if sorted_alerts else None


def _generate_optimizations(
    rule: Dict[str, Any],
    alerts: List[Dict[str, Any]],
    metrics: Optional[RuleMetrics] = None
) -> List[Dict[str, Any]]:
    """Generate optimization suggestions based on rule and alert analysis."""
    optimizations = []

    if not metrics:
        calculator = MetricsCalculator()
        metrics = calculator.calculate_rule_metrics(
            rule.get('id', ''),
            rule.get('name', ''),
            alerts,
            MetricsPeriod.WEEK
        )

    # High false positive rate
    if metrics.false_positive_rate > 0.20:
        # Analyze top contributors
        if metrics.top_source_ips and metrics.top_source_ips[0].get('percentage', 0) > 30:
            top_ip = metrics.top_source_ips[0]['value']
            optimizations.append({
                'id': f'filter-ip-{top_ip[:8]}',
                'type': 'add_filter',
                'title': 'Add IP Filter',
                'description': f"IP {top_ip} contributes {metrics.top_source_ips[0]['percentage']}% of alerts. Consider adding an exclusion.",
                'impact': 'high',
                'estimated_reduction': int(metrics.top_source_ips[0]['percentage']),
                'query_change': f"AND source_ip != '{top_ip}'"
            })

        if metrics.top_users and metrics.top_users[0].get('percentage', 0) > 30:
            top_user = metrics.top_users[0]['value']
            optimizations.append({
                'id': f'filter-user-{top_user[:8]}',
                'type': 'add_exclusion',
                'title': 'Add User Exclusion',
                'description': f"User {top_user} triggers {metrics.top_users[0]['percentage']}% of alerts. If this is a service account, consider excluding.",
                'impact': 'high',
                'estimated_reduction': int(metrics.top_users[0]['percentage']),
                'query_change': f"AND user != '{top_user}'"
            })

        # General threshold suggestion
        if not optimizations:
            optimizations.append({
                'id': 'adjust-threshold',
                'type': 'adjust_threshold',
                'title': 'Increase Detection Threshold',
                'description': 'High false positive rate suggests the detection threshold may be too sensitive.',
                'impact': 'medium',
                'estimated_reduction': 15,
                'query_change': 'HAVING COUNT(*) >= 5  -- Increase from current threshold'
            })

    # Zero alerts but enabled
    if metrics.total_alerts == 0 and rule.get('enabled', True):
        optimizations.append({
            'id': 'check-log-source',
            'type': 'fix_query',
            'title': 'Verify Log Source',
            'description': 'This rule has generated zero alerts. The log source may not be configured or the query may have issues.',
            'impact': 'high',
            'estimated_reduction': 0,
            'query_change': None
        })

    # Slow resolution time
    if metrics.mean_time_to_resolve and metrics.mean_time_to_resolve > 60 * 24:  # > 24 hours
        optimizations.append({
            'id': 'improve-context',
            'type': 'add_context',
            'title': 'Add Alert Context',
            'description': f'Mean time to resolve is {int(metrics.mean_time_to_resolve / 60)} hours. Consider adding more context to alerts.',
            'impact': 'low',
            'estimated_reduction': 0,
            'query_change': None
        })

    return optimizations


def success_response(event: Dict[str, Any], data: Dict[str, Any]) -> Dict[str, Any]:
    """Return a successful JSON response."""
    return {
        'statusCode': 200,
        'headers': {
            'Content-Type': 'application/json',
            **get_cors_headers(event)
        },
        'body': json.dumps(data, cls=DecimalEncoder)
    }


def error_response(event: Dict[str, Any], status_code: int, message: str) -> Dict[str, Any]:
    """Return an error JSON response."""
    return {
        'statusCode': status_code,
        'headers': {
            'Content-Type': 'application/json',
            **get_cors_headers(event)
        },
        'body': json.dumps({'error': message})
    }
