"""
Alerts API Handler

Lambda function to handle alert management API requests from the web UI.
Provides CRUD operations for security alerts including listing, filtering,
acknowledgment, resolution, and bulk operations.
"""

import json
import logging
import os
import sys
import re
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from typing import Any, Dict, List, Optional

# Add shared modules to path
sys.path.insert(0, '/opt/python')
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../../shared'))

# Import authentication and CORS utilities
from auth import (
    get_authenticated_user_id,
    AuthenticationError,
)
from auth.cors import get_cors_headers, cors_preflight_response

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

# Lazy-initialized AWS clients
_dynamodb = None
_alerts_table = None

ALERTS_TABLE = os.environ.get('ALERTS_TABLE', 'mantissa-alerts')


def _get_dynamodb():
    """Get lazily-initialized DynamoDB resource."""
    global _dynamodb
    if _dynamodb is None:
        import boto3
        _dynamodb = boto3.resource('dynamodb')
    return _dynamodb


def _get_alerts_table():
    """Get lazily-initialized alerts table."""
    global _alerts_table
    if _alerts_table is None:
        _alerts_table = _get_dynamodb().Table(ALERTS_TABLE)
    return _alerts_table


class DecimalEncoder(json.JSONEncoder):
    """JSON encoder that handles Decimal types from DynamoDB."""
    def default(self, obj):
        if isinstance(obj, Decimal):
            return float(obj)
        return super().default(obj)


def lambda_handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """
    Handle alerts API requests.

    Routes:
    - GET /alerts - List alerts with optional filters
    - GET /alerts/stats - Get alert statistics
    - GET /alerts/timeline - Get alert timeline data
    - GET /alerts/{alertId} - Get specific alert
    - GET /alerts/{alertId}/related - Get related alerts
    - POST /alerts/{alertId}/acknowledge - Acknowledge alert
    - POST /alerts/{alertId}/resolve - Resolve alert
    - POST /alerts/bulk-acknowledge - Bulk acknowledge alerts
    - POST /alerts/bulk-resolve - Bulk resolve alerts
    """
    # Handle CORS preflight
    method = event.get('httpMethod', 'GET')
    if method == 'OPTIONS':
        return cors_preflight_response(event)

    try:
        # Authenticate user
        try:
            user_id = get_authenticated_user_id(event)
        except AuthenticationError:
            return _error_response(event, 401, 'Authentication required')

        path = event.get('path', '')
        body = json.loads(event.get('body', '{}')) if event.get('body') else {}
        params = event.get('queryStringParameters', {}) or {}
        path_params = event.get('pathParameters', {}) or {}

        # Route requests
        if path == '/alerts' and method == 'GET':
            return handle_list_alerts(event, user_id, params)
        elif path == '/alerts/stats' and method == 'GET':
            return handle_alert_stats(event, user_id, params)
        elif path == '/alerts/timeline' and method == 'GET':
            return handle_alert_timeline(event, user_id, params)
        elif path == '/alerts/bulk-acknowledge' and method == 'POST':
            return handle_bulk_acknowledge(event, user_id, body)
        elif path == '/alerts/bulk-resolve' and method == 'POST':
            return handle_bulk_resolve(event, user_id, body)
        elif re.match(r'^/alerts/[^/]+/acknowledge$', path) and method == 'POST':
            alert_id = path.split('/')[2]
            return handle_acknowledge_alert(event, user_id, alert_id)
        elif re.match(r'^/alerts/[^/]+/resolve$', path) and method == 'POST':
            alert_id = path.split('/')[2]
            return handle_resolve_alert(event, user_id, alert_id, body)
        elif re.match(r'^/alerts/[^/]+/related$', path) and method == 'GET':
            alert_id = path.split('/')[2]
            return handle_related_alerts(event, user_id, alert_id)
        elif re.match(r'^/alerts/[^/]+$', path) and method == 'GET':
            alert_id = path.split('/')[2]
            return handle_get_alert(event, user_id, alert_id)
        else:
            return _error_response(event, 404, 'Not found')

    except Exception as e:
        logger.error(f'Error in alerts API handler: {e}', exc_info=True)
        return _error_response(event, 500, 'Internal server error')


def handle_list_alerts(
    event: Dict[str, Any],
    user_id: str,
    params: Dict[str, str]
) -> Dict[str, Any]:
    """
    List alerts with optional filters.

    Query parameters:
    - severity: Filter by severity (critical, high, medium, low, info)
    - status: Filter by status (new, acknowledged, resolved, false_positive)
    - rule_id: Filter by rule ID
    - start_time: Start time (ISO 8601)
    - end_time: End time (ISO 8601)
    - search: Search query
    - page: Page number (default 1)
    - page_size: Page size (default 50, max 100)
    """
    table = _get_alerts_table()

    # Parse pagination
    page = int(params.get('page', 1))
    page_size = min(int(params.get('page_size', 50)), 100)

    # Parse filters
    severity = params.get('severity')
    status = params.get('status')
    rule_id = params.get('rule_id')
    search = params.get('search')
    start_time = params.get('start_time')
    end_time = params.get('end_time')

    # Build filter expression
    filter_parts = []
    expression_values = {}
    expression_names = {}

    if severity:
        filter_parts.append('#sev = :severity')
        expression_names['#sev'] = 'severity'
        expression_values[':severity'] = severity

    if status:
        filter_parts.append('#st = :status')
        expression_names['#st'] = 'status'
        expression_values[':status'] = status

    if rule_id:
        filter_parts.append('rule_id = :rule_id')
        expression_values[':rule_id'] = rule_id

    if start_time:
        filter_parts.append('#ts >= :start_time')
        expression_names['#ts'] = 'timestamp'
        expression_values[':start_time'] = start_time

    if end_time:
        if '#ts' not in expression_names:
            expression_names['#ts'] = 'timestamp'
        filter_parts.append('#ts <= :end_time')
        expression_values[':end_time'] = end_time

    if search:
        filter_parts.append('(contains(title, :search) OR contains(description, :search))')
        expression_values[':search'] = search

    # Execute scan with filters
    scan_kwargs = {}
    if filter_parts:
        scan_kwargs['FilterExpression'] = ' AND '.join(filter_parts)
    if expression_values:
        scan_kwargs['ExpressionAttributeValues'] = expression_values
    if expression_names:
        scan_kwargs['ExpressionAttributeNames'] = expression_names

    # Execute scan
    try:
        response = table.scan(**scan_kwargs)
        items = response.get('Items', [])

        # Handle pagination through continued scans
        while 'LastEvaluatedKey' in response:
            scan_kwargs['ExclusiveStartKey'] = response['LastEvaluatedKey']
            response = table.scan(**scan_kwargs)
            items.extend(response.get('Items', []))
    except Exception as e:
        logger.error(f'Error scanning alerts table: {e}')
        # Return empty results if table doesn't exist or error
        items = []

    # Sort by timestamp descending
    items.sort(key=lambda x: x.get('timestamp', ''), reverse=True)

    # Apply pagination
    total = len(items)
    start_idx = (page - 1) * page_size
    end_idx = start_idx + page_size
    paginated_items = items[start_idx:end_idx]

    return _success_response(event, {
        'alerts': paginated_items,
        'total': total,
        'page': page,
        'page_size': page_size,
        'total_pages': (total + page_size - 1) // page_size
    })


def handle_get_alert(
    event: Dict[str, Any],
    user_id: str,
    alert_id: str
) -> Dict[str, Any]:
    """Get a specific alert by ID."""
    table = _get_alerts_table()

    try:
        response = table.get_item(Key={'id': alert_id})
        item = response.get('Item')

        if not item:
            return _error_response(event, 404, f'Alert {alert_id} not found')

        return _success_response(event, {'alert': item})
    except Exception as e:
        logger.error(f'Error getting alert {alert_id}: {e}')
        return _error_response(event, 500, 'Error retrieving alert')


def handle_acknowledge_alert(
    event: Dict[str, Any],
    user_id: str,
    alert_id: str
) -> Dict[str, Any]:
    """Acknowledge an alert."""
    table = _get_alerts_table()
    now = datetime.now(timezone.utc).isoformat()

    try:
        response = table.update_item(
            Key={'id': alert_id},
            UpdateExpression='SET #st = :status, acknowledged_at = :ts, acknowledged_by = :user',
            ExpressionAttributeNames={'#st': 'status'},
            ExpressionAttributeValues={
                ':status': 'acknowledged',
                ':ts': now,
                ':user': user_id
            },
            ReturnValues='ALL_NEW',
            ConditionExpression='attribute_exists(id)'
        )

        return _success_response(event, {
            'alert': response.get('Attributes'),
            'message': 'Alert acknowledged'
        })
    except _get_dynamodb().meta.client.exceptions.ConditionalCheckFailedException:
        return _error_response(event, 404, f'Alert {alert_id} not found')
    except Exception as e:
        logger.error(f'Error acknowledging alert {alert_id}: {e}')
        return _error_response(event, 500, 'Error acknowledging alert')


def handle_resolve_alert(
    event: Dict[str, Any],
    user_id: str,
    alert_id: str,
    body: Dict[str, Any]
) -> Dict[str, Any]:
    """Resolve an alert with optional resolution notes."""
    table = _get_alerts_table()
    now = datetime.now(timezone.utc).isoformat()
    resolution = body.get('resolution', '')

    try:
        update_expr = 'SET #st = :status, resolved_at = :ts, resolved_by = :user'
        expr_values = {
            ':status': 'resolved',
            ':ts': now,
            ':user': user_id
        }

        if resolution:
            update_expr += ', resolution = :resolution'
            expr_values[':resolution'] = resolution

        response = table.update_item(
            Key={'id': alert_id},
            UpdateExpression=update_expr,
            ExpressionAttributeNames={'#st': 'status'},
            ExpressionAttributeValues=expr_values,
            ReturnValues='ALL_NEW',
            ConditionExpression='attribute_exists(id)'
        )

        return _success_response(event, {
            'alert': response.get('Attributes'),
            'message': 'Alert resolved'
        })
    except _get_dynamodb().meta.client.exceptions.ConditionalCheckFailedException:
        return _error_response(event, 404, f'Alert {alert_id} not found')
    except Exception as e:
        logger.error(f'Error resolving alert {alert_id}: {e}')
        return _error_response(event, 500, 'Error resolving alert')


def handle_bulk_acknowledge(
    event: Dict[str, Any],
    user_id: str,
    body: Dict[str, Any]
) -> Dict[str, Any]:
    """Bulk acknowledge multiple alerts."""
    alert_ids = body.get('alert_ids', [])

    if not alert_ids:
        return _error_response(event, 400, 'No alert IDs provided')

    if len(alert_ids) > 100:
        return _error_response(event, 400, 'Maximum 100 alerts can be acknowledged at once')

    table = _get_alerts_table()
    now = datetime.now(timezone.utc).isoformat()

    success_count = 0
    failed_ids = []

    for alert_id in alert_ids:
        try:
            table.update_item(
                Key={'id': alert_id},
                UpdateExpression='SET #st = :status, acknowledged_at = :ts, acknowledged_by = :user',
                ExpressionAttributeNames={'#st': 'status'},
                ExpressionAttributeValues={
                    ':status': 'acknowledged',
                    ':ts': now,
                    ':user': user_id
                },
                ConditionExpression='attribute_exists(id)'
            )
            success_count += 1
        except Exception as e:
            logger.warning(f'Failed to acknowledge alert {alert_id}: {e}')
            failed_ids.append(alert_id)

    return _success_response(event, {
        'acknowledged': success_count,
        'failed': len(failed_ids),
        'failed_ids': failed_ids
    })


def handle_bulk_resolve(
    event: Dict[str, Any],
    user_id: str,
    body: Dict[str, Any]
) -> Dict[str, Any]:
    """Bulk resolve multiple alerts."""
    alert_ids = body.get('alert_ids', [])
    resolution = body.get('resolution', '')

    if not alert_ids:
        return _error_response(event, 400, 'No alert IDs provided')

    if len(alert_ids) > 100:
        return _error_response(event, 400, 'Maximum 100 alerts can be resolved at once')

    table = _get_alerts_table()
    now = datetime.now(timezone.utc).isoformat()

    success_count = 0
    failed_ids = []

    for alert_id in alert_ids:
        try:
            update_expr = 'SET #st = :status, resolved_at = :ts, resolved_by = :user'
            expr_values = {
                ':status': 'resolved',
                ':ts': now,
                ':user': user_id
            }

            if resolution:
                update_expr += ', resolution = :resolution'
                expr_values[':resolution'] = resolution

            table.update_item(
                Key={'id': alert_id},
                UpdateExpression=update_expr,
                ExpressionAttributeNames={'#st': 'status'},
                ExpressionAttributeValues=expr_values,
                ConditionExpression='attribute_exists(id)'
            )
            success_count += 1
        except Exception as e:
            logger.warning(f'Failed to resolve alert {alert_id}: {e}')
            failed_ids.append(alert_id)

    return _success_response(event, {
        'resolved': success_count,
        'failed': len(failed_ids),
        'failed_ids': failed_ids
    })


def handle_alert_stats(
    event: Dict[str, Any],
    user_id: str,
    params: Dict[str, str]
) -> Dict[str, Any]:
    """Get alert statistics."""
    table = _get_alerts_table()

    # Parse time range
    start_time = params.get('start_time')
    end_time = params.get('end_time')

    if not start_time:
        start_time = (datetime.now(timezone.utc) - timedelta(days=7)).isoformat()
    if not end_time:
        end_time = datetime.now(timezone.utc).isoformat()

    # Build filter expression
    filter_expr = '#ts >= :start_time AND #ts <= :end_time'
    expr_values = {':start_time': start_time, ':end_time': end_time}
    expr_names = {'#ts': 'timestamp'}

    try:
        response = table.scan(
            FilterExpression=filter_expr,
            ExpressionAttributeValues=expr_values,
            ExpressionAttributeNames=expr_names
        )
        items = response.get('Items', [])

        # Handle pagination
        while 'LastEvaluatedKey' in response:
            response = table.scan(
                FilterExpression=filter_expr,
                ExpressionAttributeValues=expr_values,
                ExpressionAttributeNames=expr_names,
                ExclusiveStartKey=response['LastEvaluatedKey']
            )
            items.extend(response.get('Items', []))
    except Exception as e:
        logger.error(f'Error getting alert stats: {e}')
        items = []

    # Calculate statistics
    stats = {
        'total': len(items),
        'by_severity': {},
        'by_status': {},
        'by_rule': {},
        'mttr_hours': 0,
        'acknowledgment_rate': 0
    }

    acknowledged_count = 0
    resolved_items = []

    for item in items:
        # Count by severity
        severity = item.get('severity', 'unknown')
        stats['by_severity'][severity] = stats['by_severity'].get(severity, 0) + 1

        # Count by status
        status = item.get('status', 'new')
        stats['by_status'][status] = stats['by_status'].get(status, 0) + 1

        # Count by rule
        rule_name = item.get('rule_name', 'unknown')
        stats['by_rule'][rule_name] = stats['by_rule'].get(rule_name, 0) + 1

        # Track acknowledgment
        if status in ('acknowledged', 'resolved'):
            acknowledged_count += 1

        # Track resolved for MTTR
        if status == 'resolved' and item.get('resolved_at') and item.get('timestamp'):
            resolved_items.append(item)

    # Calculate MTTR (Mean Time to Resolve)
    if resolved_items:
        total_resolution_time = 0
        for item in resolved_items:
            try:
                created = datetime.fromisoformat(item['timestamp'].replace('Z', '+00:00'))
                resolved = datetime.fromisoformat(item['resolved_at'].replace('Z', '+00:00'))
                total_resolution_time += (resolved - created).total_seconds()
            except Exception:
                pass
        if len(resolved_items) > 0:
            stats['mttr_hours'] = round(total_resolution_time / len(resolved_items) / 3600, 2)

    # Calculate acknowledgment rate
    if stats['total'] > 0:
        stats['acknowledgment_rate'] = round(acknowledged_count / stats['total'] * 100, 1)

    return _success_response(event, {
        'stats': stats,
        'period': {'start': start_time, 'end': end_time}
    })


def handle_alert_timeline(
    event: Dict[str, Any],
    user_id: str,
    params: Dict[str, str]
) -> Dict[str, Any]:
    """Get alert timeline data for charts."""
    table = _get_alerts_table()

    # Parse parameters
    start_time = params.get('start_time')
    end_time = params.get('end_time')
    interval = params.get('interval', '1h')

    if not start_time:
        start_time = (datetime.now(timezone.utc) - timedelta(days=7)).isoformat()
    if not end_time:
        end_time = datetime.now(timezone.utc).isoformat()

    # Parse interval
    interval_hours = 1
    if interval.endswith('h'):
        interval_hours = int(interval[:-1])
    elif interval.endswith('d'):
        interval_hours = int(interval[:-1]) * 24

    # Build filter
    filter_expr = '#ts >= :start_time AND #ts <= :end_time'
    expr_values = {':start_time': start_time, ':end_time': end_time}
    expr_names = {'#ts': 'timestamp'}

    try:
        response = table.scan(
            FilterExpression=filter_expr,
            ExpressionAttributeValues=expr_values,
            ExpressionAttributeNames=expr_names
        )
        items = response.get('Items', [])

        while 'LastEvaluatedKey' in response:
            response = table.scan(
                FilterExpression=filter_expr,
                ExpressionAttributeValues=expr_values,
                ExpressionAttributeNames=expr_names,
                ExclusiveStartKey=response['LastEvaluatedKey']
            )
            items.extend(response.get('Items', []))
    except Exception as e:
        logger.error(f'Error getting alert timeline: {e}')
        items = []

    # Build timeline buckets
    start_dt = datetime.fromisoformat(start_time.replace('Z', '+00:00'))
    end_dt = datetime.fromisoformat(end_time.replace('Z', '+00:00'))

    timeline = []
    current = start_dt

    while current < end_dt:
        bucket_end = current + timedelta(hours=interval_hours)
        bucket = {
            'timestamp': current.isoformat(),
            'count': 0,
            'by_severity': {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
        }

        for item in items:
            try:
                item_ts = datetime.fromisoformat(item.get('timestamp', '').replace('Z', '+00:00'))
                if current <= item_ts < bucket_end:
                    bucket['count'] += 1
                    severity = item.get('severity', 'info')
                    if severity in bucket['by_severity']:
                        bucket['by_severity'][severity] += 1
            except Exception:
                pass

        timeline.append(bucket)
        current = bucket_end

    return _success_response(event, {
        'timeline': timeline,
        'interval': interval,
        'period': {'start': start_time, 'end': end_time}
    })


def handle_related_alerts(
    event: Dict[str, Any],
    user_id: str,
    alert_id: str
) -> Dict[str, Any]:
    """Get alerts related to a specific alert."""
    table = _get_alerts_table()

    # First get the source alert
    try:
        response = table.get_item(Key={'id': alert_id})
        source_alert = response.get('Item')

        if not source_alert:
            return _error_response(event, 404, f'Alert {alert_id} not found')
    except Exception as e:
        logger.error(f'Error getting alert {alert_id}: {e}')
        return _error_response(event, 500, 'Error retrieving alert')

    # Find related alerts by rule_id or suppression_key
    rule_id = source_alert.get('rule_id')
    suppression_key = source_alert.get('suppression_key')

    related = []

    if rule_id:
        try:
            response = table.scan(
                FilterExpression='rule_id = :rule_id AND id <> :alert_id',
                ExpressionAttributeValues={
                    ':rule_id': rule_id,
                    ':alert_id': alert_id
                }
            )
            related.extend(response.get('Items', []))
        except Exception as e:
            logger.warning(f'Error finding related alerts by rule_id: {e}')

    # Also check by suppression key if different
    if suppression_key:
        try:
            response = table.scan(
                FilterExpression='suppression_key = :key AND id <> :alert_id',
                ExpressionAttributeValues={
                    ':key': suppression_key,
                    ':alert_id': alert_id
                }
            )
            # Deduplicate
            existing_ids = {a['id'] for a in related}
            for item in response.get('Items', []):
                if item['id'] not in existing_ids:
                    related.append(item)
        except Exception as e:
            logger.warning(f'Error finding related alerts by suppression_key: {e}')

    # Sort by timestamp descending and limit
    related.sort(key=lambda x: x.get('timestamp', ''), reverse=True)
    related = related[:20]

    return _success_response(event, {
        'related_alerts': related,
        'source_alert_id': alert_id,
        'count': len(related)
    })


def _success_response(event: Dict[str, Any], data: Dict[str, Any]) -> Dict[str, Any]:
    """Build a success response."""
    return {
        'statusCode': 200,
        'headers': {
            'Content-Type': 'application/json',
            **get_cors_headers(event)
        },
        'body': json.dumps(data, cls=DecimalEncoder)
    }


def _error_response(event: Dict[str, Any], status: int, message: str) -> Dict[str, Any]:
    """Build an error response."""
    return {
        'statusCode': status,
        'headers': {
            'Content-Type': 'application/json',
            **get_cors_headers(event)
        },
        'body': json.dumps({'error': message})
    }
