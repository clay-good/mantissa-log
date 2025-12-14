"""
Scheduled Query Lambda Handler

Lambda function for executing scheduled NL queries and sending
intelligence summaries to Slack channels.
"""

import os
import json
import logging
from typing import Dict, Any

from shared.auth import get_authenticated_user_id, AuthenticationError
from shared.auth.cors import get_cors_headers, cors_preflight_response

logger = logging.getLogger()
logger.setLevel(logging.INFO)


def lambda_handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """
    AWS Lambda entry point for scheduled query execution.

    This handler is triggered by:
    1. EventBridge rules (scheduled execution)
    2. API Gateway (manual execution or management)

    Args:
        event: Lambda event
        context: Lambda context

    Returns:
        Response with execution results
    """
    logger.info(f"Received event: {json.dumps(event)}")

    # Determine event source
    if 'httpMethod' in event:
        return _handle_api_request(event, context)
    else:
        return _handle_scheduled_execution(event, context)


def _handle_scheduled_execution(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """
    Handle scheduled query execution from EventBridge.

    Args:
        event: EventBridge event containing query_id
        context: Lambda context

    Returns:
        Execution result
    """
    from shared.scheduled import ScheduledQueryExecutor, ScheduledQueryConfig

    # Get query_id from event
    query_id = event.get('query_id')
    if not query_id:
        logger.error("No query_id in event")
        return {
            'statusCode': 400,
            'body': json.dumps({'error': 'query_id required'})
        }

    try:
        # Initialize executor
        config = ScheduledQueryConfig.from_environment()
        executor = ScheduledQueryExecutor(config=config)

        # Execute query
        result = executor.execute(query_id)

        logger.info(f"Query {query_id} execution result: success={result.success}")

        return {
            'statusCode': 200 if result.success else 500,
            'body': json.dumps(result.to_dict())
        }

    except Exception as e:
        logger.error(f"Error executing scheduled query: {e}")
        import traceback
        traceback.print_exc()

        return {
            'statusCode': 500,
            'body': json.dumps({'error': str(e)})
        }


def _handle_api_request(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """
    Handle API Gateway requests for scheduled query management.

    Endpoints:
    - POST /api/scheduled-queries - Create new scheduled query
    - GET /api/scheduled-queries - List user's scheduled queries
    - GET /api/scheduled-queries/{id} - Get query details
    - PUT /api/scheduled-queries/{id} - Update query
    - DELETE /api/scheduled-queries/{id} - Delete query
    - POST /api/scheduled-queries/{id}/execute - Manual execution
    - GET /api/scheduled-queries/{id}/history - Get execution history

    Args:
        event: API Gateway event
        context: Lambda context

    Returns:
        API response
    """
    from shared.scheduled import ScheduledQueryManager, ScheduledQueryExecutor, ScheduledQueryConfig

    http_method = event.get('httpMethod', '')
    path = event.get('path', '')
    path_params = event.get('pathParameters', {}) or {}
    query_params = event.get('queryStringParameters', {}) or {}

    # Handle CORS preflight
    if http_method == 'OPTIONS':
        return cors_preflight_response(event)

    # Authenticate user from JWT
    try:
        user_id = get_authenticated_user_id(event)
    except AuthenticationError:
        return _response(event, 401, {'error': 'Authentication required'})

    try:
        body = json.loads(event.get('body', '{}') or '{}')
    except json.JSONDecodeError:
        body = {}

    manager = ScheduledQueryManager()
    query_id = path_params.get('id')

    try:
        # POST /api/scheduled-queries - Create
        if http_method == 'POST' and not query_id:
            return _create_query(event, manager, user_id, body)

        # GET /api/scheduled-queries - List
        elif http_method == 'GET' and not query_id:
            return _list_queries(event, manager, user_id, query_params)

        # GET /api/scheduled-queries/{id} - Get
        elif http_method == 'GET' and query_id and 'history' not in path:
            return _get_query(event, manager, user_id, query_id)

        # PUT /api/scheduled-queries/{id} - Update
        elif http_method == 'PUT' and query_id:
            return _update_query(event, manager, user_id, query_id, body)

        # DELETE /api/scheduled-queries/{id} - Delete
        elif http_method == 'DELETE' and query_id:
            return _delete_query(event, manager, user_id, query_id)

        # POST /api/scheduled-queries/{id}/execute - Manual execute
        elif http_method == 'POST' and query_id and 'execute' in path:
            return _execute_query(event, manager, user_id, query_id)

        # GET /api/scheduled-queries/{id}/history - Get history
        elif http_method == 'GET' and query_id and 'history' in path:
            return _get_history(event, manager, user_id, query_id, query_params)

        else:
            return _response(event, 404, {'error': 'Not found'})

    except Exception as e:
        logger.error(f"API error: {e}")
        import traceback
        traceback.print_exc()
        return _response(event, 500, {'error': str(e)})


def _create_query(event: Dict, manager, user_id: str, body: Dict) -> Dict:
    """Create a new scheduled query."""
    required = ['query_text', 'schedule_expression', 'output_channel']
    for field in required:
        if field not in body:
            return _response(event, 400, {'error': f'{field} is required'})

    # Validate schedule expression
    schedule = body['schedule_expression']
    if not _validate_schedule_expression(schedule):
        return _response(event, 400, {'error': 'Invalid schedule_expression. Use rate() or cron() format.'})

    query = manager.create_query(
        user_id=user_id,
        query_text=body['query_text'],
        schedule_expression=schedule,
        output_channel=body['output_channel'],
        name=body.get('name'),
        description=body.get('description'),
        webhook_url=body.get('webhook_url'),
        timezone=body.get('timezone', 'UTC'),
        metadata=body.get('metadata')
    )

    return _response(event, 201, query.to_dict())


def _list_queries(event: Dict, manager, user_id: str, params: Dict) -> Dict:
    """List scheduled queries for user."""
    enabled_only = params.get('enabled_only', 'false').lower() == 'true'
    limit = min(int(params.get('limit', '100')), 100)

    queries = manager.list_queries(user_id, enabled_only=enabled_only, limit=limit)

    return _response(event, 200, {
        'queries': [q.to_dict() for q in queries],
        'count': len(queries)
    })


def _get_query(event: Dict, manager, user_id: str, query_id: str) -> Dict:
    """Get a specific scheduled query."""
    query = manager.get_query(user_id, query_id)

    if not query:
        return _response(event, 404, {'error': 'Query not found'})

    return _response(event, 200, query.to_dict())


def _update_query(event: Dict, manager, user_id: str, query_id: str, body: Dict) -> Dict:
    """Update a scheduled query."""
    # Validate schedule if being updated
    if 'schedule_expression' in body:
        if not _validate_schedule_expression(body['schedule_expression']):
            return _response(event, 400, {'error': 'Invalid schedule_expression'})

    query = manager.update_query(user_id, query_id, body)

    if not query:
        return _response(event, 404, {'error': 'Query not found'})

    return _response(event, 200, query.to_dict())


def _delete_query(event: Dict, manager, user_id: str, query_id: str) -> Dict:
    """Delete a scheduled query."""
    success = manager.delete_query(user_id, query_id)

    if not success:
        return _response(event, 404, {'error': 'Query not found or delete failed'})

    return _response(event, 200, {'message': 'Query deleted', 'query_id': query_id})


def _execute_query(event: Dict, manager, user_id: str, query_id: str) -> Dict:
    """Manually execute a scheduled query."""
    from shared.scheduled import ScheduledQueryExecutor, ScheduledQueryConfig

    # Verify user owns this query before executing
    query = manager.get_query(user_id, query_id)
    if not query:
        return _response(event, 404, {'error': 'Query not found'})

    config = ScheduledQueryConfig.from_environment()
    executor = ScheduledQueryExecutor(config=config, manager=manager)

    result = executor.execute(query_id)

    return _response(
        event,
        200 if result.success else 500,
        result.to_dict()
    )


def _get_history(event: Dict, manager, user_id: str, query_id: str, params: Dict) -> Dict:
    """Get execution history for a query."""
    # Verify user owns this query before fetching history
    query = manager.get_query(user_id, query_id)
    if not query:
        return _response(event, 404, {'error': 'Query not found'})

    limit = min(int(params.get('limit', '50')), 100)

    history = manager.get_execution_history(query_id, limit=limit)

    return _response(event, 200, {
        'history': history,
        'count': len(history)
    })


def _validate_schedule_expression(expression: str) -> bool:
    """Validate EventBridge schedule expression."""
    import re

    # Rate expression: rate(value unit)
    rate_pattern = r'^rate\(\d+\s+(minute|minutes|hour|hours|day|days)\)$'
    if re.match(rate_pattern, expression):
        return True

    # Cron expression: cron(min hour dom month dow year)
    cron_pattern = r'^cron\(.+\)$'
    if re.match(cron_pattern, expression):
        return True

    return False


def _response(event: Dict, status_code: int, body: Dict) -> Dict:
    """Build API Gateway response with secure CORS headers."""
    return {
        'statusCode': status_code,
        'headers': {
            'Content-Type': 'application/json',
            **get_cors_headers(event)
        },
        'body': json.dumps(body)
    }
