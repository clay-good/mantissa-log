"""
Scheduled Query Lambda Handler

Lambda function for executing scheduled NL queries and sending
intelligence summaries to Slack channels.
"""

import os
import json
import logging
from typing import Dict, Any

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

    try:
        body = json.loads(event.get('body', '{}') or '{}')
    except json.JSONDecodeError:
        body = {}

    # Get user_id from request context (JWT, API key, etc.)
    user_id = _get_user_id(event)
    if not user_id:
        return _response(401, {'error': 'Unauthorized'})

    manager = ScheduledQueryManager()
    query_id = path_params.get('id')

    try:
        # POST /api/scheduled-queries - Create
        if http_method == 'POST' and not query_id:
            return _create_query(manager, user_id, body)

        # GET /api/scheduled-queries - List
        elif http_method == 'GET' and not query_id:
            return _list_queries(manager, user_id, query_params)

        # GET /api/scheduled-queries/{id} - Get
        elif http_method == 'GET' and query_id and 'history' not in path:
            return _get_query(manager, user_id, query_id)

        # PUT /api/scheduled-queries/{id} - Update
        elif http_method == 'PUT' and query_id:
            return _update_query(manager, user_id, query_id, body)

        # DELETE /api/scheduled-queries/{id} - Delete
        elif http_method == 'DELETE' and query_id:
            return _delete_query(manager, user_id, query_id)

        # POST /api/scheduled-queries/{id}/execute - Manual execute
        elif http_method == 'POST' and query_id and 'execute' in path:
            return _execute_query(manager, query_id)

        # GET /api/scheduled-queries/{id}/history - Get history
        elif http_method == 'GET' and query_id and 'history' in path:
            return _get_history(manager, query_id, query_params)

        else:
            return _response(404, {'error': 'Not found'})

    except Exception as e:
        logger.error(f"API error: {e}")
        import traceback
        traceback.print_exc()
        return _response(500, {'error': str(e)})


def _create_query(manager, user_id: str, body: Dict) -> Dict:
    """Create a new scheduled query."""
    required = ['query_text', 'schedule_expression', 'output_channel']
    for field in required:
        if field not in body:
            return _response(400, {'error': f'{field} is required'})

    # Validate schedule expression
    schedule = body['schedule_expression']
    if not _validate_schedule_expression(schedule):
        return _response(400, {'error': 'Invalid schedule_expression. Use rate() or cron() format.'})

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

    return _response(201, query.to_dict())


def _list_queries(manager, user_id: str, params: Dict) -> Dict:
    """List scheduled queries for user."""
    enabled_only = params.get('enabled_only', 'false').lower() == 'true'
    limit = min(int(params.get('limit', '100')), 100)

    queries = manager.list_queries(user_id, enabled_only=enabled_only, limit=limit)

    return _response(200, {
        'queries': [q.to_dict() for q in queries],
        'count': len(queries)
    })


def _get_query(manager, user_id: str, query_id: str) -> Dict:
    """Get a specific scheduled query."""
    query = manager.get_query(user_id, query_id)

    if not query:
        return _response(404, {'error': 'Query not found'})

    return _response(200, query.to_dict())


def _update_query(manager, user_id: str, query_id: str, body: Dict) -> Dict:
    """Update a scheduled query."""
    # Validate schedule if being updated
    if 'schedule_expression' in body:
        if not _validate_schedule_expression(body['schedule_expression']):
            return _response(400, {'error': 'Invalid schedule_expression'})

    query = manager.update_query(user_id, query_id, body)

    if not query:
        return _response(404, {'error': 'Query not found'})

    return _response(200, query.to_dict())


def _delete_query(manager, user_id: str, query_id: str) -> Dict:
    """Delete a scheduled query."""
    success = manager.delete_query(user_id, query_id)

    if not success:
        return _response(404, {'error': 'Query not found or delete failed'})

    return _response(200, {'message': 'Query deleted', 'query_id': query_id})


def _execute_query(manager, query_id: str) -> Dict:
    """Manually execute a scheduled query."""
    from shared.scheduled import ScheduledQueryExecutor, ScheduledQueryConfig

    config = ScheduledQueryConfig.from_environment()
    executor = ScheduledQueryExecutor(config=config, manager=manager)

    result = executor.execute(query_id)

    return _response(
        200 if result.success else 500,
        result.to_dict()
    )


def _get_history(manager, query_id: str, params: Dict) -> Dict:
    """Get execution history for a query."""
    limit = min(int(params.get('limit', '50')), 100)

    history = manager.get_execution_history(query_id, limit=limit)

    return _response(200, {
        'history': history,
        'count': len(history)
    })


def _get_user_id(event: Dict) -> str:
    """Extract user ID from request context."""
    # Try various sources
    request_context = event.get('requestContext', {})

    # From Cognito authorizer
    authorizer = request_context.get('authorizer', {})
    if 'claims' in authorizer:
        return authorizer['claims'].get('sub') or authorizer['claims'].get('cognito:username')

    # From custom authorizer
    if 'principalId' in authorizer:
        return authorizer['principalId']

    # From query params (for testing)
    params = event.get('queryStringParameters', {}) or {}
    if 'user_id' in params:
        return params['user_id']

    # From body (for testing)
    try:
        body = json.loads(event.get('body', '{}') or '{}')
        if 'user_id' in body:
            return body['user_id']
    except json.JSONDecodeError:
        pass

    # Default for testing
    return os.environ.get('DEFAULT_USER_ID', 'default-user')


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


def _response(status_code: int, body: Dict) -> Dict:
    """Build API Gateway response."""
    return {
        'statusCode': status_code,
        'headers': {
            'Content-Type': 'application/json',
            'Access-Control-Allow-Origin': '*',
            'Access-Control-Allow-Headers': 'Content-Type,Authorization',
            'Access-Control-Allow-Methods': 'GET,POST,PUT,DELETE,OPTIONS'
        },
        'body': json.dumps(body)
    }
