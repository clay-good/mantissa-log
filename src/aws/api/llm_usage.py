"""
LLM Usage Analytics API

Provides usage statistics and cost analytics for LLM calls.
"""

import json
import logging
import sys
from pathlib import Path
from typing import Dict, Any

# Add shared utilities to path
sys.path.append(str(Path(__file__).parent.parent.parent / 'shared'))

from llm.usage_tracker import UsageTracker
from auth import get_authenticated_user_id, AuthenticationError
from auth.cors import get_cors_headers, cors_preflight_response

logger = logging.getLogger(__name__)


def lambda_handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """
    Lambda handler for LLM usage analytics.

    Routes:
    - GET /api/llm-usage
    - GET /api/llm-usage/summary
    - GET /api/llm-usage/daily
    """
    try:
        http_method = event.get('httpMethod', 'GET')
        path = event.get('path', '')
        query_params = event.get('queryStringParameters', {}) or {}

        # Handle CORS preflight
        if http_method == 'OPTIONS':
            return cors_preflight_response(event)

        # Authenticate user from JWT
        try:
            user_id = get_authenticated_user_id(event)
        except AuthenticationError:
            return error_response(event, 'Authentication required', 401)

        tracker = UsageTracker()

        if path.endswith('/summary'):
            return get_usage_summary(event, tracker, user_id, query_params)
        elif path.endswith('/daily'):
            return get_daily_usage(event, tracker, user_id, query_params)
        else:
            return get_usage_entries(event, tracker, user_id, query_params)

    except Exception as e:
        logger.error(f"Error in LLM usage API: {str(e)}")
        import traceback
        traceback.print_exc()
        return error_response(event, str(e), 500)


def get_usage_entries(
    event: Dict[str, Any],
    tracker: UsageTracker,
    user_id: str,
    query_params: Dict[str, str]
) -> Dict[str, Any]:
    """Get raw usage entries."""
    start_date = query_params.get('startDate')
    end_date = query_params.get('endDate')
    operation_type = query_params.get('operationType')

    entries = tracker.get_user_usage(
        user_id=user_id,
        start_date=start_date,
        end_date=end_date,
        operation_type=operation_type
    )

    # Convert Decimal to float for JSON
    for entry in entries:
        if 'cost_usd' in entry:
            entry['cost_usd'] = float(entry['cost_usd'])

    return success_response(event, {
        'entries': entries,
        'count': len(entries)
    })


def get_usage_summary(
    event: Dict[str, Any],
    tracker: UsageTracker,
    user_id: str,
    query_params: Dict[str, str]
) -> Dict[str, Any]:
    """Get usage summary."""
    start_date = query_params.get('startDate')
    end_date = query_params.get('endDate')

    summary = tracker.get_usage_summary(
        user_id=user_id,
        start_date=start_date,
        end_date=end_date
    )

    return success_response(event, summary)


def get_daily_usage(
    event: Dict[str, Any],
    tracker: UsageTracker,
    user_id: str,
    query_params: Dict[str, str]
) -> Dict[str, Any]:
    """Get daily usage."""
    days = int(query_params.get('days', '30'))

    daily_usage = tracker.get_daily_usage(
        user_id=user_id,
        days=days
    )

    return success_response(event, {
        'daily_usage': daily_usage,
        'days': days
    })


def success_response(event: Dict[str, Any], data: Dict[str, Any]) -> Dict[str, Any]:
    """Return success response with secure CORS headers."""
    return {
        'statusCode': 200,
        'headers': {
            'Content-Type': 'application/json',
            **get_cors_headers(event)
        },
        'body': json.dumps(data)
    }


def error_response(event: Dict[str, Any], message: str, status_code: int) -> Dict[str, Any]:
    """Return error response with secure CORS headers."""
    return {
        'statusCode': status_code,
        'headers': {
            'Content-Type': 'application/json',
            **get_cors_headers(event)
        },
        'body': json.dumps({'error': message})
    }
