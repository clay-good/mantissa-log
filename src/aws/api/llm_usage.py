"""
LLM Usage Analytics API

Provides usage statistics and cost analytics for LLM calls.
"""

import json
import sys
from pathlib import Path
from typing import Dict, Any

# Add shared utilities to path
sys.path.append(str(Path(__file__).parent.parent.parent / 'shared'))

from llm.usage_tracker import UsageTracker


def lambda_handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """
    Lambda handler for LLM usage analytics.
    
    Routes:
    - GET /api/llm-usage/{userId}
    - GET /api/llm-usage/{userId}/summary
    - GET /api/llm-usage/{userId}/daily
    """
    try:
        http_method = event.get('httpMethod', 'GET')
        path = event.get('path', '')
        path_params = event.get('pathParameters', {})
        query_params = event.get('queryStringParameters', {}) or {}
        
        user_id = path_params.get('userId')
        
        if not user_id:
            return error_response('userId is required', 400)
        
        tracker = UsageTracker()
        
        if path.endswith('/summary'):
            return get_usage_summary(tracker, user_id, query_params)
        elif path.endswith('/daily'):
            return get_daily_usage(tracker, user_id, query_params)
        else:
            return get_usage_entries(tracker, user_id, query_params)
            
    except Exception as e:
        print(f"Error in LLM usage API: {str(e)}")
        import traceback
        traceback.print_exc()
        return error_response(str(e), 500)


def get_usage_entries(
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
    
    return success_response({
        'entries': entries,
        'count': len(entries)
    })


def get_usage_summary(
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
    
    return success_response(summary)


def get_daily_usage(
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
    
    return success_response({
        'daily_usage': daily_usage,
        'days': days
    })


def success_response(data: Dict[str, Any]) -> Dict[str, Any]:
    """Return success response."""
    return {
        'statusCode': 200,
        'headers': {
            'Content-Type': 'application/json',
            'Access-Control-Allow-Origin': '*'
        },
        'body': json.dumps(data)
    }


def error_response(message: str, status_code: int) -> Dict[str, Any]:
    """Return error response."""
    return {
        'statusCode': status_code,
        'headers': {
            'Content-Type': 'application/json',
            'Access-Control-Allow-Origin': '*'
        },
        'body': json.dumps({'error': message})
    }
