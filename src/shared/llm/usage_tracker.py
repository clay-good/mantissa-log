"""
LLM Usage Tracker

Tracks and stores LLM usage metrics for cost monitoring and analytics.
"""

import os
from dataclasses import dataclass, asdict
from datetime import datetime
from typing import Dict, Any, List, Optional
import boto3
from decimal import Decimal


@dataclass
class UsageEntry:
    """Single LLM usage entry."""
    user_id: str
    timestamp: str
    provider: str
    model: str
    operation_type: str  # 'query_generation', 'detection_rule', 'conversation'
    input_tokens: int
    output_tokens: int
    total_tokens: int
    cost_usd: Decimal
    latency_ms: float
    request_id: str
    metadata: Dict[str, Any]


class UsageTracker:
    """Tracks LLM usage and stores in DynamoDB."""
    
    def __init__(self, table_name: Optional[str] = None):
        """Initialize usage tracker."""
        self.table_name = table_name or os.environ.get(
            'LLM_USAGE_TABLE',
            'mantissa-log-llm-usage'
        )
        self.dynamodb = boto3.resource('dynamodb')
        self.table = self.dynamodb.Table(self.table_name)
    
    def track_usage(
        self,
        user_id: str,
        provider: str,
        model: str,
        operation_type: str,
        input_tokens: int,
        output_tokens: int,
        cost_usd: float,
        latency_ms: float,
        request_id: str,
        metadata: Optional[Dict[str, Any]] = None
    ) -> None:
        """Track a single LLM usage event."""
        entry = UsageEntry(
            user_id=user_id,
            timestamp=datetime.utcnow().isoformat() + 'Z',
            provider=provider,
            model=model,
            operation_type=operation_type,
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            total_tokens=input_tokens + output_tokens,
            cost_usd=Decimal(str(cost_usd)),
            latency_ms=latency_ms,
            request_id=request_id,
            metadata=metadata or {}
        )
        
        self._store_entry(entry)
    
    def _store_entry(self, entry: UsageEntry) -> None:
        """Store usage entry in DynamoDB."""
        item = asdict(entry)
        # Convert Decimal for DynamoDB
        item['cost_usd'] = entry.cost_usd
        
        self.table.put_item(Item=item)
    
    def get_user_usage(
        self,
        user_id: str,
        start_date: Optional[str] = None,
        end_date: Optional[str] = None,
        operation_type: Optional[str] = None
    ) -> List[Dict[str, Any]]:
        """Get usage for a user within a date range."""
        from boto3.dynamodb.conditions import Key
        
        # Build query expression
        key_condition = Key('user_id').eq(user_id)
        
        if start_date and end_date:
            key_condition = key_condition & Key('timestamp').between(start_date, end_date)
        elif start_date:
            key_condition = key_condition & Key('timestamp').gte(start_date)
        elif end_date:
            key_condition = key_condition & Key('timestamp').lte(end_date)
        
        # Query
        response = self.table.query(KeyConditionExpression=key_condition)
        items = response['Items']
        
        # Filter by operation type if specified
        if operation_type:
            items = [item for item in items if item.get('operation_type') == operation_type]
        
        return items
    
    def get_usage_summary(
        self,
        user_id: str,
        start_date: Optional[str] = None,
        end_date: Optional[str] = None
    ) -> Dict[str, Any]:
        """Get usage summary for a user."""
        entries = self.get_user_usage(user_id, start_date, end_date)
        
        if not entries:
            return {
                'total_requests': 0,
                'total_tokens': 0,
                'total_cost_usd': 0.0,
                'by_provider': {},
                'by_operation': {},
                'by_model': {}
            }
        
        # Calculate totals
        total_requests = len(entries)
        total_tokens = sum(int(e['total_tokens']) for e in entries)
        total_cost = sum(float(e['cost_usd']) for e in entries)
        
        # Group by provider
        by_provider = {}
        for entry in entries:
            provider = entry['provider']
            if provider not in by_provider:
                by_provider[provider] = {
                    'requests': 0,
                    'tokens': 0,
                    'cost_usd': 0.0
                }
            by_provider[provider]['requests'] += 1
            by_provider[provider]['tokens'] += int(entry['total_tokens'])
            by_provider[provider]['cost_usd'] += float(entry['cost_usd'])
        
        # Group by operation type
        by_operation = {}
        for entry in entries:
            op_type = entry['operation_type']
            if op_type not in by_operation:
                by_operation[op_type] = {
                    'requests': 0,
                    'tokens': 0,
                    'cost_usd': 0.0
                }
            by_operation[op_type]['requests'] += 1
            by_operation[op_type]['tokens'] += int(entry['total_tokens'])
            by_operation[op_type]['cost_usd'] += float(entry['cost_usd'])
        
        # Group by model
        by_model = {}
        for entry in entries:
            model = entry['model']
            if model not in by_model:
                by_model[model] = {
                    'requests': 0,
                    'tokens': 0,
                    'cost_usd': 0.0
                }
            by_model[model]['requests'] += 1
            by_model[model]['tokens'] += int(entry['total_tokens'])
            by_model[model]['cost_usd'] += float(entry['cost_usd'])
        
        return {
            'total_requests': total_requests,
            'total_tokens': total_tokens,
            'total_cost_usd': round(total_cost, 4),
            'by_provider': by_provider,
            'by_operation': by_operation,
            'by_model': by_model
        }
    
    def get_daily_usage(
        self,
        user_id: str,
        days: int = 30
    ) -> List[Dict[str, Any]]:
        """Get daily usage for the last N days."""
        from datetime import timedelta
        
        end_date = datetime.utcnow()
        start_date = end_date - timedelta(days=days)
        
        entries = self.get_user_usage(
            user_id,
            start_date.isoformat() + 'Z',
            end_date.isoformat() + 'Z'
        )
        
        # Group by day
        daily_usage = {}
        for entry in entries:
            day = entry['timestamp'][:10]  # YYYY-MM-DD
            if day not in daily_usage:
                daily_usage[day] = {
                    'date': day,
                    'requests': 0,
                    'tokens': 0,
                    'cost_usd': 0.0
                }
            daily_usage[day]['requests'] += 1
            daily_usage[day]['tokens'] += int(entry['total_tokens'])
            daily_usage[day]['cost_usd'] += float(entry['cost_usd'])
        
        # Convert to list and sort by date
        return sorted(daily_usage.values(), key=lambda x: x['date'])


class UsageTrackerMiddleware:
    """Middleware for automatic usage tracking."""
    
    def __init__(self, tracker: UsageTracker):
        """Initialize middleware."""
        self.tracker = tracker
    
    def track_llm_call(
        self,
        user_id: str,
        operation_type: str,
        llm_response: Any,
        request_id: str,
        metadata: Optional[Dict[str, Any]] = None
    ) -> None:
        """
        Track LLM call from response object.
        
        Args:
            user_id: User making the request
            operation_type: Type of operation (query_generation, etc.)
            llm_response: LLMResponse object from provider
            request_id: Unique request ID
            metadata: Additional metadata
        """
        self.tracker.track_usage(
            user_id=user_id,
            provider=llm_response.provider,
            model=llm_response.model,
            operation_type=operation_type,
            input_tokens=llm_response.usage.input_tokens,
            output_tokens=llm_response.usage.output_tokens,
            cost_usd=llm_response.usage.cost_usd,
            latency_ms=llm_response.usage.latency_ms,
            request_id=request_id,
            metadata=metadata
        )
