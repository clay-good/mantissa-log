"""
LLM Usage Tracker

Tracks LLM API usage and costs per user, providing analytics
and cost monitoring for the BYOK (Bring Your Own Key) feature.
"""

import os
import boto3
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, asdict
from decimal import Decimal

from .provider_manager import LLMProvider


@dataclass
class UsageRecord:
    """Individual LLM usage record."""
    user_id: str
    timestamp: str
    provider: str
    model_id: str
    task_type: str  # 'query_generation', 'detection_engineering', etc.
    input_tokens: int
    output_tokens: int
    cost_usd: Decimal
    execution_id: Optional[str] = None
    session_id: Optional[str] = None

    def to_dynamodb_item(self) -> Dict[str, Any]:
        """Convert to DynamoDB item format."""
        return {
            'pk': f'user#{self.user_id}',
            'sk': f'usage#{self.timestamp}',
            'user_id': self.user_id,
            'timestamp': self.timestamp,
            'provider': self.provider,
            'model_id': self.model_id,
            'task_type': self.task_type,
            'input_tokens': self.input_tokens,
            'output_tokens': self.output_tokens,
            'cost_usd': str(self.cost_usd),  # Store as string to preserve precision
            'execution_id': self.execution_id or '',
            'session_id': self.session_id or '',
            'ttl': int((datetime.fromisoformat(self.timestamp.replace('Z', '')) + timedelta(days=90)).timestamp())
        }


@dataclass
class UsageSummary:
    """Usage summary for a time period."""
    user_id: str
    start_date: str
    end_date: str
    total_requests: int
    total_input_tokens: int
    total_output_tokens: int
    total_cost_usd: Decimal
    by_provider: Dict[str, Dict[str, Any]]
    by_model: Dict[str, Dict[str, Any]]
    by_task_type: Dict[str, Dict[str, Any]]


class UsageTracker:
    """
    Tracks LLM usage and costs per user.

    Features:
    - Record individual API calls
    - Aggregate usage statistics
    - Cost monitoring and alerts
    - Usage analytics by provider, model, task type
    """

    def __init__(self, table_name: Optional[str] = None):
        """
        Initialize usage tracker.

        Args:
            table_name: DynamoDB table for usage storage
        """
        self.table_name = table_name or os.environ.get(
            'LLM_USAGE_TABLE',
            'mantissa-log-llm-usage'
        )

        self.dynamodb = boto3.resource('dynamodb')
        self.table = self.dynamodb.Table(self.table_name)

    def record_usage(
        self,
        user_id: str,
        provider: LLMProvider,
        model_id: str,
        task_type: str,
        input_tokens: int,
        output_tokens: int,
        cost_usd: float,
        execution_id: Optional[str] = None,
        session_id: Optional[str] = None
    ) -> UsageRecord:
        """
        Record LLM usage.

        Args:
            user_id: User ID
            provider: LLM provider
            model_id: Model ID
            task_type: Type of task
            input_tokens: Input token count
            output_tokens: Output token count
            cost_usd: Cost in USD
            execution_id: Optional execution/query ID
            session_id: Optional session ID

        Returns:
            UsageRecord
        """
        timestamp = datetime.utcnow().isoformat() + 'Z'

        record = UsageRecord(
            user_id=user_id,
            timestamp=timestamp,
            provider=provider.value,
            model_id=model_id,
            task_type=task_type,
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            cost_usd=Decimal(str(cost_usd)),
            execution_id=execution_id,
            session_id=session_id
        )

        # Store in DynamoDB
        try:
            self.table.put_item(Item=record.to_dynamodb_item())
        except Exception as e:
            print(f'Error recording usage: {e}')
            # Don't fail the request if usage tracking fails
            pass

        return record

    def get_usage_summary(
        self,
        user_id: str,
        days: int = 30
    ) -> UsageSummary:
        """
        Get usage summary for a user.

        Args:
            user_id: User ID
            days: Number of days to look back

        Returns:
            UsageSummary
        """
        from boto3.dynamodb.conditions import Key

        end_date = datetime.utcnow()
        start_date = end_date - timedelta(days=days)

        try:
            # Query usage records
            response = self.table.query(
                KeyConditionExpression=
                    Key('pk').eq(f'user#{user_id}') &
                    Key('sk').between(
                        f'usage#{start_date.isoformat()}Z',
                        f'usage#{end_date.isoformat()}Z'
                    )
            )

            records = response.get('Items', [])

            # Aggregate statistics
            total_requests = len(records)
            total_input_tokens = 0
            total_output_tokens = 0
            total_cost = Decimal('0.0')

            by_provider = {}
            by_model = {}
            by_task_type = {}

            for item in records:
                input_tokens = item.get('input_tokens', 0)
                output_tokens = item.get('output_tokens', 0)
                cost = Decimal(item.get('cost_usd', '0.0'))

                total_input_tokens += input_tokens
                total_output_tokens += output_tokens
                total_cost += cost

                # Aggregate by provider
                provider = item.get('provider', 'unknown')
                if provider not in by_provider:
                    by_provider[provider] = {
                        'requests': 0,
                        'input_tokens': 0,
                        'output_tokens': 0,
                        'cost_usd': Decimal('0.0')
                    }
                by_provider[provider]['requests'] += 1
                by_provider[provider]['input_tokens'] += input_tokens
                by_provider[provider]['output_tokens'] += output_tokens
                by_provider[provider]['cost_usd'] += cost

                # Aggregate by model
                model_id = item.get('model_id', 'unknown')
                if model_id not in by_model:
                    by_model[model_id] = {
                        'requests': 0,
                        'input_tokens': 0,
                        'output_tokens': 0,
                        'cost_usd': Decimal('0.0')
                    }
                by_model[model_id]['requests'] += 1
                by_model[model_id]['input_tokens'] += input_tokens
                by_model[model_id]['output_tokens'] += output_tokens
                by_model[model_id]['cost_usd'] += cost

                # Aggregate by task type
                task_type = item.get('task_type', 'unknown')
                if task_type not in by_task_type:
                    by_task_type[task_type] = {
                        'requests': 0,
                        'input_tokens': 0,
                        'output_tokens': 0,
                        'cost_usd': Decimal('0.0')
                    }
                by_task_type[task_type]['requests'] += 1
                by_task_type[task_type]['input_tokens'] += input_tokens
                by_task_type[task_type]['output_tokens'] += output_tokens
                by_task_type[task_type]['cost_usd'] += cost

            return UsageSummary(
                user_id=user_id,
                start_date=start_date.isoformat() + 'Z',
                end_date=end_date.isoformat() + 'Z',
                total_requests=total_requests,
                total_input_tokens=total_input_tokens,
                total_output_tokens=total_output_tokens,
                total_cost_usd=total_cost,
                by_provider=by_provider,
                by_model=by_model,
                by_task_type=by_task_type
            )

        except Exception as e:
            print(f'Error getting usage summary: {e}')
            import traceback
            traceback.print_exc()

            # Return empty summary on error
            return UsageSummary(
                user_id=user_id,
                start_date=start_date.isoformat() + 'Z',
                end_date=end_date.isoformat() + 'Z',
                total_requests=0,
                total_input_tokens=0,
                total_output_tokens=0,
                total_cost_usd=Decimal('0.0'),
                by_provider={},
                by_model={},
                by_task_type={}
            )

    def get_daily_usage(
        self,
        user_id: str,
        days: int = 30
    ) -> List[Dict[str, Any]]:
        """
        Get daily usage breakdown.

        Args:
            user_id: User ID
            days: Number of days to look back

        Returns:
            List of daily usage dictionaries
        """
        from boto3.dynamodb.conditions import Key
        from collections import defaultdict

        end_date = datetime.utcnow()
        start_date = end_date - timedelta(days=days)

        try:
            # Query usage records
            response = self.table.query(
                KeyConditionExpression=
                    Key('pk').eq(f'user#{user_id}') &
                    Key('sk').between(
                        f'usage#{start_date.isoformat()}Z',
                        f'usage#{end_date.isoformat()}Z'
                    )
            )

            records = response.get('Items', [])

            # Group by date
            daily_usage = defaultdict(lambda: {
                'date': '',
                'requests': 0,
                'input_tokens': 0,
                'output_tokens': 0,
                'cost_usd': Decimal('0.0')
            })

            for item in records:
                timestamp = item.get('timestamp', '')
                date = timestamp.split('T')[0]  # Extract date part

                daily_usage[date]['date'] = date
                daily_usage[date]['requests'] += 1
                daily_usage[date]['input_tokens'] += item.get('input_tokens', 0)
                daily_usage[date]['output_tokens'] += item.get('output_tokens', 0)
                daily_usage[date]['cost_usd'] += Decimal(item.get('cost_usd', '0.0'))

            # Convert to list and sort by date
            result = list(daily_usage.values())
            result.sort(key=lambda x: x['date'])

            return result

        except Exception as e:
            print(f'Error getting daily usage: {e}')
            return []

    def check_cost_threshold(
        self,
        user_id: str,
        threshold_usd: float,
        days: int = 30
    ) -> Dict[str, Any]:
        """
        Check if user has exceeded cost threshold.

        Args:
            user_id: User ID
            threshold_usd: Cost threshold in USD
            days: Number of days to check

        Returns:
            Dictionary with threshold check results
        """
        summary = self.get_usage_summary(user_id, days)

        exceeded = float(summary.total_cost_usd) > threshold_usd

        return {
            'exceeded': exceeded,
            'threshold_usd': threshold_usd,
            'actual_cost_usd': float(summary.total_cost_usd),
            'days': days,
            'percentage': (float(summary.total_cost_usd) / threshold_usd * 100) if threshold_usd > 0 else 0
        }

    def get_top_models(
        self,
        user_id: str,
        days: int = 30,
        limit: int = 5
    ) -> List[Dict[str, Any]]:
        """
        Get top models by usage.

        Args:
            user_id: User ID
            days: Number of days to look back
            limit: Maximum number of models to return

        Returns:
            List of top models by cost
        """
        summary = self.get_usage_summary(user_id, days)

        # Sort by cost
        models = [
            {
                'model_id': model_id,
                **stats,
                'cost_usd': float(stats['cost_usd'])
            }
            for model_id, stats in summary.by_model.items()
        ]

        models.sort(key=lambda x: x['cost_usd'], reverse=True)

        return models[:limit]

    def estimate_monthly_cost(
        self,
        user_id: str,
        lookback_days: int = 7
    ) -> Dict[str, Any]:
        """
        Estimate monthly cost based on recent usage.

        Args:
            user_id: User ID
            lookback_days: Number of days to use for estimation

        Returns:
            Dictionary with cost estimate
        """
        summary = self.get_usage_summary(user_id, lookback_days)

        if lookback_days == 0:
            return {
                'estimated_monthly_cost_usd': 0.0,
                'based_on_days': 0,
                'daily_average_usd': 0.0
            }

        # Calculate daily average
        daily_average = float(summary.total_cost_usd) / lookback_days

        # Estimate monthly cost (30 days)
        estimated_monthly = daily_average * 30

        return {
            'estimated_monthly_cost_usd': round(estimated_monthly, 2),
            'based_on_days': lookback_days,
            'daily_average_usd': round(daily_average, 4),
            'actual_cost_period': float(summary.total_cost_usd)
        }
