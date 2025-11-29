"""
Scheduled Query Manager

Manages CRUD operations for scheduled NL queries with DynamoDB storage.
"""

import os
import uuid
import logging
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
from enum import Enum

logger = logging.getLogger(__name__)


class QueryFrequency(Enum):
    """Predefined query frequencies."""
    EVERY_5_MINUTES = "rate(5 minutes)"
    EVERY_15_MINUTES = "rate(15 minutes)"
    EVERY_30_MINUTES = "rate(30 minutes)"
    HOURLY = "rate(1 hour)"
    EVERY_6_HOURS = "rate(6 hours)"
    EVERY_12_HOURS = "rate(12 hours)"
    DAILY = "rate(1 day)"
    WEEKLY = "rate(7 days)"


@dataclass
class ScheduledQuery:
    """Represents a scheduled NL query."""

    query_id: str
    user_id: str
    query_text: str
    schedule_expression: str
    output_channel: str  # Slack channel name or webhook URL
    name: str = ""
    description: str = ""
    enabled: bool = True
    webhook_url: Optional[str] = None
    timezone: str = "UTC"
    created_at: str = ""
    updated_at: str = ""
    last_run_at: Optional[str] = None
    last_run_status: Optional[str] = None
    run_count: int = 0
    error_count: int = 0
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dynamodb_item(self) -> Dict[str, Any]:
        """Convert to DynamoDB item."""
        now = datetime.utcnow().isoformat() + 'Z'

        return {
            'pk': f'user#{self.user_id}',
            'sk': f'query#{self.query_id}',
            'query_id': self.query_id,
            'user_id': self.user_id,
            'query_text': self.query_text,
            'schedule_expression': self.schedule_expression,
            'output_channel': self.output_channel,
            'name': self.name,
            'description': self.description,
            'enabled': self.enabled,
            'webhook_url': self.webhook_url or '',
            'timezone': self.timezone,
            'created_at': self.created_at or now,
            'updated_at': now,
            'last_run_at': self.last_run_at or '',
            'last_run_status': self.last_run_status or '',
            'run_count': self.run_count,
            'error_count': self.error_count,
            'metadata': self.metadata,
            'ttl': int((datetime.utcnow() + timedelta(days=365)).timestamp())
        }

    @classmethod
    def from_dynamodb_item(cls, item: Dict[str, Any]) -> 'ScheduledQuery':
        """Create from DynamoDB item."""
        return cls(
            query_id=item['query_id'],
            user_id=item['user_id'],
            query_text=item['query_text'],
            schedule_expression=item['schedule_expression'],
            output_channel=item['output_channel'],
            name=item.get('name', ''),
            description=item.get('description', ''),
            enabled=item.get('enabled', True),
            webhook_url=item.get('webhook_url') or None,
            timezone=item.get('timezone', 'UTC'),
            created_at=item.get('created_at', ''),
            updated_at=item.get('updated_at', ''),
            last_run_at=item.get('last_run_at') or None,
            last_run_status=item.get('last_run_status') or None,
            run_count=item.get('run_count', 0),
            error_count=item.get('error_count', 0),
            metadata=item.get('metadata', {})
        )

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for API responses."""
        return {
            'query_id': self.query_id,
            'user_id': self.user_id,
            'query_text': self.query_text,
            'schedule_expression': self.schedule_expression,
            'output_channel': self.output_channel,
            'name': self.name,
            'description': self.description,
            'enabled': self.enabled,
            'webhook_url': self.webhook_url,
            'timezone': self.timezone,
            'created_at': self.created_at,
            'updated_at': self.updated_at,
            'last_run_at': self.last_run_at,
            'last_run_status': self.last_run_status,
            'run_count': self.run_count,
            'error_count': self.error_count,
            'metadata': self.metadata
        }


@dataclass
class ExecutionHistory:
    """Record of a scheduled query execution."""

    execution_id: str
    query_id: str
    user_id: str
    executed_at: str
    status: str  # 'success', 'failed', 'timeout'
    duration_ms: int
    result_count: int
    summary_sent: bool
    error_message: Optional[str] = None
    generated_sql: Optional[str] = None

    def to_dynamodb_item(self) -> Dict[str, Any]:
        """Convert to DynamoDB item."""
        return {
            'pk': f'query#{self.query_id}',
            'sk': f'execution#{self.executed_at}#{self.execution_id}',
            'execution_id': self.execution_id,
            'query_id': self.query_id,
            'user_id': self.user_id,
            'executed_at': self.executed_at,
            'status': self.status,
            'duration_ms': self.duration_ms,
            'result_count': self.result_count,
            'summary_sent': self.summary_sent,
            'error_message': self.error_message or '',
            'generated_sql': self.generated_sql or '',
            'ttl': int((datetime.utcnow() + timedelta(days=90)).timestamp())
        }


class ScheduledQueryManager:
    """
    Manages scheduled NL queries.

    Handles CRUD operations and EventBridge rule management for
    scheduled query execution.
    """

    def __init__(
        self,
        table_name: Optional[str] = None,
        events_client: Optional[Any] = None,
        lambda_client: Optional[Any] = None
    ):
        """
        Initialize scheduled query manager.

        Args:
            table_name: DynamoDB table name
            events_client: Optional boto3 EventBridge client
            lambda_client: Optional boto3 Lambda client
        """
        self.table_name = table_name or os.environ.get(
            'SCHEDULED_QUERIES_TABLE',
            'mantissa-log-scheduled-queries'
        )
        self._table = None
        self._events = events_client
        self._lambda = lambda_client

    @property
    def table(self):
        """Lazy-load DynamoDB table."""
        if self._table is None:
            import boto3
            dynamodb = boto3.resource('dynamodb')
            self._table = dynamodb.Table(self.table_name)
        return self._table

    @property
    def events(self):
        """Lazy-load EventBridge client."""
        if self._events is None:
            import boto3
            self._events = boto3.client('events')
        return self._events

    @property
    def lambda_client(self):
        """Lazy-load Lambda client."""
        if self._lambda is None:
            import boto3
            self._lambda = boto3.client('lambda')
        return self._lambda

    def create_query(
        self,
        user_id: str,
        query_text: str,
        schedule_expression: str,
        output_channel: str,
        name: Optional[str] = None,
        description: Optional[str] = None,
        webhook_url: Optional[str] = None,
        timezone: str = "UTC",
        metadata: Optional[Dict[str, Any]] = None
    ) -> ScheduledQuery:
        """
        Create a new scheduled query.

        Args:
            user_id: User who owns the query
            query_text: Natural language query
            schedule_expression: Cron or rate expression
            output_channel: Slack channel name
            name: Optional friendly name
            description: Optional description
            webhook_url: Optional Slack webhook URL
            timezone: Timezone for schedule
            metadata: Optional additional metadata

        Returns:
            Created ScheduledQuery
        """
        query_id = str(uuid.uuid4())[:8]
        now = datetime.utcnow().isoformat() + 'Z'

        query = ScheduledQuery(
            query_id=query_id,
            user_id=user_id,
            query_text=query_text,
            schedule_expression=schedule_expression,
            output_channel=output_channel,
            name=name or f"Scheduled Query {query_id}",
            description=description or "",
            enabled=True,
            webhook_url=webhook_url,
            timezone=timezone,
            created_at=now,
            updated_at=now,
            metadata=metadata or {}
        )

        try:
            # Store in DynamoDB
            self.table.put_item(Item=query.to_dynamodb_item())

            # Create EventBridge rule
            self._create_eventbridge_rule(query)

            logger.info(f"Created scheduled query {query_id} for user {user_id}")
            return query

        except Exception as e:
            logger.error(f"Failed to create scheduled query: {e}")
            raise

    def update_query(
        self,
        user_id: str,
        query_id: str,
        updates: Dict[str, Any]
    ) -> Optional[ScheduledQuery]:
        """
        Update an existing scheduled query.

        Args:
            user_id: User who owns the query
            query_id: Query ID to update
            updates: Dictionary of fields to update

        Returns:
            Updated ScheduledQuery or None if not found
        """
        try:
            # Get existing query
            existing = self.get_query(user_id, query_id)
            if not existing:
                return None

            # Build update expression
            allowed_fields = [
                'query_text', 'schedule_expression', 'output_channel',
                'name', 'description', 'enabled', 'webhook_url', 'timezone', 'metadata'
            ]

            update_parts = ['updated_at = :updated_at']
            expr_values = {':updated_at': datetime.utcnow().isoformat() + 'Z'}
            expr_names = {}

            for key, value in updates.items():
                if key in allowed_fields:
                    safe_key = key.replace('_', '')
                    update_parts.append(f'#{safe_key} = :{safe_key}')
                    expr_values[f':{safe_key}'] = value
                    expr_names[f'#{safe_key}'] = key

            update_expr = 'SET ' + ', '.join(update_parts)

            self.table.update_item(
                Key={
                    'pk': f'user#{user_id}',
                    'sk': f'query#{query_id}'
                },
                UpdateExpression=update_expr,
                ExpressionAttributeValues=expr_values,
                ExpressionAttributeNames=expr_names if expr_names else None
            )

            # Update EventBridge rule if schedule changed
            if 'schedule_expression' in updates or 'enabled' in updates:
                updated = self.get_query(user_id, query_id)
                if updated:
                    self._update_eventbridge_rule(updated)

            return self.get_query(user_id, query_id)

        except Exception as e:
            logger.error(f"Failed to update scheduled query: {e}")
            return None

    def delete_query(self, user_id: str, query_id: str) -> bool:
        """
        Delete a scheduled query.

        Args:
            user_id: User who owns the query
            query_id: Query ID to delete

        Returns:
            True if deleted successfully
        """
        try:
            # Get existing query for EventBridge cleanup
            existing = self.get_query(user_id, query_id)

            # Delete from DynamoDB
            self.table.delete_item(
                Key={
                    'pk': f'user#{user_id}',
                    'sk': f'query#{query_id}'
                }
            )

            # Delete EventBridge rule
            if existing:
                self._delete_eventbridge_rule(existing)

            logger.info(f"Deleted scheduled query {query_id}")
            return True

        except Exception as e:
            logger.error(f"Failed to delete scheduled query: {e}")
            return False

    def get_query(self, user_id: str, query_id: str) -> Optional[ScheduledQuery]:
        """
        Get a scheduled query by ID.

        Args:
            user_id: User who owns the query
            query_id: Query ID

        Returns:
            ScheduledQuery or None if not found
        """
        try:
            response = self.table.get_item(
                Key={
                    'pk': f'user#{user_id}',
                    'sk': f'query#{query_id}'
                }
            )

            if 'Item' in response:
                return ScheduledQuery.from_dynamodb_item(response['Item'])
            return None

        except Exception as e:
            logger.error(f"Failed to get scheduled query: {e}")
            return None

    def get_query_by_id(self, query_id: str) -> Optional[ScheduledQuery]:
        """
        Get a scheduled query by ID only (scans table).

        Args:
            query_id: Query ID

        Returns:
            ScheduledQuery or None if not found
        """
        try:
            response = self.table.scan(
                FilterExpression='query_id = :qid',
                ExpressionAttributeValues={':qid': query_id},
                Limit=1
            )

            items = response.get('Items', [])
            if items:
                return ScheduledQuery.from_dynamodb_item(items[0])
            return None

        except Exception as e:
            logger.error(f"Failed to get scheduled query by ID: {e}")
            return None

    def list_queries(
        self,
        user_id: str,
        enabled_only: bool = False,
        limit: int = 100
    ) -> List[ScheduledQuery]:
        """
        List scheduled queries for a user.

        Args:
            user_id: User ID
            enabled_only: Only return enabled queries
            limit: Maximum number to return

        Returns:
            List of ScheduledQuery objects
        """
        try:
            query_params = {
                'KeyConditionExpression': 'pk = :pk AND begins_with(sk, :sk_prefix)',
                'ExpressionAttributeValues': {
                    ':pk': f'user#{user_id}',
                    ':sk_prefix': 'query#'
                },
                'Limit': limit
            }

            if enabled_only:
                query_params['FilterExpression'] = 'enabled = :enabled'
                query_params['ExpressionAttributeValues'][':enabled'] = True

            response = self.table.query(**query_params)

            return [
                ScheduledQuery.from_dynamodb_item(item)
                for item in response.get('Items', [])
            ]

        except Exception as e:
            logger.error(f"Failed to list scheduled queries: {e}")
            return []

    def list_all_enabled_queries(self, limit: int = 1000) -> List[ScheduledQuery]:
        """
        List all enabled queries across all users.

        Args:
            limit: Maximum number to return

        Returns:
            List of enabled ScheduledQuery objects
        """
        try:
            response = self.table.scan(
                FilterExpression='enabled = :enabled AND begins_with(sk, :sk_prefix)',
                ExpressionAttributeValues={
                    ':enabled': True,
                    ':sk_prefix': 'query#'
                },
                Limit=limit
            )

            queries = [
                ScheduledQuery.from_dynamodb_item(item)
                for item in response.get('Items', [])
            ]

            # Handle pagination
            while 'LastEvaluatedKey' in response and len(queries) < limit:
                response = self.table.scan(
                    FilterExpression='enabled = :enabled AND begins_with(sk, :sk_prefix)',
                    ExpressionAttributeValues={
                        ':enabled': True,
                        ':sk_prefix': 'query#'
                    },
                    ExclusiveStartKey=response['LastEvaluatedKey'],
                    Limit=limit - len(queries)
                )
                queries.extend([
                    ScheduledQuery.from_dynamodb_item(item)
                    for item in response.get('Items', [])
                ])

            return queries

        except Exception as e:
            logger.error(f"Failed to list all enabled queries: {e}")
            return []

    def record_execution(
        self,
        query: ScheduledQuery,
        status: str,
        duration_ms: int,
        result_count: int,
        summary_sent: bool,
        error_message: Optional[str] = None,
        generated_sql: Optional[str] = None
    ) -> None:
        """
        Record a query execution in history.

        Args:
            query: The scheduled query that was executed
            status: Execution status
            duration_ms: Execution duration in milliseconds
            result_count: Number of results
            summary_sent: Whether summary was sent to Slack
            error_message: Optional error message
            generated_sql: Optional generated SQL
        """
        execution_id = str(uuid.uuid4())[:8]
        now = datetime.utcnow().isoformat() + 'Z'

        history = ExecutionHistory(
            execution_id=execution_id,
            query_id=query.query_id,
            user_id=query.user_id,
            executed_at=now,
            status=status,
            duration_ms=duration_ms,
            result_count=result_count,
            summary_sent=summary_sent,
            error_message=error_message,
            generated_sql=generated_sql
        )

        try:
            # Store execution history
            self.table.put_item(Item=history.to_dynamodb_item())

            # Update query stats
            update_expr = 'SET last_run_at = :last_run, last_run_status = :status, run_count = run_count + :inc'
            expr_values = {
                ':last_run': now,
                ':status': status,
                ':inc': 1
            }

            if status == 'failed':
                update_expr += ', error_count = error_count + :inc'

            self.table.update_item(
                Key={
                    'pk': f'user#{query.user_id}',
                    'sk': f'query#{query.query_id}'
                },
                UpdateExpression=update_expr,
                ExpressionAttributeValues=expr_values
            )

        except Exception as e:
            logger.error(f"Failed to record execution: {e}")

    def get_execution_history(
        self,
        query_id: str,
        limit: int = 50
    ) -> List[Dict[str, Any]]:
        """
        Get execution history for a query.

        Args:
            query_id: Query ID
            limit: Maximum number of records

        Returns:
            List of execution records
        """
        try:
            response = self.table.query(
                KeyConditionExpression='pk = :pk AND begins_with(sk, :sk_prefix)',
                ExpressionAttributeValues={
                    ':pk': f'query#{query_id}',
                    ':sk_prefix': 'execution#'
                },
                ScanIndexForward=False,  # Most recent first
                Limit=limit
            )

            return response.get('Items', [])

        except Exception as e:
            logger.error(f"Failed to get execution history: {e}")
            return []

    def _get_rule_name(self, query: ScheduledQuery) -> str:
        """Generate EventBridge rule name."""
        env = os.environ.get('ENVIRONMENT', 'dev')
        return f'scheduled-query-{query.query_id}-{env}'

    def _get_lambda_arn(self) -> str:
        """Get Lambda function ARN for scheduled query execution."""
        env = os.environ.get('ENVIRONMENT', 'dev')
        function_name = f'mantissa-log-scheduled-query-executor-{env}'

        try:
            response = self.lambda_client.get_function(FunctionName=function_name)
            return response['Configuration']['FunctionArn']
        except Exception:
            account_id = os.environ.get('AWS_ACCOUNT_ID', '')
            region = os.environ.get('AWS_REGION', 'us-east-1')
            return f'arn:aws:lambda:{region}:{account_id}:function:{function_name}'

    def _create_eventbridge_rule(self, query: ScheduledQuery) -> None:
        """Create EventBridge rule for scheduled query."""
        rule_name = self._get_rule_name(query)
        lambda_arn = self._get_lambda_arn()

        try:
            # Create rule
            self.events.put_rule(
                Name=rule_name,
                ScheduleExpression=query.schedule_expression,
                State='ENABLED' if query.enabled else 'DISABLED',
                Description=f'Execute scheduled query: {query.name}'
            )

            # Add Lambda permission
            self._add_lambda_permission(rule_name)

            # Set Lambda as target
            self.events.put_targets(
                Rule=rule_name,
                Targets=[
                    {
                        'Id': '1',
                        'Arn': lambda_arn,
                        'Input': f'{{"query_id": "{query.query_id}"}}'
                    }
                ]
            )

            logger.info(f"Created EventBridge rule {rule_name}")

        except Exception as e:
            logger.error(f"Failed to create EventBridge rule: {e}")

    def _update_eventbridge_rule(self, query: ScheduledQuery) -> None:
        """Update EventBridge rule for scheduled query."""
        rule_name = self._get_rule_name(query)

        try:
            self.events.put_rule(
                Name=rule_name,
                ScheduleExpression=query.schedule_expression,
                State='ENABLED' if query.enabled else 'DISABLED',
                Description=f'Execute scheduled query: {query.name}'
            )

            logger.info(f"Updated EventBridge rule {rule_name}")

        except Exception as e:
            logger.error(f"Failed to update EventBridge rule: {e}")

    def _delete_eventbridge_rule(self, query: ScheduledQuery) -> None:
        """Delete EventBridge rule for scheduled query."""
        rule_name = self._get_rule_name(query)

        try:
            # Remove targets first
            self.events.remove_targets(Rule=rule_name, Ids=['1'])

            # Delete rule
            self.events.delete_rule(Name=rule_name)

            logger.info(f"Deleted EventBridge rule {rule_name}")

        except self.events.exceptions.ResourceNotFoundException:
            pass
        except Exception as e:
            logger.error(f"Failed to delete EventBridge rule: {e}")

    def _add_lambda_permission(self, rule_name: str) -> None:
        """Add Lambda permission for EventBridge invocation."""
        lambda_arn = self._get_lambda_arn()
        function_name = lambda_arn.split(':')[-1]

        try:
            self.lambda_client.add_permission(
                FunctionName=function_name,
                StatementId=f'{rule_name}-invoke',
                Action='lambda:InvokeFunction',
                Principal='events.amazonaws.com',
                SourceArn=f'arn:aws:events:*:*:rule/{rule_name}'
            )
        except self.lambda_client.exceptions.ResourceConflictException:
            pass  # Permission already exists
        except Exception as e:
            logger.warning(f"Failed to add Lambda permission: {e}")
