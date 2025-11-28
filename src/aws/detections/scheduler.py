"""
Detection Rule Scheduler

Manages EventBridge rules for scheduled detection execution.
"""

import json
import boto3
from typing import Dict, Any, List, Optional
from datetime import datetime


class DetectionScheduler:
    """Manages scheduled execution of detection rules."""

    def __init__(self):
        self.events = boto3.client('events')
        self.lambda_client = boto3.client('lambda')
        self.dynamodb = boto3.resource('dynamodb')

    def schedule_rule(
        self,
        user_id: str,
        rule_id: str,
        schedule_expression: str
    ) -> Dict[str, Any]:
        """
        Create or update EventBridge rule for detection execution.

        Args:
            user_id: User who owns the rule
            rule_id: Detection rule ID
            schedule_expression: Cron or rate expression (e.g., "rate(5 minutes)")

        Returns:
            Scheduling result with rule ARN
        """
        rule_name = self._get_rule_name(user_id, rule_id)
        lambda_arn = self._get_lambda_arn('rule-executor')

        # Create or update EventBridge rule
        response = self.events.put_rule(
            Name=rule_name,
            ScheduleExpression=schedule_expression,
            State='ENABLED',
            Description=f'Execute detection rule {rule_id} for user {user_id}'
        )

        rule_arn = response['RuleArn']

        # Add Lambda permission for EventBridge to invoke
        self._add_lambda_permission(lambda_arn, rule_name)

        # Set Lambda as target
        self.events.put_targets(
            Rule=rule_name,
            Targets=[
                {
                    'Id': '1',
                    'Arn': lambda_arn,
                    'Input': json.dumps({
                        'rule_id': rule_id,
                        'user_id': user_id
                    })
                }
            ]
        )

        # Update rule metadata in DynamoDB
        self._update_rule_metadata(user_id, rule_id, {
            'schedule_rule_name': rule_name,
            'schedule_rule_arn': rule_arn,
            'schedule_expression': schedule_expression,
            'schedule_status': 'enabled',
            'last_scheduled': datetime.utcnow().isoformat() + 'Z'
        })

        return {
            'rule_name': rule_name,
            'rule_arn': rule_arn,
            'schedule_expression': schedule_expression,
            'status': 'enabled'
        }

    def disable_rule(self, user_id: str, rule_id: str) -> Dict[str, Any]:
        """
        Disable scheduled execution for a detection rule.

        Args:
            user_id: User who owns the rule
            rule_id: Detection rule ID

        Returns:
            Result of disable operation
        """
        rule_name = self._get_rule_name(user_id, rule_id)

        try:
            # Disable EventBridge rule
            self.events.disable_rule(Name=rule_name)

            # Update metadata
            self._update_rule_metadata(user_id, rule_id, {
                'schedule_status': 'disabled',
                'disabled_at': datetime.utcnow().isoformat() + 'Z'
            })

            return {
                'rule_name': rule_name,
                'status': 'disabled'
            }

        except self.events.exceptions.ResourceNotFoundException:
            return {
                'rule_name': rule_name,
                'status': 'not_found',
                'message': 'No scheduled rule found'
            }

    def enable_rule(self, user_id: str, rule_id: str) -> Dict[str, Any]:
        """
        Enable scheduled execution for a detection rule.

        Args:
            user_id: User who owns the rule
            rule_id: Detection rule ID

        Returns:
            Result of enable operation
        """
        rule_name = self._get_rule_name(user_id, rule_id)

        try:
            # Enable EventBridge rule
            self.events.enable_rule(Name=rule_name)

            # Update metadata
            self._update_rule_metadata(user_id, rule_id, {
                'schedule_status': 'enabled',
                'enabled_at': datetime.utcnow().isoformat() + 'Z'
            })

            return {
                'rule_name': rule_name,
                'status': 'enabled'
            }

        except self.events.exceptions.ResourceNotFoundException:
            return {
                'rule_name': rule_name,
                'status': 'not_found',
                'message': 'No scheduled rule found'
            }

    def delete_schedule(self, user_id: str, rule_id: str) -> Dict[str, Any]:
        """
        Delete scheduled execution for a detection rule.

        Args:
            user_id: User who owns the rule
            rule_id: Detection rule ID

        Returns:
            Result of delete operation
        """
        rule_name = self._get_rule_name(user_id, rule_id)

        try:
            # Remove targets first
            self.events.remove_targets(
                Rule=rule_name,
                Ids=['1']
            )

            # Delete rule
            self.events.delete_rule(Name=rule_name)

            # Update metadata
            self._update_rule_metadata(user_id, rule_id, {
                'schedule_status': 'deleted',
                'schedule_rule_name': None,
                'schedule_rule_arn': None,
                'deleted_at': datetime.utcnow().isoformat() + 'Z'
            })

            return {
                'rule_name': rule_name,
                'status': 'deleted'
            }

        except self.events.exceptions.ResourceNotFoundException:
            return {
                'rule_name': rule_name,
                'status': 'not_found',
                'message': 'No scheduled rule found'
            }

    def get_schedule_status(
        self,
        user_id: str,
        rule_id: str
    ) -> Dict[str, Any]:
        """
        Get current schedule status for a detection rule.

        Args:
            user_id: User who owns the rule
            rule_id: Detection rule ID

        Returns:
            Schedule status details
        """
        rule_name = self._get_rule_name(user_id, rule_id)

        try:
            response = self.events.describe_rule(Name=rule_name)

            return {
                'rule_name': rule_name,
                'rule_arn': response['Arn'],
                'schedule_expression': response.get('ScheduleExpression'),
                'state': response['State'],
                'description': response.get('Description')
            }

        except self.events.exceptions.ResourceNotFoundException:
            return {
                'rule_name': rule_name,
                'status': 'not_scheduled'
            }

    def list_user_schedules(self, user_id: str) -> List[Dict[str, Any]]:
        """
        List all scheduled rules for a user.

        Args:
            user_id: User ID

        Returns:
            List of scheduled rules
        """
        prefix = f'detection-{user_id}-'
        schedules = []

        paginator = self.events.get_paginator('list_rules')
        for page in paginator.paginate(NamePrefix=prefix):
            for rule in page.get('Rules', []):
                schedules.append({
                    'rule_name': rule['Name'],
                    'rule_arn': rule['Arn'],
                    'schedule_expression': rule.get('ScheduleExpression'),
                    'state': rule['State'],
                    'description': rule.get('Description')
                })

        return schedules

    def _get_rule_name(self, user_id: str, rule_id: str) -> str:
        """Generate EventBridge rule name."""
        import os
        env = os.environ.get('ENVIRONMENT', 'dev')
        return f'detection-{user_id}-{rule_id}-{env}'

    def _get_lambda_arn(self, function_name: str) -> str:
        """Get Lambda function ARN."""
        import os
        env = os.environ.get('ENVIRONMENT', 'dev')
        full_name = f'mantissa-log-{function_name}-{env}'

        try:
            response = self.lambda_client.get_function(FunctionName=full_name)
            return response['Configuration']['FunctionArn']
        except self.lambda_client.exceptions.ResourceNotFoundException:
            account_id = os.environ.get('AWS_ACCOUNT_ID')
            region = os.environ.get('AWS_REGION', 'us-east-1')
            return f'arn:aws:lambda:{region}:{account_id}:function:{full_name}'

    def _add_lambda_permission(self, lambda_arn: str, rule_name: str):
        """Add permission for EventBridge to invoke Lambda."""
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
            pass

    def _update_rule_metadata(
        self,
        user_id: str,
        rule_id: str,
        updates: Dict[str, Any]
    ):
        """Update detection rule metadata in DynamoDB."""
        table = self.dynamodb.Table(self._get_table_name('detection-rules'))

        update_expr = 'SET ' + ', '.join([f'{k} = :{k}' for k in updates.keys()])
        expr_values = {f':{k}': v for k, v in updates.items()}
        expr_values[':updated_at'] = datetime.utcnow().isoformat() + 'Z'
        update_expr += ', updated_at = :updated_at'

        table.update_item(
            Key={
                'user_id': user_id,
                'rule_id': rule_id
            },
            UpdateExpression=update_expr,
            ExpressionAttributeValues=expr_values
        )

    def _get_table_name(self, table_type: str) -> str:
        """Get DynamoDB table name."""
        import os
        prefix = os.environ.get('TABLE_PREFIX', 'mantissa-log')
        env = os.environ.get('ENVIRONMENT', 'dev')
        return f'{prefix}-{table_type}-{env}'


def lambda_handler(event, context):
    """
    Lambda handler for schedule management API.

    Endpoints:
    - POST /api/detections/schedule - Create/update schedule
    - DELETE /api/detections/schedule - Delete schedule
    - PUT /api/detections/schedule/enable - Enable schedule
    - PUT /api/detections/schedule/disable - Disable schedule
    - GET /api/detections/schedule - Get schedule status
    - GET /api/detections/schedules - List user schedules
    """
    try:
        http_method = event.get('httpMethod')
        path = event.get('path', '')
        body = json.loads(event.get('body', '{}'))
        params = event.get('queryStringParameters', {}) or {}

        scheduler = DetectionScheduler()

        # POST /api/detections/schedule - Create/update schedule
        if http_method == 'POST' and path.endswith('/schedule'):
            user_id = body.get('user_id')
            rule_id = body.get('rule_id')
            schedule_expression = body.get('schedule_expression')

            if not all([user_id, rule_id, schedule_expression]):
                return {
                    'statusCode': 400,
                    'body': json.dumps({
                        'error': 'user_id, rule_id, and schedule_expression are required'
                    })
                }

            result = scheduler.schedule_rule(user_id, rule_id, schedule_expression)

            return {
                'statusCode': 200,
                'body': json.dumps(result)
            }

        # DELETE /api/detections/schedule - Delete schedule
        elif http_method == 'DELETE' and path.endswith('/schedule'):
            user_id = params.get('user_id')
            rule_id = params.get('rule_id')

            if not all([user_id, rule_id]):
                return {
                    'statusCode': 400,
                    'body': json.dumps({
                        'error': 'user_id and rule_id are required'
                    })
                }

            result = scheduler.delete_schedule(user_id, rule_id)

            return {
                'statusCode': 200,
                'body': json.dumps(result)
            }

        # PUT /api/detections/schedule/enable - Enable schedule
        elif http_method == 'PUT' and path.endswith('/enable'):
            user_id = body.get('user_id')
            rule_id = body.get('rule_id')

            if not all([user_id, rule_id]):
                return {
                    'statusCode': 400,
                    'body': json.dumps({
                        'error': 'user_id and rule_id are required'
                    })
                }

            result = scheduler.enable_rule(user_id, rule_id)

            return {
                'statusCode': 200,
                'body': json.dumps(result)
            }

        # PUT /api/detections/schedule/disable - Disable schedule
        elif http_method == 'PUT' and path.endswith('/disable'):
            user_id = body.get('user_id')
            rule_id = body.get('rule_id')

            if not all([user_id, rule_id]):
                return {
                    'statusCode': 400,
                    'body': json.dumps({
                        'error': 'user_id and rule_id are required'
                    })
                }

            result = scheduler.disable_rule(user_id, rule_id)

            return {
                'statusCode': 200,
                'body': json.dumps(result)
            }

        # GET /api/detections/schedule - Get schedule status
        elif http_method == 'GET' and path.endswith('/schedule'):
            user_id = params.get('user_id')
            rule_id = params.get('rule_id')

            if not all([user_id, rule_id]):
                return {
                    'statusCode': 400,
                    'body': json.dumps({
                        'error': 'user_id and rule_id are required'
                    })
                }

            result = scheduler.get_schedule_status(user_id, rule_id)

            return {
                'statusCode': 200,
                'body': json.dumps(result)
            }

        # GET /api/detections/schedules - List user schedules
        elif http_method == 'GET' and path.endswith('/schedules'):
            user_id = params.get('user_id')

            if not user_id:
                return {
                    'statusCode': 400,
                    'body': json.dumps({'error': 'user_id is required'})
                }

            schedules = scheduler.list_user_schedules(user_id)

            return {
                'statusCode': 200,
                'body': json.dumps({'schedules': schedules})
            }

        else:
            return {
                'statusCode': 404,
                'body': json.dumps({'error': 'Not found'})
            }

    except Exception as e:
        print(f"Error in scheduler API: {str(e)}")
        import traceback
        traceback.print_exc()

        return {
            'statusCode': 500,
            'body': json.dumps({'error': str(e)})
        }
