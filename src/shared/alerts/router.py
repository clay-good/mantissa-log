"""
Alert Router

Routes alerts to configured integrations based on severity and rules.
"""

import json
import boto3
from typing import Dict, Any, List, Optional
from dataclasses import dataclass
from datetime import datetime


@dataclass
class Alert:
    """Alert data structure."""
    alert_id: str
    rule_id: str
    rule_name: str
    severity: str
    summary: str
    description: str
    query: str
    result_count: int
    results: List[Dict[str, Any]]
    timestamp: str
    metadata: Dict[str, Any]


class AlertRouter:
    """Routes alerts to configured integrations."""
    
    def __init__(self):
        self.dynamodb = boto3.resource('dynamodb')
        self.sqs = boto3.client('sqs')
        self.integrations_table = self.dynamodb.Table(
            self._get_table_name('integration-settings')
        )
        self.alerts_table = self.dynamodb.Table(
            self._get_table_name('alerts')
        )
    
    def route_alert(self, user_id: str, alert: Alert) -> Dict[str, Any]:
        """
        Route alert to configured integrations.
        
        Args:
            user_id: User who owns the alert
            alert: Alert to route
        
        Returns:
            Dictionary with routing results
        """
        # Get user's integrations
        integrations = self._get_user_integrations(user_id)
        
        # Filter integrations by severity
        matching_integrations = self._filter_by_severity(
            integrations,
            alert.severity
        )
        
        # Store alert in DynamoDB
        self._store_alert(user_id, alert)
        
        # Route to each matching integration
        results = []
        for integration in matching_integrations:
            result = self._send_to_integration(
                user_id,
                alert,
                integration
            )
            results.append(result)
        
        return {
            'alert_id': alert.alert_id,
            'routed_to': len(results),
            'results': results
        }
    
    def _get_user_integrations(self, user_id: str) -> List[Dict[str, Any]]:
        """Get all enabled integrations for a user."""
        response = self.integrations_table.query(
            KeyConditionExpression='user_id = :user_id',
            FilterExpression='enabled = :true',
            ExpressionAttributeValues={
                ':user_id': user_id,
                ':true': True
            }
        )
        return response.get('Items', [])
    
    def _filter_by_severity(
        self,
        integrations: List[Dict[str, Any]],
        severity: str
    ) -> List[Dict[str, Any]]:
        """Filter integrations that match alert severity."""
        matching = []
        for integration in integrations:
            severity_filter = integration.get('severity_filter', [])
            if not severity_filter or severity in severity_filter:
                matching.append(integration)
        return matching
    
    def _send_to_integration(
        self,
        user_id: str,
        alert: Alert,
        integration: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Send alert to integration via SQS."""
        queue_url = self._get_alert_queue_url()
        
        message = {
            'user_id': user_id,
            'alert_id': alert.alert_id,
            'integration_id': integration['integration_id'],
            'integration_type': integration['type'],
            'alert': {
                'rule_name': alert.rule_name,
                'severity': alert.severity,
                'summary': alert.summary,
                'description': alert.description,
                'result_count': alert.result_count,
                'results': alert.results[:10],
                'timestamp': alert.timestamp
            },
            'config': integration.get('config', {}),
            'retry_count': 0,
            'max_retries': 3
        }
        
        try:
            response = self.sqs.send_message(
                QueueUrl=queue_url,
                MessageBody=json.dumps(message)
            )
            
            return {
                'integration_id': integration['integration_id'],
                'integration_type': integration['type'],
                'status': 'queued',
                'message_id': response['MessageId']
            }
            
        except Exception as e:
            return {
                'integration_id': integration['integration_id'],
                'integration_type': integration['type'],
                'status': 'failed',
                'error': str(e)
            }
    
    def _store_alert(self, user_id: str, alert: Alert) -> None:
        """Store alert in DynamoDB for history."""
        self.alerts_table.put_item(
            Item={
                'user_id': user_id,
                'alert_id': alert.alert_id,
                'rule_id': alert.rule_id,
                'rule_name': alert.rule_name,
                'severity': alert.severity,
                'summary': alert.summary,
                'description': alert.description,
                'result_count': alert.result_count,
                'timestamp': alert.timestamp,
                'status': 'pending',
                'created_at': datetime.utcnow().isoformat() + 'Z'
            }
        )
    
    def _get_table_name(self, table_type: str) -> str:
        """Get DynamoDB table name."""
        import os
        prefix = os.environ.get('TABLE_PREFIX', 'mantissa-log')
        env = os.environ.get('ENVIRONMENT', 'dev')
        return f'{prefix}-{table_type}-{env}'
    
    def _get_alert_queue_url(self) -> str:
        """Get SQS queue URL for alert processing."""
        import os
        return os.environ.get(
            'ALERT_QUEUE_URL',
            'https://sqs.us-east-1.amazonaws.com/123456789012/mantissa-log-alerts'
        )


class NLAlertRouter:
    """Routes alerts from natural language commands."""
    
    def __init__(self, router: AlertRouter):
        self.router = router
    
    def parse_routing_command(self, command: str) -> Optional[Dict[str, Any]]:
        """Parse natural language routing command."""
        command_lower = command.lower().strip()
        
        if 'slack' in command_lower:
            return {'action': 'route_to_slack', 'integration_type': 'slack'}
        elif 'jira' in command_lower or 'ticket' in command_lower:
            return {'action': 'route_to_jira', 'integration_type': 'jira'}
        elif 'pagerduty' in command_lower or 'page' in command_lower:
            return {'action': 'route_to_pagerduty', 'integration_type': 'pagerduty'}
        
        return None
