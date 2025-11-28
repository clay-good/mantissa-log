"""
Integration Health Monitor

Monitors health of integrations and provides status reporting.
"""

import json
import boto3
from typing import Dict, Any, List
from datetime import datetime, timedelta


class IntegrationHealthMonitor:
    """Monitors and reports integration health."""
    
    def __init__(self):
        self.dynamodb = boto3.resource('dynamodb')
        self.integrations_table = self.dynamodb.Table(
            self._get_table_name('integration-settings')
        )
        self.alerts_table = self.dynamodb.Table(
            self._get_table_name('alerts')
        )
    
    def check_integration_health(
        self,
        user_id: str,
        integration_id: str
    ) -> Dict[str, Any]:
        """
        Check health of a specific integration.
        
        Returns health status with metrics.
        """
        # Get integration
        response = self.integrations_table.get_item(
            Key={
                'user_id': user_id,
                'integration_id': integration_id
            }
        )
        
        if 'Item' not in response:
            return {'status': 'not_found'}
        
        integration = response['Item']
        
        # Get recent alert deliveries
        metrics = self._get_delivery_metrics(user_id, integration_id)
        
        # Determine health status
        health_status = self._calculate_health_status(metrics)
        
        # Update integration health
        self.integrations_table.update_item(
            Key={
                'user_id': user_id,
                'integration_id': integration_id
            },
            UpdateExpression='SET health_status = :status, health_checked_at = :timestamp, health_metrics = :metrics',
            ExpressionAttributeValues={
                ':status': health_status['status'],
                ':timestamp': datetime.utcnow().isoformat() + 'Z',
                ':metrics': metrics
            }
        )
        
        return {
            **health_status,
            'integration_id': integration_id,
            'integration_type': integration['type'],
            'integration_name': integration.get('name'),
            'metrics': metrics
        }
    
    def check_all_integrations(self, user_id: str) -> List[Dict[str, Any]]:
        """Check health of all user integrations."""
        # Get all integrations
        response = self.integrations_table.query(
            KeyConditionExpression='user_id = :user_id',
            ExpressionAttributeValues={':user_id': user_id}
        )
        
        integrations = response.get('Items', [])
        
        # Check each integration
        results = []
        for integration in integrations:
            health = self.check_integration_health(
                user_id,
                integration['integration_id']
            )
            results.append(health)
        
        return results
    
    def _get_delivery_metrics(
        self,
        user_id: str,
        integration_id: str
    ) -> Dict[str, Any]:
        """Get delivery metrics for the last 24 hours."""
        # Query alerts delivered to this integration
        threshold = (datetime.utcnow() - timedelta(hours=24)).isoformat() + 'Z'
        
        # Get recent alerts
        response = self.alerts_table.query(
            KeyConditionExpression='user_id = :user_id',
            FilterExpression='created_at > :threshold',
            ExpressionAttributeValues={
                ':user_id': user_id,
                ':threshold': threshold
            }
        )
        
        alerts = response.get('Items', [])
        
        # Calculate metrics
        total_attempts = 0
        successful = 0
        failed = 0
        retried = 0
        
        for alert in alerts:
            deliveries = alert.get('deliveries', [])
            for delivery in deliveries:
                if delivery.get('integration_id') == integration_id:
                    total_attempts += 1
                    status = delivery.get('status', '')
                    
                    if status == 'delivered':
                        successful += 1
                    elif status == 'failed':
                        failed += 1
                    elif status == 'retrying':
                        retried += 1
        
        success_rate = (successful / total_attempts * 100) if total_attempts > 0 else 0
        
        return {
            'period_hours': 24,
            'total_attempts': total_attempts,
            'successful': successful,
            'failed': failed,
            'retried': retried,
            'success_rate': round(success_rate, 2)
        }
    
    def _calculate_health_status(self, metrics: Dict[str, Any]) -> Dict[str, Any]:
        """Calculate overall health status from metrics."""
        total = metrics['total_attempts']
        success_rate = metrics['success_rate']
        
        if total == 0:
            return {
                'status': 'unknown',
                'message': 'No recent delivery attempts'
            }
        
        if success_rate >= 95:
            return {
                'status': 'healthy',
                'message': 'Integration is working normally'
            }
        elif success_rate >= 80:
            return {
                'status': 'degraded',
                'message': 'Some delivery failures detected'
            }
        else:
            return {
                'status': 'unhealthy',
                'message': 'High failure rate detected'
            }
    
    def _get_table_name(self, table_type: str) -> str:
        """Get DynamoDB table name."""
        import os
        prefix = os.environ.get('TABLE_PREFIX', 'mantissa-log')
        env = os.environ.get('ENVIRONMENT', 'dev')
        return f'{prefix}-{table_type}-{env}'
