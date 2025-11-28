"""
Alert Delivery Engine

Processes alerts from SQS queue with retry logic and deduplication.
"""

import json
import time
import hashlib
import boto3
import requests
from typing import Dict, Any, Optional
from datetime import datetime, timedelta


class AlertDelivery:
    """Delivers alerts to integrations with retry and deduplication."""
    
    def __init__(self):
        self.dynamodb = boto3.resource('dynamodb')
        self.secretsmanager = boto3.client('secretsmanager')
        self.sqs = boto3.client('sqs')
        self.dedup_table = self.dynamodb.Table(self._get_table_name('alert-dedup'))
    
    def process_alert_message(self, message: Dict[str, Any]) -> Dict[str, Any]:
        """
        Process alert message from SQS.
        
        Args:
            message: SQS message with alert data
        
        Returns:
            Delivery result
        """
        user_id = message['user_id']
        alert = message['alert']
        integration_type = message['integration_type']
        integration_id = message['integration_id']
        config = message['config']
        retry_count = message.get('retry_count', 0)
        max_retries = message.get('max_retries', 3)
        
        # Check for duplicate alert
        if self._is_duplicate(user_id, alert):
            return {
                'status': 'suppressed',
                'reason': 'duplicate',
                'alert_id': message['alert_id']
            }
        
        # Get integration secrets
        secrets = self._get_integration_secrets(user_id, integration_type)
        full_config = {**config, **secrets}
        
        # Deliver alert
        try:
            result = self._deliver_alert(
                integration_type,
                alert,
                full_config
            )
            
            # Mark as delivered
            self._record_delivery(user_id, alert, integration_id, 'delivered')
            
            return {
                'status': 'delivered',
                'integration_type': integration_type,
                'result': result
            }
            
        except Exception as e:
            # Retry logic
            if retry_count < max_retries:
                # Re-queue with exponential backoff
                delay = self._calculate_backoff(retry_count)
                self._requeue_with_delay(message, delay)
                
                return {
                    'status': 'retrying',
                    'retry_count': retry_count + 1,
                    'delay_seconds': delay,
                    'error': str(e)
                }
            else:
                # Send to DLQ
                self._send_to_dlq(message, str(e))
                self._record_delivery(user_id, alert, integration_id, 'failed', str(e))
                
                return {
                    'status': 'failed',
                    'error': str(e),
                    'retries_exhausted': True
                }
    
    def _is_duplicate(self, user_id: str, alert: Dict[str, Any]) -> bool:
        """
        Check if alert is a duplicate within deduplication window.
        
        Uses hash of rule_name + severity + summary for dedup key.
        """
        # Generate dedup key
        dedup_key = self._generate_dedup_key(alert)
        
        # Check if exists in last 5 minutes
        threshold = (datetime.utcnow() - timedelta(minutes=5)).isoformat() + 'Z'
        
        try:
            response = self.dedup_table.get_item(
                Key={
                    'user_id': user_id,
                    'dedup_key': dedup_key
                }
            )
            
            if 'Item' in response:
                last_seen = response['Item'].get('timestamp', '')
                if last_seen > threshold:
                    # Duplicate within window
                    return True
            
            # Record this alert for deduplication
            self.dedup_table.put_item(
                Item={
                    'user_id': user_id,
                    'dedup_key': dedup_key,
                    'timestamp': datetime.utcnow().isoformat() + 'Z',
                    'ttl': int(time.time()) + 3600  # 1 hour TTL
                }
            )
            
            return False
            
        except Exception as e:
            print(f"Dedup check failed: {str(e)}")
            # Fail open - deliver alert if dedup check fails
            return False
    
    def _generate_dedup_key(self, alert: Dict[str, Any]) -> str:
        """Generate deduplication key from alert."""
        key_parts = [
            alert.get('rule_name', ''),
            alert.get('severity', ''),
            alert.get('summary', '')
        ]
        key_string = '|'.join(key_parts)
        return hashlib.sha256(key_string.encode()).hexdigest()
    
    def _deliver_alert(
        self,
        integration_type: str,
        alert: Dict[str, Any],
        config: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Deliver alert to specific integration type."""
        if integration_type == 'slack':
            return self._deliver_to_slack(alert, config)
        elif integration_type == 'jira':
            return self._deliver_to_jira(alert, config)
        elif integration_type == 'pagerduty':
            return self._deliver_to_pagerduty(alert, config)
        elif integration_type == 'webhook':
            return self._deliver_to_webhook(alert, config)
        else:
            raise ValueError(f"Unknown integration type: {integration_type}")
    
    def _deliver_to_slack(
        self,
        alert: Dict[str, Any],
        config: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Deliver alert to Slack."""
        webhook_url = config.get('webhook_url')
        
        payload = {
            'text': f"*{alert['rule_name']}* ({alert['severity']})",
            'username': config.get('username', 'Mantissa Log'),
            'icon_emoji': config.get('icon_emoji', ':shield:'),
            'blocks': [
                {
                    'type': 'header',
                    'text': {
                        'type': 'plain_text',
                        'text': alert['rule_name']
                    }
                },
                {
                    'type': 'section',
                    'fields': [
                        {
                            'type': 'mrkdwn',
                            'text': f"*Severity:*\n{alert['severity']}"
                        },
                        {
                            'type': 'mrkdwn',
                            'text': f"*Result Count:*\n{alert['result_count']}"
                        }
                    ]
                },
                {
                    'type': 'section',
                    'text': {
                        'type': 'mrkdwn',
                        'text': alert['description']
                    }
                }
            ]
        }
        
        if config.get('channel'):
            payload['channel'] = config['channel']
        
        response = requests.post(webhook_url, json=payload, timeout=10)
        response.raise_for_status()
        
        return {'status': 'ok', 'status_code': response.status_code}
    
    def _deliver_to_jira(
        self,
        alert: Dict[str, Any],
        config: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Deliver alert to Jira."""
        url = config['url'].rstrip('/')
        email = config['email']
        api_token = config['api_token']
        project_key = config['project_key']
        issue_type = config.get('issue_type', 'Bug')
        
        # Map severity to priority
        severity_mapping = config.get('severity_mapping', {})
        priority = severity_mapping.get(alert['severity'], 'Medium')
        
        issue_data = {
            'fields': {
                'project': {'key': project_key},
                'summary': f"{alert['rule_name']} - {alert['result_count']} matches",
                'description': alert['description'],
                'issuetype': {'name': issue_type},
                'priority': {'name': priority}
            }
        }
        
        response = requests.post(
            f'{url}/rest/api/3/issue',
            auth=(email, api_token),
            json=issue_data,
            timeout=10
        )
        response.raise_for_status()
        
        issue = response.json()
        return {'issue_key': issue['key'], 'issue_id': issue['id']}
    
    def _deliver_to_pagerduty(
        self,
        alert: Dict[str, Any],
        config: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Deliver alert to PagerDuty."""
        integration_key = config['integration_key']
        
        # Map severity to PagerDuty severity
        severity_map = {
            'critical': 'critical',
            'high': 'error',
            'medium': 'warning',
            'low': 'warning',
            'info': 'info'
        }
        pd_severity = severity_map.get(alert['severity'], 'error')
        
        payload = {
            'routing_key': integration_key,
            'event_action': 'trigger',
            'payload': {
                'summary': f"{alert['rule_name']}: {alert['result_count']} matches",
                'source': 'mantissa-log',
                'severity': pd_severity,
                'custom_details': {
                    'description': alert['description'],
                    'result_count': alert['result_count'],
                    'timestamp': alert['timestamp']
                }
            }
        }
        
        response = requests.post(
            'https://events.pagerduty.com/v2/enqueue',
            json=payload,
            timeout=10
        )
        response.raise_for_status()
        
        result = response.json()
        return {'dedup_key': result['dedup_key'], 'status': result['status']}
    
    def _deliver_to_webhook(
        self,
        alert: Dict[str, Any],
        config: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Deliver alert to custom webhook."""
        url = config['url']
        method = config.get('method', 'POST')
        headers = config.get('headers', {})
        
        payload = {
            'rule_name': alert['rule_name'],
            'severity': alert['severity'],
            'summary': alert['summary'],
            'description': alert['description'],
            'result_count': alert['result_count'],
            'timestamp': alert['timestamp'],
            'results': alert.get('results', [])
        }
        
        if method == 'POST':
            response = requests.post(url, json=payload, headers=headers, timeout=10)
        else:
            response = requests.put(url, json=payload, headers=headers, timeout=10)
        
        response.raise_for_status()
        return {'status_code': response.status_code}
    
    def _get_integration_secrets(
        self,
        user_id: str,
        integration_type: str
    ) -> Dict[str, Any]:
        """Retrieve integration secrets from Secrets Manager."""
        secret_id = f'mantissa-log/users/{user_id}/integrations/{integration_type}'
        
        try:
            response = self.secretsmanager.get_secret_value(SecretId=secret_id)
            return json.loads(response['SecretString'])
        except self.secretsmanager.exceptions.ResourceNotFoundException:
            return {}
    
    def _calculate_backoff(self, retry_count: int) -> int:
        """Calculate exponential backoff delay in seconds."""
        return min(300, (2 ** retry_count) * 5)  # Max 5 minutes
    
    def _requeue_with_delay(self, message: Dict[str, Any], delay: int) -> None:
        """Re-queue message with delay."""
        queue_url = self._get_alert_queue_url()
        
        message['retry_count'] = message.get('retry_count', 0) + 1
        
        self.sqs.send_message(
            QueueUrl=queue_url,
            MessageBody=json.dumps(message),
            DelaySeconds=min(delay, 900)  # Max 15 minutes
        )
    
    def _send_to_dlq(self, message: Dict[str, Any], error: str) -> None:
        """Send failed message to Dead Letter Queue."""
        dlq_url = self._get_dlq_url()
        
        message['final_error'] = error
        message['failed_at'] = datetime.utcnow().isoformat() + 'Z'
        
        self.sqs.send_message(
            QueueUrl=dlq_url,
            MessageBody=json.dumps(message)
        )
    
    def _record_delivery(
        self,
        user_id: str,
        alert: Dict[str, Any],
        integration_id: str,
        status: str,
        error: Optional[str] = None
    ) -> None:
        """Record delivery attempt in DynamoDB."""
        alerts_table = self.dynamodb.Table(self._get_table_name('alerts'))
        
        delivery_record = {
            'integration_id': integration_id,
            'status': status,
            'timestamp': datetime.utcnow().isoformat() + 'Z'
        }
        
        if error:
            delivery_record['error'] = error
        
        alerts_table.update_item(
            Key={
                'user_id': user_id,
                'alert_id': alert.get('alert_id', 'unknown')
            },
            UpdateExpression='SET #status = :status, deliveries = list_append(if_not_exists(deliveries, :empty_list), :delivery)',
            ExpressionAttributeNames={'#status': 'status'},
            ExpressionAttributeValues={
                ':status': status,
                ':delivery': [delivery_record],
                ':empty_list': []
            }
        )
    
    def _get_table_name(self, table_type: str) -> str:
        """Get DynamoDB table name."""
        import os
        prefix = os.environ.get('TABLE_PREFIX', 'mantissa-log')
        env = os.environ.get('ENVIRONMENT', 'dev')
        return f'{prefix}-{table_type}-{env}'
    
    def _get_alert_queue_url(self) -> str:
        """Get SQS queue URL."""
        import os
        return os.environ.get('ALERT_QUEUE_URL', '')
    
    def _get_dlq_url(self) -> str:
        """Get Dead Letter Queue URL."""
        import os
        return os.environ.get('ALERT_DLQ_URL', '')
