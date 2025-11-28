"""
Query-to-Rule Conversion API

Converts ad hoc queries into scheduled detection rules.
"""

import json
import boto3
import yaml
from datetime import datetime
from typing import Dict, Any, Optional
from pathlib import Path


s3 = boto3.client('s3')
dynamodb = boto3.resource('dynamodb')


def lambda_handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """
    Lambda handler for converting queries to detection rules.
    
    Expected input:
    {
        "query": "SELECT ...",
        "ruleName": "my_detection_rule",
        "description": "Description of what this detects",
        "schedule": "rate(5 minutes)" or "cron(0 * * * ? *)",
        "threshold": 10,
        "severity": "high",
        "alertDestinations": ["slack", "email"],
        "userId": "user123"
    }
    """
    try:
        body = json.loads(event.get('body', '{}'))
        
        # Validate required fields
        required_fields = ['query', 'ruleName', 'description', 'schedule', 'severity', 'userId']
        for field in required_fields:
            if field not in body:
                return error_response(f"Missing required field: {field}", 400)
        
        # Create detection rule YAML
        rule = create_detection_rule(
            name=body['ruleName'],
            description=body['description'],
            query=body['query'],
            schedule=body['schedule'],
            threshold=body.get('threshold', 1),
            severity=body['severity'],
            alert_destinations=body.get('alertDestinations', [])
        )
        
        # Save rule to S3
        rule_key = save_rule_to_s3(
            rule=rule,
            user_id=body['userId'],
            rule_name=body['ruleName']
        )
        
        # Track rule metadata in DynamoDB
        save_rule_metadata(
            user_id=body['userId'],
            rule_name=body['ruleName'],
            s3_key=rule_key,
            schedule=body['schedule'],
            severity=body['severity']
        )
        
        return {
            'statusCode': 200,
            'headers': {
                'Content-Type': 'application/json',
                'Access-Control-Allow-Origin': '*'
            },
            'body': json.dumps({
                'message': 'Detection rule created successfully',
                'ruleKey': rule_key,
                'rule': rule
            })
        }
        
    except Exception as e:
        print(f"Error creating detection rule: {str(e)}")
        return error_response(str(e), 500)


def create_detection_rule(
    name: str,
    description: str,
    query: str,
    schedule: str,
    threshold: int,
    severity: str,
    alert_destinations: list
) -> Dict[str, Any]:
    """Create a detection rule in YAML format."""
    
    rule = {
        'name': name,
        'description': description,
        'data_source': 'custom',
        'query': query.strip(),
        'schedule': schedule,
        'threshold': threshold,
        'severity': severity,
        'enabled': True,
        'created_at': datetime.utcnow().isoformat() + 'Z',
        'metadata': {
            'created_from': 'web_ui',
            'version': '1.0'
        }
    }
    
    # Add alert configuration if destinations specified
    if alert_destinations:
        rule['alert'] = []
        for dest in alert_destinations:
            if dest == 'slack':
                rule['alert'].append({
                    'type': 'slack',
                    'channel': '${SLACK_CHANNEL}',
                    'severity_threshold': severity
                })
            elif dest == 'email':
                rule['alert'].append({
                    'type': 'email',
                    'recipients': ['${ALERT_EMAIL}']
                })
            elif dest == 'jira':
                rule['alert'].append({
                    'type': 'jira',
                    'project': '${JIRA_PROJECT}',
                    'issue_type': 'Security Finding'
                })
            elif dest == 'pagerduty':
                rule['alert'].append({
                    'type': 'pagerduty',
                    'service_key': '${PAGERDUTY_SERVICE_KEY}',
                    'severity_threshold': 'high'
                })
    
    return rule


def save_rule_to_s3(rule: Dict[str, Any], user_id: str, rule_name: str) -> str:
    """Save detection rule to S3."""
    
    bucket = get_rules_bucket()
    
    # Create safe filename
    safe_name = rule_name.lower().replace(' ', '_').replace('-', '_')
    rule_key = f'user_rules/{user_id}/{safe_name}.yaml'
    
    # Convert to YAML
    rule_yaml = yaml.dump(rule, default_flow_style=False, sort_keys=False)
    
    # Upload to S3
    s3.put_object(
        Bucket=bucket,
        Key=rule_key,
        Body=rule_yaml.encode('utf-8'),
        ContentType='application/x-yaml',
        Metadata={
            'user_id': user_id,
            'created_at': datetime.utcnow().isoformat()
        }
    )
    
    return rule_key


def save_rule_metadata(
    user_id: str,
    rule_name: str,
    s3_key: str,
    schedule: str,
    severity: str
) -> None:
    """Save rule metadata to DynamoDB for tracking."""
    
    table_name = get_rules_table_name()
    table = dynamodb.Table(table_name)
    
    table.put_item(
        Item={
            'user_id': user_id,
            'rule_name': rule_name,
            's3_key': s3_key,
            'schedule': schedule,
            'severity': severity,
            'enabled': True,
            'created_at': datetime.utcnow().isoformat(),
            'updated_at': datetime.utcnow().isoformat(),
            'executions': 0,
            'last_execution': None,
            'last_alert': None
        }
    )


def get_rules_bucket() -> str:
    """Get the S3 bucket name for rules from environment."""
    import os
    return os.environ.get('RULES_BUCKET', 'mantissa-log-rules')


def get_rules_table_name() -> str:
    """Get the DynamoDB table name for rule metadata."""
    import os
    return os.environ.get('RULES_TABLE', 'mantissa-log-rules')


def error_response(message: str, status_code: int) -> Dict[str, Any]:
    """Return an error response."""
    return {
        'statusCode': status_code,
        'headers': {
            'Content-Type': 'application/json',
            'Access-Control-Allow-Origin': '*'
        },
        'body': json.dumps({
            'error': message
        })
    }
