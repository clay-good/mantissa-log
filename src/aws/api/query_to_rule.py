"""
Query-to-Rule Conversion API

Converts natural language queries and ad hoc SQL queries into Sigma detection rules.
Uses LLM to generate complete Sigma YAML with MITRE ATT&CK mapping.
"""

import json
import logging
import os
import yaml
from datetime import datetime
from typing import Dict, Any, Optional

from auth import get_authenticated_user_id, AuthenticationError
from auth.cors import get_cors_headers, cors_preflight_response
from utils.lazy_init import aws_clients

logger = logging.getLogger(__name__)


def _get_s3():
    """Get lazily-initialized S3 client."""
    return aws_clients.s3


def _get_dynamodb():
    """Get lazily-initialized DynamoDB resource."""
    return aws_clients.dynamodb


def lambda_handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """
    Lambda handler for converting queries/descriptions to Sigma detection rules.

    Supports two modes:
    1. Natural Language mode: Provide a description and let LLM generate Sigma rule
    2. SQL mode: Provide SQL query directly (legacy, still supported)

    Expected input (Natural Language mode - preferred):
    {
        "description": "Detect when CloudTrail logging is disabled",
        "logSource": "cloudtrail",  # optional hint
        "severity": "high",
        "schedule": "rate(5 minutes)",
        "alertDestinations": ["slack", "email"],
        "mode": "natural_language"  # optional, auto-detected
    }

    Expected input (SQL mode - legacy):
    {
        "query": "SELECT ...",
        "ruleName": "my_detection_rule",
        "description": "Description of what this detects",
        "schedule": "rate(5 minutes)",
        "threshold": 10,
        "severity": "high",
        "alertDestinations": ["slack", "email"],
        "mode": "sql"
    }
    """
    try:
        http_method = event.get('httpMethod', 'POST')

        # Handle CORS preflight
        if http_method == 'OPTIONS':
            return cors_preflight_response(event)

        # Authenticate user from JWT
        try:
            user_id = get_authenticated_user_id(event)
        except AuthenticationError:
            return error_response(event, 'Authentication required', 401)

        body = json.loads(event.get('body', '{}'))

        # Determine mode
        mode = body.get('mode', 'auto')
        if mode == 'auto':
            # Auto-detect: if SQL query provided, use SQL mode, otherwise NL mode
            mode = 'sql' if 'query' in body and body['query'].strip().upper().startswith('SELECT') else 'natural_language'

        if mode == 'natural_language':
            return handle_natural_language_mode(event, user_id, body)
        else:
            return handle_sql_mode(event, user_id, body)

    except Exception as e:
        logger.error(f"Error creating detection rule: {str(e)}")
        return error_response(event, str(e), 500)


def handle_natural_language_mode(event: Dict[str, Any], user_id: str, body: Dict[str, Any]) -> Dict[str, Any]:
    """Handle natural language to Sigma conversion."""
    # Validate required fields
    if 'description' not in body:
        return error_response(event, "Missing required field: description", 400)

    # Get LLM provider
    llm_provider = get_llm_provider()

    # Import the NL to Sigma converter
    from ...shared.detection.nl_to_sigma import NLToSigmaConverter

    converter = NLToSigmaConverter(
        llm_provider=llm_provider,
        default_author=body.get('author', 'Mantissa Security')
    )

    # Convert natural language to Sigma
    result = converter.convert(
        natural_language=body['description'],
        log_source_hint=body.get('logSource'),
        severity_hint=body.get('severity'),
        additional_context=body.get('additionalContext')
    )

    if not result.success:
        return error_response(event, f"Failed to generate Sigma rule: {result.error}", 400)

    # Add alert destinations to the rule
    sigma_dict = result.sigma_dict
    if body.get('alertDestinations'):
        sigma_dict['x-mantissa'] = {
            'schedule': body.get('schedule', 'rate(15 minutes)'),
            'alert_destinations': body['alertDestinations'],
            'threshold': body.get('threshold', 1),
            'enabled': True
        }

    # Generate final YAML
    final_yaml = yaml.dump(sigma_dict, default_flow_style=False, sort_keys=False)

    # Save rule to S3
    rule_name = sigma_dict.get('title', 'unnamed_rule')
    rule_key = save_sigma_rule_to_s3(
        sigma_yaml=final_yaml,
        rule_id=result.rule_id,
        user_id=user_id
    )

    # Save rule metadata to DynamoDB
    save_sigma_rule_metadata(
        user_id=user_id,
        rule_id=result.rule_id,
        rule_name=rule_name,
        s3_key=rule_key,
        schedule=body.get('schedule', 'rate(15 minutes)'),
        severity=sigma_dict.get('level', 'medium'),
        mitre_techniques=result.mitre_techniques,
        mitre_tactics=result.mitre_tactics,
        confidence_score=result.confidence_score
    )

    return success_response(event, {
        'message': 'Sigma detection rule created successfully',
        'ruleId': result.rule_id,
        'ruleKey': rule_key,
        'sigmaYaml': final_yaml,
        'mitreAttack': {
            'tactics': result.mitre_tactics,
            'techniques': result.mitre_techniques
        },
        'confidenceScore': result.confidence_score,
        'warnings': result.warnings
    })


def handle_sql_mode(event: Dict[str, Any], user_id: str, body: Dict[str, Any]) -> Dict[str, Any]:
    """Handle legacy SQL mode - creates custom rule format."""
    # Validate required fields
    required_fields = ['query', 'ruleName', 'description', 'schedule', 'severity']
    for field in required_fields:
        if field not in body:
            return error_response(event, f"Missing required field: {field}", 400)

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
        user_id=user_id,
        rule_name=body['ruleName']
    )

    # Track rule metadata in DynamoDB
    save_rule_metadata(
        user_id=user_id,
        rule_name=body['ruleName'],
        s3_key=rule_key,
        schedule=body['schedule'],
        severity=body['severity']
    )

    return success_response(event, {
        'message': 'Detection rule created successfully (legacy SQL mode)',
        'ruleKey': rule_key,
        'rule': rule
    })


def get_llm_provider():
    """Get the configured LLM provider."""
    provider_type = os.environ.get('LLM_PROVIDER', 'bedrock')

    if provider_type == 'bedrock':
        from ...shared.llm.providers import BedrockProvider
        return BedrockProvider()
    elif provider_type == 'anthropic':
        from ...shared.llm.providers import AnthropicProvider
        api_key = os.environ.get('ANTHROPIC_API_KEY')
        return AnthropicProvider(api_key=api_key)
    elif provider_type == 'openai':
        from ...shared.llm.providers import OpenAIProvider
        api_key = os.environ.get('OPENAI_API_KEY')
        return OpenAIProvider(api_key=api_key)
    else:
        # Default to Bedrock for AWS Lambda
        from ...shared.llm.providers import BedrockProvider
        return BedrockProvider()


def create_detection_rule(
    name: str,
    description: str,
    query: str,
    schedule: str,
    threshold: int,
    severity: str,
    alert_destinations: list
) -> Dict[str, Any]:
    """Create a detection rule in legacy YAML format."""

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
            'version': '1.0',
            'format': 'legacy_sql'
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
            elif dest == 'webhook':
                rule['alert'].append({
                    'type': 'webhook',
                    'url': '${WEBHOOK_URL}'
                })

    return rule


def save_sigma_rule_to_s3(
    sigma_yaml: str,
    rule_id: str,
    user_id: str
) -> str:
    """Save Sigma rule to S3."""
    bucket = get_rules_bucket()

    # Create safe filename
    safe_id = rule_id.replace('/', '_').replace('\\', '_')
    rule_key = f'sigma_rules/{user_id}/{safe_id}.yml'

    # Upload to S3
    _get_s3().put_object(
        Bucket=bucket,
        Key=rule_key,
        Body=sigma_yaml.encode('utf-8'),
        ContentType='application/x-yaml',
        Metadata={
            'user_id': user_id,
            'rule_id': rule_id,
            'format': 'sigma',
            'created_at': datetime.utcnow().isoformat()
        }
    )

    logger.info(f"Saved Sigma rule to s3://{bucket}/{rule_key}")
    return rule_key


def save_sigma_rule_metadata(
    user_id: str,
    rule_id: str,
    rule_name: str,
    s3_key: str,
    schedule: str,
    severity: str,
    mitre_techniques: list,
    mitre_tactics: list,
    confidence_score: float
) -> None:
    """Save Sigma rule metadata to DynamoDB."""
    table_name = get_rules_table_name()
    table = _get_dynamodb().Table(table_name)

    table.put_item(
        Item={
            'user_id': user_id,
            'rule_id': rule_id,
            'rule_name': rule_name,
            's3_key': s3_key,
            'format': 'sigma',
            'schedule': schedule,
            'severity': severity,
            'mitre_techniques': mitre_techniques,
            'mitre_tactics': mitre_tactics,
            'confidence_score': str(confidence_score),
            'enabled': True,
            'created_at': datetime.utcnow().isoformat(),
            'updated_at': datetime.utcnow().isoformat(),
            'executions': 0,
            'last_execution': None,
            'last_alert': None,
            'false_positive_count': 0,
            'true_positive_count': 0
        }
    )

    logger.info(f"Saved Sigma rule metadata for {rule_id}")


def save_rule_to_s3(rule: Dict[str, Any], user_id: str, rule_name: str) -> str:
    """Save detection rule to S3."""

    bucket = get_rules_bucket()

    # Create safe filename
    safe_name = rule_name.lower().replace(' ', '_').replace('-', '_')
    rule_key = f'user_rules/{user_id}/{safe_name}.yaml'

    # Convert to YAML
    rule_yaml = yaml.dump(rule, default_flow_style=False, sort_keys=False)

    # Upload to S3
    _get_s3().put_object(
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
    table = _get_dynamodb().Table(table_name)

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
    return os.environ.get('RULES_BUCKET', 'mantissa-log-rules')


def get_rules_table_name() -> str:
    """Get the DynamoDB table name for rule metadata."""
    return os.environ.get('RULES_TABLE', 'mantissa-log-rules')


def success_response(event: Dict[str, Any], data: Dict[str, Any]) -> Dict[str, Any]:
    """Return a success response with secure CORS headers."""
    return {
        'statusCode': 200,
        'headers': {
            'Content-Type': 'application/json',
            **get_cors_headers(event)
        },
        'body': json.dumps(data)
    }


def error_response(event: Dict[str, Any], message: str, status_code: int) -> Dict[str, Any]:
    """Return an error response with secure CORS headers."""
    return {
        'statusCode': status_code,
        'headers': {
            'Content-Type': 'application/json',
            **get_cors_headers(event)
        },
        'body': json.dumps({
            'error': message
        })
    }
