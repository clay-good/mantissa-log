"""AWS Lambda handler for scheduled detection engine execution."""

import json
import os
from datetime import datetime
from typing import Any, Dict

from shared.detection import (
    DetectionEngine,
    RuleLoader,
    AthenaQueryExecutor,
    DynamoDBStateManager,
    AlertGenerator,
)


def lambda_handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """Lambda handler for detection engine execution.

    This function is triggered by EventBridge on a schedule and:
    1. Loads all enabled detection rules
    2. Executes each rule against Athena
    3. Generates alerts for triggered detections
    4. Routes alerts to configured destinations

    Args:
        event: Lambda event (from EventBridge)
        context: Lambda context

    Returns:
        Response with execution summary
    """
    # Load configuration from environment variables
    rules_path = os.environ.get("RULES_PATH", "/opt/rules")
    rules_s3_bucket = os.environ.get("RULES_S3_BUCKET")
    athena_database = os.environ.get("ATHENA_DATABASE", "mantissa_logs")
    athena_output_location = os.environ.get("ATHENA_OUTPUT_LOCATION")
    state_table = os.environ.get("STATE_TABLE", "mantissa-log-state")
    aws_region = os.environ.get("AWS_REGION", "us-east-1")

    # Use S3 rules path if configured, otherwise use local
    if rules_s3_bucket:
        rules_location = f"s3://{rules_s3_bucket}/rules"
    else:
        rules_location = rules_path

    try:
        # Initialize components
        print(f"Initializing detection engine with rules from {rules_location}")

        rule_loader = RuleLoader(rules_location)
        query_executor = AthenaQueryExecutor(
            database=athena_database,
            output_location=athena_output_location,
            region=aws_region
        )
        state_manager = DynamoDBStateManager(
            table_name=state_table,
            region=aws_region
        )
        alert_generator = AlertGenerator()

        engine = DetectionEngine(
            rule_loader=rule_loader,
            query_executor=query_executor,
            state_manager=state_manager
        )

        # Load rules
        print("Loading detection rules...")
        rule_loader.load_all_rules()
        enabled_rules = rule_loader.get_enabled_rules()
        print(f"Loaded {len(enabled_rules)} enabled rules")

        # Execute all enabled rules
        print("Executing detection rules...")
        results = engine.execute_all_rules()

        # Filter for triggered alerts
        triggered = engine.get_triggered_alerts(results, check_suppression=True)

        print(f"Execution complete: {len(results)} rules executed, {len(triggered)} alerts triggered")

        # Generate and route alerts
        alerts_sent = 0
        for detection_result in triggered:
            try:
                # Get the rule for alert configuration
                rule = rule_loader.get_rule_by_id(detection_result.rule_id)
                if not rule:
                    print(f"Warning: Rule {detection_result.rule_id} not found for alert routing")
                    continue

                # Generate alert object
                alert = alert_generator.generate_alert(
                    rule_id=detection_result.rule_id,
                    rule_name=detection_result.rule_name,
                    severity=detection_result.severity,
                    title=detection_result.alert_title,
                    description=detection_result.alert_body,
                    results=detection_result.results,
                    destinations=rule.alert.destinations,
                    tags=rule.tags,
                    mitre_attack=rule.mitre_attack.__dict__ if rule.mitre_attack else None,
                    suppression_key=detection_result.suppression_key
                )

                # Route alert to destinations
                route_alert(alert, alert_generator)

                # Record alert in history
                state_manager.record_alert(
                    suppression_key=alert.suppression_key or alert.id,
                    alert_data=alert.to_dict()
                )

                alerts_sent += 1

            except Exception as e:
                print(f"Error routing alert for rule {detection_result.rule_id}: {e}")
                continue

        # Return summary
        return {
            "statusCode": 200,
            "body": json.dumps({
                "timestamp": datetime.utcnow().isoformat(),
                "rules_executed": len(results),
                "alerts_triggered": len(triggered),
                "alerts_sent": alerts_sent,
                "execution_errors": sum(1 for r in results if r.error)
            })
        }

    except Exception as e:
        print(f"Fatal error in detection engine execution: {e}")
        import traceback
        traceback.print_exc()

        return {
            "statusCode": 500,
            "body": json.dumps({
                "error": str(e),
                "timestamp": datetime.utcnow().isoformat()
            })
        }


def route_alert(alert: Any, alert_generator: AlertGenerator) -> None:
    """Route an alert to configured destinations.

    Args:
        alert: Alert object to route
        alert_generator: AlertGenerator instance for formatting
    """
    import boto3

    # Get alert routing configuration from environment
    slack_webhook_secret = os.environ.get("SLACK_WEBHOOK_SECRET")
    pagerduty_key_secret = os.environ.get("PAGERDUTY_KEY_SECRET")
    email_topic_arn = os.environ.get("EMAIL_SNS_TOPIC_ARN")

    secrets_client = boto3.client('secretsmanager')
    sns_client = boto3.client('sns')

    for destination in alert.destinations:
        try:
            if destination == "slack" and slack_webhook_secret:
                # Get Slack webhook URL from Secrets Manager
                secret_value = secrets_client.get_secret_value(SecretId=slack_webhook_secret)
                webhook_url = json.loads(secret_value['SecretString'])['webhook_url']

                # Format and send to Slack
                import requests
                slack_payload = alert_generator.format_for_slack(alert)
                response = requests.post(webhook_url, json=slack_payload, timeout=10)
                response.raise_for_status()
                print(f"Alert sent to Slack: {alert.id}")

            elif destination == "pagerduty" and pagerduty_key_secret:
                # Get PagerDuty routing key from Secrets Manager
                secret_value = secrets_client.get_secret_value(SecretId=pagerduty_key_secret)
                routing_key = json.loads(secret_value['SecretString'])['routing_key']

                # Format and send to PagerDuty
                import requests
                pd_payload = alert_generator.format_for_pagerduty(alert)
                pd_payload['routing_key'] = routing_key

                response = requests.post(
                    'https://events.pagerduty.com/v2/enqueue',
                    json=pd_payload,
                    timeout=10
                )
                response.raise_for_status()
                print(f"Alert sent to PagerDuty: {alert.id}")

            elif destination == "email" and email_topic_arn:
                # Format and send email via SNS
                email_content = alert_generator.format_for_email(alert)

                sns_client.publish(
                    TopicArn=email_topic_arn,
                    Subject=email_content['subject'],
                    Message=email_content['body']
                )
                print(f"Alert sent to email: {alert.id}")

            else:
                print(f"Warning: Destination {destination} not configured for alert {alert.id}")

        except Exception as e:
            print(f"Error routing alert {alert.id} to {destination}: {e}")
            continue
