"""AWS Lambda handler for alert routing."""

import json
import os
from typing import Any, Dict

import boto3
from botocore.exceptions import ClientError

from shared.alerting import AlertRouter, RouterConfig, AlertEnricher
from shared.alerting.handlers import (
    SlackHandler,
    PagerDutyHandler,
    EmailHandler,
    WebhookHandler,
)
from shared.detection.alert_generator import Alert
from shared.detection.state_manager import DynamoDBStateManager


def lambda_handler(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
    """Lambda handler for routing security alerts to configured destinations.

    This function:
    1. Receives alerts from the detection engine or SNS
    2. Loads handler configurations from Secrets Manager
    3. Initializes appropriate handlers
    4. Enriches alerts if configured
    5. Routes alerts to destinations
    6. Returns routing results

    Args:
        event: Lambda event (direct invocation, SNS, or API Gateway)
        context: Lambda context

    Returns:
        Routing results
    """
    # Load configuration
    aws_region = os.environ.get("AWS_REGION", "us-east-1")
    secrets_prefix = os.environ.get("SECRETS_PREFIX", "mantissa-log")
    state_table = os.environ.get("STATE_TABLE", "mantissa-log-state")
    enable_enrichment = os.environ.get("ENABLE_ENRICHMENT", "true").lower() == "true"
    enable_ip_geo = os.environ.get("ENABLE_IP_GEOLOCATION", "false").lower() == "true"

    try:
        # Parse event to extract alert(s)
        alerts = _parse_event(event)

        if not alerts:
            print("No alerts found in event")
            return {
                "statusCode": 400,
                "body": json.dumps({"error": "No alerts in event"})
            }

        print(f"Processing {len(alerts)} alert(s)")

        # Load handler configurations
        handlers = _load_handlers(secrets_prefix, aws_region)

        if not handlers:
            print("Warning: No handlers configured")

        # Create router configuration
        router_config = RouterConfig(
            default_destinations=_get_default_destinations(),
            severity_routing=_get_severity_routing(),
            enrichment_enabled=enable_enrichment,
            max_concurrent_sends=5
        )

        # Create enricher if enabled
        enricher = None
        if enable_enrichment:
            state_manager = DynamoDBStateManager(
                table_name=state_table,
                region=aws_region
            )

            enricher = AlertEnricher(
                enable_ip_geolocation=enable_ip_geo,
                enable_threat_intel=False,  # Disabled by default
                enable_related_alerts=True,
                state_manager=state_manager
            )

        # Create router
        router = AlertRouter(
            handlers=handlers,
            config=router_config,
            enricher=enricher
        )

        # Route alerts
        results = router.route_alerts(alerts)

        # Log results
        for result in results:
            if result.success:
                print(f"Alert {result.alert_id}: Successfully sent to {len(result.destinations_succeeded)} destination(s)")
            else:
                print(f"Alert {result.alert_id}: Failed to send to all destinations")

            if result.destinations_failed:
                for dest, error in result.destinations_failed.items():
                    print(f"  {dest}: {error}")

        # Return summary
        success_count = sum(1 for r in results if r.success)

        return {
            "statusCode": 200,
            "body": json.dumps({
                "alerts_processed": len(alerts),
                "alerts_sent": success_count,
                "results": [r.to_dict() for r in results]
            })
        }

    except Exception as e:
        print(f"Fatal error in alert router: {e}")
        import traceback
        traceback.print_exc()

        return {
            "statusCode": 500,
            "body": json.dumps({
                "error": str(e)
            })
        }


def _parse_event(event: Dict[str, Any]) -> list:
    """Parse Lambda event to extract alerts.

    Args:
        event: Lambda event

    Returns:
        List of Alert objects
    """
    alerts = []

    # Direct invocation with alerts array
    if "alerts" in event:
        for alert_data in event["alerts"]:
            alerts.append(_deserialize_alert(alert_data))

    # Direct invocation with single alert
    elif "alert" in event:
        alerts.append(_deserialize_alert(event["alert"]))

    # SNS event
    elif "Records" in event:
        for record in event["Records"]:
            if record.get("EventSource") == "aws:sns":
                message = json.loads(record["Sns"]["Message"])
                if "alert" in message:
                    alerts.append(_deserialize_alert(message["alert"]))
                elif "alerts" in message:
                    for alert_data in message["alerts"]:
                        alerts.append(_deserialize_alert(alert_data))

    # API Gateway event
    elif "body" in event:
        body = json.loads(event["body"]) if isinstance(event["body"], str) else event["body"]
        if "alert" in body:
            alerts.append(_deserialize_alert(body["alert"]))
        elif "alerts" in body:
            for alert_data in body["alerts"]:
                alerts.append(_deserialize_alert(alert_data))

    return alerts


def _deserialize_alert(alert_data: Dict) -> Alert:
    """Deserialize alert from dictionary.

    Args:
        alert_data: Alert dictionary

    Returns:
        Alert object
    """
    from datetime import datetime

    return Alert(
        id=alert_data["id"],
        rule_id=alert_data["rule_id"],
        rule_name=alert_data["rule_name"],
        severity=alert_data["severity"],
        title=alert_data["title"],
        description=alert_data["description"],
        timestamp=datetime.fromisoformat(alert_data["timestamp"]),
        destinations=alert_data.get("destinations", []),
        results=alert_data.get("results", []),
        metadata=alert_data.get("metadata", {}),
        mitre_attack=alert_data.get("mitre_attack"),
        tags=alert_data.get("tags", []),
        suppression_key=alert_data.get("suppression_key")
    )


def _load_handlers(secrets_prefix: str, region: str) -> Dict:
    """Load alert handlers from Secrets Manager.

    Args:
        secrets_prefix: Prefix for secret names
        region: AWS region

    Returns:
        Dictionary of handler name to handler instance
    """
    handlers = {}
    secrets_client = boto3.client('secretsmanager', region_name=region)

    # Try to load Slack handler
    try:
        slack_secret = secrets_client.get_secret_value(
            SecretId=f"{secrets_prefix}/slack"
        )
        slack_config = json.loads(slack_secret['SecretString'])

        handlers["slack"] = SlackHandler(
            webhook_url=slack_config["webhook_url"],
            channel=slack_config.get("channel"),
            username=slack_config.get("username", "Mantissa Log")
        )
        print("Loaded Slack handler")

    except ClientError as e:
        if e.response['Error']['Code'] != 'ResourceNotFoundException':
            print(f"Error loading Slack config: {e}")

    # Try to load PagerDuty handler
    try:
        pd_secret = secrets_client.get_secret_value(
            SecretId=f"{secrets_prefix}/pagerduty"
        )
        pd_config = json.loads(pd_secret['SecretString'])

        handlers["pagerduty"] = PagerDutyHandler(
            routing_key=pd_config["routing_key"]
        )
        print("Loaded PagerDuty handler")

    except ClientError as e:
        if e.response['Error']['Code'] != 'ResourceNotFoundException':
            print(f"Error loading PagerDuty config: {e}")

    # Try to load Email handler
    try:
        email_secret = secrets_client.get_secret_value(
            SecretId=f"{secrets_prefix}/email"
        )
        email_config = json.loads(email_secret['SecretString'])

        handlers["email"] = EmailHandler(
            recipients=email_config["recipients"],
            smtp_host=email_config.get("smtp_host"),
            smtp_port=email_config.get("smtp_port"),
            smtp_username=email_config.get("smtp_username"),
            smtp_password=email_config.get("smtp_password"),
            smtp_use_tls=email_config.get("smtp_use_tls", True),
            from_address=email_config.get("from_address", "mantissa-log@example.com"),
            use_ses=email_config.get("use_ses", False),
            ses_region=email_config.get("ses_region", region)
        )
        print("Loaded Email handler")

    except ClientError as e:
        if e.response['Error']['Code'] != 'ResourceNotFoundException':
            print(f"Error loading Email config: {e}")

    # Try to load Webhook handler
    try:
        webhook_secret = secrets_client.get_secret_value(
            SecretId=f"{secrets_prefix}/webhook"
        )
        webhook_config = json.loads(webhook_secret['SecretString'])

        handlers["webhook"] = WebhookHandler(
            webhook_url=webhook_config["webhook_url"],
            headers=webhook_config.get("headers"),
            method=webhook_config.get("method", "POST")
        )
        print("Loaded Webhook handler")

    except ClientError as e:
        if e.response['Error']['Code'] != 'ResourceNotFoundException':
            print(f"Error loading Webhook config: {e}")

    return handlers


def _get_default_destinations() -> list:
    """Get default alert destinations from environment.

    Returns:
        List of default destination names
    """
    default_str = os.environ.get("DEFAULT_DESTINATIONS", "slack")
    return [d.strip() for d in default_str.split(",") if d.strip()]


def _get_severity_routing() -> Dict[str, list]:
    """Get severity-based routing configuration from environment.

    Returns:
        Dictionary of severity to destination list
    """
    # Default severity routing
    routing = {
        "critical": ["slack", "pagerduty", "email"],
        "high": ["slack", "email"],
        "medium": ["slack"],
        "low": ["slack"],
        "info": []
    }

    # Override from environment if provided
    severity_routing_str = os.environ.get("SEVERITY_ROUTING")
    if severity_routing_str:
        try:
            routing = json.loads(severity_routing_str)
        except json.JSONDecodeError as e:
            print(f"Error parsing SEVERITY_ROUTING: {e}")

    return routing
