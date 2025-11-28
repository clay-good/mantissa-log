# Alert Routing Configuration Guide

This guide covers setting up alert destinations and configuring routing rules.

## Overview

Mantissa Log can route alerts to multiple destinations:
- Slack
- PagerDuty
- Email (SMTP or AWS SES)
- Microsoft Teams
- Custom Webhooks

Alert routing supports:
- Severity-based routing
- Multiple destinations per alert
- Automatic enrichment
- Retry logic

## Configuration Overview

Alert destinations are configured in AWS Secrets Manager. Each destination type has its own secret format.

```bash
# Get secrets prefix from terraform outputs
SECRETS_PREFIX="mantissa-log/alerts"
AWS_REGION="us-east-1"
```

## Slack Integration

### Create Slack Webhook

1. Go to https://api.slack.com/apps
2. Click "Create New App"
3. Choose "From scratch"
4. Name your app "Mantissa Log"
5. Select your workspace
6. Click "Incoming Webhooks"
7. Toggle "Activate Incoming Webhooks" to On
8. Click "Add New Webhook to Workspace"
9. Select channel for alerts
10. Copy the Webhook URL

### Configure Slack in Secrets Manager

```bash
aws secretsmanager create-secret \
  --name mantissa-log/alerts/slack \
  --secret-string '{
    "webhook_url": "https://hooks.slack.com/services/YOUR/WEBHOOK/URL",
    "channel": "#security-alerts",
    "username": "Mantissa Log",
    "icon_emoji": ":warning:",
    "severity_channels": {
      "critical": "#critical-alerts",
      "high": "#high-priority",
      "medium": "#security-alerts",
      "low": "#security-alerts",
      "info": "#info-alerts"
    },
    "mention_on_critical": true,
    "critical_mentions": "@channel"
  }' \
  --region $AWS_REGION
```

### Slack Configuration Options

| Field | Required | Description |
|-------|----------|-------------|
| webhook_url | Yes | Slack incoming webhook URL |
| channel | No | Default channel (override webhook default) |
| username | No | Bot username (default: "Mantissa Log") |
| icon_emoji | No | Bot icon emoji |
| severity_channels | No | Map severity levels to different channels |
| mention_on_critical | No | Mention @channel for critical alerts |
| critical_mentions | No | Who to mention for critical alerts |

### Test Slack Integration

```bash
# Invoke alert router with test alert
ALERT_ROUTER=$(cat terraform-outputs.json | jq -r '.alert_router_function_name.value')

cat > test-slack-alert.json <<EOF
{
  "alert_id": "test-slack-001",
  "title": "Test Slack Alert",
  "description": "Testing Slack integration",
  "severity": "low",
  "rule_name": "test_rule",
  "source": "manual_test",
  "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "metadata": {
    "test": true
  }
}
EOF

aws lambda invoke \
  --function-name $ALERT_ROUTER \
  --payload file://test-slack-alert.json \
  response.json

# Check Slack channel for alert
```

## PagerDuty Integration

### Get PagerDuty Integration Key

1. Log into PagerDuty
2. Go to Services
3. Select or create a service
4. Click "Integrations" tab
5. Add integration "Events API v2"
6. Copy the Integration Key

### Configure PagerDuty in Secrets Manager

```bash
aws secretsmanager create-secret \
  --name mantissa-log/alerts/pagerduty \
  --secret-string '{
    "integration_key": "YOUR_INTEGRATION_KEY",
    "severity_mapping": {
      "critical": "critical",
      "high": "error",
      "medium": "warning",
      "low": "info",
      "info": "info"
    },
    "route_critical_only": false,
    "include_enrichment": true
  }' \
  --region $AWS_REGION
```

### PagerDuty Configuration Options

| Field | Required | Description |
|-------|----------|-------------|
| integration_key | Yes | PagerDuty Integration Key |
| severity_mapping | No | Map Mantissa severities to PagerDuty |
| route_critical_only | No | Only send critical alerts |
| include_enrichment | No | Include enrichment data in alerts |

### Test PagerDuty Integration

```bash
cat > test-pagerduty-alert.json <<EOF
{
  "alert_id": "test-pd-001",
  "title": "Test PagerDuty Alert",
  "description": "Testing PagerDuty integration",
  "severity": "high",
  "rule_name": "test_rule",
  "source": "manual_test",
  "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "evidence": {
    "user": "testuser",
    "ip": "192.168.1.100"
  }
}
EOF

aws lambda invoke \
  --function-name $ALERT_ROUTER \
  --payload file://test-pagerduty-alert.json \
  response.json

# Check PagerDuty for incident
```

## Email Integration

### Option 1: SMTP

Configure with any SMTP server (Gmail, SendGrid, etc.):

```bash
aws secretsmanager create-secret \
  --name mantissa-log/alerts/email \
  --secret-string '{
    "smtp_host": "smtp.gmail.com",
    "smtp_port": 587,
    "smtp_username": "your-email@gmail.com",
    "smtp_password": "your-app-password",
    "from_address": "alerts@mantissalog.com",
    "from_name": "Mantissa Log Alerts",
    "to_addresses": [
      "security-team@company.com",
      "soc@company.com"
    ],
    "cc_addresses": [],
    "severity_recipients": {
      "critical": ["oncall@company.com", "director@company.com"],
      "high": ["oncall@company.com"]
    },
    "use_html": true,
    "use_tls": true
  }' \
  --region $AWS_REGION
```

### Option 2: AWS SES

Use AWS Simple Email Service:

**First, verify email addresses:**
```bash
aws ses verify-email-identity \
  --email-address alerts@company.com \
  --region $AWS_REGION

aws ses verify-email-identity \
  --email-address security-team@company.com \
  --region $AWS_REGION
```

**Configure SES in Secrets Manager:**
```bash
aws secretsmanager create-secret \
  --name mantissa-log/alerts/email \
  --secret-string '{
    "use_ses": true,
    "from_address": "alerts@company.com",
    "from_name": "Mantissa Log",
    "to_addresses": [
      "security-team@company.com"
    ],
    "severity_recipients": {
      "critical": ["oncall@company.com"],
      "high": ["security-leads@company.com"]
    },
    "use_html": true
  }' \
  --region $AWS_REGION
```

### Email Configuration Options

| Field | Required | Description |
|-------|----------|-------------|
| use_ses | No | Use AWS SES instead of SMTP |
| smtp_host | Yes* | SMTP server hostname (*if not using SES) |
| smtp_port | Yes* | SMTP server port (*if not using SES) |
| smtp_username | Yes* | SMTP username (*if not using SES) |
| smtp_password | Yes* | SMTP password (*if not using SES) |
| from_address | Yes | Sender email address |
| from_name | No | Sender display name |
| to_addresses | Yes | List of recipient emails |
| cc_addresses | No | List of CC recipient emails |
| severity_recipients | No | Additional recipients by severity |
| use_html | No | Send HTML formatted emails (default: true) |
| use_tls | No | Use TLS for SMTP (default: true) |

## Microsoft Teams Integration

### Create Teams Webhook

1. In Teams, go to the channel
2. Click "..." next to channel name
3. Select "Connectors"
4. Find "Incoming Webhook"
5. Click "Configure"
6. Name it "Mantissa Log"
7. Copy the webhook URL

### Configure Teams in Secrets Manager

```bash
aws secretsmanager create-secret \
  --name mantissa-log/alerts/teams \
  --secret-string '{
    "webhook_url": "https://outlook.office.com/webhook/YOUR_WEBHOOK_URL",
    "severity_colors": {
      "critical": "Attention",
      "high": "Attention",
      "medium": "Warning",
      "low": "Good",
      "info": "Accent"
    },
    "include_enrichment": true
  }' \
  --region $AWS_REGION
```

## Custom Webhook Integration

For custom integrations or unsupported systems:

```bash
aws secretsmanager create-secret \
  --name mantissa-log/alerts/webhook \
  --secret-string '{
    "url": "https://your-system.com/api/alerts",
    "method": "POST",
    "headers": {
      "Authorization": "Bearer YOUR_API_TOKEN",
      "Content-Type": "application/json"
    },
    "payload_template": {
      "event_type": "security_alert",
      "severity": "{{severity}}",
      "title": "{{title}}",
      "description": "{{description}}",
      "timestamp": "{{timestamp}}",
      "custom_field": "value"
    },
    "retry_count": 3,
    "timeout": 30
  }' \
  --region $AWS_REGION
```

### Webhook Configuration Options

| Field | Required | Description |
|-------|----------|-------------|
| url | Yes | Webhook URL |
| method | No | HTTP method (default: POST) |
| headers | No | Custom HTTP headers |
| payload_template | No | Custom JSON payload template |
| retry_count | No | Number of retries (default: 3) |
| timeout | No | Request timeout in seconds (default: 30) |

### Payload Template Variables

Available variables in payload_template:
- `{{alert_id}}`
- `{{title}}`
- `{{description}}`
- `{{severity}}`
- `{{category}}`
- `{{rule_name}}`
- `{{source}}`
- `{{timestamp}}`
- `{{evidence}}` (JSON)
- `{{enrichment}}` (JSON)

## Routing Rules

### Severity-Based Routing

Configure different destinations based on alert severity:

```yaml
# In alert router configuration
routing_rules:
  critical:
    - pagerduty
    - slack
    - email
  high:
    - slack
    - email
  medium:
    - slack
  low:
    - slack
  info:
    - slack
```

This is configured in the Lambda environment variables:

```bash
aws lambda update-function-configuration \
  --function-name mantissa-log-alert-router \
  --environment Variables='{
    "SECRETS_PREFIX": "mantissa-log/alerts",
    "AWS_REGION": "us-east-1",
    "ROUTING_RULES": "{\"critical\":[\"pagerduty\",\"slack\",\"email\"],\"high\":[\"slack\",\"email\"],\"medium\":[\"slack\"],\"low\":[\"slack\"],\"info\":[\"slack\"]}"
  }'
```

### Category-Based Routing

Route specific categories to different destinations:

```bash
# Example: Route compliance alerts to separate channel
aws secretsmanager create-secret \
  --name mantissa-log/alerts/compliance-slack \
  --secret-string '{
    "webhook_url": "https://hooks.slack.com/services/YOUR/COMPLIANCE/WEBHOOK",
    "channel": "#compliance-alerts"
  }' \
  --region $AWS_REGION
```

### Time-Based Routing

Route alerts differently based on time of day:

```python
# Custom Lambda function for time-based routing
import boto3
from datetime import datetime, time

def lambda_handler(event, context):
    alert = event
    current_time = datetime.utcnow().time()

    # Business hours: 9 AM - 5 PM UTC
    business_hours = time(9, 0) <= current_time <= time(17, 0)

    if alert['severity'] == 'critical':
        # Always page for critical
        destinations = ['pagerduty', 'slack']
    elif alert['severity'] == 'high':
        if business_hours:
            destinations = ['slack', 'email']
        else:
            destinations = ['pagerduty']  # Page after hours
    else:
        destinations = ['slack']

    return {'destinations': destinations}
```

## Alert Enrichment

Alert enrichment adds context to alerts before routing.

### Enable Enrichment

Set in Lambda environment variables:

```bash
aws lambda update-function-configuration \
  --function-name mantissa-log-alert-router \
  --environment Variables='{
    "ENRICHMENT_ENABLED": "true",
    "ENABLE_IP_GEOLOCATION": "true",
    "ENABLE_RELATED_ALERTS": "true",
    "GEOLOCATION_PROVIDER": "ip-api"
  }'
```

### Enrichment Features

**IP Geolocation:**
- Adds location data for IP addresses in alerts
- Supported providers: ip-api, MaxMind, ipinfo

**Related Alerts:**
- Finds similar alerts from past 24 hours
- Groups related security events

**Historical Context:**
- Shows if this is a repeat occurrence
- Provides trend information

### Example Enriched Alert

```json
{
  "alert_id": "alert-001",
  "title": "Multiple Failed Logins",
  "severity": "high",
  "evidence": {
    "ip": "203.0.113.42",
    "user": "admin",
    "attempts": 10
  },
  "enrichment": {
    "geolocation": {
      "country": "China",
      "city": "Beijing",
      "lat": 39.9042,
      "lon": 116.4074,
      "isp": "Example ISP"
    },
    "related_alerts": [
      {
        "alert_id": "alert-456",
        "title": "Port Scan Detected",
        "timestamp": "2024-01-15T10:15:00Z",
        "similarity": 0.85
      }
    ],
    "historical": {
      "first_seen": "2024-01-14T08:00:00Z",
      "occurrence_count": 3,
      "trend": "increasing"
    }
  }
}
```

## Monitoring Alert Delivery

### Check Alert Router Logs

```bash
aws logs tail /aws/lambda/mantissa-log-alert-router --follow
```

### View Delivery Statistics

```bash
# CloudWatch metrics for alert router
aws cloudwatch get-metric-statistics \
  --namespace AWS/Lambda \
  --metric-name Invocations \
  --dimensions Name=FunctionName,Value=mantissa-log-alert-router \
  --start-time $(date -u -d '1 hour ago' +%Y-%m-%dT%H:%M:%S) \
  --end-time $(date -u +%Y-%m-%dT%H:%M:%S) \
  --period 300 \
  --statistics Sum

# Check for errors
aws cloudwatch get-metric-statistics \
  --namespace AWS/Lambda \
  --metric-name Errors \
  --dimensions Name=FunctionName,Value=mantissa-log-alert-router \
  --start-time $(date -u -d '1 hour ago' +%Y-%m-%dT%H:%M:%S) \
  --end-time $(date -u +%Y-%m-%dT%H:%M:%S) \
  --period 300 \
  --statistics Sum
```

### Alert Delivery Dashboard

Create CloudWatch dashboard:

```bash
aws cloudwatch put-dashboard \
  --dashboard-name mantissa-log-alerts \
  --dashboard-body file://dashboard.json
```

dashboard.json:
```json
{
  "widgets": [
    {
      "type": "metric",
      "properties": {
        "metrics": [
          ["AWS/Lambda", "Invocations", {"stat": "Sum", "label": "Total Alerts"}],
          [".", "Errors", {"stat": "Sum", "label": "Failed Deliveries"}]
        ],
        "period": 300,
        "stat": "Sum",
        "region": "us-east-1",
        "title": "Alert Delivery"
      }
    }
  ]
}
```

## Troubleshooting

### Alerts Not Delivered

**Check secret exists:**
```bash
aws secretsmanager get-secret-value \
  --secret-id mantissa-log/alerts/slack
```

**Check Lambda logs:**
```bash
aws logs tail /aws/lambda/mantissa-log-alert-router --since 10m
```

**Test manually:**
```bash
aws lambda invoke \
  --function-name mantissa-log-alert-router \
  --payload file://test-alert.json \
  --log-type Tail \
  response.json

# Check base64 decoded logs
cat response.json | jq -r '.LogResult' | base64 -d
```

### Slack Webhook Errors

**Error: "invalid_payload"**
- Check webhook URL is correct
- Verify JSON format in secret

**Error: "channel_not_found"**
- Ensure channel exists
- Verify app has permission to post

### PagerDuty Integration Issues

**Error: "Invalid integration key"**
- Verify integration key in secret
- Check Events API v2 is enabled
- Ensure key is not from v1 API

### Email Delivery Failures

**SMTP timeout:**
- Check network connectivity
- Verify SMTP port (usually 587 or 465)
- Ensure security group allows outbound

**SES bounces:**
- Verify email addresses in SES
- Check SES sending limits
- Review SES reputation dashboard

### Update Secrets

```bash
# Update existing secret
aws secretsmanager update-secret \
  --secret-id mantissa-log/alerts/slack \
  --secret-string '{
    "webhook_url": "https://hooks.slack.com/services/NEW/WEBHOOK/URL",
    "channel": "#new-channel"
  }'

# Changes take effect immediately
```
