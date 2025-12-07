# Advanced Alerting Feature

Comprehensive alerting system with NL routing, health monitoring, retry logic, and deduplication.

## Overview

The Advanced Alerting feature provides enterprise-grade alert delivery with intelligent routing, automatic retries, deduplication, and health monitoring. Alerts can be configured through natural language commands and are delivered reliably to multiple integration types.

## Key Features

- Natural language alert routing commands
- Integration health monitoring with metrics
- Exponential backoff retry logic
- Alert deduplication (5-minute window)
- Dead Letter Queue for failed alerts
- Multi-integration routing by severity
- Delivery status tracking
- Async processing via SQS

## Architecture

```
Detection Rule Triggers
         ↓
   Alert Router
         ↓
    SQS Queue
         ↓
  Alert Delivery
     ↓     ↓     ↓
  Slack  Jira  PagerDuty
```

### Components

1. **Alert Router** - Routes alerts to appropriate integrations
2. **SQS Queue** - Async message queue for alert delivery
3. **Alert Delivery Engine** - Processes queue with retry logic
4. **Deduplication Table** - Prevents duplicate alerts
5. **Health Monitor** - Tracks integration health
6. **Dead Letter Queue** - Stores failed alerts

## Implementation

### Backend Components

#### 1. Alert Router ([src/shared/alerts/router.py](../../src/shared/alerts/router.py))

Routes alerts to configured integrations based on severity.

**Alert Data Structure:**
```python
@dataclass
class Alert:
    alert_id: str          # Unique alert ID
    rule_id: str           # Detection rule ID
    rule_name: str         # Detection rule name
    severity: str          # critical, high, medium, low, info
    summary: str           # Brief summary
    description: str       # Detailed description
    query: str             # SQL query that triggered
    result_count: int      # Number of matches
    results: List[Dict]    # Query results (limited)
    timestamp: str         # ISO timestamp
    metadata: Dict         # Additional metadata
```

**Routing Flow:**
```python
from alerts.router import AlertRouter, Alert

router = AlertRouter()

alert = Alert(
    alert_id='alert-123',
    rule_id='rule-456',
    rule_name='Failed Login Attempts',
    severity='high',
    summary='15 failed login attempts detected',
    description='Multiple failed login attempts from IP 203.0.113.42',
    query='SELECT ...',
    result_count=15,
    results=[...],
    timestamp='2024-11-27T10:30:00Z',
    metadata={}
)

# Route alert
result = router.route_alert(user_id='user-123', alert=alert)

# Result:
# {
#   'alert_id': 'alert-123',
#   'routed_to': 2,
#   'results': [
#     {'integration_id': 'slack-...', 'status': 'queued'},
#     {'integration_id': 'jira-...', 'status': 'queued'}
#   ]
# }
```

**Severity Filtering:**
```python
# Integration configured with severity_filter: ['critical', 'high']
# Alert with severity: 'high' → Routed
# Alert with severity: 'medium' → Not routed
```

**Natural Language Routing:**
```python
from alerts.router import NLAlertRouter

nl_router = NLAlertRouter(router)

# Parse routing commands
command = "Send to Slack"
parsed = nl_router.parse_routing_command(command)
# {'action': 'route_to_slack', 'integration_type': 'slack'}

command = "Create a Jira ticket"
parsed = nl_router.parse_routing_command(command)
# {'action': 'route_to_jira', 'integration_type': 'jira'}

command = "Page the on-call engineer"
parsed = nl_router.parse_routing_command(command)
# {'action': 'route_to_pagerduty', 'integration_type': 'pagerduty'}
```

#### 2. Alert Delivery ([src/shared/alerts/delivery.py](../../src/shared/alerts/delivery.py))

Processes alerts from SQS with retry logic and deduplication.

**Delivery Flow:**
```
1. Receive message from SQS
2. Check for duplicate (5-minute window)
3. Retrieve integration secrets
4. Attempt delivery
5. On success: Mark as delivered
6. On failure: Retry with exponential backoff
7. After max retries: Send to DLQ
```

**Deduplication:**
```python
# Dedup key generated from:
dedup_key = sha256(f"{rule_name}|{severity}|{summary}")

# Check if alert with same key exists in last 5 minutes
# If yes: Suppress (return 'suppressed' status)
# If no: Deliver and record for future dedup checks
```

**Retry Logic:**
```python
# Exponential backoff formula:
delay_seconds = min(300, (2 ** retry_count) * 5)

# Retry schedule:
# Retry 0: 5 seconds
# Retry 1: 10 seconds
# Retry 2: 20 seconds
# Retry 3: 40 seconds (final retry)
# Max: 300 seconds (5 minutes)
```

**Integration-Specific Delivery:**

**Slack:**
```python
def _deliver_to_slack(alert, config):
    payload = {
        'text': f"*{alert['rule_name']}* ({alert['severity']})",
        'username': 'Mantissa Log',
        'icon_emoji': ':shield:',
        'blocks': [
            {
                'type': 'header',
                'text': {'type': 'plain_text', 'text': alert['rule_name']}
            },
            {
                'type': 'section',
                'fields': [
                    {'type': 'mrkdwn', 'text': f"*Severity:*\n{alert['severity']}"},
                    {'type': 'mrkdwn', 'text': f"*Result Count:*\n{alert['result_count']}"}
                ]
            },
            {
                'type': 'section',
                'text': {'type': 'mrkdwn', 'text': alert['description']}
            }
        ]
    }

    response = requests.post(config['webhook_url'], json=payload)
    return {'status': 'ok', 'status_code': response.status_code}
```

**Jira:**
```python
def _deliver_to_jira(alert, config):
    issue_data = {
        'fields': {
            'project': {'key': config['project_key']},
            'summary': f"{alert['rule_name']} - {alert['result_count']} matches",
            'description': alert['description'],
            'issuetype': {'name': config['issue_type']},
            'priority': {'name': severity_mapping[alert['severity']]}
        }
    }

    response = requests.post(
        f"{config['url']}/rest/api/3/issue",
        auth=(config['email'], config['api_token']),
        json=issue_data
    )

    issue = response.json()
    return {'issue_key': issue['key'], 'issue_id': issue['id']}
```

**PagerDuty:**
```python
def _deliver_to_pagerduty(alert, config):
    payload = {
        'routing_key': config['integration_key'],
        'event_action': 'trigger',
        'payload': {
            'summary': f"{alert['rule_name']}: {alert['result_count']} matches",
            'source': 'mantissa-log',
            'severity': severity_map[alert['severity']],
            'custom_details': {
                'description': alert['description'],
                'result_count': alert['result_count']
            }
        }
    }

    response = requests.post(
        'https://events.pagerduty.com/v2/enqueue',
        json=payload
    )

    result = response.json()
    return {'dedup_key': result['dedup_key'], 'status': result['status']}
```

#### 3. Health Monitor ([src/shared/alerts/health_monitor.py](../../src/shared/alerts/health_monitor.py))

Monitors integration health with delivery metrics.

**Health Check:**
```python
from alerts.health_monitor import IntegrationHealthMonitor

monitor = IntegrationHealthMonitor()

# Check specific integration
health = monitor.check_integration_health(
    user_id='user-123',
    integration_id='slack-...'
)

# Result:
# {
#   'status': 'healthy',
#   'message': 'Integration is working normally',
#   'integration_id': 'slack-...',
#   'integration_type': 'slack',
#   'integration_name': 'Slack Security Alerts',
#   'metrics': {
#     'period_hours': 24,
#     'total_attempts': 47,
#     'successful': 46,
#     'failed': 1,
#     'retried': 2,
#     'success_rate': 97.87
#   }
# }

# Check all integrations
all_health = monitor.check_all_integrations(user_id='user-123')
```

**Health Status Calculation:**
```
Success Rate >= 95%  → healthy
Success Rate >= 80%  → degraded
Success Rate < 80%   → unhealthy
No attempts          → unknown
```

**Metrics Tracked:**
- Total delivery attempts (last 24 hours)
- Successful deliveries
- Failed deliveries
- Retried deliveries
- Success rate percentage

### Infrastructure

#### SQS Queue

**Alert Queue:**
```
Name: mantissa-log-alerts-{env}
Type: Standard
Visibility Timeout: 60 seconds
Message Retention: 4 days
Maximum Message Size: 256 KB
Dead Letter Queue: mantissa-log-alerts-dlq-{env}
Max Receive Count: 3
```

**Dead Letter Queue:**
```
Name: mantissa-log-alerts-dlq-{env}
Type: Standard
Message Retention: 14 days
Purpose: Store failed alerts for manual review
```

#### DynamoDB Tables

**Alerts Table:**
```
Name: mantissa-log-alerts-{env}
Hash Key: user_id (S)
Range Key: alert_id (S)

Attributes:
- rule_id
- rule_name
- severity
- summary
- description
- result_count
- timestamp
- status (pending, delivered, failed)
- deliveries[] (array of delivery attempts)
- created_at

GSI: RuleAlertsIndex (rule_id + timestamp)
TTL: 30 days
```

**Alert Deduplication Table:**
```
Name: mantissa-log-alert-dedup-{env}
Hash Key: user_id (S)
Range Key: dedup_key (S)

Attributes:
- timestamp (last seen)
- ttl (1 hour)

Purpose: Track recent alerts for deduplication
```

## User Workflows

### Configuring Alert Routing via NL

**Scenario 1: Add Slack Routing to Existing Rule**

```
User: "Show me failed login attempts"
System: [Generates SQL, executes, shows results]

User: "Create a detection to run every hour"
System: [Creates detection rule with ID: rule-789]

User: "Send to Slack if this triggers"
System:
  - Parses command: route_to_slack
  - Checks if Slack integration exists
  - If exists: Adds routing to rule-789
  - If not: "Slack is not configured. Set it up in Settings > Integrations"

Response:
  "Alert routing configured. Critical and high severity alerts from this rule will be sent to Slack Security Alerts."
```

**Scenario 2: Multi-Integration Routing**

```
User: "Create a Jira ticket and page on-call for critical alerts"
System:
  - Parses: route_to_jira + route_to_pagerduty
  - Checks both integrations exist
  - Configures rule with both routes
  - Severity filter: critical only

Response:
  "Alert routing configured:
   - Jira tickets will be created in SEC project
   - PagerDuty will page on-call team
   - Only for critical severity alerts"
```

### Alert Delivery Flow

**1. Detection Rule Triggers**
```
Detection rule: "Failed Login Attempts"
Schedule: Every 5 minutes
Query: SELECT * FROM cloudtrail WHERE eventname = 'ConsoleLogin' AND errorcode IS NOT NULL
Results: 15 matches found
```

**2. Alert Created**
```
Alert ID: alert-abc-123
Rule ID: rule-789
Severity: high
Result Count: 15
```

**3. Router Processes Alert**
```
User integrations:
  - Slack (severity_filter: [critical, high])  ✓ Matches
  - Jira (severity_filter: [critical])         ✗ Doesn't match
  - PagerDuty (severity_filter: [critical])    ✗ Doesn't match

Routes to: Slack only
```

**4. Message Sent to SQS**
```
{
  "user_id": "user-123",
  "alert_id": "alert-abc-123",
  "integration_id": "slack-xyz-456",
  "integration_type": "slack",
  "alert": {...},
  "config": {"channel": "#security-alerts"},
  "retry_count": 0,
  "max_retries": 3
}
```

**5. Delivery Engine Processes**
```
Step 1: Dedup check
  - Generate dedup key: sha256("Failed Login Attempts|high|15 failed...")
  - Check if exists in last 5 minutes
  - Not found → Proceed

Step 2: Get secrets
  - Retrieve webhook_url from Secrets Manager
  - Merge with config

Step 3: Deliver
  - POST to Slack webhook
  - Response: 200 OK

Step 4: Record
  - Update alert status: delivered
  - Add delivery record with timestamp
```

**6. Alert Delivered**
```
Slack message appears in #security-alerts:

Failed Login Attempts (high)

Severity: high
Result Count: 15

Multiple failed login attempts detected from IP 203.0.113.42 targeting admin accounts.
```

### Handling Failures

**Scenario: Slack Webhook Returns 500 Error**

```
Attempt 1: Failed (500 Internal Server Error)
  ↓
Wait 5 seconds
  ↓
Attempt 2: Failed (500 Internal Server Error)
  ↓
Wait 10 seconds
  ↓
Attempt 3: Failed (500 Internal Server Error)
  ↓
Wait 20 seconds
  ↓
Attempt 4: Failed (500 Internal Server Error)
  ↓
Max retries exceeded
  ↓
Send to Dead Letter Queue
  ↓
Mark alert as failed
  ↓
Update integration health status: degraded
```

**DLQ Message:**
```json
{
  "user_id": "user-123",
  "alert_id": "alert-abc-123",
  "integration_id": "slack-xyz-456",
  "final_error": "500 Internal Server Error",
  "failed_at": "2024-11-27T10:35:23Z",
  "retry_count": 4
}
```

### Health Monitoring

**Dashboard View:**

```
Integration Health Status

Slack Security Alerts
  Status: Healthy ✓
  Success Rate: 97.87%
  Last 24h: 46/47 delivered
  Last Check: 2 minutes ago

Jira Security Tickets
  Status: Degraded ⚠
  Success Rate: 82.35%
  Last 24h: 14/17 delivered
  Last Check: 5 minutes ago

PagerDuty On-Call
  Status: Healthy ✓
  Success Rate: 100%
  Last 24h: 3/3 delivered
  Last Check: 1 minute ago
```

## Security

### Credential Handling

**Never in Transit:**
- Webhook URLs never in SQS messages
- API tokens never in SQS messages
- Integration keys never in SQS messages

**Retrieval Pattern:**
```python
# SQS message contains only:
message = {
    'integration_id': 'slack-xyz',
    'integration_type': 'slack',
    'config': {'channel': '#security-alerts'}  # Non-sensitive only
}

# Lambda retrieves secrets:
secrets = secretsmanager.get_secret_value(
    SecretId=f'mantissa-log/users/{user_id}/integrations/slack'
)
# Returns: {'webhook_url': 'https://hooks.slack.com/...'}

# Merge for delivery:
full_config = {**message['config'], **secrets}
```

### Alert Data Privacy

**Limited Results:**
```python
# Only first 10 results included in message
'results': alert.results[:10]

# Full results available in Athena/S3
# Alerts table stores only metadata
```

## Performance

### Async Processing

**Benefits:**
- Non-blocking alert delivery
- Automatic retry without blocking
- Scalable to thousands of alerts/minute
- Independent failure isolation

**SQS Throughput:**
- Standard queue: Nearly unlimited throughput
- Batch processing: Up to 10 messages at once
- Parallel Lambda executions

### Deduplication Performance

**DynamoDB Query:**
```python
# Single-item lookup by partition + sort key
response = table.get_item(
    Key={
        'user_id': 'user-123',
        'dedup_key': '8f5a7d...'
    }
)
# Latency: ~1-2ms
```

**TTL Cleanup:**
- Automatic cleanup after 1 hour
- No scan costs
- Minimal storage

## Monitoring

### CloudWatch Metrics

**Alert Queue:**
- `ApproximateNumberOfMessagesVisible`
- `ApproximateNumberOfMessagesNotVisible`
- `NumberOfMessagesSent`
- `NumberOfMessagesDeleted`

**DLQ:**
- `ApproximateNumberOfMessagesVisible` (alarm if > 0)

**Lambda:**
- `Invocations`
- `Errors`
- `Duration`
- `Throttles`

### Alarms

**Critical:**
- DLQ has messages (immediate notification)
- Alert delivery Lambda error rate > 5%
- Queue depth > 1000 messages

**Warning:**
- Average delivery latency > 30 seconds
- Integration health degraded
- Retry rate > 20%

## Testing

### Unit Tests

```python
def test_alert_routing():
    router = AlertRouter()
    alert = Alert(
        alert_id='test-1',
        rule_id='rule-1',
        severity='high',
        ...
    )

    result = router.route_alert('user-123', alert)

    assert result['routed_to'] == 2
    assert result['results'][0]['status'] == 'queued'

def test_deduplication():
    delivery = AlertDelivery()

    alert = {'rule_name': 'Test', 'severity': 'high', 'summary': 'Test alert'}

    # First delivery
    is_dup1 = delivery._is_duplicate('user-123', alert)
    assert is_dup1 == False

    # Immediate duplicate
    is_dup2 = delivery._is_duplicate('user-123', alert)
    assert is_dup2 == True

def test_retry_backoff():
    delivery = AlertDelivery()

    assert delivery._calculate_backoff(0) == 5
    assert delivery._calculate_backoff(1) == 10
    assert delivery._calculate_backoff(2) == 20
    assert delivery._calculate_backoff(3) == 40
    assert delivery._calculate_backoff(10) == 300  # Max

def test_health_status():
    monitor = IntegrationHealthMonitor()

    # Healthy
    metrics = {'total_attempts': 100, 'successful': 97, 'success_rate': 97.0}
    status = monitor._calculate_health_status(metrics)
    assert status['status'] == 'healthy'

    # Degraded
    metrics = {'total_attempts': 100, 'successful': 85, 'success_rate': 85.0}
    status = monitor._calculate_health_status(metrics)
    assert status['status'] == 'degraded'
```

### Integration Tests

```python
def test_end_to_end_delivery():
    # Create alert
    alert = Alert(...)

    # Route
    router = AlertRouter()
    result = router.route_alert('user-123', alert)

    # Verify queued
    assert result['results'][0]['status'] == 'queued'

    # Process from queue
    delivery = AlertDelivery()
    message = get_sqs_message()
    delivery_result = delivery.process_alert_message(message)

    # Verify delivered
    assert delivery_result['status'] == 'delivered'

    # Check health updated
    monitor = IntegrationHealthMonitor()
    health = monitor.check_integration_health('user-123', 'slack-xyz')
    assert health['metrics']['successful'] >= 1
```

## Future Enhancements

### 1. Alert Aggregation
- Group similar alerts within time window
- Send single notification with aggregate count
- Reduce notification fatigue

### 2. Smart Throttling
- Rate limit per integration
- Configurable max alerts per hour
- Batch alerts when threshold exceeded

### 3. Escalation Policies
- If no response in X minutes, escalate
- Multi-tier escalation (Slack → PagerDuty)
- Time-based escalation rules

### 4. Alert Templates
- Customizable message templates per integration
- Variable substitution (rule name, count, etc.)
- Conditional formatting based on severity

### 5. Delivery Analytics
- Dashboard with delivery metrics
- Success rate trends
- Integration performance comparison
- Cost per alert delivered

## Documentation

- [Alert Router](../../src/shared/alerts/router.py)
- [Alert Delivery](../../src/shared/alerts/delivery.py)
- [Health Monitor](../../src/shared/alerts/health_monitor.py)
