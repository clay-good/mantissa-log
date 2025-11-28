# System Integration Architecture

Complete overview of how all Mantissa Log components integrate and communicate.

## Overview

Mantissa Log is a serverless SIEM platform built on AWS services. This document describes how all components work together to provide log ingestion, detection, alerting, and response capabilities.

## Architecture Diagram

```
┌─────────────────────────────────────────────────────────────────────┐
│                         Data Sources                                 │
│  CloudTrail │ VPC Flow │ S3 Access │ Lambda │ Custom Logs           │
└───────────────────────────┬─────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────────────┐
│                      Ingestion Layer                                 │
│                                                                       │
│  ┌──────────────┐      ┌──────────────┐      ┌──────────────┐      │
│  │   Kinesis    │      │   Firehose   │      │  S3 Direct   │      │
│  │   Stream     │─────▶│   Delivery   │─────▶│   Upload     │      │
│  └──────────────┘      └──────────────┘      └──────────────┘      │
└───────────────────────────┬─────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────────────┐
│                       Storage Layer                                  │
│                                                                       │
│  ┌──────────────────────────────────────────────────────────────┐  │
│  │                      S3 Buckets                               │  │
│  │  - mantissa-log-cloudtrail-<account>                         │  │
│  │  - mantissa-log-vpc-flow-<account>                           │  │
│  │  - mantissa-log-custom-<account>                             │  │
│  │                                                               │  │
│  │  Partitioned by: year/month/day/hour                         │  │
│  │  Format: Parquet (compressed with Snappy)                    │  │
│  │  Lifecycle: 90 days hot, 1 year glacier, 7 years deep        │  │
│  └──────────────────────────────────────────────────────────────┘  │
└───────────────────────────┬─────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────────────┐
│                        Query Layer                                   │
│                                                                       │
│  ┌──────────────────────────────────────────────────────────────┐  │
│  │                    AWS Athena                                 │  │
│  │                                                               │  │
│  │  Database: mantissa_log                                      │  │
│  │                                                               │  │
│  │  Tables:                                                      │  │
│  │  - cloudtrail_logs (partitioned by dt)                       │  │
│  │  - vpc_flow_logs (partitioned by dt)                         │  │
│  │  - s3_access_logs (partitioned by dt)                        │  │
│  │  - lambda_logs (partitioned by dt)                           │  │
│  │  - custom_logs (partitioned by dt, source)                   │  │
│  └──────────────────────────────────────────────────────────────┘  │
└───────────────────────────┬─────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────────────┐
│                     Detection Layer                                  │
│                                                                       │
│  ┌──────────────┐      ┌──────────────┐      ┌──────────────┐      │
│  │  EventBridge │      │     Rule     │      │    Alert     │      │
│  │  Scheduler   │─────▶│   Executor   │─────▶│   Router     │      │
│  └──────────────┘      └──────────────┘      └──────────────┘      │
│       │                     │                       │               │
│       │                     │                       │               │
│  rate(5 min)          Execute Query           Route by Severity     │
│  rate(1 hour)         Check Threshold         Filter Integrations   │
│  cron(0 9 * * *)      Create Alert            Send to SQS           │
│                                                                       │
│  ┌────────────────────────────────────────────────────────────┐    │
│  │                    DynamoDB Tables                          │    │
│  │  - detection-rules (user_id, rule_id)                      │    │
│  │  - alert-history (user_id, alert_id)                       │    │
│  │  - dedup-cache (dedup_key, expires_at)                     │    │
│  └────────────────────────────────────────────────────────────┘    │
└───────────────────────────┬─────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────────────┐
│                      Alerting Layer                                  │
│                                                                       │
│  ┌──────────────┐      ┌──────────────┐      ┌──────────────┐      │
│  │  SQS Queue   │      │    Alert     │      │ Integration  │      │
│  │  (FIFO)      │─────▶│   Delivery   │─────▶│   Targets    │      │
│  └──────────────┘      └──────────────┘      └──────────────┘      │
│       │                     │                       │               │
│       │                     │                       │               │
│  Dedup by          Exponential Backoff        Slack Webhook         │
│  Message Group     5s → 10s → 20s → 40s       Jira Ticket           │
│  DLQ after 3       Retry up to 3 times        PagerDuty Incident    │
│                    Check Dedup Cache          Custom Webhook        │
│                                                                       │
│  ┌────────────────────────────────────────────────────────────┐    │
│  │                  AWS Secrets Manager                        │    │
│  │  - mantissa-log/users/{user_id}/integrations/slack         │    │
│  │  - mantissa-log/users/{user_id}/integrations/jira          │    │
│  │  - mantissa-log/users/{user_id}/integrations/pagerduty     │    │
│  └────────────────────────────────────────────────────────────┘    │
└───────────────────────────┬─────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────────────┐
│                   User Interface Layer                               │
│                                                                       │
│  ┌──────────────┐      ┌──────────────┐      ┌──────────────┐      │
│  │     React    │      │   API GW     │      │    Lambda    │      │
│  │   Frontend   │─────▶│   (REST)     │─────▶│   Functions  │      │
│  └──────────────┘      └──────────────┘      └──────────────┘      │
│       │                     │                       │               │
│       │                     │                       │               │
│  Vite + React         Cognito Auth            Query Executor        │
│  TailwindCSS          JWT Tokens              Rule Executor         │
│  Monochrome UI        CORS Enabled            Integration Wizard    │
│                                                Alert Dashboard       │
│                                                                       │
│  ┌────────────────────────────────────────────────────────────┐    │
│  │                    Amazon Cognito                           │    │
│  │  - User Pool (authentication)                              │    │
│  │  - Identity Pool (AWS credentials)                         │    │
│  │  - OAuth 2.0 / SAML 2.0 integration                        │    │
│  └────────────────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────────────────┘
```

## Data Flow

### 1. Log Ingestion Flow

**CloudTrail Logs:**
```
AWS API Call
    → CloudTrail Service
    → S3 Bucket (mantissa-log-cloudtrail-<account>)
    → Glue Crawler (discovers schema)
    → Athena Table (cloudtrail_logs)
```

**VPC Flow Logs:**
```
VPC Network Activity
    → VPC Flow Logs
    → Kinesis Firehose
    → Data Transformation (Lambda)
    → S3 Bucket (mantissa-log-vpc-flow-<account>)
    → Glue Crawler
    → Athena Table (vpc_flow_logs)
```

**Custom Application Logs:**
```
Application
    → Kinesis Stream
    → Kinesis Firehose
    → Data Transformation (Lambda)
    → S3 Bucket (mantissa-log-custom-<account>)
    → Glue Crawler
    → Athena Table (custom_logs)
```

### 2. Detection Execution Flow

**Scheduled Detection:**
```
EventBridge Rule (rate(5 minutes))
    → Lambda: rule_executor.py
    → DynamoDB: Get detection rule
    → Athena: Execute query
    → Check threshold
    → If exceeded:
        → Create Alert object
        → AlertRouter.route_alert()
        → Filter integrations by severity
        → Send to SQS queue
```

**Query Execution Details:**
```python
# rule_executor.py
def execute_rule(rule_id, user_id):
    rule = get_rule(user_id, rule_id)

    # Execute Athena query
    result = athena.start_query_execution(
        QueryString=rule['query'],
        Database='mantissa_log'
    )

    # Wait for completion
    wait_for_query(execution_id)

    # Get results
    results = get_query_results(execution_id)

    # Check threshold
    if len(results) > rule['threshold']['value']:
        # Create alert
        alert = Alert(
            alert_id=f"alert-{uuid4()}",
            rule_id=rule_id,
            severity=rule['severity'],
            summary=f"{len(results)} matches"
        )

        # Route to integrations
        alert_router.route_alert(user_id, alert)
```

### 3. Alert Routing Flow

**Alert Router:**
```
Alert Created
    → AlertRouter.route_alert(user_id, alert)
    → DynamoDB: Get user integrations
    → Filter by severity_filter:
        if alert.severity in integration.severity_filter
    → For each matching integration:
        → SQS.send_message(
            QueueUrl=alert_queue,
            MessageGroupId=f"{user_id}:{integration_id}",
            MessageBody={
                user_id, alert, integration_id, integration_type
            }
        )
```

**Natural Language Routing:**
```python
# alerts/router.py
class NLAlertRouter:
    def parse_routing_command(self, command: str):
        # "Send to Slack" → route_to_slack
        # "Create a Jira ticket" → route_to_jira
        # "Page the on-call" → route_to_pagerduty

        if 'slack' in command.lower():
            return 'route_to_slack'
        elif 'jira' in command.lower():
            return 'route_to_jira'
        elif 'page' in command.lower():
            return 'route_to_pagerduty'
```

### 4. Alert Delivery Flow

**SQS to Integration:**
```
SQS Queue (FIFO)
    → Lambda: alert_delivery.py (triggered by SQS)
    → Check deduplication:
        dedup_key = sha256(rule_name + severity + summary)
        if exists in DynamoDB dedup-cache (TTL 5 min):
            return 'suppressed'
    → Secrets Manager: Get integration credentials
    → Deliver alert:
        - Slack: POST to webhook_url
        - Jira: POST /rest/api/3/issue
        - PagerDuty: POST /v2/enqueue
        - Webhook: POST to custom URL
    → On success:
        - DynamoDB: Record delivery in alert-history
        - Return success
    → On failure:
        - Calculate backoff: min(300, 2^retry * 5)
        - If retry_count < 3:
            - Requeue with visibility timeout = backoff
        - Else:
            - Send to Dead Letter Queue
```

**Exponential Backoff:**
```
Attempt 1: Immediate
Attempt 2: 5 seconds delay
Attempt 3: 10 seconds delay
Attempt 4: 20 seconds delay
Max delay: 300 seconds
Max retries: 3
```

**Deduplication:**
```python
# alerts/delivery.py
def _is_duplicate(self, user_id, alert):
    dedup_key = hashlib.sha256(
        f"{alert.rule_name}|{alert.severity}|{alert.summary}".encode()
    ).hexdigest()

    table = dynamodb.Table('mantissa-log-dedup-cache-dev')
    response = table.get_item(Key={'dedup_key': dedup_key})

    if response.get('Item'):
        # Exists in cache (created within last 5 minutes)
        return True

    # Add to cache with TTL
    table.put_item(Item={
        'dedup_key': dedup_key,
        'user_id': user_id,
        'alert_id': alert.alert_id,
        'created_at': datetime.utcnow().isoformat(),
        'expires_at': int(time.time()) + 300  # TTL 5 minutes
    })

    return False
```

### 5. Integration Setup Flow

**Slack Integration:**
```
User: Click "Add Integration" → "Slack"
    → SlackWizard.jsx renders

Step 1: Setup
    → User creates Slack app
    → Enables Incoming Webhooks
    → Copies webhook URL
    → Enters in wizard

Step 2: Test
    → Click "Send Test Message"
    → POST /api/integrations/validate
    → validators.py: SlackValidator.validate()
        → Check URL format
        → POST test message to webhook
        → Return success/failure
    → Display result
    → Auto-advance to Step 3

Step 3: Configure
    → Select severity filter (checkboxes)
    → Click "Complete Setup"
    → POST /api/integrations/wizard/slack/save
        → Store webhook_url in Secrets Manager
        → Store config in DynamoDB
        → Return integration_id
    → Show success message
```

**Jira Integration:**
```
User: Click "Add Integration" → "Jira"
    → JiraWizard.jsx renders

Step 1: Credentials
    → User generates API token at id.atlassian.com
    → Enters URL, email, token
    → Click "Next"
    → POST /api/integrations/wizard/jira/projects
        → Validate credentials
        → Fetch accessible projects
        → Return project list

Step 2: Project
    → Select project from dropdown
    → Select issue type (Bug, Task, etc.)
    → Click "Test Connection"
    → validators.py: JiraValidator.validate()
    → Auto-advance to Step 3

Step 3: Mapping
    → Map severity to Jira priority
        Critical → Highest
        High → High
        Medium → Medium
        Low → Low
        Info → Lowest
    → Click "Complete Setup"
    → POST /api/integrations/wizard/jira/save
        → Store api_token in Secrets Manager
        → Store config in DynamoDB
```

### 6. Query Execution Flow

**Ad-Hoc Query:**
```
User: Enter query in UI
    → POST /api/query/execute
    → Lambda: query_executor.py
    → AthenaQueryExecutor.execute_query()
        → athena.start_query_execution()
        → Wait for completion (poll every 1s, max 5min)
        → get_query_results() with pagination
        → Format results as JSON
        → Return {
            execution_id,
            status,
            results,
            statistics: {
                data_scanned_bytes,
                execution_time_ms,
                result_count
            }
        }
    → Display results in UI
```

**Query Result Format:**
```json
{
  "execution_id": "abc-123-def-456",
  "status": "SUCCEEDED",
  "results": [
    {
      "timestamp": "2024-11-27T10:30:00Z",
      "eventName": "ConsoleLogin",
      "userIdentity": "alice@example.com",
      "sourceIPAddress": "203.0.113.42"
    }
  ],
  "statistics": {
    "data_scanned_bytes": 1048576,
    "execution_time_ms": 1250,
    "result_count": 1
  }
}
```

### 7. Health Monitoring Flow

**Integration Health Check:**
```
Periodic Lambda (rate(5 minutes))
    → IntegrationHealthMonitor.check_all_integrations()
    → For each user:
        → For each integration:
            → DynamoDB: Query alert-history (last 24h)
            → Calculate metrics:
                total_attempts = count(*)
                successful = count(status='delivered')
                failed = count(status='failed')
                success_rate = (successful / total) * 100
            → Determine status:
                if success_rate >= 95: 'healthy'
                elif success_rate >= 80: 'degraded'
                else: 'unhealthy'
            → DynamoDB: Update integration health_status
```

**Health Status Display:**
```
GET /api/integrations
    → Returns integrations with health_status
    → UI displays:
        ✓ Healthy (green) - Success rate ≥ 95%
        ⚠ Degraded (yellow) - Success rate ≥ 80%
        ✗ Unhealthy (red) - Success rate < 80%
```

## API Endpoints

### Query API

**Execute Query**
```
POST /api/query/execute
Request:
{
  "query": "SELECT * FROM cloudtrail_logs WHERE eventName = 'ConsoleLogin' LIMIT 10",
  "database": "mantissa_log",
  "wait": true
}

Response:
{
  "execution_id": "abc-123",
  "status": "SUCCEEDED",
  "results": [...],
  "statistics": {...}
}
```

### Detection API

**Create Detection Rule**
```
POST /api/detections/rules
Request:
{
  "user_id": "user-123",
  "name": "Failed Console Logins",
  "description": "Detect failed console login attempts",
  "query": "SELECT * FROM cloudtrail_logs WHERE eventName = 'ConsoleLogin' AND errorCode IS NOT NULL",
  "severity": "high",
  "threshold": {
    "type": "count",
    "value": 5
  },
  "schedule_expression": "rate(5 minutes)",
  "enabled": true
}

Response:
{
  "rule_id": "rule-abc-123",
  "status": "created",
  "schedule_status": "enabled"
}
```

**Schedule Detection Rule**
```
POST /api/detections/schedule
Request:
{
  "user_id": "user-123",
  "rule_id": "rule-abc-123",
  "schedule_expression": "rate(5 minutes)"
}

Response:
{
  "rule_name": "detection-user-123-rule-abc-123-dev",
  "rule_arn": "arn:aws:events:us-east-1:123456789012:rule/...",
  "schedule_expression": "rate(5 minutes)",
  "status": "enabled"
}
```

**List Schedules**
```
GET /api/detections/schedules?user_id=user-123

Response:
{
  "schedules": [
    {
      "rule_name": "detection-user-123-rule-abc-123-dev",
      "rule_arn": "arn:aws:events:...",
      "schedule_expression": "rate(5 minutes)",
      "state": "ENABLED"
    }
  ]
}
```

### Integration API

**Validate Integration**
```
POST /api/integrations/validate
Request:
{
  "type": "slack",
  "config": {
    "webhook_url": "https://hooks.slack.com/services/...",
    "channel": "#security-alerts"
  }
}

Response:
{
  "success": true,
  "message": "Successfully sent test message to Slack",
  "details": {"response": "ok", "latency_ms": 187}
}
```

**Save Integration**
```
POST /api/integrations/wizard/slack/save
Request:
{
  "userId": "user-123",
  "name": "Slack Security Alerts",
  "config": {
    "webhook_url": "https://hooks.slack.com/...",
    "channel": "#security-alerts",
    "username": "Mantissa Log",
    "icon_emoji": ":shield:"
  },
  "severity_filter": ["critical", "high"],
  "enabled": true
}

Response:
{
  "integration_id": "slack-2024-11-27T10:30:00Z",
  "message": "Slack integration saved successfully",
  "integration": {...}
}
```

**Get Jira Projects**
```
POST /api/integrations/wizard/jira/projects
Request:
{
  "url": "https://acme.atlassian.net",
  "email": "security@acme.com",
  "api_token": "ATATT3xFfG..."
}

Response:
{
  "projects": [
    {"key": "SEC", "name": "Security Engineering", "id": "10000"},
    {"key": "SOPS", "name": "SecOps", "id": "10001"}
  ]
}
```

## DynamoDB Schema

### detection-rules Table

```
Partition Key: user_id (String)
Sort Key: rule_id (String)

Attributes:
{
  "user_id": "user-123",
  "rule_id": "rule-abc-123",
  "name": "Failed Console Logins",
  "description": "Detect failed console login attempts",
  "query": "SELECT * FROM cloudtrail_logs WHERE...",
  "severity": "high",
  "threshold": {
    "type": "count",
    "value": 5
  },
  "schedule_expression": "rate(5 minutes)",
  "schedule_rule_name": "detection-user-123-rule-abc-123-dev",
  "schedule_rule_arn": "arn:aws:events:...",
  "schedule_status": "enabled",
  "enabled": true,
  "created_at": "2024-11-27T10:00:00Z",
  "updated_at": "2024-11-27T10:30:00Z",
  "last_executed": "2024-11-27T10:30:00Z"
}

GSI: enabled-rules-index
  Partition Key: enabled (String: "true" | "false")
  Sort Key: last_executed (String)
```

### integrations Table

```
Partition Key: user_id (String)
Sort Key: integration_id (String)

Attributes:
{
  "user_id": "user-123",
  "integration_id": "slack-2024-11-27T10:30:00Z",
  "type": "slack",
  "name": "Slack Security Alerts",
  "config": {
    "webhook_url": "STORED_IN_SECRETS_MANAGER",
    "channel": "#security-alerts",
    "username": "Mantissa Log",
    "icon_emoji": ":shield:"
  },
  "severity_filter": ["critical", "high"],
  "enabled": true,
  "health_status": "healthy",
  "health_metrics": {
    "success_rate": 98.5,
    "total_attempts": 100,
    "successful": 98,
    "failed": 2,
    "last_24h": true
  },
  "last_test": "2024-11-27T10:30:05Z",
  "created_at": "2024-11-27T10:30:00Z",
  "updated_at": "2024-11-27T10:30:00Z"
}

GSI: type-index
  Partition Key: type (String)
  Sort Key: created_at (String)
```

### alert-history Table

```
Partition Key: user_id (String)
Sort Key: alert_id (String)

Attributes:
{
  "user_id": "user-123",
  "alert_id": "alert-def-456",
  "rule_id": "rule-abc-123",
  "rule_name": "Failed Console Logins",
  "severity": "high",
  "summary": "10 matches for Failed Console Logins",
  "description": "Detect failed console login attempts",
  "result_count": 10,
  "timestamp": "2024-11-27T10:30:00Z",
  "delivery_attempts": [
    {
      "integration_id": "slack-2024-11-27T10:30:00Z",
      "integration_type": "slack",
      "status": "delivered",
      "timestamp": "2024-11-27T10:30:02Z",
      "latency_ms": 187
    }
  ],
  "created_at": "2024-11-27T10:30:00Z"
}

GSI: rule-alerts-index
  Partition Key: rule_id (String)
  Sort Key: timestamp (String)

GSI: severity-index
  Partition Key: severity (String)
  Sort Key: timestamp (String)
```

### dedup-cache Table

```
Partition Key: dedup_key (String)

Attributes:
{
  "dedup_key": "sha256_hash",
  "user_id": "user-123",
  "alert_id": "alert-def-456",
  "rule_name": "Failed Console Logins",
  "severity": "high",
  "summary": "10 matches",
  "created_at": "2024-11-27T10:30:00Z",
  "expires_at": 1732704900  // TTL: 5 minutes from created_at
}

TTL Attribute: expires_at
```

## Secrets Manager Format

### Slack Integration Secret

```
Secret ID: mantissa-log/users/user-123/integrations/slack
Secret String:
{
  "webhook_url": "https://hooks.slack.com/services/T.../B.../X..."
}
```

### Jira Integration Secret

```
Secret ID: mantissa-log/users/user-123/integrations/jira
Secret String:
{
  "api_token": "ATATT3xFfGF0..."
}
```

### PagerDuty Integration Secret

```
Secret ID: mantissa-log/users/user-123/integrations/pagerduty
Secret String:
{
  "integration_key": "abc123def456..."
}
```

### Webhook Integration Secret

```
Secret ID: mantissa-log/users/user-123/integrations/webhook
Secret String:
{
  "headers": {
    "Authorization": "Bearer token123",
    "X-API-Key": "key456"
  }
}
```

## EventBridge Rules

### Detection Schedule

```
Rule Name: detection-user-123-rule-abc-123-dev
Schedule Expression: rate(5 minutes)
State: ENABLED
Target: Lambda (mantissa-log-rule-executor-dev)
Input:
{
  "rule_id": "rule-abc-123",
  "user_id": "user-123"
}
```

### Health Monitor Schedule

```
Rule Name: mantissa-log-health-monitor-dev
Schedule Expression: rate(5 minutes)
State: ENABLED
Target: Lambda (mantissa-log-health-monitor-dev)
```

## SQS Queues

### Alert Queue (FIFO)

```
Queue Name: mantissa-log-alerts-dev.fifo
Type: FIFO
Content-Based Deduplication: Enabled
Message Retention: 4 days
Visibility Timeout: 300 seconds (5 minutes)
Receive Wait Time: 0 seconds (short polling)

Message Group ID: {user_id}:{integration_id}
  Ensures ordered delivery per integration

Dead Letter Queue: mantissa-log-alerts-dlq-dev.fifo
Max Receive Count: 3
```

### Alert DLQ (FIFO)

```
Queue Name: mantissa-log-alerts-dlq-dev.fifo
Type: FIFO
Message Retention: 14 days
Purpose: Store failed alerts after 3 retry attempts
```

## Lambda Functions

### rule-executor

```
Function: mantissa-log-rule-executor-dev
Runtime: Python 3.12
Memory: 512 MB
Timeout: 300 seconds (5 minutes)
Trigger: EventBridge scheduled rules
Handler: rule_executor.lambda_handler

Environment Variables:
- ATHENA_OUTPUT_BUCKET
- TABLE_PREFIX
- ENVIRONMENT
- AWS_ACCOUNT_ID

IAM Permissions:
- athena:StartQueryExecution
- athena:GetQueryExecution
- athena:GetQueryResults
- s3:GetObject
- s3:PutObject
- dynamodb:GetItem
- dynamodb:UpdateItem
- sqs:SendMessage
```

### alert-delivery

```
Function: mantissa-log-alert-delivery-dev
Runtime: Python 3.12
Memory: 256 MB
Timeout: 60 seconds
Trigger: SQS (mantissa-log-alerts-dev.fifo)
Handler: alert_delivery.lambda_handler
Batch Size: 1 (process one alert at a time)

Environment Variables:
- TABLE_PREFIX
- ENVIRONMENT

IAM Permissions:
- secretsmanager:GetSecretValue
- dynamodb:GetItem
- dynamodb:PutItem
- dynamodb:UpdateItem
- dynamodb:Query
- sqs:SendMessage (for DLQ)
```

### query-executor

```
Function: mantissa-log-query-executor-dev
Runtime: Python 3.12
Memory: 512 MB
Timeout: 300 seconds
Trigger: API Gateway
Handler: query_executor.lambda_handler

IAM Permissions:
- athena:StartQueryExecution
- athena:GetQueryExecution
- athena:GetQueryResults
- athena:StopQueryExecution
- s3:GetObject
- s3:PutObject
```

### integration-wizard

```
Function: mantissa-log-integration-wizard-dev
Runtime: Python 3.12
Memory: 256 MB
Timeout: 30 seconds
Trigger: API Gateway
Handler: integration_wizard.lambda_handler

IAM Permissions:
- secretsmanager:CreateSecret
- secretsmanager:UpdateSecret
- secretsmanager:GetSecretValue
- dynamodb:PutItem
- dynamodb:GetItem
- dynamodb:UpdateItem
```

### scheduler

```
Function: mantissa-log-scheduler-dev
Runtime: Python 3.12
Memory: 256 MB
Timeout: 30 seconds
Trigger: API Gateway
Handler: scheduler.lambda_handler

IAM Permissions:
- events:PutRule
- events:DeleteRule
- events:EnableRule
- events:DisableRule
- events:DescribeRule
- events:ListRules
- events:PutTargets
- events:RemoveTargets
- lambda:GetFunction
- lambda:AddPermission
- dynamodb:UpdateItem
```

## Complete Request Flow Example

**User Creates Detection Rule with Scheduled Execution:**

1. User fills out form in UI:
   - Name: "Suspicious Console Logins"
   - Query: "SELECT * FROM cloudtrail_logs WHERE eventName = 'ConsoleLogin' AND errorCode IS NOT NULL"
   - Severity: "high"
   - Threshold: count > 3
   - Schedule: "rate(5 minutes)"

2. Frontend sends request:
   ```javascript
   POST /api/detections/rules
   {
     "user_id": "user-123",
     "name": "Suspicious Console Logins",
     "query": "SELECT * FROM cloudtrail_logs...",
     "severity": "high",
     "threshold": {"type": "count", "value": 3},
     "schedule_expression": "rate(5 minutes)",
     "enabled": true
   }
   ```

3. API Gateway → Lambda: Create rule
   - DynamoDB: Insert rule into detection-rules table
   - Generate rule_id: "rule-xyz-789"
   - Return rule_id to frontend

4. Frontend sends schedule request:
   ```javascript
   POST /api/detections/schedule
   {
     "user_id": "user-123",
     "rule_id": "rule-xyz-789",
     "schedule_expression": "rate(5 minutes)"
   }
   ```

5. Scheduler Lambda:
   - EventBridge: Create rule "detection-user-123-rule-xyz-789-dev"
   - Schedule: rate(5 minutes)
   - Target: rule-executor Lambda
   - Input: {"rule_id": "rule-xyz-789", "user_id": "user-123"}
   - DynamoDB: Update rule with schedule metadata

6. Every 5 minutes, EventBridge triggers rule-executor:
   - Get rule from DynamoDB
   - Execute Athena query
   - Wait for results
   - Check threshold: if len(results) > 3
   - Create Alert object
   - AlertRouter routes to integrations filtered by severity="high"
   - Send to SQS queue for async delivery

7. SQS triggers alert-delivery Lambda:
   - Check deduplication cache (5-minute window)
   - If not duplicate:
     - Get integration secrets from Secrets Manager
     - Deliver to Slack webhook
     - Record delivery in alert-history
   - If failure:
     - Retry with exponential backoff (5s, 10s, 20s)
     - After 3 failures, send to DLQ

8. User sees alert in Slack:
   ```
   🔴 High Severity Alert

   Suspicious Console Logins
   4 matches found

   Query: SELECT * FROM cloudtrail_logs WHERE...
   Rule ID: rule-xyz-789
   Timestamp: 2024-11-27T10:30:00Z
   ```

9. User views alert history in UI:
   - GET /api/alerts?user_id=user-123
   - Displays table with:
     - Timestamp
     - Rule Name
     - Severity
     - Result Count
     - Integrations (with delivery status)

## Security Architecture

### Authentication Flow

```
User Login
    → Cognito User Pool
    → OAuth 2.0 Authorization
    → JWT ID Token + Access Token
    → Frontend stores tokens
    → API requests include: Authorization: Bearer {id_token}
    → API Gateway validates token with Cognito
    → Lambda receives user context
```

### Authorization Model

```
Resource-Based Access Control:
- All resources scoped by user_id
- DynamoDB queries filter by user_id partition key
- Secrets Manager paths include /users/{user_id}/
- S3 bucket policies restrict to user prefix
- IAM policies enforce user isolation
```

### Secret Management

```
Sensitive Data Flow:
User enters API token
    → HTTPS to API Gateway
    → Lambda receives plaintext
    → Secrets Manager: CreateSecret with KMS encryption
    → DynamoDB stores: "STORED_IN_SECRETS_MANAGER"

Alert Delivery:
Lambda triggered
    → Secrets Manager: GetSecretValue
    → KMS decrypts secret
    → Lambda uses plaintext temporarily
    → Makes API call to integration
    → Plaintext cleared from memory
```

### Network Security

```
VPC Configuration:
- Lambda functions in private subnets
- NAT Gateway for outbound internet (Slack, Jira, PagerDuty)
- VPC Endpoints for AWS services (no internet):
  - DynamoDB VPC Endpoint
  - S3 VPC Endpoint
  - Secrets Manager VPC Endpoint
  - SQS VPC Endpoint

Security Groups:
- Lambda SG: Outbound HTTPS (443) only
- VPC Endpoint SG: Inbound from Lambda SG only
```

## Monitoring and Observability

### CloudWatch Metrics

**Lambda Metrics:**
- Invocations
- Duration
- Errors
- Throttles
- Concurrent Executions

**Athena Metrics:**
- DataScannedInBytes
- EngineExecutionTime
- QueryPlanningTime
- ServiceProcessingTime

**SQS Metrics:**
- NumberOfMessagesSent
- NumberOfMessagesReceived
- ApproximateAgeOfOldestMessage
- NumberOfMessagesDeleted

**Custom Metrics:**
```python
cloudwatch.put_metric_data(
    Namespace='MantissaLog',
    MetricData=[
        {
            'MetricName': 'AlertsRouted',
            'Value': 1,
            'Unit': 'Count',
            'Dimensions': [
                {'Name': 'Severity', 'Value': 'high'},
                {'Name': 'IntegrationType', 'Value': 'slack'}
            ]
        }
    ]
)
```

### CloudWatch Logs

**Log Groups:**
- /aws/lambda/mantissa-log-rule-executor-dev
- /aws/lambda/mantissa-log-alert-delivery-dev
- /aws/lambda/mantissa-log-query-executor-dev
- /aws/lambda/mantissa-log-integration-wizard-dev
- /aws/lambda/mantissa-log-scheduler-dev

**Log Insights Queries:**
```
# Failed alert deliveries
fields @timestamp, user_id, integration_type, error
| filter status = "failed"
| sort @timestamp desc

# Query execution times
fields @timestamp, execution_time_ms, data_scanned_bytes
| stats avg(execution_time_ms), sum(data_scanned_bytes) by bin(5m)

# Alert volume by severity
fields @timestamp, severity
| stats count() by severity, bin(1h)
```

### X-Ray Tracing

```
Enabled for all Lambda functions:
- Trace detection execution end-to-end
- Identify bottlenecks in query execution
- Monitor integration delivery latency
- Visualize alert routing flow
```

## Cost Optimization

### Athena Optimization

**Partitioning:**
```sql
-- Partition by date
PARTITION (dt='2024-11-27')

-- Query with partition filter
SELECT * FROM cloudtrail_logs
WHERE dt >= '2024-11-20'
  AND eventName = 'ConsoleLogin'
```

**Data Formats:**
- Parquet: 87% smaller than JSON
- Snappy compression: Additional 20% reduction
- Columnar storage: Only scan needed columns

**Cost Example:**
```
JSON: 1 GB scanned = $5.00/TB = $0.005
Parquet: 130 MB scanned = $0.00065
Savings: 87% reduction in data scanned costs
```

### Lambda Optimization

**Memory Sizing:**
- rule-executor: 512 MB (query execution needs more memory)
- alert-delivery: 256 MB (simple HTTP requests)
- query-executor: 512 MB (result processing)
- integration-wizard: 256 MB (validation logic)

**Concurrency Limits:**
- Reserved concurrency: 10 per function
- Prevents cost overruns from runaway executions

### S3 Lifecycle Policies

```
Lifecycle Rule: cloudtrail-logs
- 0-90 days: S3 Standard
- 90-365 days: S3 Glacier Instant Retrieval
- 365-2555 days: S3 Glacier Deep Archive
- 2555+ days: Delete
```

## Disaster Recovery

### Backup Strategy

**DynamoDB:**
- Point-in-time recovery enabled
- Daily backups to S3
- Cross-region replication for production

**S3:**
- Versioning enabled
- Cross-region replication
- MFA delete protection

**Secrets Manager:**
- Automatic rotation disabled (manual rotation via UI)
- Replica secrets in secondary region

### Recovery Procedures

**Lambda Failure:**
```
1. Check CloudWatch Logs for errors
2. Verify IAM permissions
3. Check DLQ for failed messages
4. Redrive DLQ messages after fix
```

**Athena Query Timeout:**
```
1. Check query complexity
2. Verify partition filters used
3. Increase Lambda timeout if needed
4. Consider query optimization
```

**Integration Delivery Failure:**
```
1. Check integration health status
2. Verify credentials in Secrets Manager
3. Test integration manually via wizard
4. Check SQS DLQ for failed messages
5. Redrive after fixing integration
```

## Performance Benchmarks

### Query Execution

```
Dataset: 1 million CloudTrail events (90 days)
Format: Parquet with Snappy compression
Size: 450 MB

Simple Query (1 day filter):
- Data Scanned: 5 MB
- Execution Time: 1.2 seconds
- Cost: $0.000025

Complex Query (7 day filter, aggregation):
- Data Scanned: 35 MB
- Execution Time: 3.8 seconds
- Cost: $0.000175
```

### Alert Delivery

```
Slack Webhook:
- Latency: 150-300 ms
- Success Rate: 99.8%
- Retry Rate: 0.2%

Jira API:
- Latency: 400-800 ms
- Success Rate: 99.5%
- Retry Rate: 0.5%

PagerDuty:
- Latency: 200-400 ms
- Success Rate: 99.9%
- Retry Rate: 0.1%
```

### End-to-End Latency

```
Detection to Notification:
- EventBridge trigger: 0 ms (scheduled)
- Rule execution: 2-5 seconds (query dependent)
- Alert routing: 100-200 ms
- SQS delivery: 50-100 ms
- Integration delivery: 150-800 ms

Total: 2.3-6.1 seconds from detection to notification
```

## Future Enhancements

### 1. Machine Learning Detection
- Anomaly detection using AWS SageMaker
- Behavioral analytics for user activity
- Threat intelligence enrichment

### 2. Incident Response
- Automated response actions (Lambda, Systems Manager)
- Runbook execution
- Evidence collection

### 3. Compliance Reporting
- PCI DSS compliance dashboards
- SOC 2 audit trails
- GDPR data access logs

### 4. Advanced Query Features
- Saved query templates
- Query parameterization
- Scheduled reports

## Documentation References

- [Query Executor](../../src/aws/api/query_executor.py)
- [Rule Executor](../../src/aws/detections/rule_executor.py)
- [Scheduler](../../src/aws/detections/scheduler.py)
- [Alert Router](../../src/shared/alerts/router.py)
- [Alert Delivery](../../src/shared/alerts/delivery.py)
- [Integration Validators](../../src/shared/integrations/validators.py)
- [Advanced Alerting](../features/advanced-alerting.md)
- [Integration Wizards](../features/integration-wizards.md)
