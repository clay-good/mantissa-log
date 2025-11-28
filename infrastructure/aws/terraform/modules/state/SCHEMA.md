# DynamoDB Table Schemas

This document describes the schema for DynamoDB tables used in Mantissa Log.

## User Settings Table

Stores user preferences, LLM configuration, and application settings.

**Table Name:** `mantissa-log-user-settings-{environment}`

**Primary Key:**
- `user_id` (String, Hash Key)

**Attributes:**

```json
{
  "user_id": "string",
  "llm_provider": "anthropic|openai|google|bedrock",
  "llm_model": "string",
  "api_key_secret_id": "string",
  "preferences": {
    "query_model": "string",
    "detection_model": "string",
    "max_tokens": 2000,
    "temperature": 0.0
  },
  "ui_preferences": {
    "theme": "light|dark",
    "default_time_range": "24h|7d|30d",
    "items_per_page": 25
  },
  "created_at": "ISO8601 timestamp",
  "updated_at": "ISO8601 timestamp"
}
```

**Example:**

```json
{
  "user_id": "user-123",
  "llm_provider": "anthropic",
  "llm_model": "claude-3-5-sonnet-20241022",
  "api_key_secret_id": "arn:aws:secretsmanager:us-east-1:123456789012:secret:user-123-anthropic-key",
  "preferences": {
    "query_model": "claude-3-5-sonnet-20241022",
    "detection_model": "claude-3-5-sonnet-20241022",
    "max_tokens": 2000,
    "temperature": 0.0
  },
  "ui_preferences": {
    "theme": "dark",
    "default_time_range": "24h",
    "items_per_page": 50
  },
  "created_at": "2024-11-27T10:00:00Z",
  "updated_at": "2024-11-27T15:30:00Z"
}
```

## Detection Rules Table

Tracks metadata for user-created detection rules.

**Table Name:** `mantissa-log-detection-rules-{environment}`

**Primary Key:**
- `user_id` (String, Hash Key)
- `rule_name` (String, Range Key)

**Global Secondary Indexes:**
- `EnabledRulesIndex`: Hash: `enabled`, Range: `severity`

**Attributes:**

```json
{
  "user_id": "string",
  "rule_name": "string",
  "s3_key": "string",
  "schedule": "string",
  "threshold": 1,
  "severity": "critical|high|medium|low|info",
  "enabled": "true|false",
  "alert_destinations": ["slack", "email", "jira", "pagerduty"],
  "created_at": "ISO8601 timestamp",
  "updated_at": "ISO8601 timestamp",
  "created_from": "web_ui|api|cli",
  "executions": 0,
  "last_execution": "ISO8601 timestamp",
  "last_execution_status": "success|error",
  "last_alert": "ISO8601 timestamp",
  "alert_count": 0,
  "data_scanned_mb": 0,
  "avg_duration_ms": 0
}
```

**Example:**

```json
{
  "user_id": "user-123",
  "rule_name": "failed_login_attempts",
  "s3_key": "user_rules/user-123/failed_login_attempts.yaml",
  "schedule": "rate(5 minutes)",
  "threshold": 10,
  "severity": "high",
  "enabled": "true",
  "alert_destinations": ["slack", "email"],
  "created_at": "2024-11-27T10:00:00Z",
  "updated_at": "2024-11-27T15:30:00Z",
  "created_from": "web_ui",
  "executions": 145,
  "last_execution": "2024-11-27T15:25:00Z",
  "last_execution_status": "success",
  "last_alert": "2024-11-26T08:30:00Z",
  "alert_count": 3,
  "data_scanned_mb": 250,
  "avg_duration_ms": 1234
}
```

## Integration Settings Table

Stores configuration for alert integrations.

**Table Name:** `mantissa-log-integration-settings-{environment}`

**Primary Key:**
- `user_id` (String, Hash Key)
- `integration_id` (String, Range Key)

**Global Secondary Indexes:**
- `IntegrationTypeIndex`: Hash: `integration_type`

**Attributes:**

```json
{
  "user_id": "string",
  "integration_id": "string",
  "integration_type": "slack|jira|pagerduty|email|webhook",
  "enabled": true,
  "config": {
    // Type-specific configuration (stored encrypted)
  },
  "secret_arn": "string",
  "status": "configured|error|not_configured",
  "last_test": "ISO8601 timestamp",
  "last_test_status": "success|error",
  "last_test_error": "string",
  "created_at": "ISO8601 timestamp",
  "updated_at": "ISO8601 timestamp"
}
```

**Type-Specific Configurations:**

### Slack Integration

```json
{
  "user_id": "user-123",
  "integration_id": "slack-main",
  "integration_type": "slack",
  "enabled": true,
  "config": {
    "channel": "siem-alerts",
    "webhook_url_secret": "arn:aws:secretsmanager:...",
    "severity_filter": ["critical", "high", "medium"],
    "mention_on_critical": true,
    "mention_user": "@oncall"
  },
  "secret_arn": "arn:aws:secretsmanager:us-east-1:123456789012:secret:user-123-slack-webhook",
  "status": "configured",
  "last_test": "2024-11-27T14:00:00Z",
  "last_test_status": "success",
  "created_at": "2024-11-20T10:00:00Z",
  "updated_at": "2024-11-27T14:00:00Z"
}
```

### Jira Integration

```json
{
  "user_id": "user-123",
  "integration_id": "jira-security",
  "integration_type": "jira",
  "enabled": true,
  "config": {
    "jira_url": "https://company.atlassian.net",
    "project_key": "SEC",
    "issue_type": "Security Finding",
    "priority_mapping": {
      "critical": "Highest",
      "high": "High",
      "medium": "Medium",
      "low": "Low",
      "info": "Lowest"
    },
    "assignee": "security-team",
    "labels": ["mantissa-log", "automated"]
  },
  "secret_arn": "arn:aws:secretsmanager:us-east-1:123456789012:secret:user-123-jira-api-token",
  "status": "configured",
  "last_test": "2024-11-27T14:00:00Z",
  "last_test_status": "success",
  "created_at": "2024-11-20T11:00:00Z",
  "updated_at": "2024-11-27T14:00:00Z"
}
```

### PagerDuty Integration

```json
{
  "user_id": "user-123",
  "integration_id": "pagerduty-oncall",
  "integration_type": "pagerduty",
  "enabled": true,
  "config": {
    "service_key": "arn:aws:secretsmanager:...",
    "severity_threshold": "high",
    "dedup_key_prefix": "mantissa-log"
  },
  "secret_arn": "arn:aws:secretsmanager:us-east-1:123456789012:secret:user-123-pagerduty-key",
  "status": "configured",
  "last_test": "2024-11-27T14:00:00Z",
  "last_test_status": "success",
  "created_at": "2024-11-20T12:00:00Z",
  "updated_at": "2024-11-27T14:00:00Z"
}
```

### Email Integration

```json
{
  "user_id": "user-123",
  "integration_id": "email-security-team",
  "integration_type": "email",
  "enabled": true,
  "config": {
    "recipients": ["security@company.com", "oncall@company.com"],
    "from_address": "mantissa-log@company.com",
    "severity_filter": ["critical", "high"],
    "include_query_results": true,
    "max_results_in_email": 10
  },
  "status": "configured",
  "last_test": "2024-11-27T14:00:00Z",
  "last_test_status": "success",
  "created_at": "2024-11-20T13:00:00Z",
  "updated_at": "2024-11-27T14:00:00Z"
}
```

### Custom Webhook Integration

```json
{
  "user_id": "user-123",
  "integration_id": "webhook-custom-siem",
  "integration_type": "webhook",
  "enabled": true,
  "config": {
    "url": "https://siem.company.com/api/alerts",
    "method": "POST",
    "headers": {
      "Content-Type": "application/json",
      "Authorization": "Bearer ${SECRET}"
    },
    "payload_template": "custom",
    "retry_count": 3,
    "timeout_seconds": 30
  },
  "secret_arn": "arn:aws:secretsmanager:us-east-1:123456789012:secret:user-123-webhook-token",
  "status": "configured",
  "last_test": "2024-11-27T14:00:00Z",
  "last_test_status": "success",
  "created_at": "2024-11-20T14:00:00Z",
  "updated_at": "2024-11-27T14:00:00Z"
}
```

## Access Patterns

### User Settings

1. **Get user settings by user_id**
   ```
   GetItem(user_id)
   ```

2. **Update user preferences**
   ```
   UpdateItem(user_id, preferences)
   ```

### Detection Rules

1. **List all rules for a user**
   ```
   Query(user_id)
   ```

2. **Get specific rule**
   ```
   GetItem(user_id, rule_name)
   ```

3. **List all enabled rules**
   ```
   Query on EnabledRulesIndex where enabled = "true"
   ```

4. **List high-severity enabled rules**
   ```
   Query on EnabledRulesIndex where enabled = "true" AND severity = "high"
   ```

5. **Update rule execution statistics**
   ```
   UpdateItem(user_id, rule_name, executions++, last_execution)
   ```

### Integration Settings

1. **List all integrations for a user**
   ```
   Query(user_id)
   ```

2. **Get specific integration**
   ```
   GetItem(user_id, integration_id)
   ```

3. **List all integrations of a specific type**
   ```
   Query on IntegrationTypeIndex where integration_type = "slack"
   ```

4. **Update integration test status**
   ```
   UpdateItem(user_id, integration_id, last_test, last_test_status)
   ```

## Security Considerations

1. **API Keys and Secrets**
   - NEVER store API keys or tokens directly in DynamoDB
   - Store references to AWS Secrets Manager ARNs
   - Use KMS encryption for all sensitive data

2. **Encryption**
   - All tables use server-side encryption with KMS
   - Enable encryption in transit (HTTPS only)

3. **Access Control**
   - Use IAM policies to restrict access to user's own data
   - Implement row-level security using IAM conditions
   - Audit all access with CloudTrail

4. **Data Retention**
   - Configure TTL for temporary data if needed
   - Enable point-in-time recovery for all tables
   - Regular backups to S3

## Cost Optimization

1. **Use PAY_PER_REQUEST billing mode** for unpredictable workloads
2. **Implement TTL** for temporary data (e.g., session tokens)
3. **Monitor GSI usage** and remove unused indexes
4. **Use projection type** wisely in GSIs (ALL vs KEYS_ONLY)
5. **Batch operations** when possible to reduce request count
