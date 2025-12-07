# Query-to-Rule Conversion Feature

This document describes the Query-to-Rule Conversion feature implemented in Mantissa Log, which allows users to convert ad hoc natural language queries into scheduled detection rules.

## Overview

The Query-to-Rule Conversion feature enables users to:
1. Ask questions about their logs in natural language
2. Review the generated SQL query and results
3. Convert the query into a scheduled detection rule with a wizard interface
4. Configure alert routing to multiple destinations
5. Track and manage their custom detection rules

This implements **Phase 1** of the Future Roadmap: Enhanced Query-to-Rule Conversion.

## Architecture

### Backend Components

#### 1. Query-to-Rule API (`src/aws/api/query_to_rule.py`)

Lambda function that converts queries into detection rules.

**Endpoint:** `POST /api/query-to-rule`

**Request Body:**
```json
{
  "query": "SELECT ...",
  "ruleName": "my_detection_rule",
  "description": "Description of what this detects",
  "schedule": "rate(5 minutes)",
  "threshold": 10,
  "severity": "high",
  "alertDestinations": ["slack", "email"],
  "userId": "user123"
}
```

**Response:**
```json
{
  "message": "Detection rule created successfully",
  "ruleKey": "user_rules/user123/my_detection_rule.yaml",
  "rule": {
    "name": "my_detection_rule",
    "description": "...",
    "query": "SELECT ...",
    "schedule": "rate(5 minutes)",
    "threshold": 10,
    "severity": "high",
    "enabled": true
  }
}
```

**Functionality:**
- Validates input parameters
- Creates detection rule in YAML format
- Saves rule to S3 bucket
- Tracks metadata in DynamoDB
- Returns rule details

#### 2. Integrations API (`src/aws/api/integrations.py`)

Lambda function for managing alert integrations.

**Endpoints:**
- `GET /integrations` - List all integrations
- `GET /integrations/{id}` - Get specific integration
- `POST /integrations` - Create/update integration
- `POST /integrations/{id}/test` - Test integration
- `DELETE /integrations/{id}` - Delete integration

**Supported Integration Types:**
- Slack (webhooks)
- Email (SES)
- Jira (API)
- PagerDuty (Events API)
- Custom Webhooks

**Security:**
- API keys and tokens stored in AWS Secrets Manager
- No sensitive data in DynamoDB
- KMS encryption for all data at rest
- IAM-based access control

### Database Schema

#### User Settings Table

Stores user preferences and LLM configuration.

```
Table: mantissa-log-user-settings-{environment}
Primary Key: user_id (String)

Attributes:
- llm_provider: anthropic|openai|google|bedrock
- llm_model: string
- api_key_secret_id: string (reference to Secrets Manager)
- preferences: object
- ui_preferences: object
- created_at: timestamp
- updated_at: timestamp
```

#### Detection Rules Table

Tracks user-created detection rules.

```
Table: mantissa-log-detection-rules-{environment}
Primary Key: user_id (String), rule_name (String)
GSI: EnabledRulesIndex (enabled, severity)

Attributes:
- user_id: string
- rule_name: string
- s3_key: string
- schedule: string
- threshold: number
- severity: critical|high|medium|low|info
- enabled: boolean
- alert_destinations: array
- executions: number
- last_execution: timestamp
- last_alert: timestamp
```

#### Integration Settings Table

Stores alert integration configurations.

```
Table: mantissa-log-integration-settings-{environment}
Primary Key: user_id (String), integration_id (String)
GSI: IntegrationTypeIndex (integration_type)

Attributes:
- user_id: string
- integration_id: string
- integration_type: slack|jira|pagerduty|email|webhook
- enabled: boolean
- config: object
- secret_arn: string (reference to Secrets Manager)
- status: configured|error|not_configured
- last_test: timestamp
- last_test_status: success|error
```

### Frontend Components

#### 1. DetectionRuleWizard (`web/src/components/DetectionRuleWizard.jsx`)

Multi-step wizard for creating detection rules from queries.

**Steps:**
1. **Rule Details** - Name, description, severity
2. **Schedule & Threshold** - Execution schedule, alert threshold
3. **Alert Routing** - Select integration destinations
4. **Review** - Summary and confirmation

**Features:**
- Step-by-step validation
- Integration status indicators
- Schedule presets (5min, 15min, 30min, hourly, daily)
- Severity selection (critical, high, medium, low, info)
- Alert destination selection with configuration status
- Query preview and cost estimation placeholder

**Props:**
```javascript
<DetectionRuleWizard
  query={string}              // SQL query to convert
  onClose={function}          // Close modal handler
  onSave={function}           // Save handler
  integrations={array}        // Available integrations
/>
```

#### 2. IntegrationStatus (`web/src/components/IntegrationStatus.jsx`)

Component for displaying and managing alert integrations.

**Features:**
- Visual status indicators (configured, error, warning, not configured)
- Quick setup links
- Test connection buttons
- Configuration details display
- Last tested timestamp

**Props:**
```javascript
<IntegrationStatus
  integrations={array}        // Integration list
  onConfigure={function}      // Configuration handler
/>
```

#### 3. QueryInterface Update (`web/src/components/QueryInterface/index.jsx`)

Enhanced query interface with "Save as Detection Rule" button.

**Location:** Results section, visible after successful query execution

**Button Behavior:**
- Only appears after query succeeds
- Opens DetectionRuleWizard modal
- Passes current SQL query and explanation
- Displays success toast on rule creation

### Hooks

#### useIntegrations (`web/src/hooks/useIntegrations.js`)

React Query hooks for integration management.

**Exports:**
- `useIntegrations()` - Fetch all integrations
- `useIntegration(id)` - Fetch specific integration
- `useSaveIntegration()` - Create/update integration
- `useTestIntegration()` - Test integration connection
- `useDeleteIntegration()` - Delete integration
- `useDefaultIntegrations()` - Get default integration templates

## User Flow

### Creating a Detection Rule

1. **Query Phase**
   - User asks: "Show me all failed login attempts in the last hour"
   - System generates SQL query using LLM
   - System executes query and displays results

2. **Conversion Phase**
   - User clicks "Save as Detection Rule" button
   - DetectionRuleWizard modal opens

3. **Step 1: Rule Details**
   - User enters rule name (e.g., "failed_login_attempts")
   - User enters description (auto-populated from LLM explanation)
   - User selects severity (critical, high, medium, low, info)

4. **Step 2: Schedule & Threshold**
   - User selects execution schedule (e.g., "Every 5 minutes")
   - User sets threshold (e.g., "10 or more matches")

5. **Step 3: Alert Routing**
   - User selects alert destinations
   - System shows configuration status for each integration
   - Green badge: "Configured" (ready to use)
   - Yellow badge: "Setup Required" (needs configuration)

6. **Step 4: Review**
   - User reviews all settings
   - System displays complete rule summary
   - User clicks "Create Detection Rule"

7. **Completion**
   - System creates rule in S3
   - System saves metadata to DynamoDB
   - Success notification displayed
   - Rule begins executing on schedule

### Managing Integrations

1. User navigates to Settings > Integrations
2. IntegrationStatus component displays all available integrations
3. User clicks "Configure" on an integration (e.g., Slack)
4. Integration setup wizard appears
5. User provides required credentials/configuration
6. System stores secrets in AWS Secrets Manager
7. System saves configuration to DynamoDB
8. User clicks "Test Connection"
9. System sends test alert and displays result
10. Integration status updates to "Configured"

## Security Considerations

### API Key Storage

**Never Store in DynamoDB:**
- API keys
- Auth tokens
- Webhook URLs
- Service keys

**Always Use Secrets Manager:**
- Store all sensitive credentials in AWS Secrets Manager
- Reference by ARN in DynamoDB
- Enable automatic rotation where possible
- Use KMS encryption

**Access Control:**
- IAM policies restrict access to user's own secrets
- Secrets named with user ID: `mantissa-log/{user_id}/{integration_id}`
- CloudTrail logging for all secret access

### Data Encryption

**At Rest:**
- DynamoDB tables encrypted with KMS
- S3 buckets encrypted (server-side)
- Secrets Manager encrypted with KMS

**In Transit:**
- HTTPS only for all API calls
- TLS 1.2+ required
- Secure webhook URLs (https://)

### User Isolation

**Row-Level Security:**
- All DynamoDB queries filtered by user_id
- IAM policies enforce user isolation
- No cross-user data access possible

**S3 Bucket Structure:**
```
mantissa-log-rules/
  user_rules/
    {user_id}/
      rule1.yaml
      rule2.yaml
```

## Cost Optimization

### Query Execution Costs

**Athena Costs:**
- $5 per TB scanned
- Partitioning reduces data scanned
- Query result caching enabled

**Lambda Costs:**
- $0.0000166667 per GB-second
- Optimized execution times
- Right-sized memory allocation

**DynamoDB Costs:**
- PAY_PER_REQUEST billing mode
- Efficient query patterns
- Minimal read/write operations

**Cost Projection (Future Phase 2):**
- Display estimated monthly cost when creating rule
- Based on query data scanned and execution frequency
- Warning if cost exceeds threshold
- Optimization suggestions

## Monitoring and Metrics

### Rule Execution Tracking

Each rule execution updates:
- `executions` - Total execution count
- `last_execution` - Timestamp of last run
- `last_execution_status` - success|error
- `data_scanned_mb` - Cumulative data scanned
- `avg_duration_ms` - Average execution time

### Integration Health

Each integration test updates:
- `last_test` - Timestamp of last test
- `last_test_status` - success|error
- `last_test_error` - Error message if failed

### CloudWatch Metrics

- Rule execution duration
- Rule execution success/failure rate
- Alert delivery success/failure rate
- Integration health status
- Query performance metrics

## Future Enhancements

### Phase 2: Cost Projection (Planned)
- Real-time cost estimation
- Monthly cost projections
- Cost optimization recommendations
- Budget alerts

### Phase 3: Conversational Context (Planned)
- Session-based conversation memory
- Multi-turn query refinement
- Follow-up command recognition
- Context-aware rule suggestions

### Phase 4: LLM Model Configuration (Planned)
- Bring Your Own API Keys
- Model selection (Claude, GPT-4, Gemini)
- Usage tracking per user
- Cost comparison across providers

### Phase 5: Integration Wizards (Planned)
- Step-by-step setup guides
- Screenshot tutorials
- Test integration flows
- Configuration validation

### Phase 6: Advanced Alerting (Planned)
- Alert suppression and deduplication
- Retry logic with exponential backoff
- Dead letter queue for failed alerts
- Alert enrichment and context

## Testing

### Backend Tests

```bash
# Test query-to-rule API
pytest tests/unit/api/test_query_to_rule.py

# Test integrations API
pytest tests/unit/api/test_integrations.py
```

### Frontend Tests

```bash
# Test DetectionRuleWizard component
npm test -- DetectionRuleWizard.test.jsx

# Test IntegrationStatus component
npm test -- IntegrationStatus.test.jsx

# Test integration hooks
npm test -- useIntegrations.test.js
```

### Integration Tests

```bash
# Test complete query-to-rule flow
pytest tests/integration/test_query_to_rule_flow.py

# Test alert delivery
pytest tests/integration/test_alert_delivery.py
```

## Documentation

- [DynamoDB Schema Documentation](../../infrastructure/aws/terraform/modules/state/SCHEMA.md)
- [API Documentation](../api/README.md)
- [Integration Setup Guides](../integrations/)
- [User Guide](../user-guide.md)

## Support

For issues or questions:
- GitHub Issues: https://github.com/your-org/mantissa-log/issues
- Documentation: https://docs.mantissa-log.io
- Email: support@mantissa-log.io
