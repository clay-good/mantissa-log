# Mantissa Log Deployment Guide

This guide covers detailed setup instructions for deploying Mantissa Log in different modes.

## Prerequisites (All Modes)

### Cloud Provider Account
- **AWS**: Account with permissions for Lambda, S3, Athena, DynamoDB, Glue, EventBridge, IAM
- **GCP**: Project with Cloud Functions, BigQuery, Cloud Storage, Firestore, Cloud Scheduler
- **Azure**: Subscription with Functions, Synapse, Blob Storage, Cosmos DB, Logic Apps

### Local Tools
- Terraform >= 1.5
- Python >= 3.11
- Node.js >= 18
- AWS CLI / gcloud CLI / Azure CLI (depending on provider)
- Git

### Required Credentials
- LLM API key (Anthropic, OpenAI, or cloud-native)
- Log source API keys (Okta, Azure AD, etc. - depending on collectors)

---

## Mode 1: SIEM-Only Deployment

Deploy core log aggregation, querying, detection, and alerting without APM or SOAR.

### Step 1: Clone and Configure

```bash
git clone https://github.com/your-org/mantissa-log.git
cd mantissa-log
```

### Step 2: Configure Terraform Variables

```bash
cd infrastructure/aws/terraform
cp terraform.tfvars.example terraform.tfvars
```

Edit `terraform.tfvars`:

```hcl
# Deployment Configuration
environment    = "prod"
aws_region     = "us-east-1"
project_name   = "mantissa-log"

# Module Flags - SIEM Only
enable_siem = true
enable_apm  = false
enable_soar = false

# LLM Configuration
llm_provider = "bedrock"  # or "anthropic", "openai"

# Storage
data_bucket_name = "mantissa-log-data"
log_retention_days = 90

# Alert Destinations
slack_webhook_url = "https://hooks.slack.com/services/..."
pagerduty_routing_key = "..."  # optional
```

### Step 3: Initialize and Deploy Infrastructure

```bash
terraform init
terraform plan -var-file=terraform.tfvars
terraform apply -var-file=terraform.tfvars
```

### Step 4: Deploy Lambda Functions

```bash
cd ../../..
bash scripts/deploy.sh --environment prod
```

### Step 5: Configure Log Collectors

For each log source, create a collector configuration in DynamoDB or via the UI:

**Example: Okta Collector**
```json
{
  "collector_id": "okta-prod",
  "source_type": "okta",
  "enabled": true,
  "schedule": "rate(5 minutes)",
  "config": {
    "domain": "your-org.okta.com",
    "api_token_secret": "okta-api-token"
  }
}
```

See [docs/collectors/](collectors/) for configuration guides for each source.

### Step 6: Configure Detection Rules

Import default Sigma rules:

```bash
python scripts/import_sigma_rules.py --directory rules/sigma/
```

### Step 7: Configure Alert Routing

Set up routing rules via environment variables or DynamoDB:

```json
{
  "route_id": "critical-to-pagerduty",
  "conditions": {
    "severity": ["critical"]
  },
  "destination": "pagerduty",
  "config": {
    "routing_key": "your-pagerduty-key"
  }
}
```

### Step 8: Deploy Frontend

```bash
cd web
npm install
npm run build

# Deploy to S3/CloudFront (or your preferred hosting)
aws s3 sync dist/ s3://mantissa-log-frontend/
```

### Step 9: Verify Deployment

1. Access the web UI
2. Navigate to Query page
3. Try: "Show me all events from the last hour"
4. Navigate to Detections page - verify rules are loaded
5. Check CloudWatch Logs for any Lambda errors

---

## Mode 2: SIEM + Observability Deployment

Add APM capabilities to the SIEM core.

### Step 1: Update Terraform Variables

In `terraform.tfvars`:

```hcl
# Module Flags - SIEM + Observability
enable_siem = true
enable_apm  = true
enable_soar = false
```

### Step 2: Apply Infrastructure Changes

```bash
cd infrastructure/aws/terraform
terraform plan -var-file=terraform.tfvars
terraform apply -var-file=terraform.tfvars
```

This will create additional resources:
- OTLP receiver Lambda endpoints
- APM Glue tables (traces, metrics, spans)
- Service map API endpoint

### Step 3: Deploy Updated Lambda Functions

```bash
cd ../../..
bash scripts/deploy.sh --environment prod --include-apm
```

### Step 4: Configure OpenTelemetry in Your Applications

Point your OTLP exporter to the Mantissa endpoint:

**Python Example:**
```python
from opentelemetry import trace
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter

trace.set_tracer_provider(TracerProvider())
tracer = trace.get_tracer(__name__)

otlp_exporter = OTLPSpanExporter(
    endpoint="https://your-api-gateway.execute-api.us-east-1.amazonaws.com/prod/v1/traces"
)
```

**Node.js Example:**
```javascript
const { OTLPTraceExporter } = require('@opentelemetry/exporter-trace-otlp-http');

const exporter = new OTLPTraceExporter({
  url: 'https://your-api-gateway.execute-api.us-east-1.amazonaws.com/prod/v1/traces',
});
```

### Step 5: Verify APM Data Flow

1. Generate some application traffic
2. Query: "Show me all traces from the last hour"
3. Navigate to Service Map page - verify services appear
4. Click on a service to view trace details

### Step 6: Configure APM Detection Rules

Create latency detection rules:

```yaml
title: High Latency - Checkout Service
id: apm-latency-checkout
status: stable
level: high
description: Detects high latency in checkout service
logsource:
  product: apm
  service: traces
detection:
  selection:
    service_name: "checkout-service"
  condition: selection | avg(duration_ms) > 5000
  timeframe: 5m
```

---

## Mode 3: Full Platform Deployment

Add SOAR capabilities for automated response.

### Step 1: Update Terraform Variables

In `terraform.tfvars`:

```hcl
# Module Flags - Full Platform
enable_siem = true
enable_apm  = true
enable_soar = true

# SOAR Configuration
soar_approval_timeout_minutes = 60
soar_playbook_bucket = "mantissa-log-playbooks"
```

### Step 2: Apply Infrastructure Changes

```bash
cd infrastructure/aws/terraform
terraform plan -var-file=terraform.tfvars
terraform apply -var-file=terraform.tfvars
```

Additional resources created:
- Playbook DynamoDB table
- Execution tracking table
- Approval workflow Lambda
- SOAR action executor Lambda

### Step 3: Deploy Updated Lambda Functions

```bash
cd ../../..
bash scripts/deploy.sh --environment prod --include-apm --include-soar
```

### Step 4: Configure Identity Provider Integration

For response actions (disable user, terminate sessions), configure provider credentials:

**Okta Configuration:**
```json
{
  "provider": "okta",
  "domain": "your-org.okta.com",
  "api_token_secret": "arn:aws:secretsmanager:us-east-1:123456789:secret:okta-api-token"
}
```

**Azure AD Configuration:**
```json
{
  "provider": "azure_ad",
  "tenant_id": "your-tenant-id",
  "client_id": "your-client-id",
  "client_secret_arn": "arn:aws:secretsmanager:us-east-1:123456789:secret:azure-ad-secret"
}
```

### Step 5: Create Your First Playbook

**Option A: From Natural Language**

Navigate to Playbooks → Create → "Generate from description":

```
When a credential compromise is detected with high severity:
1. Disable the user account in Okta
2. Terminate all active sessions
3. Create a Jira ticket for the security team
4. Notify the #security-incidents Slack channel
```

**Option B: From IR Plan Document**

Upload a markdown incident response plan:

```markdown
# Credential Compromise Response

## Trigger
Alert with tags: credential-compromise, brute-force

## Response Steps
1. **Disable Account** - Immediately disable the compromised user account
2. **Revoke Sessions** - Terminate all active sessions for the user
3. **Create Ticket** - Create incident ticket in Jira project SEC
4. **Notify Team** - Send notification to security team Slack channel
```

**Option C: Manual YAML**

Create `playbooks/credential-compromise.yml`:

```yaml
name: Credential Compromise Response
version: "1.0.0"
status: active

trigger:
  type: alert
  conditions:
    rule_id: "credential_*"
    severity:
      - high
      - critical

steps:
  - id: disable-user
    name: Disable User Account
    action_type: disable_user
    parameters:
      user_id: "{{alert.user_id}}"
      provider: okta
    requires_approval: true
    on_failure: continue

  - id: revoke-sessions
    name: Revoke All Sessions
    action_type: revoke_sessions
    parameters:
      user_id: "{{alert.user_id}}"
    depends_on:
      - disable-user

  - id: create-ticket
    name: Create Incident Ticket
    action_type: create_ticket
    parameters:
      system: jira
      project: SEC
      title: "Credential Compromise: {{alert.user_id}}"
```

### Step 6: Configure Approval Workflow

By default, dangerous actions require approval. Configure approvers:

```json
{
  "approval_config": {
    "approvers": [
      "security-team@your-org.com",
      "@security-oncall"
    ],
    "notification_channel": "#security-approvals",
    "timeout_minutes": 60,
    "auto_approve_after_timeout": false
  }
}
```

### Step 7: Test Playbook Execution

1. Navigate to Playbooks → select your playbook
2. Click "Test Run" with sample alert data
3. Verify each step executes correctly
4. Check execution logs for audit trail

### Security Considerations for SOAR

1. **Principle of Least Privilege**: Grant SOAR Lambda only necessary permissions
2. **Approval Required**: Enable approval for destructive actions
3. **Audit Logging**: All actions are logged to CloudWatch and DynamoDB
4. **Secret Management**: Store provider credentials in Secrets Manager
5. **Rate Limiting**: Configure rate limits to prevent runaway automation

---

## Feature Flags and Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `ENABLE_APM_COLLECTOR` | Enable OTLP trace/metric ingestion | `false` |
| `ENABLE_SOAR_EXECUTOR` | Enable playbook execution | `false` |
| `ENABLE_PLAYBOOK_GENERATION` | Enable LLM-based playbook generation | `false` |
| `SOAR_DRY_RUN_MODE` | Execute playbooks without taking action | `false` |

### Runtime Feature Toggles

Features can be toggled at runtime via DynamoDB:

```json
{
  "feature_id": "soar_executor",
  "enabled": true,
  "config": {
    "max_concurrent_executions": 10,
    "default_timeout_seconds": 3600
  }
}
```

### Enabling Features After Initial Deployment

1. Update `terraform.tfvars` with new flags
2. Run `terraform apply`
3. Deploy updated Lambda functions
4. Update frontend environment variables
5. Clear browser cache to see UI changes

---

## Cost Considerations

### SIEM Only (Base Costs)

| Service | Monthly Estimate | Notes |
|---------|-----------------|-------|
| Lambda | $50-200 | Depends on query volume |
| S3 | $20-100 | Depends on log volume |
| Athena | $100-500 | $5/TB scanned |
| DynamoDB | $25-100 | State and alert storage |
| **Total** | **$200-900/month** | |

### Adding Observability (+APM)

| Additional Service | Monthly Estimate | Notes |
|-------------------|-----------------|-------|
| Lambda (OTLP) | $20-100 | Additional ingestion |
| S3 (traces/metrics) | $50-200 | Additional storage |
| Athena (APM queries) | $50-200 | More tables to query |
| **Additional Total** | **$120-500/month** | |

### Adding SOAR (+Response)

| Additional Service | Monthly Estimate | Notes |
|-------------------|-----------------|-------|
| Lambda (executor) | $10-50 | Playbook executions |
| DynamoDB (playbooks) | $10-25 | Playbook/execution storage |
| Step Functions | $0-25 | If using for orchestration |
| **Additional Total** | **$20-100/month** | |

### Full Platform Total

| Mode | Monthly Estimate |
|------|-----------------|
| SIEM Only | $200-900 |
| SIEM + Observability | $320-1,400 |
| Full Platform | $340-1,500 |

**Note**: Actual costs depend heavily on data volume, query patterns, and playbook execution frequency. Monitor AWS Cost Explorer for accurate billing.

---

## Troubleshooting

### Common Issues

**Lambda Cold Starts**
- Symptom: First request takes 3-10 seconds
- Solution: Enable provisioned concurrency for critical functions

**Athena Query Timeout**
- Symptom: Queries fail after 120 seconds
- Solution: Add time range filters, optimize partitioning

**OTLP Data Not Appearing**
- Check OTLP endpoint URL is correct
- Verify API Gateway authorizer allows requests
- Check CloudWatch Logs for ingestion Lambda

**Playbook Execution Stuck**
- Check approval status in DynamoDB
- Verify provider credentials are valid
- Check executor Lambda CloudWatch Logs

### Getting Help

- [GitHub Issues](https://github.com/your-org/mantissa-log/issues)
- [Documentation](docs/)
- [Operations Runbook](docs/operations/runbook.md)
