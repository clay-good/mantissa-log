# Log Sources Configuration Guide

This guide covers configuring all supported log sources for Mantissa Log.

## Overview

Mantissa Log supports multiple log sources:

- **AWS Native**: CloudTrail, VPC Flow Logs, GuardDuty
- **SaaS Identity & Access**: Okta, Duo Security, Microsoft 365, Google Workspace
- **SaaS Collaboration**: Slack, GitHub
- **SaaS Security**: CrowdStrike Falcon
- **SaaS Data & Business**: Salesforce, Snowflake
- **Infrastructure**: Kubernetes, Docker, Jamf Pro
- **Secrets Management**: 1Password
- **Multi-Cloud**: Azure Monitor, GCP Cloud Logging
- **Custom Applications**: JSON-formatted application logs

All logs are:
1. Collected via scheduled Lambda functions (SaaS/multi-cloud) or native AWS integrations
2. Written to S3 buckets (organized by source and date)
3. Cataloged in AWS Glue (schema discovery)
4. Queried via Amazon Athena (SQL engine)
5. Analyzed by Sigma detection rules

## Collector Architecture

SaaS and multi-cloud log sources use scheduled Lambda collectors:

- **Collection Schedule**: Hourly by default (configurable)
- **State Management**: DynamoDB checkpoints track last collection time
- **Credentials**: Stored securely in AWS Secrets Manager
- **Output**: Raw logs and ECS-normalized logs in S3
- **Glue Tables**: Automatically created for each source

## AWS CloudTrail

CloudTrail records AWS API activity and account events.

### Automatic Setup

The deployment script automatically creates and configures CloudTrail:

```bash
# CloudTrail is set up during deployment
bash scripts/deploy.sh
```

### Manual Setup

If you need to configure CloudTrail manually:

```bash
# Get logs bucket
LOGS_BUCKET=$(cat terraform-outputs.json | jq -r '.logs_bucket.value')
REGION="us-east-1"
TRAIL_NAME="mantissa-log-trail"

# Create trail
aws cloudtrail create-trail \
  --name $TRAIL_NAME \
  --s3-bucket-name $LOGS_BUCKET \
  --s3-key-prefix cloudtrail/ \
  --is-multi-region-trail \
  --enable-log-file-validation \
  --region $REGION

# Start logging
aws cloudtrail start-logging \
  --name $TRAIL_NAME \
  --region $REGION
```

### Verify CloudTrail

```bash
# Check trail status
aws cloudtrail get-trail-status --name $TRAIL_NAME

# Should show: "IsLogging": true

# Check for log files
aws s3 ls s3://$LOGS_BUCKET/cloudtrail/ --recursive | head -10
```

### Example Queries

```sql
-- Failed login attempts
SELECT
    useridentity.principalid,
    sourceipaddress,
    eventtime,
    errorcode,
    errormessage
FROM cloudtrail
WHERE eventname = 'ConsoleLogin'
  AND errorcode IS NOT NULL
  AND year = '2024'
  AND month = '01'
ORDER BY eventtime DESC
LIMIT 100;

-- Root account activity
SELECT
    eventtime,
    eventname,
    sourceipaddress,
    requestparameters
FROM cloudtrail
WHERE useridentity.type = 'Root'
  AND year = '2024'
  AND month = '01'
ORDER BY eventtime DESC;
```

## VPC Flow Logs

VPC Flow Logs capture network traffic metadata for your VPCs.

### Enable VPC Flow Logs

```bash
# Get logs bucket
LOGS_BUCKET=$(cat terraform-outputs.json | jq -r '.logs_bucket.value')

# Enable flow logs for a VPC
VPC_ID="vpc-12345678"

aws ec2 create-flow-logs \
  --resource-type VPC \
  --resource-ids $VPC_ID \
  --traffic-type ALL \
  --log-destination-type s3 \
  --log-destination "arn:aws:s3:::$LOGS_BUCKET/vpc-flow-logs/"
```

## AWS GuardDuty

GuardDuty provides intelligent threat detection findings.

### Enable GuardDuty

```bash
# Enable GuardDuty detector
aws guardduty create-detector \
  --enable \
  --finding-publishing-frequency FIFTEEN_MINUTES

# Get detector ID
DETECTOR_ID=$(aws guardduty list-detectors --query 'DetectorIds[0]' --output text)
```

## Custom Application Logs

Add your own application logs to Mantissa Log.

### Requirements

Logs must be:
- JSON format (one object per line)
- Written to the Mantissa Log S3 bucket
- Organized by date for partitioning

### Example Log Format

```json
{
  "timestamp": "2024-01-15T10:30:45.123Z",
  "level": "ERROR",
  "service": "api-gateway",
  "user_id": "user123",
  "request_id": "req-456",
  "method": "POST",
  "path": "/api/orders",
  "status_code": 500,
  "error_message": "Database connection failed",
  "duration_ms": 1234,
  "source_ip": "192.168.1.100"
}
```

## SaaS and Multi-Cloud Collectors

All SaaS and multi-cloud collectors follow the same configuration pattern:

1. Enable the collector in Terraform variables
2. Store API credentials in AWS Secrets Manager
3. Deploy infrastructure with `terraform apply`
4. Verify collection in S3 and Athena

### Okta

Okta System Log API provides authentication and user management events.

**Enable in Terraform:**

```hcl
# infrastructure/aws/terraform/environments/prod.tfvars
enable_collectors = {
  okta = true
  # ... other collectors
}
```

**Store API Credentials:**

```bash
# Create API token in Okta Admin Console:
# Security > API > Tokens > Create Token

aws secretsmanager create-secret \
  --name mantissa/okta/domain \
  --secret-string "your-org.okta.com"

aws secretsmanager create-secret \
  --name mantissa/okta/api_token \
  --secret-string "your-okta-api-token"
```

**Verify Collection:**

```bash
# Check S3 for logs
aws s3 ls s3://mantissa-log-prod-logs/okta/raw/ --recursive

# Query via Athena
SELECT * FROM okta_logs LIMIT 10;
```

### Google Workspace

Google Workspace Reports API provides admin, drive, and login activity.

**Prerequisites:**
- Google Workspace admin account
- Service account with domain-wide delegation
- Admin SDK API enabled

**Enable in Terraform:**

```hcl
enable_collectors = {
  google_workspace = true
}
```

**Store API Credentials:**

```bash
# Download service account JSON from Google Cloud Console
# Store the entire JSON as secret

aws secretsmanager create-secret \
  --name mantissa/google_workspace/service_account \
  --secret-string file://service-account-key.json

aws secretsmanager create-secret \
  --name mantissa/google_workspace/customer_id \
  --secret-string "C0xxxxxxx"

aws secretsmanager create-secret \
  --name mantissa/google_workspace/admin_email \
  --secret-string "admin@yourdomain.com"
```

### Microsoft 365

Microsoft Graph API and Office 365 Management API for audit logs.

**Prerequisites:**
- Azure AD app registration
- API permissions: AuditLog.Read.All, Directory.Read.All

**Enable in Terraform:**

```hcl
enable_collectors = {
  microsoft365 = true
}
```

**Store API Credentials:**

```bash
aws secretsmanager create-secret \
  --name mantissa/microsoft365/tenant_id \
  --secret-string "your-tenant-id"

aws secretsmanager create-secret \
  --name mantissa/microsoft365/client_id \
  --secret-string "your-app-client-id"

aws secretsmanager create-secret \
  --name mantissa/microsoft365/client_secret \
  --secret-string "your-app-client-secret"
```

### GitHub

GitHub Audit Log API for enterprise and organization activity.

**Prerequisites:**
- GitHub Enterprise Cloud or GitHub Enterprise Server
- Personal access token with `admin:org` scope

**Enable in Terraform:**

```hcl
enable_collectors = {
  github = true
}
```

**Store API Credentials:**

```bash
aws secretsmanager create-secret \
  --name mantissa/github/token \
  --secret-string "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxx"

aws secretsmanager create-secret \
  --name mantissa/github/org \
  --secret-string "your-org-name"
```

### Slack

Slack Audit Logs API (Enterprise Grid only).

**Prerequisites:**
- Slack Enterprise Grid plan
- Workspace admin access

**Enable in Terraform:**

```hcl
enable_collectors = {
  slack = true
}
```

**Store API Credentials:**

```bash
# Create app in api.slack.com with auditlogs:read scope

aws secretsmanager create-secret \
  --name mantissa/slack/token \
  --secret-string "xoxp-your-slack-token"
```

### Duo Security

Duo Admin API for MFA authentication logs.

**Enable in Terraform:**

```hcl
enable_collectors = {
  duo = true
}
```

**Store API Credentials:**

```bash
# Generate in Duo Admin Panel > Applications > Protect an Application > Admin API

aws secretsmanager create-secret \
  --name mantissa/duo/integration_key \
  --secret-string "DI..."

aws secretsmanager create-secret \
  --name mantissa/duo/secret_key \
  --secret-string "your-duo-secret"

aws secretsmanager create-secret \
  --name mantissa/duo/api_hostname \
  --secret-string "api-xxxxxxxx.duosecurity.com"
```

### CrowdStrike Falcon

CrowdStrike Falcon Event Streams API for EDR telemetry.

**Prerequisites:**
- Falcon Enterprise or Elite subscription
- API client with Event Streams permissions

**Enable in Terraform:**

```hcl
enable_collectors = {
  crowdstrike = true
}
```

**Store API Credentials:**

```bash
# Create API client in Falcon console

aws secretsmanager create-secret \
  --name mantissa/crowdstrike/client_id \
  --secret-string "your-client-id"

aws secretsmanager create-secret \
  --name mantissa/crowdstrike/client_secret \
  --secret-string "your-client-secret"

aws secretsmanager create-secret \
  --name mantissa/crowdstrike/cloud \
  --secret-string "us-1"
```

### Salesforce

Salesforce EventLogFile API for login and setup audit trail.

**Enable in Terraform:**

```hcl
enable_collectors = {
  salesforce = true
}
```

**Store API Credentials:**

```bash
# Create Connected App in Salesforce Setup

aws secretsmanager create-secret \
  --name mantissa/salesforce/instance_url \
  --secret-string "https://yourorg.my.salesforce.com"

aws secretsmanager create-secret \
  --name mantissa/salesforce/client_id \
  --secret-string "your-consumer-key"

aws secretsmanager create-secret \
  --name mantissa/salesforce/client_secret \
  --secret-string "your-consumer-secret"

aws secretsmanager create-secret \
  --name mantissa/salesforce/username \
  --secret-string "api-user@yourorg.com"

aws secretsmanager create-secret \
  --name mantissa/salesforce/password \
  --secret-string "your-password-with-security-token"
```

### Snowflake

Snowflake ACCOUNT_USAGE schema for query and access history.

**Enable in Terraform:**

```hcl
enable_collectors = {
  snowflake = true
}
```

**Store API Credentials:**

```bash
aws secretsmanager create-secret \
  --name mantissa/snowflake/account \
  --secret-string "your-account.snowflakecomputing.com"

aws secretsmanager create-secret \
  --name mantissa/snowflake/username \
  --secret-string "mantissa_log_reader"

aws secretsmanager create-secret \
  --name mantissa/snowflake/password \
  --secret-string "your-password"

aws secretsmanager create-secret \
  --name mantissa/snowflake/warehouse \
  --secret-string "COMPUTE_WH"
```

### Docker

Docker API for container lifecycle events.

**Enable in Terraform:**

```hcl
enable_collectors = {
  docker = true
}
```

**Store API Credentials:**

```bash
# For Docker API over TLS
aws secretsmanager create-secret \
  --name mantissa/docker/host \
  --secret-string "tcp://docker-host:2376"

aws secretsmanager create-secret \
  --name mantissa/docker/tls_cert \
  --secret-string file://client-cert.pem

aws secretsmanager create-secret \
  --name mantissa/docker/tls_key \
  --secret-string file://client-key.pem
```

### Kubernetes

Kubernetes Audit Logs via API server.

**Enable in Terraform:**

```hcl
enable_collectors = {
  kubernetes = true
}
```

**Store API Credentials:**

```bash
aws secretsmanager create-secret \
  --name mantissa/kubernetes/api_server \
  --secret-string "https://k8s-api.example.com"

aws secretsmanager create-secret \
  --name mantissa/kubernetes/token \
  --secret-string "your-service-account-token"

# Or use kubeconfig
aws secretsmanager create-secret \
  --name mantissa/kubernetes/kubeconfig \
  --secret-string file://~/.kube/config
```

### Jamf Pro

Jamf Pro API for macOS/iOS device management logs.

**Enable in Terraform:**

```hcl
enable_collectors = {
  jamf = true
}
```

**Store API Credentials:**

```bash
aws secretsmanager create-secret \
  --name mantissa/jamf/url \
  --secret-string "https://your-org.jamfcloud.com"

aws secretsmanager create-secret \
  --name mantissa/jamf/username \
  --secret-string "api-user"

aws secretsmanager create-secret \
  --name mantissa/jamf/password \
  --secret-string "your-password"
```

### 1Password

1Password Events API for vault access logs.

**Enable in Terraform:**

```hcl
enable_collectors = {
  onepassword = true
}
```

**Store API Credentials:**

```bash
# Generate bearer token in 1Password Business account

aws secretsmanager create-secret \
  --name mantissa/onepassword/token \
  --secret-string "your-1password-token"
```

### Azure Monitor

Azure Monitor Logs for Azure Activity and Sign-in logs.

**Prerequisites:**
- Azure subscription
- App registration with Log Analytics Reader role

**Enable in Terraform:**

```hcl
enable_collectors = {
  azure_monitor = true
}
```

**Store API Credentials:**

```bash
aws secretsmanager create-secret \
  --name mantissa/azure_monitor/tenant_id \
  --secret-string "your-azure-tenant-id"

aws secretsmanager create-secret \
  --name mantissa/azure_monitor/client_id \
  --secret-string "your-app-client-id"

aws secretsmanager create-secret \
  --name mantissa/azure_monitor/client_secret \
  --secret-string "your-app-secret"

aws secretsmanager create-secret \
  --name mantissa/azure_monitor/subscription_id \
  --secret-string "your-subscription-id"

aws secretsmanager create-secret \
  --name mantissa/azure_monitor/workspace_id \
  --secret-string "your-log-analytics-workspace-id"
```

### GCP Cloud Logging

GCP Cloud Logging API for cloud audit and VPC flow logs.

**Prerequisites:**
- GCP project
- Service account with Logging Viewer role

**Enable in Terraform:**

```hcl
enable_collectors = {
  gcp_logging = true
}
```

**Store API Credentials:**

```bash
# Download service account key from GCP Console

aws secretsmanager create-secret \
  --name mantissa/gcp_logging/service_account \
  --secret-string file://gcp-service-account-key.json

aws secretsmanager create-secret \
  --name mantissa/gcp_logging/project_id \
  --secret-string "your-gcp-project-id"
```

## Collector Management

### List Active Collectors

```bash
# From Terraform outputs
terraform output collector_function_names

# Check Lambda functions
aws lambda list-functions \
  --query 'Functions[?contains(FunctionName, `collector`)].[FunctionName, LastModified]' \
  --output table
```

### Monitor Collection Status

```bash
# Check S3 for recent logs (last hour)
for source in okta google_workspace microsoft365 github; do
  echo "=== $source ==="
  aws s3 ls s3://mantissa-log-prod-logs/$source/raw/ \
    --recursive --human-readable \
    | tail -5
done

# Check DynamoDB checkpoints
aws dynamodb scan \
  --table-name mantissa-log-prod-checkpoints \
  --query 'Items[*].[collector_id.S, last_fetch_time.S]' \
  --output table
```

### Troubleshooting Collectors

```bash
# View Lambda logs for specific collector
aws logs tail /aws/lambda/mantissa-log-prod-collector-okta \
  --follow \
  --format short

# Check for errors
aws logs filter-log-events \
  --log-group-name /aws/lambda/mantissa-log-prod-collector-okta \
  --filter-pattern "ERROR" \
  --max-items 20

# Manual invocation for testing
aws lambda invoke \
  --function-name mantissa-log-prod-collector-okta \
  --log-type Tail \
  /dev/stdout
```

### Adjust Collection Schedule

Edit environment tfvars file:

```hcl
# infrastructure/aws/terraform/environments/prod.tfvars
collection_schedule = "rate(30 minutes)"  # More frequent
# or
collection_schedule = "rate(2 hours)"     # Less frequent
```

Apply changes:

```bash
cd infrastructure/aws/terraform
terraform apply -var-file="environments/prod.tfvars"
```
