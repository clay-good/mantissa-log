# Mantissa Log - Collector Lambda Functions Module

This Terraform module deploys all SaaS and multi-cloud log collector Lambda functions for Mantissa Log.

## Overview

The collectors module provisions:

- **15 Lambda functions** for log collection from various sources
- **EventBridge schedules** for automated hourly collection
- **IAM roles and policies** with least-privilege access
- **CloudWatch log groups** for collector monitoring
- **Encrypted secrets** integration via AWS Secrets Manager

## Supported Collectors

### SaaS Platforms
- **Okta**: Authentication and user management logs
- **Google Workspace**: Admin and drive activity logs
- **Microsoft 365**: Audit logs and sign-in events
- **GitHub**: Repository audit logs
- **Slack**: Workspace audit logs
- **Salesforce**: Event log files
- **Snowflake**: Account usage and query history
- **1Password**: Events API logs
- **Jamf Pro**: Device management logs

### Security & Infrastructure
- **Duo Security**: MFA authentication logs
- **CrowdStrike**: Falcon endpoint detection logs
- **Docker**: Container runtime events
- **Kubernetes**: Audit logs

### Multi-Cloud
- **Azure Monitor**: Activity, sign-in, and audit logs
- **GCP Cloud Logging**: Audit, VPC flow, firewall, and GKE logs

## Usage

```hcl
module "collectors" {
  source = "./modules/collectors"

  name_prefix             = "mantissa-prod"
  aws_region              = "us-east-1"
  aws_account_id          = data.aws_caller_identity.current.account_id
  s3_bucket               = module.storage.logs_bucket_name
  s3_bucket_arn           = module.storage.logs_bucket_arn
  checkpoint_table        = module.state.checkpoint_table_name
  checkpoint_table_arn    = module.state.checkpoint_table_arn
  kms_key_arn             = module.secrets.kms_key_arn
  cloudwatch_log_retention = 30
  collection_schedule     = "rate(1 hour)"
  log_level               = "INFO"
  environment             = "production"

  enable_collectors = {
    okta             = true
    google_workspace = true
    microsoft365     = false  # Disable specific collectors as needed
    github           = true
    slack            = true
    duo              = true
    crowdstrike      = true
    salesforce       = true
    snowflake        = true
    docker           = true
    kubernetes       = true
    jamf             = true
    onepassword      = true
    azure_monitor    = true
    gcp_logging      = true
  }
}
```

## Prerequisites

### 1. Secrets Manager Setup

Each collector requires API credentials stored in AWS Secrets Manager:

```bash
# Okta
aws secretsmanager create-secret \
  --name mantissa/okta/domain \
  --secret-string "your-domain.okta.com"

aws secretsmanager create-secret \
  --name mantissa/okta/api_token \
  --secret-string "your-api-token"

# Google Workspace
aws secretsmanager create-secret \
  --name mantissa/google-workspace/customer_id \
  --secret-string "C01234567"

aws secretsmanager create-secret \
  --name mantissa/google-workspace/credentials \
  --secret-string '{"type":"service_account","project_id":"..."}'

# Continue for other collectors...
```

### 2. S3 Bucket

Logs are stored in partitioned S3 structure:

```
s3://your-bucket/
├── okta/
│   ├── raw/
│   │   └── year=2025/month=01/day=28/
│   └── normalized/
│       └── year=2025/month=01/day=28/
├── google-workspace/
├── microsoft365/
└── ...
```

### 3. DynamoDB Checkpoint Table

Collection state is tracked in DynamoDB:

```hcl
resource "aws_dynamodb_table" "checkpoints" {
  name         = "mantissa-checkpoints"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "collector_id"

  attribute {
    name = "collector_id"
    type = "S"
  }
}
```

## Collector Configuration

### Schedule Customization

Change collection frequency:

```hcl
# Every 30 minutes
collection_schedule = "rate(30 minutes)"

# Every 6 hours
collection_schedule = "rate(6 hours)"

# Daily at midnight UTC
collection_schedule = "cron(0 0 * * ? *)"

# Hourly (default)
collection_schedule = "rate(1 hour)"
```

### Memory and Timeout

Adjust Lambda resources:

```hcl
# In main.tf locals
lambda_timeout = 900  # 15 minutes (default)
lambda_memory  = 512  # MB (default)

# For high-volume collectors, increase:
lambda_timeout = 1800  # 30 minutes (max for EventBridge)
lambda_memory  = 1024  # 1 GB
```

### Enable/Disable Collectors

Control which collectors are deployed:

```hcl
enable_collectors = {
  okta             = true
  google_workspace = false  # Skip if not using
  microsoft365     = true
  github           = true
  slack            = false  # Skip if not using
  # ...
}
```

## Monitoring

### CloudWatch Metrics

Each collector publishes metrics:

- **Invocations**: Number of executions
- **Duration**: Execution time in milliseconds
- **Errors**: Failed invocations
- **Throttles**: Rate-limited executions

View metrics:

```bash
aws cloudwatch get-metric-statistics \
  --namespace AWS/Lambda \
  --metric-name Invocations \
  --dimensions Name=FunctionName,Value=mantissa-prod-collector-okta \
  --start-time 2025-01-28T00:00:00Z \
  --end-time 2025-01-28T23:59:59Z \
  --period 3600 \
  --statistics Sum
```

### CloudWatch Logs

View collector logs:

```bash
aws logs tail /aws/lambda/mantissa-prod-collector-okta --follow
```

Filter for errors:

```bash
aws logs filter-log-events \
  --log-group-name /aws/lambda/mantissa-prod-collector-okta \
  --filter-pattern "ERROR"
```

### Checkpoints

Query collection state:

```bash
aws dynamodb get-item \
  --table-name mantissa-checkpoints \
  --key '{"collector_id": {"S": "okta"}}'
```

## Troubleshooting

### Collector Not Running

Check EventBridge rule:

```bash
aws events describe-rule --name mantissa-prod-okta-collector-schedule
aws events list-targets-by-rule --rule mantissa-prod-okta-collector-schedule
```

### Permission Errors

Verify IAM role has required permissions:

```bash
aws iam get-role-policy \
  --role-name mantissa-prod-collectors-role \
  --policy-name mantissa-prod-collectors-policy
```

### Secrets Access Denied

Ensure secrets exist and have correct KMS permissions:

```bash
aws secretsmanager describe-secret --secret-id mantissa/okta/api_token
```

### No Logs Collected

1. Check collector logs for API errors
2. Verify API credentials are valid
3. Ensure checkpoint table is accessible
4. Confirm S3 bucket write permissions

## Cost Optimization

### Lambda Pricing

Estimated monthly costs (per collector):

- **Invocations**: 720/month (hourly) = $0.00014
- **Duration**: 2 min avg @ 512 MB = $0.50
- **Total per collector**: ~$0.50/month

**15 collectors**: ~$7.50/month

### Reduce Costs

1. **Increase collection interval**:
   ```hcl
   collection_schedule = "rate(6 hours)"  # Reduce to 120 invocations/month
   ```

2. **Right-size memory**:
   - Start with 256 MB
   - Monitor actual usage
   - Increase only if needed

3. **Selective enablement**:
   - Only enable collectors for sources you use
   - Disable unused collectors

## Security Considerations

1. **Secrets Rotation**: Rotate API credentials regularly
2. **Least Privilege**: Collectors can only write to S3, read secrets, update checkpoints
3. **Encryption**: All secrets encrypted with KMS
4. **VPC**: Optionally deploy in VPC for network isolation
5. **CloudTrail**: All API calls logged for audit

## Outputs

The module outputs:

- `collector_function_arns`: Map of collector Lambda ARNs
- `collector_function_names`: Map of collector function names
- `collector_schedules`: Map of EventBridge rule ARNs
- `collector_role_arn`: IAM role ARN
- `collector_log_groups`: Map of CloudWatch log group names

## Examples

### Invoke Collector Manually

```bash
aws lambda invoke \
  --function-name mantissa-prod-collector-okta \
  --payload '{}' \
  response.json
```

### View Collection Stats

```bash
# Check S3 objects collected
aws s3 ls s3://mantissa-logs/okta/normalized/year=2025/month=01/day=28/ --recursive

# Check last collection time
aws dynamodb get-item \
  --table-name mantissa-checkpoints \
  --key '{"collector_id": {"S": "okta"}}' \
  --query 'Item.last_collection_time.S'
```

### Update Collector Code

```bash
# Repackage and deploy
cd infrastructure/aws/terraform/modules/collectors
terraform apply -target=module.collectors
```

## References

- [AWS Lambda](https://docs.aws.amazon.com/lambda/)
- [EventBridge Schedules](https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-create-rule-schedule.html)
- [Secrets Manager](https://docs.aws.amazon.com/secretsmanager/)
- [DynamoDB](https://docs.aws.amazon.com/dynamodb/)
