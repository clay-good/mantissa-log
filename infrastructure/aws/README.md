# AWS Infrastructure

Infrastructure as Code for deploying Mantissa Log on Amazon Web Services.

## Deployment Methods

Two deployment methods are supported:

1. **Terraform** (recommended) - Modular, reusable, infrastructure as code
2. **CloudFormation** - Native AWS IaC for those who prefer it

## Directory Structure

```
aws/
├── terraform/           # Terraform modules and configuration
│   ├── main.tf
│   ├── variables.tf
│   ├── outputs.tf
│   ├── modules/        # Reusable modules
│   └── environments/   # Environment-specific configs
└── cloudformation/     # CloudFormation templates
    └── mantissa-stack.yaml
```

## Terraform Deployment

### Prerequisites

- AWS account with appropriate permissions
- AWS CLI v2 configured
- Terraform 1.5+

### Quick Start

```bash
cd terraform

# Initialize Terraform
terraform init

# Review planned changes
terraform plan -var-file=environments/dev.tfvars

# Apply configuration
terraform apply -var-file=environments/dev.tfvars
```

### Modules

Infrastructure is organized into focused modules:

- **storage** - S3 buckets and lifecycle policies
- **ingestion** - Log routing and Kinesis configuration
- **catalog** - Glue databases, tables, and crawlers
- **compute** - Lambda functions for detection, queries, routing
- **scheduling** - EventBridge rules for periodic execution
- **api** - API Gateway configuration
- **auth** - Cognito user pools and app clients
- **secrets** - Secrets Manager setup
- **monitoring** - CloudWatch dashboards and alarms

### Environments

Environment-specific variable files:

- `environments/dev.tfvars` - Development environment
- `environments/staging.tfvars.example` - Staging template
- `environments/prod.tfvars.example` - Production template

Copy example files and customize for your needs.

### Outputs

After deployment, Terraform outputs:

- S3 bucket names
- API Gateway endpoint URL
- Cognito user pool ID
- Lambda function ARNs
- Athena workgroup name

### State Management

Configure remote state backend in `backend.tf`:

```hcl
terraform {
  backend "s3" {
    bucket         = "mantissa-log-terraform-state"
    key            = "prod/terraform.tfstate"
    region         = "us-east-1"
    encrypt        = true
    dynamodb_table = "mantissa-log-terraform-locks"
  }
}
```

## CloudFormation Deployment

Alternative deployment using CloudFormation:

```bash
cd cloudformation

# Validate template
aws cloudformation validate-template \
  --template-body file://mantissa-stack.yaml

# Deploy stack
aws cloudformation create-stack \
  --stack-name mantissa-log-dev \
  --template-body file://mantissa-stack.yaml \
  --parameters file://parameters-dev.json \
  --capabilities CAPABILITY_IAM

# Check status
aws cloudformation describe-stacks \
  --stack-name mantissa-log-dev
```

## Architecture Components

### Storage Layer

S3 buckets for log storage:

- Main logs bucket with date partitioning
- Athena query results bucket
- Configuration bucket
- Lifecycle policies for cost optimization

### Compute Layer

Lambda functions:

- `detection-engine` - Executes detection rules on schedule
- `llm-query` - Processes natural language queries
- `alert-router` - Routes alerts to destinations
- `api-*` - API Gateway handlers

### Catalog Layer

Glue resources:

- Database for log tables
- Table definitions for each log type
- Views for normalized schemas
- Optional crawlers for partition discovery

### API Layer

API Gateway configuration:

- REST API for web interface
- Lambda integrations
- Cognito authorizer
- CORS configuration
- Rate limiting

### Monitoring

CloudWatch resources:

- Log groups for Lambda functions
- Metrics and dashboards
- Alarms for errors and performance
- SNS topics for alerting

## Configuration

### Required Variables

See `terraform/variables.tf` for all options. Key variables:

```hcl
# Region
aws_region = "us-east-1"

# Environment name
environment = "dev"

# Project prefix for resource naming
project_prefix = "mantissa-log"

# Log retention
log_retention_days = 365

# Alert destinations
slack_webhook_url = "https://hooks.slack.com/services/..."
pagerduty_api_key = "secret"

# LLM provider
llm_provider = "bedrock"  # or "anthropic" or "openai"
```

### Secrets Management

Store sensitive values in AWS Secrets Manager:

```bash
# Create secret for Slack webhook
aws secretsmanager create-secret \
  --name mantissa-log/slack-webhook \
  --secret-string "https://hooks.slack.com/services/..."

# Create secret for PagerDuty API key
aws secretsmanager create-secret \
  --name mantissa-log/pagerduty-api-key \
  --secret-string "your-api-key"
```

Reference in Terraform:

```hcl
data "aws_secretsmanager_secret_version" "slack_webhook" {
  secret_id = "mantissa-log/slack-webhook"
}
```

## Security Considerations

### IAM Roles

Each component has least-privilege IAM role:

- Detection engine: Read S3, query Athena, write DynamoDB
- LLM query: Query Athena, read Glue catalog
- Alert router: Read Secrets Manager, invoke external APIs

### Encryption

All data encrypted:

- S3: SSE-S3 or SSE-KMS
- DynamoDB: Encryption at rest
- Lambda: Encrypted environment variables
- Secrets Manager: KMS encryption

### Network Security

- Lambda functions in VPC (optional but recommended)
- Security groups for network isolation
- PrivateLink for AWS service access

## Cost Optimization

### Storage

- Lifecycle policies transition to IA after 30 days
- Delete old logs after retention period
- Use compression for log files

### Compute

- Right-size Lambda memory allocation
- Use provisioned concurrency only where needed
- Optimize cold start performance

### Query

- Partition data by date
- Use columnar formats (Parquet)
- Limit query result sizes

## Monitoring

### Dashboards

CloudWatch dashboards show:

- Lambda invocation metrics
- Athena query performance
- S3 storage usage
- API Gateway request counts

### Alarms

Configured alarms for:

- Lambda error rates
- Athena query failures
- Unusual S3 access patterns
- API Gateway 5xx errors

## Scaling

Infrastructure scales automatically:

- S3: Unlimited storage
- Lambda: Auto-scales to demand
- Athena: Serverless, no provisioning
- DynamoDB: On-demand or provisioned capacity

## Disaster Recovery

### Backups

- S3 versioning enabled
- Cross-region replication (optional)
- Terraform state in S3 with versioning
- Detection rules in version control

### Recovery

```bash
# Restore from Terraform state
terraform apply -var-file=environments/prod.tfvars

# Restore S3 data from version
aws s3api restore-object \
  --bucket mantissa-log-logs \
  --key path/to/object \
  --version-id version-id
```

## Troubleshooting

### Terraform Issues

```bash
# Refresh state
terraform refresh

# Reimport resource
terraform import aws_s3_bucket.logs mantissa-log-logs

# Destroy and recreate specific resource
terraform destroy -target=aws_lambda_function.detection_engine
terraform apply -target=aws_lambda_function.detection_engine
```

### Lambda Issues

```bash
# View logs
aws logs tail /aws/lambda/mantissa-log-detection-engine --follow

# Invoke manually
aws lambda invoke \
  --function-name mantissa-log-detection-engine \
  --payload '{}' \
  response.json
```

### Athena Issues

```bash
# Check query status
aws athena get-query-execution \
  --query-execution-id xxx

# View query results
aws athena get-query-results \
  --query-execution-id xxx
```

## Updating Infrastructure

```bash
# Pull latest code
git pull

# Review changes
terraform plan -var-file=environments/prod.tfvars

# Apply updates
terraform apply -var-file=environments/prod.tfvars

# Update Lambda code
cd ../../src/aws/lambdas/detection_engine
zip -r function.zip .
aws lambda update-function-code \
  --function-name mantissa-log-detection-engine \
  --zip-file fileb://function.zip
```

## Cleanup

To destroy all resources:

```bash
# WARNING: This will delete all data
terraform destroy -var-file=environments/dev.tfvars
```

## Additional Resources

- [AWS Deployment Guide](../../docs/deployment/aws-deployment.md)
- [Cost Optimization Guide](../../docs/operations/scaling.md)
- [Troubleshooting Guide](../../docs/deployment/troubleshooting.md)
