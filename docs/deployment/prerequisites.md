# Deployment Prerequisites

This document outlines the requirements for deploying Mantissa Log to AWS.

## AWS Requirements

### AWS Account
- Active AWS account with administrative access
- Root user access or IAM user with sufficient permissions
- MFA enabled (recommended)

### Required AWS Permissions

The deploying user or role needs the following permissions:

**Core Services:**
- IAM: Create/manage roles, policies
- S3: Create/manage buckets, objects
- Lambda: Create/manage functions, layers
- DynamoDB: Create/manage tables
- CloudWatch: Create/manage log groups, alarms
- EventBridge: Create/manage rules, targets
- Secrets Manager: Create/manage secrets

**Data Services:**
- Athena: Create/manage workgroups, run queries
- Glue: Create/manage databases, tables, crawlers

**Networking & Security:**
- VPC: Read VPC/subnet information (if using VPC)
- Cognito: Create/manage user pools, clients
- API Gateway: Create/manage REST APIs

**Infrastructure:**
- CloudTrail: Create/manage trails (optional)
- GuardDuty: Enable/manage detector (optional)

### AWS Service Quotas

Verify these quotas in your AWS account:

| Service | Quota | Required | Notes |
|---------|-------|----------|-------|
| Lambda | Concurrent executions | 100 | Can increase if needed |
| Lambda | Function storage | 75 GB | For all deployment packages |
| DynamoDB | Tables per region | 256 | Need ~3-5 tables |
| S3 | Buckets | 100 | Need ~3-4 buckets |
| Athena | Active queries | 25 | Default is sufficient |
| CloudWatch | Log groups | 1,000,000 | Default is sufficient |

### AWS Region Selection

Choose a region based on:
- Data residency requirements
- Service availability (verify all services are available)
- Bedrock availability (if using AWS Bedrock for LLM)
- Latency to log sources
- Cost considerations

**Recommended regions:**
- us-east-1 (Virginia) - Most services, lowest cost
- us-west-2 (Oregon) - Good service availability
- eu-west-1 (Ireland) - EU data residency
- ap-southeast-1 (Singapore) - Asia Pacific

### Cost Estimates

Monthly cost estimates for different deployment sizes:

**Small Deployment (< 1M events/month):**
- S3 storage: $5-15
- Lambda executions: $10-30
- DynamoDB: $5-10
- Athena queries: $5-20
- Glue: $5-10
- Other services: $10-20
- **Total: ~$40-105/month**

**Medium Deployment (1M-10M events/month):**
- S3 storage: $15-50
- Lambda executions: $30-100
- DynamoDB: $10-30
- Athena queries: $20-100
- Glue: $10-30
- Other services: $20-50
- **Total: ~$105-360/month**

**Large Deployment (10M+ events/month):**
- S3 storage: $50-200
- Lambda executions: $100-500
- DynamoDB: $30-200
- Athena queries: $100-500
- Glue: $30-100
- Other services: $50-100
- **Total: ~$360-1,600/month**

**Additional costs:**
- CloudTrail: $2 per 100,000 events
- GuardDuty: $4.50 per million events
- VPC Flow Logs: $0.50 per GB ingested
- Data transfer: Variable based on region
- LLM API costs (if using external providers)

**Cost optimization tips:**
- Use S3 Intelligent-Tiering for log storage
- Enable DynamoDB on-demand billing for variable workloads
- Set CloudWatch log retention to 30-90 days
- Use Athena workgroup query limits
- Configure S3 lifecycle policies to archive old logs

## Local Development Tools

### Required Tools

**Terraform:**
- Version: >= 1.5.0
- Installation: https://www.terraform.io/downloads
- Verify: `terraform --version`

**AWS CLI:**
- Version: >= 2.0
- Installation: https://aws.amazon.com/cli/
- Verify: `aws --version`

**Python:**
- Version: >= 3.11
- Installation: https://www.python.org/downloads/
- Verify: `python3 --version`

**Git:**
- Version: >= 2.0
- Installation: https://git-scm.com/downloads
- Verify: `git --version`

**Bash:**
- Version: >= 4.0
- Required for deployment scripts
- Default on macOS/Linux

**Zip:**
- Required for Lambda packaging
- Default on most systems
- Verify: `zip --version`

### Optional Tools

**jq:**
- For JSON parsing in scripts
- Installation: `brew install jq` (macOS) or `apt-get install jq` (Linux)

**AWS Vault:**
- For credential management
- Installation: https://github.com/99designs/aws-vault

**Terraform Docs:**
- For generating Terraform documentation
- Installation: https://terraform-docs.io/

### Python Dependencies

Install required Python packages:

```bash
pip install -r requirements.txt
```

Key dependencies:
- boto3 >= 1.28.0 (AWS SDK)
- anthropic >= 0.18.0 (Anthropic API)
- openai >= 1.0.0 (OpenAI API)
- pydantic >= 2.0.0 (Data validation)
- jsonschema >= 4.0.0 (Schema validation)

## AWS Configuration

### Configure AWS Credentials

**Option 1: AWS CLI configuration**
```bash
aws configure
```

Provide:
- AWS Access Key ID
- AWS Secret Access Key
- Default region
- Output format (json recommended)

**Option 2: Environment variables**
```bash
export AWS_ACCESS_KEY_ID=your_access_key
export AWS_SECRET_ACCESS_KEY=your_secret_key
export AWS_DEFAULT_REGION=us-east-1
```

**Option 3: AWS profiles**
```bash
aws configure --profile mantissa-log
export AWS_PROFILE=mantissa-log
```

### Verify AWS Access

```bash
# Test AWS credentials
aws sts get-caller-identity

# Expected output:
# {
#   "UserId": "...",
#   "Account": "123456789012",
#   "Arn": "arn:aws:iam::123456789012:user/your-user"
# }
```

### Configure AWS Permissions

If using an IAM user, attach the following managed policies:
- `IAMFullAccess` (or create custom policy)
- `AmazonS3FullAccess`
- `AWSLambda_FullAccess`
- `AmazonDynamoDBFullAccess`
- `CloudWatchFullAccess`
- `AmazonAthenaFullAccess`
- `AWSGlueConsoleFullAccess`

Or create a custom policy with minimum required permissions.

## LLM Provider Setup

### AWS Bedrock

**Prerequisites:**
- Bedrock available in deployment region
- Model access enabled for Claude models

**Enable Bedrock:**
1. Navigate to AWS Bedrock console
2. Request model access for:
   - Claude 3 Sonnet
   - Claude 3 Haiku (recommended for cost)
3. Wait for access approval (usually instant)

**Verify access:**
```bash
aws bedrock list-foundation-models --region us-east-1
```

**Cost:** Pay-per-use, no upfront costs

### Anthropic API

**Prerequisites:**
- Anthropic API account
- API key

**Setup:**
1. Sign up at https://console.anthropic.com
2. Generate API key
3. Store in AWS Secrets Manager during deployment

**Cost:** Pay-per-use based on tokens

### OpenAI API

**Prerequisites:**
- OpenAI account
- API key

**Setup:**
1. Sign up at https://platform.openai.com
2. Generate API key
3. Store in AWS Secrets Manager during deployment

**Cost:** Pay-per-use based on tokens

## Network Requirements

### Outbound Connectivity

The deployment requires outbound internet access for:
- Lambda functions calling external LLM APIs (if not using Bedrock)
- Downloading Python dependencies during packaging
- Terraform downloading providers

### VPC Deployment (Optional)

If deploying into a VPC:
- Lambda functions need NAT Gateway or VPC endpoints
- Required VPC endpoints:
  - com.amazonaws.<region>.s3
  - com.amazonaws.<region>.dynamodb
  - com.amazonaws.<region>.secretsmanager
  - com.amazonaws.<region>.athena
  - com.amazonaws.<region>.glue

### Firewall Rules

If using outbound firewall rules:
- HTTPS (443) to AWS service endpoints
- HTTPS (443) to LLM provider APIs (if applicable)
- HTTPS (443) to PyPI for package downloads

## Security Considerations

### Encryption

**Data at rest:**
- S3 buckets: AES-256 encryption enabled by default
- DynamoDB: AWS-managed encryption
- Secrets Manager: KMS encryption

**Data in transit:**
- All AWS API calls use TLS 1.2+
- API Gateway endpoints use HTTPS only

### Access Control

**IAM Roles:**
- Lambda execution roles follow least privilege
- Service-to-service communication via IAM roles
- No long-lived credentials in Lambda functions

**Cognito:**
- User authentication for API access
- MFA support available
- Password policy enforced

### Secrets Management

**Required secrets:**
- LLM API keys (if using external providers)
- Alert destination credentials (Slack, PagerDuty, etc.)
- SMTP credentials (if using email alerts)

All secrets stored in AWS Secrets Manager with encryption.

### Compliance

**Data residency:**
- All data stored in selected AWS region
- No cross-region replication by default

**Audit logging:**
- CloudTrail logs all API calls
- Lambda execution logs in CloudWatch
- Access logs for API Gateway

**Data retention:**
- CloudWatch logs: 30 days default (configurable)
- S3 logs: Configurable lifecycle policies
- DynamoDB: Configurable TTL for state data

## Pre-Deployment Checklist

- [ ] AWS account created and accessible
- [ ] IAM user/role has required permissions
- [ ] AWS CLI installed and configured
- [ ] Terraform >= 1.5.0 installed
- [ ] Python >= 3.11 installed
- [ ] Git installed
- [ ] AWS region selected
- [ ] LLM provider chosen and configured
- [ ] Cost estimates reviewed and approved
- [ ] Network requirements understood
- [ ] Security requirements documented
- [ ] Backup/disaster recovery plan defined
- [ ] Alert destinations identified (Slack, PagerDuty, etc.)
- [ ] Log sources identified (CloudTrail, VPC Flow Logs, etc.)

## Next Steps

Once all prerequisites are met:
1. Review [AWS Deployment Guide](aws-deployment.md)
2. Run deployment script
3. Configure log sources
4. Test alert routing
5. Review [Troubleshooting Guide](troubleshooting.md) if needed
