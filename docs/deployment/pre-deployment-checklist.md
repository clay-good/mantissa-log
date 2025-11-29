# Pre-Deployment Checklist

Complete this checklist before deploying Mantissa Log to ensure a smooth deployment.

## Prerequisites

### AWS Account Setup

- [ ] AWS account created with billing enabled
- [ ] IAM user or role with administrator permissions
- [ ] AWS CLI v2 installed and configured
- [ ] AWS credentials configured (`aws configure` completed)
- [ ] Verified credentials work: `aws sts get-caller-identity`
- [ ] Confirmed account is not in organizational restricted mode
- [ ] Billing alerts configured (recommended)

### Required Software

- [ ] **Terraform** >= 1.5 installed
  ```bash
  terraform --version
  # Expected: Terraform v1.5.0 or higher
  ```

- [ ] **Python** 3.11+ installed
  ```bash
  python3 --version
  # Expected: Python 3.11.x or higher
  ```

- [ ] **Node.js** >= 18 installed
  ```bash
  node --version
  # Expected: v18.x.x or higher
  ```

- [ ] **npm** installed
  ```bash
  npm --version
  # Expected: 9.x.x or higher
  ```

- [ ] **Git** installed
  ```bash
  git --version
  ```

- [ ] **jq** installed (for JSON processing)
  ```bash
  jq --version
  ```

### AWS Service Limits

Verify your AWS account has sufficient service limits:

- [ ] Lambda concurrent executions: >= 100
- [ ] S3 buckets: >= 10 available
- [ ] DynamoDB tables: >= 5 available
- [ ] CloudWatch log groups: >= 20 available
- [ ] API Gateway APIs: >= 5 available
- [ ] Cognito user pools: >= 1 available
- [ ] CloudFront distributions: >= 1 available

Check limits:
```bash
# Lambda
aws service-quotas get-service-quota \
  --service-code lambda \
  --quota-code L-B99A9384 \
  --query 'Quota.Value'

# S3
aws service-quotas get-service-quota \
  --service-code s3 \
  --quota-code L-DC2B2D3D \
  --query 'Quota.Value'
```

### AWS Region Selection

- [ ] Selected deployment region
- [ ] Confirmed Bedrock availability in region (if using AWS Bedrock)
  - Bedrock available in: us-east-1, us-west-2, eu-west-1, ap-southeast-1
- [ ] Confirmed region supports all required services
- [ ] Considered data residency requirements
- [ ] Considered latency to users

### Cost Considerations

- [ ] Reviewed estimated monthly costs
- [ ] Set up AWS Cost Explorer
- [ ] Configured billing alerts
- [ ] Approved budget with finance team (if applicable)
- [ ] Understood cost breakdown:
  - S3 storage: ~$23/TB/month
  - Athena queries: $5/TB scanned
  - Lambda executions: ~$20/million requests
  - DynamoDB: Pay-per-request or provisioned
  - CloudFront: ~$85/TB data transfer

**Estimated monthly cost for small deployment (100GB logs/day):**
- S3: ~$70
- Athena: ~$50
- Lambda: ~$20
- DynamoDB: ~$5
- CloudFront: ~$10
- **Total: ~$155/month**

## LLM Provider Setup

Choose and configure ONE of the following:

### Option 1: AWS Bedrock (Recommended)

- [ ] Confirmed Bedrock availability in deployment region
- [ ] Enabled Bedrock in AWS Console
- [ ] Requested access to Claude models
- [ ] Verified model access:
  ```bash
  aws bedrock list-foundation-models \
    --region us-east-1 \
    --query 'modelSummaries[?contains(modelId, `anthropic.claude`)].modelId'
  ```
- [ ] Set `llm_provider = "bedrock"` in tfvars

**Pros:** No API keys needed, IAM-based access, no additional billing

### Option 2: Anthropic API

- [ ] Created Anthropic account at console.anthropic.com
- [ ] Generated API key
- [ ] Tested API key:
  ```bash
  curl https://api.anthropic.com/v1/messages \
    -H "x-api-key: $ANTHROPIC_API_KEY" \
    -H "anthropic-version: 2023-06-01" \
    -H "content-type: application/json" \
    -d '{"model":"claude-3-haiku-20240307","max_tokens":1024,"messages":[{"role":"user","content":"Hello"}]}'
  ```
- [ ] Prepared to add API key in web interface after deployment
- [ ] Set `llm_provider = "anthropic"` in tfvars

**Pros:** Latest models, fast updates, direct Anthropic support

### Option 3: OpenAI API

- [ ] Created OpenAI account at platform.openai.com
- [ ] Generated API key
- [ ] Tested API key:
  ```bash
  curl https://api.openai.com/v1/chat/completions \
    -H "Authorization: Bearer $OPENAI_API_KEY" \
    -H "Content-Type: application/json" \
    -d '{"model":"gpt-4","messages":[{"role":"user","content":"Hello"}]}'
  ```
- [ ] Prepared to add API key in web interface after deployment
- [ ] Set `llm_provider = "openai"` in tfvars

**Pros:** Widely available, good documentation

### Option 4: Google Gemini

- [ ] Created Google Cloud project
- [ ] Enabled Vertex AI API
- [ ] Generated API key at aistudio.google.com
- [ ] Tested API key:
  ```bash
  curl "https://generativelanguage.googleapis.com/v1/models/gemini-pro:generateContent?key=$GOOGLE_API_KEY" \
    -H 'Content-Type: application/json' \
    -d '{"contents":[{"parts":[{"text":"Hello"}]}]}'
  ```
- [ ] Prepared to add API key in web interface after deployment
- [ ] Set `llm_provider = "google"` in tfvars

## Configuration Files

### Terraform Backend

- [ ] Decided on S3 bucket name for Terraform state
- [ ] Bucket name is globally unique
- [ ] Bucket name follows naming convention (lowercase, hyphens only)
- [ ] Example: `mantissa-log-terraform-state-123456789012`

### Environment Variables

- [ ] Determined environment name: `dev`, `staging`, or `prod`
- [ ] Chosen project prefix (default: `mantissa-log`)
- [ ] Reviewed `environments/dev.tfvars.example`
- [ ] Created customized `environments/dev.tfvars` (or staging/prod)

### Alert Destinations (Optional)

If configuring Slack alerts:

- [ ] Created Slack app or webhook
- [ ] Obtained webhook URL
- [ ] Prepared to store webhook in AWS Secrets Manager after deployment
- [ ] Decided on Slack channel for alerts

If configuring Jira integration:

- [ ] Obtained Jira URL
- [ ] Generated Jira API token
- [ ] Identified Jira project key
- [ ] Prepared to configure in web interface after deployment

If configuring PagerDuty:

- [ ] Created PagerDuty service
- [ ] Generated Events API v2 integration key
- [ ] Prepared to configure in web interface after deployment

## Log Sources

### CloudTrail (Highly Recommended)

- [ ] Decided on CloudTrail trail configuration
- [ ] Multi-region trail recommended for comprehensive coverage
- [ ] Confirmed S3 costs acceptable for CloudTrail volume
- [ ] Deployment script will create trail automatically (or skip if exists)

### VPC Flow Logs (Optional)

- [ ] Identified VPCs to monitor
- [ ] Confirmed S3 costs acceptable for flow log volume
- [ ] Noted VPC IDs for post-deployment configuration

### GuardDuty (Optional)

- [ ] GuardDuty enabled in account
- [ ] Confirmed findings export to S3 is acceptable
- [ ] Noted GuardDuty detector ID for post-deployment configuration

### SaaS Sources (Optional)

For each SaaS source you plan to enable:

- [ ] API access configured
- [ ] API credentials/keys obtained
- [ ] Confirmed API rate limits are acceptable
- [ ] Prepared to store credentials in AWS Secrets Manager after deployment

## Network and Security

### VPC Deployment (Optional)

If deploying Lambda functions in VPC:

- [ ] VPC created with private subnets
- [ ] NAT Gateway configured for internet access
- [ ] Security groups defined
- [ ] VPC endpoints for AWS services (optional, reduces NAT costs):
  - S3 endpoint
  - DynamoDB endpoint
  - Secrets Manager endpoint
  - Bedrock endpoint (if using)

### KMS Encryption (Recommended for Production)

- [ ] Decided whether to use KMS encryption
- [ ] If yes: Created KMS key or will use AWS-managed key
- [ ] Configured KMS key policy if using customer-managed key
- [ ] Set `enable_kms_encryption = true` in tfvars

### IAM Permissions

- [ ] Confirmed deployment user/role has:
  - Full S3 permissions
  - Lambda create/update permissions
  - DynamoDB create permissions
  - CloudFormation permissions (for Terraform)
  - IAM role creation permissions
  - CloudWatch Logs permissions
  - API Gateway permissions
  - Cognito permissions
  - CloudFront permissions

## Deployment Preparation

### Local Environment

- [ ] Cloned repository
  ```bash
  git clone <repository-url>
  cd mantissa-log
  ```

- [ ] Reviewed project structure
- [ ] Read deployment documentation
- [ ] Understood deployment scripts

### Dry Run Checks

- [ ] Tested AWS credentials:
  ```bash
  aws sts get-caller-identity
  ```

- [ ] Verified Terraform works:
  ```bash
  cd infrastructure/aws/terraform
  terraform init -backend=false
  terraform validate
  ```

- [ ] Verified Python dependencies can be installed:
  ```bash
  cd ../../../
  pip3 install -r requirements.txt
  ```

- [ ] Verified Node.js dependencies can be installed:
  ```bash
  cd web
  npm install
  cd ..
  ```

### Deployment Plan

- [ ] Allocated 30-45 minutes for deployment
- [ ] Ensured stable internet connection
- [ ] Prepared to monitor deployment logs
- [ ] Have backup plan if deployment fails
- [ ] Notified team of deployment window (if applicable)

## Post-Deployment Preparation

### User Access

- [ ] Determined admin email address for Cognito
- [ ] Created strong password meeting requirements:
  - Minimum 8 characters
  - Uppercase letter
  - Lowercase letter
  - Number
  - Special character

### Testing Plan

- [ ] Planned first test query
- [ ] Prepared sample log data (or will use CloudTrail)
- [ ] Identified team members for user acceptance testing

### Documentation

- [ ] Team members aware of deployment
- [ ] Runbook prepared for common issues
- [ ] Escalation plan documented

## Final Checks

Before running deployment:

- [ ] All prerequisite software installed and verified
- [ ] AWS credentials configured and tested
- [ ] LLM provider selected and configured
- [ ] Configuration files customized
- [ ] Cost budget approved
- [ ] Deployment time allocated
- [ ] Team notified

**If all boxes are checked, you're ready to deploy!**

Run:
```bash
bash scripts/deploy.sh
```

## Troubleshooting Checklist Failures

### "Terraform not found"

```bash
# macOS
brew install terraform

# Linux
wget https://releases.hashicorp.com/terraform/1.6.0/terraform_1.6.0_linux_amd64.zip
unzip terraform_1.6.0_linux_amd64.zip
sudo mv terraform /usr/local/bin/
```

### "AWS credentials not configured"

```bash
aws configure
# Enter:
# - AWS Access Key ID
# - AWS Secret Access Key
# - Default region (e.g., us-east-1)
# - Default output format (json)
```

### "Python version too old"

```bash
# macOS
brew install python@3.11

# Linux
sudo apt update
sudo apt install python3.11
```

### "Node.js not found"

```bash
# macOS
brew install node

# Linux
curl -fsSL https://deb.nodesource.com/setup_18.x | sudo -E bash -
sudo apt install -y nodejs
```

### "Service quota exceeded"

Request quota increase:
```bash
aws service-quotas request-service-quota-increase \
  --service-code lambda \
  --quota-code L-B99A9384 \
  --desired-value 200
```

Or use AWS Console: Service Quotas > AWS Services > Lambda > Request quota increase

## References

- [AWS Deployment Guide](aws-deployment.md)
- [Quick Reference](quick-reference.md)
- [Troubleshooting Guide](troubleshooting.md)
- [Architecture Overview](../architecture.md)
