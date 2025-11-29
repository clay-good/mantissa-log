# AWS Deployment Guide

This guide provides comprehensive instructions for deploying Mantissa Log to AWS.

## Quick Start

For experienced users who have completed all prerequisites:

```bash
# Clone repository
git clone <repository-url>
cd mantissa-log-dev

# Run deployment
bash scripts/deploy.sh
```

Follow the interactive prompts to configure and deploy.

## Full Deployment Guide

### Step 1: Verify Prerequisites

Before starting deployment, verify all prerequisites are met:

```bash
# Check Terraform
terraform --version
# Expected: Terraform v1.5.0 or higher

# Check AWS CLI
aws --version
# Expected: aws-cli/2.x.x or higher

# Check Python
python3 --version
# Expected: Python 3.11.x or higher

# Verify AWS credentials
aws sts get-caller-identity
# Should return your AWS account details
```

If any checks fail, see [Prerequisites](prerequisites.md).

### Step 2: Clone Repository

```bash
git clone <repository-url>
cd mantissa-log-dev
```

### Step 3: Review Configuration Options

Before running the deployment, understand the configuration options:

**Environment:**
- `dev` - Development environment (lower redundancy, cost-optimized)
- `staging` - Pre-production environment (medium redundancy)
- `prod` - Production environment (high redundancy, multi-AZ)

**AWS Region:**
- Select based on data residency, cost, and service availability
- Verify Bedrock availability if using AWS Bedrock
- Recommended: us-east-1, us-west-2, eu-west-1

**LLM Provider:**
- `bedrock` - AWS Bedrock (recommended, no API keys needed)
- `anthropic` - Anthropic API (requires API key)
- `openai` - OpenAI API (requires API key)

**Log Sources:**
- VPC Flow Logs - Network traffic analysis
- GuardDuty - Threat detection findings
- CloudTrail - AWS API activity (recommended)

### Step 4: Run Deployment Script

Start the deployment:

```bash
bash scripts/deploy.sh
```

The script will guide you through the deployment process.

### Step 5: Interactive Configuration

The deployment script will prompt for configuration:

```
Configuration:

Environment name (dev/staging/prod) [dev]: prod
AWS Region [us-east-1]: us-east-1
Project prefix [mantissa-log]: mantissa-log
S3 bucket for Terraform state [mantissa-log-terraform-state]:
Enable VPC Flow Logs ingestion? (y/n) [y]: y
Enable GuardDuty integration? (y/n) [y]: y
LLM Provider (bedrock/anthropic/openai) [bedrock]: bedrock
```

**Configuration Summary** will be displayed. Review carefully:

```
Configuration Summary:
  Environment: prod
  Region: us-east-1
  Project Prefix: mantissa-log
  State Bucket: mantissa-log-terraform-state
  VPC Flow Logs: y
  GuardDuty: y
  LLM Provider: bedrock

Proceed with deployment? (y/n):
```

Type `y` to continue.

### Step 6: Infrastructure Deployment

The script will now:

1. **Check prerequisites** - Verify tools and AWS access
2. **Create state bucket** - S3 bucket for Terraform state
3. **Configure backend** - Set up Terraform remote state
4. **Package Lambda functions** - Build deployment packages
5. **Deploy infrastructure** - Create AWS resources with Terraform

**Terraform Plan Review:**

The script will show a Terraform plan. Review the resources to be created:

```
Terraform will perform the following actions:

  # module.storage.aws_s3_bucket.logs_bucket will be created
  # module.compute.aws_lambda_function.detection_engine will be created
  # module.data.aws_dynamodb_table.state_table will be created
  ...

Plan: 45 to add, 0 to change, 0 to destroy.
```

Type `y` to apply the plan.

**Deployment time:** 5-10 minutes depending on region and resources.

### Step 7: Post-Deployment Configuration

After infrastructure deployment completes:

**CloudTrail Setup:**

The script will optionally create a CloudTrail trail:

```
Checking CloudTrail configuration...
  Creating CloudTrail trail: mantissa-log-trail
  CloudTrail configured and started
```

**Admin User Creation:**

Create an admin user for the web interface:

```
Setting up Cognito admin user...
Create admin user? (y/n) [y]: y
Admin email address: admin@example.com
Admin password (min 8 chars, upper, lower, number, special):
  Admin user created: admin@example.com
```

**Password requirements:**
- Minimum 8 characters
- At least one uppercase letter
- At least one lowercase letter
- At least one number
- At least one special character

### Step 8: Smoke Tests

The deployment script automatically runs smoke tests:

```
Running smoke tests...

S3 Buckets:
  Testing Logs bucket exists... PASS
  Testing Logs bucket encryption enabled... PASS
  Testing Logs bucket public access blocked... PASS
  Testing Athena results bucket exists... PASS

Glue Data Catalog:
  Testing Glue database exists... PASS
  Found tables: cloudtrail vpc_flow_logs guardduty

Lambda Functions:
  Testing Detection engine function exists... PASS
  Testing Detection engine has execution role... PASS
  Testing LLM query function exists... PASS
  Testing Alert router function exists... PASS

DynamoDB Tables:
  Testing State table exists... PASS
  Testing State table has TTL enabled... PASS

EventBridge Rules:
  Testing Detection schedule rule exists... PASS
  Testing Detection schedule rule is enabled... PASS

Cognito:
  Testing User pool exists... PASS
  Testing User pool client exists... PASS

API Gateway:
  API Endpoint: https://abc123.execute-api.us-east-1.amazonaws.com/prod
  Testing API endpoint is accessible... PASS

Athena:
  Testing Athena workgroup exists... PASS

Query Execution Test:
  Testing Athena query execution... PASS

==========================================
Smoke Test Summary
==========================================

Tests Passed: 18
Tests Failed: 0

All smoke tests passed!
```

If any tests fail, see [Troubleshooting](troubleshooting.md).

### Step 9: Web Application Deployment

After infrastructure deployment, the script will prompt to deploy the web application:

```
Web application deployment...

Deploy web application to CloudFront? (y/n) [y]: y
```

Type `y` to deploy the web interface.

**Web Deployment Process:**

The deployment script will:

1. **Load Terraform outputs** - Retrieve S3 bucket and CloudFront details
2. **Create environment configuration** - Generate `.env.production` with API endpoints
3. **Install dependencies** - Run npm install for React application
4. **Build application** - Compile with Vite build tool
5. **Deploy to S3** - Upload static assets with appropriate cache headers
6. **Invalidate CloudFront** - Clear CDN cache to serve new version

**Build output:**

```
Building web application...
  Running Vite build...
  vite v5.0.8 building for production...
  ✓ 1250 modules transformed.
  dist/index.html                   0.45 kB │ gzip:  0.30 kB
  dist/assets/index-a1b2c3d4.css   45.21 kB │ gzip: 12.34 kB
  dist/assets/index-e5f6g7h8.js   234.56 kB │ gzip: 78.90 kB
  Build completed successfully

Deploying to S3...
  Syncing files to s3://mantissa-log-prod-web/
  Uploading index.html with no-cache policy...
  Files deployed to S3

Invalidating CloudFront cache...
  Invalidation created: I2ABCDEFGHIJK
  Waiting for invalidation to complete (this may take 1-2 minutes)...
  CloudFront cache invalidated

==========================================
Web Deployment Complete!
==========================================

Application URL: https://d123abc456xyz.cloudfront.net

Configuration:
  API Endpoint: https://abc123.execute-api.us-east-1.amazonaws.com/prod
  User Pool ID: us-east-1_ABC123XYZ
  Region: us-east-1

Next steps:
1. Open the application URL in your browser
2. Log in with your Cognito credentials
3. Configure LLM settings in Settings > LLM Configuration
4. Set up alert integrations in Settings > Integrations

Note: It may take a few minutes for CloudFront to serve the updated content globally
```

**Deployment time:** 2-5 minutes including build and CloudFront invalidation.

**Skip web deployment:**

To skip web deployment and deploy it later:

```
Deploy web application to CloudFront? (y/n) [y]: n
  Skipping web deployment
  You can deploy the web app later by running: ./scripts/deploy-web.sh
```

### Step 10: Deployment Summary

The script will display a deployment summary:

```
==========================================
Deployment Complete!
==========================================

Environment: prod
Region: us-east-1

API Endpoint: https://abc123.execute-api.us-east-1.amazonaws.com/prod
Web Application: https://d123abc456xyz.cloudfront.net
Cognito User Pool ID: us-east-1_ABC123XYZ
Cognito Client ID: 1a2b3c4d5e6f7g8h9i0j

Next steps:
1. Configure alert destinations in AWS Secrets Manager
2. Review and enable detection rules
3. Configure log sources (CloudTrail, VPC Flow Logs, etc.)
4. Access the web interface at: https://d123abc456xyz.cloudfront.net
```

**Save these outputs** - you'll need them for configuration.

### Step 11: Access Web Interface

Open the CloudFront URL in your browser:

```
https://d123abc456xyz.cloudfront.net
```

**First-time login:**

1. Enter the admin email address created earlier
2. Enter the admin password
3. You may be prompted to change your password
4. Accept terms and complete profile setup

**Web Interface Features:**

- **Query Interface** - Natural language query with SQL preview
- **Alerts Dashboard** - View recent alerts and their status
- **Detection Rules** - Browse, edit, and enable/disable rules
- **Settings** - Configure LLM providers, integrations, and preferences
- **Conversations** - Multi-turn query sessions with context

**Troubleshooting web access:**

If the web interface doesn't load:

1. Check CloudFront distribution status:
   ```bash
   DIST_ID=$(cat terraform-outputs.json | jq -r '.cloudfront_distribution_id.value')
   aws cloudfront get-distribution --id $DIST_ID --query 'Distribution.Status'
   ```
   Expected: `"Deployed"`

2. Verify S3 bucket has files:
   ```bash
   WEB_BUCKET=$(cat terraform-outputs.json | jq -r '.web_bucket_name.value')
   aws s3 ls s3://$WEB_BUCKET/
   ```
   Expected: `index.html` and `assets/` directory

3. Check browser console for errors (F12 Developer Tools)

4. Redeploy web application:
   ```bash
   bash scripts/deploy-web.sh
   ```

### Step 12: Configure Alert Destinations

Configure where alerts should be sent:

**Slack Integration:**

1. Create a Slack webhook URL:
   - Go to https://api.slack.com/apps
   - Create new app
   - Enable Incoming Webhooks
   - Copy webhook URL

2. Store in Secrets Manager:
   ```bash
   aws secretsmanager create-secret \
     --name mantissa-log/alerts/slack \
     --secret-string '{
       "webhook_url": "https://hooks.slack.com/services/YOUR/WEBHOOK/URL",
       "channel": "#security-alerts",
       "username": "Mantissa Log"
     }' \
     --region us-east-1
   ```

**PagerDuty Integration:**

1. Get PagerDuty Integration Key:
   - Go to PagerDuty Service
   - Add Integration
   - Select "Events API v2"
   - Copy Integration Key

2. Store in Secrets Manager:
   ```bash
   aws secretsmanager create-secret \
     --name mantissa-log/alerts/pagerduty \
     --secret-string '{
       "integration_key": "YOUR_INTEGRATION_KEY"
     }' \
     --region us-east-1
   ```

**Email Integration:**

Option 1: SMTP
```bash
aws secretsmanager create-secret \
  --name mantissa-log/alerts/email \
  --secret-string '{
    "smtp_host": "smtp.gmail.com",
    "smtp_port": 587,
    "smtp_username": "your-email@gmail.com",
    "smtp_password": "your-app-password",
    "from_address": "alerts@example.com",
    "to_addresses": ["security-team@example.com"]
  }' \
  --region us-east-1
```

Option 2: AWS SES
```bash
# First verify email addresses in SES
aws ses verify-email-identity --email-address alerts@example.com

aws secretsmanager create-secret \
  --name mantissa-log/alerts/email \
  --secret-string '{
    "use_ses": true,
    "from_address": "alerts@example.com",
    "to_addresses": ["security-team@example.com"]
  }' \
  --region us-east-1
```

### Step 13: Configure Detection Rules

Detection rules are stored in the `rules/` directory and automatically uploaded during deployment.

**Review default rules:**

```bash
ls -la rules/
```

**Enable/disable specific rules:**

Edit rule files to set `enabled: true` or `enabled: false`:

```yaml
# rules/aws/cloudtrail-root-activity.yaml
name: "Root Account Activity"
enabled: true  # Set to false to disable
severity: "critical"
...
```

**Upload updated rules:**

```bash
# Get rules bucket name
RULES_BUCKET=$(cat terraform-outputs.json | jq -r '.rules_bucket.value')

# Upload rules
aws s3 sync rules/ s3://$RULES_BUCKET/rules/ \
  --exclude "*.md" \
  --exclude "README*"
```

**Create custom rules:**

1. Create new YAML file in `rules/` directory
2. Follow the schema in `rules/schema.json`
3. Upload to S3
4. Rules are loaded on next detection cycle (5 minutes)

### Step 14: Configure Log Sources

**CloudTrail (Already configured by deployment script):**

Verify CloudTrail is logging:

```bash
aws cloudtrail get-trail-status --name mantissa-log-trail
```

Expected: `"IsLogging": true`

**VPC Flow Logs:**

Enable for VPCs you want to monitor:

```bash
# Get logs bucket
LOGS_BUCKET=$(cat terraform-outputs.json | jq -r '.logs_bucket.value')

# Enable VPC Flow Logs
aws ec2 create-flow-logs \
  --resource-type VPC \
  --resource-ids vpc-12345678 \
  --traffic-type ALL \
  --log-destination-type s3 \
  --log-destination "arn:aws:s3:::$LOGS_BUCKET/vpc-flow-logs/" \
  --log-format '${version} ${account-id} ${interface-id} ${srcaddr} ${dstaddr} ${srcport} ${dstport} ${protocol} ${packets} ${bytes} ${start} ${end} ${action} ${log-status}'
```

**GuardDuty:**

Enable GuardDuty findings export:

```bash
# Get logs bucket
LOGS_BUCKET=$(cat terraform-outputs.json | jq -r '.logs_bucket.value')

# Get GuardDuty detector ID
DETECTOR_ID=$(aws guardduty list-detectors --query 'DetectorIds[0]' --output text)

# Create publishing destination
aws guardduty create-publishing-destination \
  --detector-id $DETECTOR_ID \
  --destination-type S3 \
  --destination-properties DestinationArn=arn:aws:s3:::$LOGS_BUCKET/guardduty/,KmsKeyArn=arn:aws:kms:us-east-1:123456789012:key/abc-def
```

**Custom Log Sources:**

For custom applications or services:

1. Configure to write logs to S3 bucket in JSON format
2. Use prefix: `s3://$LOGS_BUCKET/custom-logs/`
3. Create Glue table for log schema
4. Write detection rules targeting the new table

### Step 15: Test the Deployment

**Test Alert Routing:**

Invoke the alert router Lambda directly:

```bash
# Get function name
ALERT_ROUTER=$(cat terraform-outputs.json | jq -r '.alert_router_function_name.value')

# Create test alert
cat > test-alert.json <<EOF
{
  "alert_id": "test-001",
  "title": "Test Alert",
  "description": "This is a test alert from deployment verification",
  "severity": "low",
  "rule_name": "test_rule",
  "source": "manual_test",
  "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "metadata": {
    "test": true
  }
}
EOF

# Invoke Lambda
aws lambda invoke \
  --function-name $ALERT_ROUTER \
  --payload file://test-alert.json \
  --region us-east-1 \
  response.json

# Check response
cat response.json
```

You should receive the test alert in configured destinations (Slack, email, etc.).

**Test LLM Query:**

Query your logs using natural language:

```bash
# Get API endpoint
API_ENDPOINT=$(cat terraform-outputs.json | jq -r '.api_endpoint.value')

# Get Cognito user pool details for authentication
USER_POOL_ID=$(cat terraform-outputs.json | jq -r '.user_pool_id.value')
CLIENT_ID=$(cat terraform-outputs.json | jq -r '.user_pool_client_id.value')

# Authenticate (get token)
# This requires setting up proper authentication flow
# See Cognito documentation for details

# Query logs
curl -X POST "$API_ENDPOINT/query" \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "question": "Show me failed login attempts in the last hour",
    "execute": true
  }'
```

**Test Detection Engine:**

The detection engine runs automatically every 5 minutes. To trigger manually:

```bash
# Get function name
DETECTION_ENGINE=$(cat terraform-outputs.json | jq -r '.detection_engine_function_name.value')

# Invoke manually
aws lambda invoke \
  --function-name $DETECTION_ENGINE \
  --region us-east-1 \
  response.json

# Check logs
aws logs tail /aws/lambda/$DETECTION_ENGINE --follow
```

### Step 16: Monitor the Deployment

**CloudWatch Dashboards:**

Access CloudWatch to view metrics:
- Lambda execution counts and errors
- DynamoDB read/write capacity
- S3 bucket sizes
- Athena query execution times

**CloudWatch Logs:**

View Lambda function logs:

```bash
# Detection Engine logs
aws logs tail /aws/lambda/mantissa-log-detection-engine --follow

# LLM Query Handler logs
aws logs tail /aws/lambda/mantissa-log-llm-query --follow

# Alert Router logs
aws logs tail /aws/lambda/mantissa-log-alert-router --follow
```

**Athena Query History:**

Monitor queries in Athena console:
- Query execution times
- Data scanned
- Failed queries

**Cost Monitoring:**

Set up billing alerts:

```bash
# Create SNS topic for billing alerts
aws sns create-topic --name mantissa-log-billing-alerts

# Subscribe email
aws sns subscribe \
  --topic-arn arn:aws:sns:us-east-1:123456789012:mantissa-log-billing-alerts \
  --protocol email \
  --notification-endpoint your-email@example.com

# Create billing alarm (requires us-east-1)
aws cloudwatch put-metric-alarm \
  --alarm-name mantissa-log-monthly-cost \
  --alarm-description "Alert when estimated monthly cost exceeds threshold" \
  --metric-name EstimatedCharges \
  --namespace AWS/Billing \
  --statistic Maximum \
  --period 21600 \
  --evaluation-periods 1 \
  --threshold 100 \
  --comparison-operator GreaterThanThreshold \
  --alarm-actions arn:aws:sns:us-east-1:123456789012:mantissa-log-billing-alerts \
  --region us-east-1
```

## Configuration Reference

### Environment Variables

Lambda functions use these environment variables:

**Detection Engine:**
- `GLUE_DATABASE` - Glue catalog database name
- `ATHENA_WORKGROUP` - Athena workgroup for queries
- `RULES_BUCKET` - S3 bucket containing detection rules
- `STATE_TABLE` - DynamoDB table for detection state
- `ALERT_TOPIC_ARN` - SNS topic for alerts

**LLM Query Handler:**
- `GLUE_DATABASE` - Glue catalog database name
- `ATHENA_WORKGROUP` - Athena workgroup
- `LLM_PROVIDER` - bedrock, anthropic, or openai
- `LLM_MODEL` - Model name (e.g., claude-3-haiku)
- `SESSION_TABLE` - DynamoDB table for sessions

**Alert Router:**
- `SECRETS_PREFIX` - Prefix for Secrets Manager secrets
- `ENRICHMENT_ENABLED` - Enable alert enrichment (true/false)

### Terraform Variables

Key variables in `terraform.tfvars`:

```hcl
environment = "prod"
aws_region = "us-east-1"
project_prefix = "mantissa-log"

# LLM Configuration
llm_provider = "bedrock"
llm_model = "anthropic.claude-3-haiku-20240307-v1:0"

# Detection Engine
detection_schedule = "rate(5 minutes)"
detection_timeout = 900

# Alert Configuration
alert_enrichment_enabled = true

# Log Retention
cloudwatch_log_retention_days = 30

# Data Retention
s3_lifecycle_days = 90
s3_glacier_days = 365

# Resource Sizing
lambda_memory_size = 512
dynamodb_billing_mode = "PAY_PER_REQUEST"
```

### Detection Rule Schema

Detection rules use this YAML schema:

```yaml
name: "Rule Name"
description: "Detailed description"
enabled: true
severity: "critical|high|medium|low|info"
category: "access|network|data|compliance|threat"

query: |
  SELECT
    field1,
    field2
  FROM table
  WHERE condition

threshold:
  count: 1
  window: "5m|1h|24h"

metadata:
  mitre_attack:
    - "TA0001"
  references:
    - "https://example.com/doc"
  tags:
    - "aws"
    - "cloudtrail"
```

## Advanced Configuration

### Multi-Region Deployment

To deploy to multiple regions:

1. Run deployment script for each region
2. Use different state buckets per region
3. Configure cross-region replication for logs (optional)
4. Use Route53 for failover between regions

### High Availability Setup

For production deployments:

1. Enable DynamoDB global tables (multi-region)
2. Configure Lambda reserved concurrency
3. Set up CloudWatch alarms for failures
4. Enable S3 cross-region replication
5. Use multiple alert destinations

### Custom VPC Deployment

To deploy Lambda functions in VPC:

1. Edit `infrastructure/aws/terraform/modules/compute/main.tf`
2. Uncomment VPC configuration sections
3. Provide subnet IDs and security group IDs
4. Ensure NAT Gateway or VPC endpoints exist
5. Redeploy with `terraform apply`

### Custom Domain Setup

To use custom domain for API:

1. Register domain in Route53
2. Create ACM certificate
3. Add custom domain to API Gateway
4. Create Route53 alias record
5. Update Cognito callback URLs

## Updating the Deployment

### Update Infrastructure and Lambda Functions

To update an existing deployment:

```bash
bash scripts/update.sh
```

This will:
1. Check Git status
2. Pull latest code
3. Check for breaking changes
4. Package updated Lambda functions
5. Update infrastructure
6. Update Lambda function code
7. Update detection rules
8. Run smoke tests

### Update Web Application Only

To redeploy just the web application after making changes:

```bash
bash scripts/deploy-web.sh
```

This is useful when:
- Updating UI components or styling
- Fixing bugs in the React application
- Adding new features to the web interface
- Changing environment configuration

The script will:
1. Build the latest React application
2. Deploy to S3 with optimized caching
3. Invalidate CloudFront cache
4. Verify deployment

**Development workflow:**

For active web development:

```bash
# Make changes to web/src/
cd web
npm run dev  # Start development server

# Test locally at http://localhost:5173

# When ready to deploy:
cd ..
bash scripts/deploy-web.sh
```

**Cache busting:**

The deployment script automatically handles cache busting:
- Static assets (JS, CSS, images) get 1-year cache with content hashes
- `index.html` gets no-cache policy
- CloudFront cache is invalidated after each deployment

## Destroying the Deployment

To completely remove the deployment:

```bash
bash scripts/destroy.sh
```

**WARNING:** This will destroy all infrastructure and optionally delete all log data.

The script will:
1. Confirm destruction multiple times
2. Empty S3 buckets
3. Destroy infrastructure with Terraform
4. Delete S3 buckets (optional)
5. Clean up local files

## Next Steps

After successful deployment:

1. Review [Troubleshooting Guide](troubleshooting.md)
2. Configure additional log sources
3. Customize detection rules
4. Set up dashboards and reports
5. Train team on using the system
6. Establish runbooks for common scenarios
7. Schedule regular reviews of alerts and rules
