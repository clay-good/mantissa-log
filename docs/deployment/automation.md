# Deployment Automation Guide

Comprehensive guide to automating Mantissa Log deployment, updates, and testing across development, staging, and production environments.

## Overview

Mantissa Log provides fully automated deployment through:
- Shell scripts for manual deployment
- GitHub Actions workflows for CI/CD
- Terraform for infrastructure as code
- Automated testing and validation

## Deployment Scripts

### deploy.sh

Full deployment script with interactive prompts and validation.

**Usage:**
```bash
./scripts/deploy.sh
```

**What it does:**
1. Checks prerequisites (Terraform, AWS CLI, Python)
2. Collects configuration (environment, region, features)
3. Creates Terraform state bucket with versioning and encryption
4. Configures Terraform backend
5. Packages Lambda functions
6. Deploys infrastructure with Terraform
7. Uploads detection rules to S3
8. Configures CloudTrail (if needed)
9. Creates Cognito admin user
10. Runs smoke tests
11. Displays deployment summary

**Example output:**
```
==========================================
Mantissa Log Deployment Script
==========================================

Checking prerequisites...
  Terraform version: 1.6.0
  aws-cli/2.13.0
  AWS Account: 123456789012
  Python 3.11.0
  Prerequisites check passed!

Configuration:
  Environment: dev
  Region: us-east-1
  Project Prefix: mantissa-log
  State Bucket: mantissa-log-terraform-state
  VPC Flow Logs: y
  GuardDuty: y
  LLM Provider: bedrock

Proceed with deployment? (y/n): y

... (deployment progress) ...

==========================================
Deployment Complete!
==========================================

Environment: dev
Region: us-east-1

API Endpoint: https://abc123.execute-api.us-east-1.amazonaws.com/prod
Cognito User Pool ID: us-east-1_ABC123
Cognito Client ID: 7abc123def456
```

### package-lambdas.sh

Packages Lambda functions with dependencies.

**Usage:**
```bash
./scripts/package-lambdas.sh
```

**What it does:**
1. Installs Python dependencies from requirements.txt
2. Copies shared source code
3. Creates Lambda function packages
4. Creates Lambda layer with shared dependencies
5. Validates package sizes against Lambda limits

**Output:**
```
Packaging Lambda functions for deployment...

Creating shared Lambda layer...
  Installing shared dependencies...
  Copying shared modules...
  Creating layer package...
  Layer created: build/lambda/mantissa-log-layer.zip
  Size: 12M

Packaging Detection Engine (detection-engine)...
  Installing dependencies...
  Copying source code...
  Creating deployment package...
  Package created: build/lambda/detection-engine.zip
  Size: 15M

Validating packages...
  Validation complete

Lambda packaging complete!
Packages location: build/lambda
```

### update.sh

Updates an existing deployment with code and infrastructure changes.

**Usage:**
```bash
./scripts/update.sh
```

**What it does:**
1. Checks Git status for uncommitted changes
2. Pulls latest code from repository
3. Checks changelog for breaking changes
4. Packages updated Lambda functions
5. Updates infrastructure with Terraform
6. Updates Lambda function code
7. Uploads new detection rules
8. Runs smoke tests

**Example:**
```
==========================================
Mantissa Log Update Script
==========================================

Checking Git status...
  Git status OK

Pulling latest code...
  Current branch: main
  Code updated

Packaging updated Lambda functions...
  ...

Updating infrastructure...
  Running terraform init to update providers...
  Creating Terraform plan...

Apply these changes? (y/n): y

  Applying Terraform changes...
  Infrastructure updated

Updating Lambda function code...
  Updating detection engine...
    Detection engine updated
  Updating LLM query handler...
    LLM query handler updated
  Updating alert router...
    Alert router updated

==========================================
Update Complete
==========================================
```

### destroy.sh

Safely destroys all infrastructure with confirmation prompts.

**Usage:**
```bash
./scripts/destroy.sh
```

**What it does:**
1. Requires multiple confirmations
2. Prompts for S3 bucket deletion
3. Empties S3 buckets
4. Destroys infrastructure with Terraform
5. Optionally deletes state bucket
6. Cleans up local files

**Safety features:**
- Requires typing "DELETE" for final confirmation
- Optional data preservation
- State bucket deletion is separate prompt

**Example:**
```
==========================================
Mantissa Log Destruction Script
==========================================

WARNING: This will destroy all Mantissa Log infrastructure
         and optionally delete all log data.

This action will:
  - Destroy all Lambda functions
  - Delete Glue database and tables
  - Remove EventBridge rules
  - Delete Cognito user pool
  - Remove API Gateway
  - Delete DynamoDB tables

Are you absolutely sure you want to destroy everything? (yes/no): yes

Delete S3 buckets and ALL log data? (yes/no): no

Final confirmation - type 'DELETE' to proceed: DELETE

Emptying S3 buckets...
  Emptying logs bucket: mantissa-log-logs-dev
  Emptying Athena results bucket: mantissa-log-athena-results-dev

Destroying infrastructure with Terraform...
  Running terraform destroy...
  Infrastructure destroyed

==========================================
Destruction Complete
==========================================
```

### smoke-test.sh

Validates deployment with automated health checks.

**Usage:**
```bash
./scripts/smoke-test.sh terraform-outputs.json
```

**What it tests:**
1. S3 buckets exist and are encrypted
2. Glue database and tables are created
3. Lambda functions are deployed
4. DynamoDB tables have TTL enabled
5. EventBridge rules are enabled
6. Cognito user pool is configured
7. API Gateway is accessible
8. Athena workgroup exists
9. Simple query execution works

**Example output:**
```
Running smoke tests...

S3 Buckets:
  Testing Logs bucket exists... PASS
  Testing Logs bucket encryption enabled... PASS
  Testing Logs bucket public access blocked... PASS
  Testing Athena results bucket exists... PASS

Glue Data Catalog:
  Testing Glue database exists... PASS
  Found tables: cloudtrail vpc_flow_logs guardduty_findings

Lambda Functions:
  Testing Detection engine function exists... PASS
  Testing Detection engine has execution role... PASS
  Testing LLM query function exists... PASS
  Testing Alert router function exists... PASS

Query Execution Test:
  Testing Athena query execution... PASS

==========================================
Smoke Test Summary
==========================================

Tests Passed: 18
Tests Failed: 0

All smoke tests passed!
```

## GitHub Actions Workflows

### deploy.yml

Automated deployment workflow with AWS OIDC authentication.

**Triggers:**
- Push to `main` branch (deploys to dev)
- Git tags `v*` (deploys to prod)
- Manual workflow dispatch (choose environment)

**Steps:**
1. Checkout code
2. Set up Python and install dependencies
3. Configure AWS credentials via OIDC
4. Setup Terraform
5. Package Lambda functions
6. Upload Lambda packages to S3
7. Create Terraform backend configuration
8. Terraform init, plan, and apply
9. Extract outputs
10. Upload detection rules
11. Run smoke tests
12. Update Lambda function code
13. Create deployment summary
14. Send Slack notification

**Usage:**
```yaml
# Manual deployment
gh workflow run deploy.yml -f environment=staging

# Automatic on push
git push origin main  # Deploys to dev

# Automatic on tag
git tag v1.0.0
git push origin v1.0.0  # Deploys to prod
```

**Required Secrets:**
- `AWS_DEPLOY_ROLE_ARN` - IAM role for OIDC
- `AWS_REGION` - Deployment region
- `TERRAFORM_STATE_BUCKET` - S3 bucket for state
- `TERRAFORM_LOCK_TABLE` - DynamoDB table for locks
- `LAMBDA_ARTIFACTS_BUCKET` - S3 bucket for Lambda packages
- `SLACK_WEBHOOK_URL` - Slack webhook for notifications

### terraform-plan.yml

Automated Terraform plan review on pull requests.

**Triggers:**
- Pull requests that modify `infrastructure/**`

**Steps:**
1. Checkout code
2. Configure AWS credentials
3. Setup Terraform
4. Create backend configuration
5. Run `terraform fmt -check`
6. Run `terraform init`
7. Run `terraform validate`
8. Run `terraform plan` for dev and staging
9. Post plan as PR comment

**Example PR comment:**
```markdown
## Terraform Plan: dev

<details>
<summary>Show Plan</summary>

```terraform
Terraform will perform the following actions:

  # module.compute.aws_lambda_function.detection_engine will be updated in-place
  ~ resource "aws_lambda_function" "detection_engine" {
        id               = "mantissa-log-detection-engine-dev"
      ~ memory_size      = 512 -> 1024
        # (10 unchanged attributes hidden)
    }

Plan: 0 to add, 1 to change, 0 to destroy.
```

</details>

*Pushed by: @user, Action: `pull_request`*
```

### release.yml

Automated release creation with artifact publishing.

**Triggers:**
- Git tags `v*.*.*`

**Steps:**
1. Run all tests
2. Build Lambda packages
3. Build web interface
4. Create GitHub release
5. Upload Lambda packages as artifacts
6. Publish Terraform module
7. Deploy to production

**Creates:**
- GitHub release with changelog
- Lambda function .zip files
- Web interface build
- Terraform module package

**Example:**
```bash
# Create release
git tag v1.2.3
git push origin v1.2.3

# GitHub Actions will:
# 1. Run tests
# 2. Build packages
# 3. Create release: https://github.com/user/repo/releases/tag/v1.2.3
# 4. Deploy to production
```

## Environment Configuration

### Development (dev.tfvars)

Minimal cost configuration for testing:

```hcl
environment = "dev"
aws_region  = "us-east-1"

log_retention_days = 90
enable_glacier     = false
enable_vpc         = false
enable_kms_encryption = false

lambda_memory_detection = 512
detection_engine_schedule = "rate(5 minutes)"

cloudwatch_log_retention_days = 14
```

### Staging (staging.tfvars)

Production-like configuration for pre-release testing:

```hcl
environment = "staging"
aws_region  = "us-east-1"

log_retention_days = 180
enable_glacier     = true
enable_vpc         = true
enable_kms_encryption = true

lambda_memory_detection = 1024
detection_engine_schedule = "rate(5 minutes)"

cloudwatch_log_retention_days = 30
```

### Production (prod.tfvars.example)

Full production configuration:

```hcl
environment = "prod"
aws_region  = "us-east-1"

log_retention_days = 365
enable_glacier     = true
enable_vpc         = true
vpc_id     = "vpc-xxxxxxxxx"
subnet_ids = ["subnet-xxxxxxxxx", "subnet-yyyyyyyyy"]
enable_kms_encryption = true
kms_key_arn = "arn:aws:kms:us-east-1:123456789012:key/xxx"

lambda_memory_detection = 1024
detection_engine_schedule = "rate(5 minutes)"

cloudwatch_log_retention_days = 30
```

## CI/CD Pipeline

### Pull Request Flow

```
Developer creates PR
        ↓
GitHub Actions triggered
        ↓
Run tests (test.yml)
        ↓
Run Terraform plan (terraform-plan.yml)
        ↓
Post plan as PR comment
        ↓
Code review + approval
        ↓
Merge to main
```

### Deployment Flow

```
Merge to main
        ↓
GitHub Actions triggered (deploy.yml)
        ↓
Build Lambda packages
        ↓
Upload to S3
        ↓
Terraform apply (dev)
        ↓
Run smoke tests
        ↓
Update Lambda code
        ↓
Send Slack notification
```

### Release Flow

```
Create git tag (v1.2.3)
        ↓
GitHub Actions triggered (release.yml)
        ↓
Run all tests
        ↓
Build Lambda packages
        ↓
Build web interface
        ↓
Create GitHub release
        ↓
Deploy to production
        ↓
Send notifications
```

## Best Practices

### Pre-Deployment

1. **Test locally:**
   ```bash
   pytest
   terraform validate
   ```

2. **Review changes:**
   ```bash
   git diff
   terraform plan
   ```

3. **Check cost estimates:**
   ```bash
   terraform plan | grep "will be created"
   ```

### Deployment

1. **Use staging first:**
   ```bash
   # Deploy to staging
   terraform apply -var-file=environments/staging.tfvars

   # Validate
   ./scripts/smoke-test.sh terraform-outputs.json

   # Then deploy to prod
   terraform apply -var-file=environments/prod.tfvars
   ```

2. **Tag releases:**
   ```bash
   git tag -a v1.2.3 -m "Release version 1.2.3"
   git push origin v1.2.3
   ```

3. **Monitor deployments:**
   ```bash
   # Watch GitHub Actions
   gh run watch

   # Check CloudWatch logs
   aws logs tail /aws/lambda/mantissa-log-detection-engine-prod --follow
   ```

### Post-Deployment

1. **Verify smoke tests pass**
2. **Check CloudWatch metrics**
3. **Review first detection results**
4. **Validate alert routing**
5. **Update documentation**

## Rollback Procedures

### Lambda Function Rollback

```bash
# List versions
aws lambda list-versions-by-function \
    --function-name mantissa-log-detection-engine-prod

# Rollback to previous version
aws lambda update-function-code \
    --function-name mantissa-log-detection-engine-prod \
    --s3-bucket lambda-artifacts \
    --s3-key lambda/detection-engine-v1.2.2.zip
```

### Infrastructure Rollback

```bash
# Revert to previous Terraform state
cd infrastructure/aws/terraform

# Show history
terraform state list

# Rollback with previous code
git checkout v1.2.2
terraform apply
```

### Full Rollback

```bash
# Destroy current deployment
./scripts/destroy.sh

# Checkout previous version
git checkout v1.2.2

# Redeploy
./scripts/deploy.sh
```

## Monitoring Deployments

### CloudWatch Logs

```bash
# Lambda function logs
aws logs tail /aws/lambda/mantissa-log-detection-engine-prod --follow

# API Gateway logs
aws logs tail API-Gateway-Execution-Logs_abc123/prod --follow
```

### Metrics

```bash
# Lambda invocations
aws cloudwatch get-metric-statistics \
    --namespace AWS/Lambda \
    --metric-name Invocations \
    --dimensions Name=FunctionName,Value=mantissa-log-detection-engine-prod \
    --start-time 2025-01-01T00:00:00Z \
    --end-time 2025-01-02T00:00:00Z \
    --period 3600 \
    --statistics Sum

# Athena query execution
aws cloudwatch get-metric-statistics \
    --namespace AWS/Athena \
    --metric-name EngineExecutionTime \
    --start-time 2025-01-01T00:00:00Z \
    --end-time 2025-01-02T00:00:00Z \
    --period 3600 \
    --statistics Average
```

## Troubleshooting

### Deployment Failures

**Terraform state locked:**
```bash
# Force unlock (use carefully)
terraform force-unlock <lock-id>
```

**Lambda package too large:**
```bash
# Use S3 upload instead
aws s3 cp build/lambda/detection-engine.zip s3://lambda-artifacts/
aws lambda update-function-code \
    --function-name mantissa-log-detection-engine-prod \
    --s3-bucket lambda-artifacts \
    --s3-key detection-engine.zip
```

**Permission denied:**
```bash
# Check AWS credentials
aws sts get-caller-identity

# Verify IAM permissions
aws iam simulate-principal-policy \
    --policy-source-arn <your-role-arn> \
    --action-names lambda:UpdateFunctionCode
```

### CI/CD Failures

**GitHub Actions workflow fails:**
1. Check workflow logs in GitHub Actions tab
2. Verify secrets are configured
3. Check AWS OIDC trust policy
4. Validate Terraform configuration

**Smoke tests fail:**
1. Check Terraform outputs are correct
2. Verify resources were created
3. Check CloudWatch logs for errors
4. Run smoke tests manually with verbose output

## Security Considerations

1. **Use OIDC for AWS authentication** (no long-lived credentials)
2. **Store secrets in AWS Secrets Manager**
3. **Enable MFA for production deployments**
4. **Restrict Terraform state bucket access**
5. **Use separate AWS accounts for environments**
6. **Enable CloudTrail for audit logging**
7. **Scan Lambda packages for vulnerabilities**
8. **Rotate credentials regularly**

## Resources

- [Terraform Documentation](https://www.terraform.io/docs)
- [GitHub Actions Documentation](https://docs.github.com/actions)
- [AWS CLI Documentation](https://docs.aws.amazon.com/cli/)
- [Mantissa Log GitHub Repository](https://github.com/clay-good/mantissa-log)
