# CI/CD Pipeline Documentation

This document describes the continuous integration and continuous deployment (CI/CD) pipeline for Mantissa Log.

## Overview

Mantissa Log uses GitHub Actions for CI/CD with three primary workflows:

1. **Tests** - Run on every push and pull request
2. **Terraform Plan** - Run on pull requests affecting infrastructure
3. **Deploy** - Run on main branch commits, tags, and manual triggers

## Workflows

### 1. Tests Workflow

**File**: `.github/workflows/test.yml`

**Triggers**:
- Push to `main` or `develop` branches
- Pull requests to `main` or `develop` branches

**Jobs**:

#### Test Job
Runs tests across multiple Python versions (3.11, 3.12):

1. Checkout code
2. Set up Python with caching
3. Install dependencies
4. Run unit tests with coverage
5. Run integration tests
6. Upload coverage to Codecov

#### Lint Job
Checks code quality:

1. Checkout code
2. Set up Python
3. Install linting tools
4. Check code formatting with black
5. Lint with flake8
6. Type check with mypy

**Required Secrets**: None

**Usage**:
```bash
# Locally run tests
make test

# Run specific test suites
make test-unit
make test-integration
make test-coverage
```

### 2. Terraform Plan Workflow

**File**: `.github/workflows/terraform-plan.yml`

**Triggers**:
- Pull requests affecting `infrastructure/` directory
- Pull requests affecting `.github/workflows/terraform-plan.yml`

**Jobs**:

#### Terraform Plan
Runs for both `dev` and `staging` environments in parallel:

1. Checkout code
2. Configure AWS credentials (OIDC)
3. Setup Terraform
4. Create backend configuration
5. Run `terraform fmt -check`
6. Run `terraform init`
7. Run `terraform validate`
8. Run `terraform plan`
9. Post plan output as PR comment
10. Fail if plan fails

**Required Secrets**:
- `AWS_DEPLOY_ROLE_ARN` - AWS IAM role ARN for OIDC authentication
- `AWS_REGION` - AWS region for deployment
- `TERRAFORM_STATE_BUCKET` - S3 bucket for Terraform state
- `TERRAFORM_LOCK_TABLE` - DynamoDB table for state locking
- `LAMBDA_ARTIFACTS_BUCKET` - S3 bucket for Lambda function packages

**Permissions**:
- `id-token: write` - For OIDC authentication
- `contents: read` - For reading repository
- `pull-requests: write` - For commenting on PRs

### 3. Deploy Workflow

**File**: `.github/workflows/deploy.yml`

**Triggers**:
- Push to `main` branch (deploys to `dev`)
- Tags matching `v*` (deploys to `prod`)
- Manual workflow dispatch (choose environment)

**Jobs**:

#### Deploy
Comprehensive deployment process:

1. **Setup**
   - Checkout code
   - Set up Python with caching
   - Install Python dependencies
   - Configure AWS credentials

2. **Terraform**
   - Setup Terraform
   - Create backend configuration
   - Run `terraform init`
   - Run `terraform plan`
   - Run `terraform apply` (if on main, tag, or manual)
   - Extract outputs to JSON

3. **Lambda Functions**
   - Package all Lambda functions
   - Upload packages to S3
   - Update function code for core functions

4. **Web Application**
   - Setup Node.js with caching
   - Build and deploy web app to S3/CloudFront

5. **Post-Deployment**
   - Upload detection rules to S3
   - Run smoke tests
   - Create deployment summary
   - Notify Slack (optional)

**Required Secrets**:
- `AWS_DEPLOY_ROLE_ARN`
- `AWS_REGION`
- `TERRAFORM_STATE_BUCKET`
- `TERRAFORM_LOCK_TABLE`
- `LAMBDA_ARTIFACTS_BUCKET`
- `SLACK_WEBHOOK_URL` (optional)

**Manual Trigger**:
```bash
# Via GitHub UI:
# Actions > Deploy > Run workflow > Select environment

# Via GitHub CLI:
gh workflow run deploy.yml -f environment=prod
```

## Required GitHub Secrets

### AWS Authentication

```bash
# AWS OIDC Role ARN
AWS_DEPLOY_ROLE_ARN=arn:aws:iam::123456789012:role/GitHubActionsDeployRole

# AWS Region
AWS_REGION=us-east-1
```

### Terraform State

```bash
# S3 bucket for Terraform state
TERRAFORM_STATE_BUCKET=mantissa-log-terraform-state

# DynamoDB table for state locking
TERRAFORM_LOCK_TABLE=mantissa-log-terraform-locks
```

### Lambda Artifacts

```bash
# S3 bucket for Lambda deployment packages
LAMBDA_ARTIFACTS_BUCKET=mantissa-log-lambda-artifacts
```

### Slack Notifications (Optional)

```bash
# Slack webhook URL for deployment notifications
SLACK_WEBHOOK_URL=https://hooks.slack.com/services/YOUR/WEBHOOK/URL
```

## Setting Up AWS OIDC

### 1. Create OIDC Provider

```bash
aws iam create-open-id-connect-provider \
  --url https://token.actions.githubusercontent.com \
  --client-id-list sts.amazonaws.com \
  --thumbprint-list 6938fd4d98bab03faadb97b34396831e3780aea1
```

### 2. Create IAM Role

```hcl
# infrastructure/aws/iam/github-actions-role.tf

data "aws_iam_policy_document" "github_actions_assume_role" {
  statement {
    actions = ["sts:AssumeRoleWithWebIdentity"]

    principals {
      type        = "Federated"
      identifiers = [aws_iam_openid_connect_provider.github.arn]
    }

    condition {
      test     = "StringEquals"
      variable = "token.actions.githubusercontent.com:aud"
      values   = ["sts.amazonaws.com"]
    }

    condition {
      test     = "StringLike"
      variable = "token.actions.githubusercontent.com:sub"
      values   = ["repo:your-org/mantissa-log:*"]
    }
  }
}

resource "aws_iam_role" "github_actions" {
  name               = "GitHubActionsDeployRole"
  assume_role_policy = data.aws_iam_policy_document.github_actions_assume_role.json
}

resource "aws_iam_role_policy_attachment" "github_actions_admin" {
  role       = aws_iam_role.github_actions.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}
```

### 3. Add Secrets to GitHub

```bash
# Via GitHub UI:
# Settings > Secrets and variables > Actions > New repository secret

# Or via GitHub CLI:
gh secret set AWS_DEPLOY_ROLE_ARN --body "arn:aws:iam::123456789012:role/GitHubActionsDeployRole"
gh secret set AWS_REGION --body "us-east-1"
gh secret set TERRAFORM_STATE_BUCKET --body "mantissa-log-terraform-state"
gh secret set TERRAFORM_LOCK_TABLE --body "mantissa-log-terraform-locks"
gh secret set LAMBDA_ARTIFACTS_BUCKET --body "mantissa-log-lambda-artifacts"
```

## Local Development

### Running Tests Locally

```bash
# Install dependencies
make install

# Run all tests
make test

# Run specific test suites
make test-unit          # Unit tests only
make test-integration   # Integration tests only
make test-sigma         # Sigma conversion tests
make test-coverage      # With coverage report

# Code quality
make lint               # Run linters
make format             # Auto-format code
make type-check         # Type checking
```

### Pre-commit Hooks

Install pre-commit hooks to run checks before commits:

```bash
# Install pre-commit
pip install pre-commit

# Install hooks
pre-commit install

# Run hooks manually
pre-commit run --all-files
```

**Hooks configured** (`.pre-commit-config.yaml`):
- Trailing whitespace removal
- YAML validation
- Large file prevention
- Black formatting
- Flake8 linting
- MyPy type checking
- Terraform formatting

### Testing Deployment Locally

```bash
# Test Lambda packaging
bash scripts/package-lambdas.sh

# Test Terraform plan
cd infrastructure/aws/terraform
terraform init
terraform plan -var-file=environments/dev.tfvars

# Test web build
cd web
npm install
npm run build
```

## Environment Management

### Environment Promotion

The typical flow:

```
Developer → PR → Review → Merge → Dev
                                    ↓
                            Manual approval
                                    ↓
                                  Staging
                                    ↓
                            Manual approval
                                    ↓
                            Tag release (v1.0.0)
                                    ↓
                                  Production
```

### Creating a Release

```bash
# Tag for production deployment
git tag v1.0.0
git push origin v1.0.0

# GitHub Actions automatically deploys to prod
```

### Manual Deployment

```bash
# Via GitHub UI
# Actions > Deploy > Run workflow > Select environment > Run

# Via GitHub CLI
gh workflow run deploy.yml -f environment=staging
```

## Monitoring Deployments

### GitHub Actions UI

View workflow runs:
```
Repository > Actions > Select workflow
```

### Deployment Status

Check via GitHub CLI:
```bash
# List recent workflow runs
gh run list --workflow=deploy.yml

# View specific run
gh run view RUN_ID

# Watch logs in real-time
gh run watch RUN_ID
```

### CloudWatch Logs

After deployment, check Lambda logs:
```bash
# Detection engine
aws logs tail /aws/lambda/mantissa-log-dev-detection-engine --follow

# LLM query handler
aws logs tail /aws/lambda/mantissa-log-dev-llm-query --follow
```

## Troubleshooting

### Failed Tests

1. Check test output in GitHub Actions
2. Run tests locally to reproduce
3. Fix issues and push again

```bash
make test-unit      # Run failing tests locally
make lint           # Check code quality issues
```

### Failed Terraform Plan

1. Review plan output in PR comment
2. Check for syntax errors
3. Validate locally

```bash
cd infrastructure/aws/terraform
terraform fmt -recursive
terraform validate
terraform plan -var-file=environments/dev.tfvars
```

### Failed Deployment

1. Check GitHub Actions logs
2. Review CloudWatch logs
3. Check Terraform state

```bash
# View workflow logs
gh run view --log

# Check Terraform state
cd infrastructure/aws/terraform
terraform show
terraform state list
```

### Rollback Deployment

```bash
# Revert to previous commit
git revert HEAD
git push origin main

# Or deploy specific version
gh workflow run deploy.yml -f environment=prod
```

## Security Best Practices

### Secrets Management

- Never commit secrets to repository
- Use GitHub Secrets for sensitive data
- Rotate secrets regularly
- Use OIDC instead of long-lived credentials

### Least Privilege

- GitHub Actions role should have minimum required permissions
- Consider separate roles per environment
- Enable CloudTrail logging for audit

### Code Review

- All changes require PR review
- Terraform plans posted to PR for visibility
- Automated tests must pass
- Manual approval for production deployments

## Cost Optimization

### GitHub Actions Minutes

- Free tier: 2,000 minutes/month
- Use caching to reduce build times
- Skip unnecessary jobs when possible

**Current usage**:
- Tests: ~5 minutes per run
- Terraform Plan: ~3 minutes per environment
- Deploy: ~15 minutes per deployment

### AWS Costs

- OIDC authentication: Free
- S3 for Terraform state: <$1/month
- DynamoDB for state locking: <$1/month
- Lambda artifacts bucket: <$5/month

**Total CI/CD AWS cost**: ~$10/month

## Advanced Configuration

### Matrix Builds

Test across multiple versions:

```yaml
strategy:
  matrix:
    python-version: ['3.11', '3.12']
    os: [ubuntu-latest, macos-latest]
```

### Conditional Steps

Skip steps based on conditions:

```yaml
- name: Deploy to Production
  if: startsWith(github.ref, 'refs/tags/v')
  run: ./scripts/deploy.sh prod
```

### Custom Workflows

Create custom workflows for specific tasks:

```yaml
# .github/workflows/security-scan.yml
name: Security Scan
on:
  schedule:
    - cron: '0 0 * * 0'  # Weekly

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Run Bandit
        run: bandit -r src/
      - name: Run Safety
        run: safety check
```

## References

- [GitHub Actions Documentation](https://docs.github.com/en/actions)
- [Terraform GitHub Actions](https://github.com/hashicorp/setup-terraform)
- [AWS OIDC with GitHub Actions](https://docs.github.com/en/actions/deployment/security-hardening-your-deployments/configuring-openid-connect-in-amazon-web-services)
- [Codecov GitHub Action](https://github.com/codecov/codecov-action)
