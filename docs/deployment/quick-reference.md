# Deployment Quick Reference

Common deployment tasks and commands for Mantissa Log.

## Initial Deployment

### Full Stack Deployment

Deploy everything (infrastructure + web interface):

```bash
bash scripts/deploy.sh
```

Follow the interactive prompts. The script handles:
- Terraform infrastructure
- Lambda function packaging
- CloudTrail configuration
- Admin user creation
- Web application build and deployment

### Infrastructure Only

Deploy just the backend infrastructure:

```bash
cd infrastructure/aws/terraform
terraform init
terraform plan -var-file=environments/dev.tfvars
terraform apply -var-file=environments/dev.tfvars
```

### Web Application Only

Deploy just the React web interface (after infrastructure exists):

```bash
bash scripts/deploy-web.sh
```

Requires `terraform-outputs.json` from infrastructure deployment.

## Updating Deployments

### Update Everything

Update infrastructure, Lambda code, and rules:

```bash
bash scripts/update.sh
```

### Update Web App Only

Redeploy just the web interface after UI changes:

```bash
bash scripts/deploy-web.sh
```

This rebuilds and deploys the React app without touching infrastructure.

### Update Lambda Functions Only

Rebuild and update Lambda function code:

```bash
# Package functions
bash scripts/package-lambdas.sh

# Update specific function
aws lambda update-function-code \
  --function-name mantissa-log-dev-detection-engine \
  --zip-file fileb://dist/lambdas/detection-engine.zip

# Or update all via Terraform
cd infrastructure/aws/terraform
terraform apply -var-file=environments/dev.tfvars
```

### Update Detection Rules Only

Upload new or modified rules:

```bash
# Get rules bucket from outputs
RULES_BUCKET=$(cat terraform-outputs.json | jq -r '.rules_bucket.value')

# Upload rules
aws s3 sync rules/ "s3://$RULES_BUCKET/rules/" \
  --exclude "*.md" \
  --exclude "README*"
```

Rules are automatically loaded on next detection cycle (5 minutes).

## Environment Management

### Deploy to Multiple Environments

```bash
# Deploy dev environment
bash scripts/deploy.sh
# Select "dev" when prompted

# Deploy staging environment
bash scripts/deploy.sh
# Select "staging" when prompted

# Deploy production environment
bash scripts/deploy.sh
# Select "prod" when prompted
```

Each environment gets its own:
- Terraform state file
- S3 buckets
- Lambda functions
- DynamoDB tables
- CloudFront distribution

### Switch Between Environments

```bash
# View dev environment
cd infrastructure/aws/terraform
terraform workspace select dev
terraform output

# View prod environment
terraform workspace select prod
terraform output
```

### Environment-Specific Variables

Edit environment tfvars files:

```bash
# Development settings
vim infrastructure/aws/terraform/environments/dev.tfvars

# Production settings
vim infrastructure/aws/terraform/environments/prod.tfvars
```

## Common Tasks

### View Deployment Outputs

```bash
# From terraform-outputs.json
cat terraform-outputs.json | jq

# From Terraform directly
cd infrastructure/aws/terraform
terraform output

# Specific output
terraform output api_endpoint
terraform output web_url
```

### Get Web Application URL

```bash
cat terraform-outputs.json | jq -r '.web_url.value'
```

Or from AWS:

```bash
DIST_ID=$(cat terraform-outputs.json | jq -r '.cloudfront_distribution_id.value')
aws cloudfront get-distribution --id $DIST_ID --query 'Distribution.DomainName' --output text
```

### Get API Endpoint

```bash
cat terraform-outputs.json | jq -r '.api_endpoint.value'
```

### View Lambda Function Logs

```bash
# Detection engine
aws logs tail /aws/lambda/mantissa-log-dev-detection-engine --follow

# LLM query handler
aws logs tail /aws/lambda/mantissa-log-dev-llm-query --follow

# Alert router
aws logs tail /aws/lambda/mantissa-log-dev-alert-router --follow
```

### Manually Trigger Detection Engine

```bash
FUNCTION_NAME=$(cat terraform-outputs.json | jq -r '.detection_engine_function_name.value')

aws lambda invoke \
  --function-name "$FUNCTION_NAME" \
  response.json

cat response.json
```

### Test Web Deployment Locally

```bash
cd web

# Create local .env file
cat > .env.local <<EOF
VITE_API_ENDPOINT=https://your-api-id.execute-api.us-east-1.amazonaws.com/prod
VITE_AWS_REGION=us-east-1
VITE_USER_POOL_ID=us-east-1_XXXXXXXXX
VITE_USER_POOL_CLIENT_ID=your-client-id
EOF

# Run development server
npm run dev

# Access at http://localhost:5173
```

### Invalidate CloudFront Cache

```bash
DIST_ID=$(cat terraform-outputs.json | jq -r '.cloudfront_distribution_id.value')

aws cloudfront create-invalidation \
  --distribution-id "$DIST_ID" \
  --paths "/*"
```

## Troubleshooting

### Deployment Failed Partway Through

1. Check Terraform state:
   ```bash
   cd infrastructure/aws/terraform
   terraform show
   ```

2. Attempt to continue:
   ```bash
   terraform apply -var-file=environments/dev.tfvars
   ```

3. If state is corrupted, use state management:
   ```bash
   terraform state list
   terraform state pull > backup.tfstate
   ```

### Web App Won't Load

1. Verify deployment:
   ```bash
   WEB_BUCKET=$(cat terraform-outputs.json | jq -r '.web_bucket_name.value')
   aws s3 ls "s3://$WEB_BUCKET/"
   ```

2. Check CloudFront status:
   ```bash
   DIST_ID=$(cat terraform-outputs.json | jq -r '.cloudfront_distribution_id.value')
   aws cloudfront get-distribution --id "$DIST_ID" --query 'Distribution.Status'
   ```
   Must be "Deployed"

3. Redeploy:
   ```bash
   bash scripts/deploy-web.sh
   ```

### Lambda Function Errors

1. View recent errors:
   ```bash
   aws logs filter-log-events \
     --log-group-name /aws/lambda/mantissa-log-dev-detection-engine \
     --filter-pattern "ERROR" \
     --start-time $(date -u -d '1 hour ago' +%s)000
   ```

2. Update function code:
   ```bash
   bash scripts/package-lambdas.sh
   terraform apply -var-file=environments/dev.tfvars
   ```

### Terraform State Locked

```bash
# Get lock ID from error message
LOCK_ID="abc-123-def-456"

# Force unlock (use with caution)
terraform force-unlock "$LOCK_ID"
```

### Can't Authenticate to Web Interface

1. Verify Cognito user exists:
   ```bash
   USER_POOL_ID=$(cat terraform-outputs.json | jq -r '.cognito_user_pool_id.value')
   aws cognito-idp list-users --user-pool-id "$USER_POOL_ID"
   ```

2. Reset user password:
   ```bash
   aws cognito-idp admin-set-user-password \
     --user-pool-id "$USER_POOL_ID" \
     --username "admin@example.com" \
     --password "NewPassword123!" \
     --permanent
   ```

## Cleanup

### Delete Specific Environment

```bash
bash scripts/destroy.sh
# Select environment to destroy when prompted
```

### Delete All Resources

```bash
# Dev environment
cd infrastructure/aws/terraform
terraform workspace select dev
terraform destroy -var-file=environments/dev.tfvars

# Staging environment
terraform workspace select staging
terraform destroy -var-file=environments/staging.tfvars

# Production environment
terraform workspace select prod
terraform destroy -var-file=environments/prod.tfvars
```

### Empty S3 Buckets Before Destroy

Terraform can't destroy non-empty S3 buckets:

```bash
# Get bucket names
LOGS_BUCKET=$(cat terraform-outputs.json | jq -r '.logs_bucket_name.value')
WEB_BUCKET=$(cat terraform-outputs.json | jq -r '.web_bucket_name.value')

# Empty buckets
aws s3 rm "s3://$LOGS_BUCKET" --recursive
aws s3 rm "s3://$WEB_BUCKET" --recursive

# Now run destroy
terraform destroy -var-file=environments/dev.tfvars
```

## Performance Optimization

### Enable Lambda Reserved Concurrency

For production workloads:

```bash
aws lambda put-function-concurrency \
  --function-name mantissa-log-prod-detection-engine \
  --reserved-concurrent-executions 10
```

### Enable DynamoDB Auto Scaling

Add to terraform variables:

```hcl
dynamodb_billing_mode = "PROVISIONED"
dynamodb_read_capacity = 5
dynamodb_write_capacity = 5
enable_autoscaling = true
```

### Configure CloudFront Custom Domain

1. Create ACM certificate in us-east-1
2. Add CNAME to CloudFront distribution
3. Create Route53 alias record

See [AWS Deployment Guide](aws-deployment.md) for details.

## Monitoring

### CloudWatch Dashboard

Create a custom dashboard:

```bash
aws cloudwatch put-dashboard \
  --dashboard-name mantissa-log-prod \
  --dashboard-body file://cloudwatch-dashboard.json
```

### Billing Alerts

Set up cost monitoring:

```bash
aws cloudwatch put-metric-alarm \
  --alarm-name mantissa-log-monthly-cost \
  --metric-name EstimatedCharges \
  --namespace AWS/Billing \
  --statistic Maximum \
  --period 21600 \
  --evaluation-periods 1 \
  --threshold 100 \
  --comparison-operator GreaterThanThreshold \
  --region us-east-1
```

### Lambda Execution Metrics

```bash
# Invocations
aws cloudwatch get-metric-statistics \
  --namespace AWS/Lambda \
  --metric-name Invocations \
  --dimensions Name=FunctionName,Value=mantissa-log-dev-detection-engine \
  --start-time $(date -u -d '1 day ago' +%Y-%m-%dT%H:%M:%S) \
  --end-time $(date -u +%Y-%m-%dT%H:%M:%S) \
  --period 3600 \
  --statistics Sum

# Errors
aws cloudwatch get-metric-statistics \
  --namespace AWS/Lambda \
  --metric-name Errors \
  --dimensions Name=FunctionName,Value=mantissa-log-dev-detection-engine \
  --start-time $(date -u -d '1 day ago' +%Y-%m-%dT%H:%M:%S) \
  --end-time $(date -u +%Y-%m-%dT%H:%M:%S) \
  --period 3600 \
  --statistics Sum
```

## Useful Commands Reference

```bash
# Package Lambda functions
bash scripts/package-lambdas.sh

# Deploy infrastructure
bash scripts/deploy.sh

# Deploy web app only
bash scripts/deploy-web.sh

# Update existing deployment
bash scripts/update.sh

# Run smoke tests
bash scripts/smoke-test.sh terraform-outputs.json

# Destroy everything
bash scripts/destroy.sh

# View Terraform outputs
cat terraform-outputs.json | jq

# Tail Lambda logs
aws logs tail /aws/lambda/FUNCTION_NAME --follow

# List S3 buckets
aws s3 ls

# List Lambda functions
aws lambda list-functions --query 'Functions[?contains(FunctionName, `mantissa-log`)].FunctionName'

# List DynamoDB tables
aws dynamodb list-tables --query 'TableNames[?contains(@, `mantissa-log`)]'

# Get CloudFront distributions
aws cloudfront list-distributions --query 'DistributionList.Items[*].[Id,DomainName]'

# View API Gateway APIs
aws apigatewayv2 get-apis --query 'Items[?contains(Name, `mantissa-log`)]'
```
