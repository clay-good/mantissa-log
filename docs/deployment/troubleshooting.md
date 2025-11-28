# Troubleshooting Guide

This guide helps diagnose and resolve common issues during deployment and operation of Mantissa Log.

## Deployment Issues

### Terraform State Bucket Creation Fails

**Symptom:**
```
Error creating S3 bucket: BucketAlreadyExists
```

**Cause:**
S3 bucket names must be globally unique across all AWS accounts.

**Solution:**
1. Choose a different bucket name with a unique prefix:
   ```bash
   # Use organization or account-specific prefix
   mantissa-log-mycompany-terraform-state
   mantissa-log-123456789012-terraform-state
   ```

2. Or delete the existing bucket if you own it:
   ```bash
   aws s3 rb s3://mantissa-log-terraform-state --force
   ```

### Terraform Init Fails

**Symptom:**
```
Error: Failed to initialize backend
```

**Cause:**
- Backend configuration incorrect
- Insufficient permissions
- DynamoDB lock table doesn't exist

**Solution:**

Check backend configuration:
```bash
cat infrastructure/aws/terraform/backend.tf
```

Verify DynamoDB table exists:
```bash
aws dynamodb describe-table --table-name mantissa-log-terraform-locks
```

Recreate table if needed:
```bash
aws dynamodb create-table \
  --table-name mantissa-log-terraform-locks \
  --attribute-definitions AttributeName=LockID,AttributeType=S \
  --key-schema AttributeName=LockID,KeyType=HASH \
  --billing-mode PAY_PER_REQUEST
```

### Lambda Packaging Fails

**Symptom:**
```
ERROR: Could not find a version that satisfies the requirement
```

**Cause:**
- Python version mismatch
- Missing dependencies
- Network connectivity issues

**Solution:**

Verify Python version:
```bash
python3 --version
# Should be 3.11 or higher
```

Install dependencies manually:
```bash
pip install -r requirements.txt --upgrade
```

Use specific Python version:
```bash
python3.11 -m pip install -r requirements.txt -t build/lambda/layer/python
```

Check network connectivity:
```bash
curl -I https://pypi.org
```

### Lambda Package Too Large

**Symptom:**
```
WARNING: detection-engine.zip is larger than 50MB direct upload limit
```

**Cause:**
Lambda package with dependencies exceeds direct upload limit.

**Solution:**

The deployment automatically handles this, but if manual upload needed:

1. Upload to S3:
   ```bash
   aws s3 cp build/lambda/detection-engine.zip s3://your-bucket/lambda/
   ```

2. Update Lambda from S3:
   ```bash
   aws lambda update-function-code \
     --function-name mantissa-log-detection-engine \
     --s3-bucket your-bucket \
     --s3-key lambda/detection-engine.zip
   ```

Or reduce package size:
```bash
# Remove unnecessary dependencies
# Edit requirements.txt to remove unused packages
# Rebuild
bash scripts/package-lambdas.sh
```

### Terraform Apply Fails - Resource Limit

**Symptom:**
```
Error: LimitExceededException: Account has exceeded maximum number of Lambda functions
```

**Cause:**
AWS service quota exceeded.

**Solution:**

Check current limits:
```bash
aws service-quotas get-service-quota \
  --service-code lambda \
  --quota-code L-9FEE3D26
```

Request quota increase:
1. Go to AWS Service Quotas console
2. Search for Lambda
3. Request increase for "Concurrent executions"

Or clean up unused Lambda functions:
```bash
# List all functions
aws lambda list-functions --query 'Functions[].FunctionName'

# Delete unused functions
aws lambda delete-function --function-name old-function
```

### Terraform Apply Fails - Permissions

**Symptom:**
```
Error: AccessDenied: User is not authorized to perform: iam:CreateRole
```

**Cause:**
IAM user/role lacks required permissions.

**Solution:**

Check current permissions:
```bash
aws iam get-user-policy --user-name your-user --policy-name your-policy
```

Add required permissions:
```bash
# Create custom policy
cat > mantissa-log-policy.json <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "iam:CreateRole",
        "iam:AttachRolePolicy",
        "iam:PutRolePolicy",
        "lambda:*",
        "s3:*",
        "dynamodb:*"
      ],
      "Resource": "*"
    }
  ]
}
EOF

# Attach policy
aws iam put-user-policy \
  --user-name your-user \
  --policy-name MantissaLogDeployment \
  --policy-document file://mantissa-log-policy.json
```

Or use administrator access (not recommended for production):
```bash
aws iam attach-user-policy \
  --user-name your-user \
  --policy-arn arn:aws:iam::aws:policy/AdministratorAccess
```

### CloudTrail Creation Fails

**Symptom:**
```
Error: InsufficientS3BucketPolicyException
```

**Cause:**
S3 bucket policy doesn't allow CloudTrail to write logs.

**Solution:**

The deployment script should handle this, but if manual fix needed:

```bash
# Get logs bucket name
LOGS_BUCKET=$(cat terraform-outputs.json | jq -r '.logs_bucket.value')

# Create bucket policy
cat > cloudtrail-policy.json <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AWSCloudTrailAclCheck",
      "Effect": "Allow",
      "Principal": {
        "Service": "cloudtrail.amazonaws.com"
      },
      "Action": "s3:GetBucketAcl",
      "Resource": "arn:aws:s3:::$LOGS_BUCKET"
    },
    {
      "Sid": "AWSCloudTrailWrite",
      "Effect": "Allow",
      "Principal": {
        "Service": "cloudtrail.amazonaws.com"
      },
      "Action": "s3:PutObject",
      "Resource": "arn:aws:s3:::$LOGS_BUCKET/cloudtrail/*",
      "Condition": {
        "StringEquals": {
          "s3:x-amz-acl": "bucket-owner-full-control"
        }
      }
    }
  ]
}
EOF

# Apply policy
aws s3api put-bucket-policy \
  --bucket $LOGS_BUCKET \
  --policy file://cloudtrail-policy.json
```

### Cognito User Creation Fails

**Symptom:**
```
InvalidPasswordException: Password does not conform to policy
```

**Cause:**
Password doesn't meet Cognito password policy requirements.

**Solution:**

Use a password that meets all requirements:
- Minimum 8 characters
- At least one uppercase letter
- At least one lowercase letter
- At least one number
- At least one special character (!@#$%^&*)

Example valid password: `SecurePass123!`

## Smoke Test Failures

### S3 Bucket Tests Fail

**Symptom:**
```
Testing Logs bucket exists... FAIL
```

**Cause:**
- Terraform didn't create bucket
- Wrong region
- Permissions issue

**Solution:**

Check if bucket exists:
```bash
LOGS_BUCKET=$(cat terraform-outputs.json | jq -r '.logs_bucket.value')
aws s3 ls s3://$LOGS_BUCKET
```

Check region:
```bash
aws s3api get-bucket-location --bucket $LOGS_BUCKET
```

Manually create if needed:
```bash
aws s3 mb s3://$LOGS_BUCKET --region us-east-1
```

### Lambda Function Tests Fail

**Symptom:**
```
Testing Detection engine function exists... FAIL
```

**Cause:**
- Lambda function not created
- Wrong function name in outputs
- Permissions issue

**Solution:**

List Lambda functions:
```bash
aws lambda list-functions --query 'Functions[?contains(FunctionName, `mantissa-log`)].FunctionName'
```

Check Terraform outputs:
```bash
cat terraform-outputs.json | jq -r '.detection_engine_function_name.value'
```

Check Lambda logs for creation errors:
```bash
aws cloudformation describe-stack-events \
  --stack-name mantissa-log \
  --query 'StackEvents[?ResourceType==`AWS::Lambda::Function`]'
```

### DynamoDB Table Tests Fail

**Symptom:**
```
Testing State table has TTL enabled... FAIL
```

**Cause:**
TTL not enabled on table.

**Solution:**

Enable TTL manually:
```bash
STATE_TABLE=$(cat terraform-outputs.json | jq -r '.state_table_name.value')

aws dynamodb update-time-to-live \
  --table-name $STATE_TABLE \
  --time-to-live-specification "Enabled=true, AttributeName=ttl"
```

Verify TTL status:
```bash
aws dynamodb describe-time-to-live --table-name $STATE_TABLE
```

### API Gateway Test Fails

**Symptom:**
```
Testing API endpoint is accessible... FAIL
```

**Cause:**
- API not deployed
- Wrong endpoint URL
- API requires authentication

**Solution:**

Check API Gateway deployment:
```bash
API_ID=$(cat terraform-outputs.json | jq -r '.api_endpoint.value' | cut -d'/' -f3 | cut -d'.' -f1)
aws apigateway get-deployments --rest-api-id $API_ID
```

Test endpoint directly:
```bash
API_ENDPOINT=$(cat terraform-outputs.json | jq -r '.api_endpoint.value')
curl -v $API_ENDPOINT/health
```

If returns 401/403, this is expected (requires authentication).

### Athena Query Test Fails

**Symptom:**
```
Testing Athena query execution... FAIL (Status: FAILED)
```

**Cause:**
- Glue database not created
- Athena workgroup misconfigured
- Query execution error

**Solution:**

Check query execution error:
```bash
WORKGROUP=$(cat terraform-outputs.json | jq -r '.athena_workgroup_name.value')
QUERY_ID=<from-error-message>

aws athena get-query-execution \
  --query-execution-id $QUERY_ID \
  --query 'QueryExecution.Status.StateChangeReason'
```

Check Glue database:
```bash
DATABASE=$(cat terraform-outputs.json | jq -r '.database_name.value')
aws glue get-database --name $DATABASE
```

Test manual query:
```bash
aws athena start-query-execution \
  --query-string "SELECT 1" \
  --query-execution-context Database=$DATABASE \
  --work-group $WORKGROUP \
  --result-configuration OutputLocation=s3://$ATHENA_BUCKET/test/
```

## Runtime Issues

### Detection Engine Not Running

**Symptom:**
No alerts being generated, logs show no activity.

**Cause:**
- EventBridge rule disabled
- Lambda function errors
- No detection rules loaded

**Solution:**

Check EventBridge rule:
```bash
RULE_NAME=$(cat terraform-outputs.json | jq -r '.detection_schedule_rule_name.value')
aws events describe-rule --name $RULE_NAME
```

Enable if disabled:
```bash
aws events enable-rule --name $RULE_NAME
```

Check Lambda logs:
```bash
FUNCTION_NAME=$(cat terraform-outputs.json | jq -r '.detection_engine_function_name.value')
aws logs tail /aws/lambda/$FUNCTION_NAME --since 1h
```

Check detection rules:
```bash
RULES_BUCKET=$(cat terraform-outputs.json | jq -r '.rules_bucket.value')
aws s3 ls s3://$RULES_BUCKET/rules/
```

Manually trigger detection:
```bash
aws lambda invoke \
  --function-name $FUNCTION_NAME \
  --log-type Tail \
  response.json

# Check response
cat response.json
```

### Alerts Not Being Sent

**Symptom:**
Detection engine finds issues but alerts don't arrive.

**Cause:**
- Alert router not configured
- Secrets not set up
- Handler errors

**Solution:**

Check alert router logs:
```bash
ALERT_ROUTER=$(cat terraform-outputs.json | jq -r '.alert_router_function_name.value')
aws logs tail /aws/lambda/$ALERT_ROUTER --since 1h --follow
```

Verify secrets exist:
```bash
aws secretsmanager list-secrets \
  --query 'SecretList[?contains(Name, `mantissa-log/alerts`)].Name'
```

Test alert routing directly:
```bash
cat > test-alert.json <<EOF
{
  "alert_id": "test-001",
  "title": "Test Alert",
  "description": "Manual test",
  "severity": "low",
  "rule_name": "test",
  "source": "manual",
  "timestamp": "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
}
EOF

aws lambda invoke \
  --function-name $ALERT_ROUTER \
  --payload file://test-alert.json \
  --log-type Tail \
  response.json

# Check for errors in base64 decoded logs
cat response.json
```

Check handler configuration:
```bash
# Slack
aws secretsmanager get-secret-value \
  --secret-id mantissa-log/alerts/slack \
  --query SecretString --output text | jq

# PagerDuty
aws secretsmanager get-secret-value \
  --secret-id mantissa-log/alerts/pagerduty \
  --query SecretString --output text | jq
```

### LLM Queries Failing

**Symptom:**
```
Error: Failed to generate query
```

**Cause:**
- LLM provider not configured
- API key invalid/missing
- Rate limiting
- Model not available

**Solution:**

Check LLM provider configuration:
```bash
aws lambda get-function-configuration \
  --function-name mantissa-log-llm-query \
  --query 'Environment.Variables'
```

For Bedrock:
```bash
# Check model access
aws bedrock list-foundation-models \
  --region us-east-1 \
  --query 'modelSummaries[?contains(modelId, `claude`)]'
```

For Anthropic/OpenAI:
```bash
# Check secret exists
aws secretsmanager get-secret-value \
  --secret-id mantissa-log/llm/api-key \
  --query SecretString --output text
```

Check Lambda logs for detailed error:
```bash
aws logs tail /aws/lambda/mantissa-log-llm-query --since 10m
```

Test LLM provider directly:
```bash
# For Bedrock
aws bedrock-runtime invoke-model \
  --model-id anthropic.claude-3-haiku-20240307-v1:0 \
  --body '{"messages":[{"role":"user","content":"test"}],"anthropic_version":"bedrock-2023-05-31","max_tokens":100}' \
  --region us-east-1 \
  output.json

cat output.json
```

### High Costs

**Symptom:**
AWS bill higher than expected.

**Cause:**
- Athena scanning too much data
- High query frequency
- Large log volumes
- Inefficient queries

**Solution:**

Check Athena costs:
```bash
# Get data scanned per query
aws athena get-query-execution \
  --query-execution-id <query-id> \
  --query 'QueryExecution.Statistics.DataScannedInBytes'
```

Optimize queries:
1. Add partition filters to detection rules
2. Use columnar storage (Parquet)
3. Limit query scope

Check Lambda costs:
```bash
# Get invocation count
aws cloudwatch get-metric-statistics \
  --namespace AWS/Lambda \
  --metric-name Invocations \
  --dimensions Name=FunctionName,Value=mantissa-log-detection-engine \
  --start-time $(date -u -d '30 days ago' +%Y-%m-%dT%H:%M:%S) \
  --end-time $(date -u +%Y-%m-%dT%H:%M:%S) \
  --period 86400 \
  --statistics Sum
```

Reduce detection frequency:
```bash
# Edit EventBridge rule
aws events put-rule \
  --name mantissa-log-detection-schedule \
  --schedule-expression "rate(15 minutes)"  # Change from 5 to 15 minutes
```

Convert S3 logs to Parquet:
```bash
# Run Glue crawler to create Parquet tables
# Update detection rules to use Parquet tables
```

Set up cost alerts (see aws-deployment.md).

### Performance Issues

**Symptom:**
Queries taking too long, timeouts.

**Cause:**
- Large data volumes
- Inefficient queries
- No partitioning

**Solution:**

Enable partitioning:
```sql
-- In Glue table definition
CREATE EXTERNAL TABLE cloudtrail_partitioned (
  ...
)
PARTITIONED BY (
  year STRING,
  month STRING,
  day STRING
)
```

Add partition filters to queries:
```sql
SELECT * FROM cloudtrail
WHERE year = '2024'
  AND month = '01'
  AND day = '15'
  AND eventTime > '2024-01-15T00:00:00Z'
```

Increase Lambda timeout:
```bash
aws lambda update-function-configuration \
  --function-name mantissa-log-detection-engine \
  --timeout 900  # 15 minutes (max)
```

Increase Lambda memory (more CPU):
```bash
aws lambda update-function-configuration \
  --function-name mantissa-log-detection-engine \
  --memory-size 1024  # Default is 512
```

Use Athena query optimization:
```sql
-- Create optimized tables
CREATE TABLE cloudtrail_optimized
WITH (
  format = 'PARQUET',
  parquet_compression = 'SNAPPY',
  partitioned_by = ARRAY['year', 'month', 'day']
) AS
SELECT * FROM cloudtrail
```

## Data Issues

### Missing Logs

**Symptom:**
Expected logs not appearing in Athena queries.

**Cause:**
- Log source not configured
- S3 path incorrect
- Glue crawler not run
- Partition not added

**Solution:**

Check S3 bucket for logs:
```bash
LOGS_BUCKET=$(cat terraform-outputs.json | jq -r '.logs_bucket.value')
aws s3 ls s3://$LOGS_BUCKET/cloudtrail/ --recursive | head -20
```

Run Glue crawler:
```bash
aws glue start-crawler --name mantissa-log-crawler

# Wait for completion
aws glue get-crawler --name mantissa-log-crawler \
  --query 'Crawler.State'
```

Add partitions manually:
```bash
# For CloudTrail
DATABASE=$(cat terraform-outputs.json | jq -r '.database_name.value')

aws athena start-query-execution \
  --query-string "MSCK REPAIR TABLE cloudtrail" \
  --query-execution-context Database=$DATABASE \
  --work-group mantissa-log
```

Verify table schema:
```bash
aws glue get-table \
  --database-name $DATABASE \
  --name cloudtrail \
  --query 'Table.StorageDescriptor.Columns'
```

### Incorrect Query Results

**Symptom:**
Queries return wrong or incomplete data.

**Cause:**
- Schema mismatch
- Data type conversion errors
- Time zone issues

**Solution:**

Check data samples:
```sql
SELECT * FROM cloudtrail LIMIT 10
```

Verify schema matches data:
```bash
# Compare Glue schema with actual S3 files
aws s3 cp s3://$LOGS_BUCKET/cloudtrail/2024/01/15/file.json - | jq '.' | head -50
```

Fix time zone issues:
```sql
-- Convert to UTC explicitly
SELECT
  CAST(eventtime AS TIMESTAMP) AT TIME ZONE 'UTC' as event_time_utc
FROM cloudtrail
```

Update Glue table schema:
```bash
aws glue update-table --database-name $DATABASE --table-input file://table-schema.json
```

## Diagnostic Commands

### Comprehensive Health Check

```bash
#!/bin/bash

echo "=== Mantissa Log Health Check ==="
echo ""

# Check AWS connectivity
echo "AWS Connectivity:"
aws sts get-caller-identity && echo "  ✓ AWS CLI working" || echo "  ✗ AWS CLI failed"
echo ""

# Check Terraform outputs
echo "Terraform Outputs:"
if [ -f terraform-outputs.json ]; then
  echo "  ✓ Outputs file exists"
  jq -r 'keys[]' terraform-outputs.json | head -5
else
  echo "  ✗ Outputs file missing"
fi
echo ""

# Check Lambda functions
echo "Lambda Functions:"
for func in detection-engine llm-query alert-router; do
  if aws lambda get-function --function-name mantissa-log-$func &>/dev/null; then
    echo "  ✓ $func exists"
  else
    echo "  ✗ $func missing"
  fi
done
echo ""

# Check S3 buckets
echo "S3 Buckets:"
for bucket in logs athena-results rules; do
  BUCKET_NAME=$(cat terraform-outputs.json 2>/dev/null | jq -r ".${bucket//-/_}_bucket.value")
  if [ -n "$BUCKET_NAME" ] && aws s3 ls s3://$BUCKET_NAME &>/dev/null; then
    echo "  ✓ $bucket exists"
  else
    echo "  ✗ $bucket missing or inaccessible"
  fi
done
echo ""

# Check DynamoDB tables
echo "DynamoDB Tables:"
STATE_TABLE=$(cat terraform-outputs.json 2>/dev/null | jq -r '.state_table_name.value')
if [ -n "$STATE_TABLE" ] && aws dynamodb describe-table --table-name $STATE_TABLE &>/dev/null; then
  echo "  ✓ State table exists"
else
  echo "  ✗ State table missing"
fi
echo ""

# Check EventBridge rules
echo "EventBridge Rules:"
RULE_NAME=$(cat terraform-outputs.json 2>/dev/null | jq -r '.detection_schedule_rule_name.value')
if [ -n "$RULE_NAME" ]; then
  STATE=$(aws events describe-rule --name $RULE_NAME --query 'State' --output text 2>/dev/null)
  if [ "$STATE" = "ENABLED" ]; then
    echo "  ✓ Detection schedule enabled"
  else
    echo "  ✗ Detection schedule disabled or missing"
  fi
fi
echo ""

# Check recent Lambda executions
echo "Recent Lambda Activity:"
for func in detection-engine llm-query alert-router; do
  LOG_GROUP="/aws/lambda/mantissa-log-$func"
  if aws logs describe-log-groups --log-group-name-prefix $LOG_GROUP &>/dev/null; then
    LAST_EVENT=$(aws logs describe-log-streams \
      --log-group-name $LOG_GROUP \
      --order-by LastEventTime \
      --descending \
      --max-items 1 \
      --query 'logStreams[0].lastEventTimestamp' \
      --output text 2>/dev/null)
    if [ -n "$LAST_EVENT" ] && [ "$LAST_EVENT" != "None" ]; then
      AGO=$(( ($(date +%s) - $LAST_EVENT/1000) / 60 ))
      echo "  ✓ $func: active ${AGO}m ago"
    else
      echo "  ? $func: no recent activity"
    fi
  fi
done
```

Save as `health-check.sh` and run:
```bash
bash health-check.sh
```

## Getting Help

### Collect Diagnostic Information

When reporting issues, collect:

```bash
# System information
echo "OS: $(uname -a)"
echo "AWS CLI: $(aws --version)"
echo "Terraform: $(terraform --version)"
echo "Python: $(python3 --version)"

# AWS account
aws sts get-caller-identity

# Terraform state
cd infrastructure/aws/terraform
terraform show -json > terraform-state.json

# Lambda logs (last 1 hour)
for func in detection-engine llm-query alert-router; do
  aws logs filter-log-events \
    --log-group-name /aws/lambda/mantissa-log-$func \
    --start-time $(($(date +%s) - 3600))000 \
    > logs-$func.json
done

# CloudWatch metrics
aws cloudwatch get-metric-statistics \
  --namespace AWS/Lambda \
  --metric-name Errors \
  --dimensions Name=FunctionName,Value=mantissa-log-detection-engine \
  --start-time $(date -u -d '1 hour ago' +%Y-%m-%dT%H:%M:%S) \
  --end-time $(date -u +%Y-%m-%dT%H:%M:%S) \
  --period 300 \
  --statistics Sum
```

### Support Channels

1. Check documentation
2. Search GitHub issues
3. Review CloudWatch logs
4. Check AWS CloudFormation events
5. Contact support with diagnostic information

### Common Log Patterns

Look for these patterns in CloudWatch Logs:

**Success:**
```
[INFO] Detection cycle completed successfully
[INFO] Generated 0 alerts
```

**Configuration issues:**
```
[ERROR] Failed to load detection rules
[ERROR] Secrets Manager secret not found
```

**Runtime errors:**
```
[ERROR] Athena query failed
[ERROR] LLM provider timeout
[ERROR] Alert routing failed
```

**Performance issues:**
```
[WARN] Query execution time exceeded 60s
[WARN] Lambda timeout approaching
```
