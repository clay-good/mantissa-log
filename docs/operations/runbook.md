# Operations Runbook

This runbook covers daily operations, common tasks, and procedures for Mantissa Log.

## Daily Operations

### Morning Checklist

```bash
# 1. Check system health
bash scripts/smoke-test.sh terraform-outputs.json

# 2. Review overnight alerts
aws logs filter-log-events \
  --log-group-name /aws/lambda/mantissa-log-detection-engine \
  --start-time $(($(date -d 'yesterday' +%s) * 1000)) \
  --filter-pattern "[time, request_id, level=ERROR, ...]"

# 3. Check alert delivery
aws logs tail /aws/lambda/mantissa-log-alert-router --since 24h \
  | grep "Alert sent"

# 4. Monitor costs
aws ce get-cost-and-usage \
  --time-period Start=$(date -d '7 days ago' +%Y-%m-%d),End=$(date +%Y-%m-%d) \
  --granularity DAILY \
  --metrics BlendedCost
```

### Weekly Tasks

- Review new detection rules
- Analyze alert trends
- Check for false positives
- Update rule thresholds
- Rotate API keys (if applicable)
- Review CloudWatch dashboards
- Check S3 storage costs

### Monthly Tasks

- Review and tune detection rules
- Audit user access (Cognito)
- Review compliance logs
- Update documentation
- Plan capacity changes
- Review cost optimization opportunities
- Test disaster recovery procedures

## Common Operations

### Adding New Users

Create Cognito user for API access:

```bash
USER_POOL_ID=$(cat terraform-outputs.json | jq -r '.user_pool_id.value')
USER_EMAIL="newuser@company.com"
TEMP_PASSWORD="TempPass123!"

# Create user
aws cognito-idp admin-create-user \
  --user-pool-id $USER_POOL_ID \
  --username $USER_EMAIL \
  --user-attributes Name=email,Value=$USER_EMAIL Name=email_verified,Value=true \
  --temporary-password $TEMP_PASSWORD \
  --message-action SUPPRESS

# Set permanent password
aws cognito-idp admin-set-user-password \
  --user-pool-id $USER_POOL_ID \
  --username $USER_EMAIL \
  --password "SecurePass123!" \
  --permanent
```

### Tuning Detection Rules

**Analyze rule performance:**

```bash
# Check how often each rule triggers
aws logs filter-log-events \
  --log-group-name /aws/lambda/mantissa-log-detection-engine \
  --start-time $(($(date -d '7 days ago' +%s) * 1000)) \
  --filter-pattern '"rule_name"' \
  | jq '.events[].message' | jq -r '.rule_name' | sort | uniq -c | sort -nr
```

**Adjust threshold:**

```bash
# Edit rule file
vim rules/aws/cloudtrail/failed-logins.yaml

# Change threshold
threshold:
  count: 10  # Increased from 5
  window: "5m"

# Upload updated rule
RULES_BUCKET=$(cat terraform-outputs.json | jq -r '.rules_bucket.value')
aws s3 cp rules/aws/cloudtrail/failed-logins.yaml \
  s3://$RULES_BUCKET/rules/aws/cloudtrail/
```

### Investigating Alerts

**View recent alerts:**

```bash
# Get alerts from DynamoDB
STATE_TABLE=$(cat terraform-outputs.json | jq -r '.state_table_name.value')

aws dynamodb scan \
  --table-name $STATE_TABLE \
  --filter-expression "begins_with(alert_id, :prefix)" \
  --expression-attribute-values '{":prefix":{"S":"alert-"}}' \
  --limit 10
```

**Deep dive into specific alert:**

```bash
ALERT_ID="alert-20240115-001"

# Get alert details
aws dynamodb get-item \
  --table-name $STATE_TABLE \
  --key "{\"alert_id\":{\"S\":\"$ALERT_ID\"}}"

# Find related logs
aws logs filter-log-events \
  --log-group-name /aws/lambda/mantissa-log-detection-engine \
  --filter-pattern "$ALERT_ID"
```

**Query evidence:**

```bash
# Use natural language query
curl -X POST "$API_ENDPOINT/query" \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "question": "Show me all events from IP 203.0.113.42 in the last hour",
    "execute": true
  }'
```

### Common Maintenance Tasks

**Update Lambda functions:**

```bash
# Package new code
bash scripts/package-lambdas.sh

# Update functions
DETECTION_ENGINE=$(cat terraform-outputs.json | jq -r '.detection_engine_function_name.value')

aws lambda update-function-code \
  --function-name $DETECTION_ENGINE \
  --zip-file fileb://build/lambda/detection-engine.zip
```

**Add partitions to tables:**

```bash
DATABASE=$(cat terraform-outputs.json | jq -r '.database_name.value')
WORKGROUP=$(cat terraform-outputs.json | jq -r '.athena_workgroup_name.value')

# Add today's partition
YEAR=$(date +%Y)
MONTH=$(date +%m)
DAY=$(date +%d)

aws athena start-query-execution \
  --query-string "MSCK REPAIR TABLE cloudtrail" \
  --query-execution-context Database=$DATABASE \
  --work-group $WORKGROUP
```

**Clean old data:**

```bash
# Remove old Athena query results
ATHENA_BUCKET=$(cat terraform-outputs.json | jq -r '.athena_results_bucket.value')

aws s3 rm s3://$ATHENA_BUCKET/ --recursive \
  --exclude "*" \
  --include "*/$(date -d '30 days ago' +%Y/%m/%d)/*"
```

## Monitoring

### Key Metrics to Watch

**Detection Engine:**
- Execution success rate
- Query execution time
- Rules processed per cycle
- Alerts generated

**Alert Router:**
- Delivery success rate
- Destination failures
- Routing latency

**LLM Query Handler:**
- Query generation success rate
- LLM API latency
- SQL validation failures

### CloudWatch Dashboards

Create monitoring dashboard:

```bash
cat > dashboard.json << 'EOF'
{
  "widgets": [
    {
      "type": "metric",
      "properties": {
        "metrics": [
          ["AWS/Lambda", "Invocations", {"stat": "Sum"}],
          [".", "Errors", {"stat": "Sum"}],
          [".", "Duration", {"stat": "Average"}]
        ],
        "period": 300,
        "region": "us-east-1",
        "title": "Lambda Metrics"
      }
    }
  ]
}
EOF

aws cloudwatch put-dashboard \
  --dashboard-name mantissa-log-ops \
  --dashboard-body file://dashboard.json
```

### Setting Up Alarms

**Detection engine failures:**

```bash
aws cloudwatch put-metric-alarm \
  --alarm-name mantissa-log-detection-errors \
  --alarm-description "Alert on detection engine errors" \
  --metric-name Errors \
  --namespace AWS/Lambda \
  --statistic Sum \
  --period 300 \
  --evaluation-periods 2 \
  --threshold 5 \
  --comparison-operator GreaterThanThreshold \
  --dimensions Name=FunctionName,Value=mantissa-log-detection-engine \
  --alarm-actions arn:aws:sns:us-east-1:123456789012:ops-alerts
```

**High query costs:**

```bash
aws cloudwatch put-metric-alarm \
  --alarm-name mantissa-log-high-athena-cost \
  --alarm-description "Alert on high Athena costs" \
  --metric-name DataScannedInBytes \
  --namespace AWS/Athena \
  --statistic Sum \
  --period 86400 \
  --evaluation-periods 1 \
  --threshold 1000000000000 \
  --comparison-operator GreaterThanThreshold
```

## Common Queries

### Security Investigations

**Find all activity from suspicious IP:**

```sql
SELECT
    eventtime,
    eventname,
    useridentity.principalid,
    requestparameters
FROM cloudtrail
WHERE sourceipaddress = '203.0.113.42'
  AND year = '2024'
  AND month = '01'
  AND day = '15'
ORDER BY eventtime DESC
```

**Trace user activity:**

```sql
SELECT
    eventtime,
    eventname,
    sourceipaddress,
    resources
FROM cloudtrail
WHERE useridentity.principalid = 'AIDAI23EXAMPLE'
  AND year = '2024'
  AND month = '01'
ORDER BY eventtime DESC
```

**Find privilege escalations:**

```sql
SELECT
    eventtime,
    useridentity.principalid,
    eventname,
    requestparameters
FROM cloudtrail
WHERE eventsource = 'iam.amazonaws.com'
  AND eventname IN (
    'AttachUserPolicy',
    'AttachRolePolicy',
    'PutUserPolicy',
    'PutRolePolicy'
  )
  AND year = '2024'
  AND month = '01'
ORDER BY eventtime DESC
```

### Performance Analysis

**Query execution times:**

```sql
SELECT
    query_id,
    query,
    data_scanned_in_bytes / 1024 / 1024 / 1024 as gb_scanned,
    execution_time_millis / 1000 as execution_seconds
FROM athena_query_history
WHERE submission_date >= CURRENT_DATE - INTERVAL '7' DAY
ORDER BY data_scanned_in_bytes DESC
LIMIT 20
```

**Most expensive queries:**

```bash
# Check CloudWatch Logs Insights
aws logs start-query \
  --log-group-name /aws/lambda/mantissa-log-detection-engine \
  --start-time $(($(date -d '7 days ago' +%s) * 1000)) \
  --end-time $(($(date +%s) * 1000)) \
  --query-string '
    fields @timestamp, rule_name, data_scanned_bytes
    | filter data_scanned_bytes > 1000000000
    | sort data_scanned_bytes desc
    | limit 20
  '
```

## Incident Response

### Alert Triage

**Priority 1: Critical Alerts**
- Root account usage
- IAM policy changes granting admin access
- S3 bucket made public
- Security group opened to internet
- GuardDuty critical findings

**Actions:**
1. Verify alert is legitimate
2. Assess scope of impact
3. Begin containment
4. Notify security team
5. Start incident log

**Priority 2: High Alerts**
- Multiple failed logins
- Unusual API activity
- Large data transfers
- Configuration changes

**Actions:**
1. Review evidence
2. Check for related alerts
3. Investigate user/resource
4. Determine if escalation needed

### Investigation Workflow

```bash
# 1. Get alert details
ALERT_ID="alert-20240115-001"

aws dynamodb get-item \
  --table-name $STATE_TABLE \
  --key "{\"alert_id\":{\"S\":\"$ALERT_ID\"}}" \
  > alert-details.json

# 2. Extract key fields
jq -r '.Item.evidence.S' alert-details.json

# 3. Query related activity
# Use fields from evidence to build query

# 4. Check for related alerts
aws dynamodb scan \
  --table-name $STATE_TABLE \
  --filter-expression "sourceip = :ip" \
  --expression-attribute-values "{\":ip\":{\"S\":\"203.0.113.42\"}}"

# 5. Document findings
echo "Investigation: $ALERT_ID" > investigation-log.md
echo "Date: $(date)" >> investigation-log.md
echo "Analyst: $USER" >> investigation-log.md
```

### Containment Actions

**Disable compromised user:**

```bash
USER_NAME="compromised-user"

aws iam delete-access-key \
  --user-name $USER_NAME \
  --access-key-id AKIAIOSFODNN7EXAMPLE

aws iam attach-user-policy \
  --user-name $USER_NAME \
  --policy-arn arn:aws:iam::aws:policy/AWSDenyAll
```

**Block IP address:**

```bash
# Add to NACL
VPC_ID="vpc-12345678"
NACL_ID=$(aws ec2 describe-network-acls \
  --filters "Name=vpc-id,Values=$VPC_ID" \
  --query 'NetworkAcls[0].NetworkAclId' --output text)

aws ec2 create-network-acl-entry \
  --network-acl-id $NACL_ID \
  --rule-number 100 \
  --protocol -1 \
  --rule-action deny \
  --cidr-block 203.0.113.42/32 \
  --ingress
```

**Revoke active sessions:**

```bash
# Force user to re-authenticate
aws cognito-idp admin-user-global-sign-out \
  --user-pool-id $USER_POOL_ID \
  --username $USER_NAME
```

## Troubleshooting Workflows

### No Alerts Being Generated

```bash
# 1. Check EventBridge rule
RULE_NAME=$(cat terraform-outputs.json | jq -r '.detection_schedule_rule_name.value')
aws events describe-rule --name $RULE_NAME

# 2. Check Lambda executions
DETECTION_ENGINE=$(cat terraform-outputs.json | jq -r '.detection_engine_function_name.value')
aws cloudwatch get-metric-statistics \
  --namespace AWS/Lambda \
  --metric-name Invocations \
  --dimensions Name=FunctionName,Value=$DETECTION_ENGINE \
  --start-time $(date -u -d '1 hour ago' +%Y-%m-%dT%H:%M:%S) \
  --end-time $(date -u +%Y-%m-%dT%H:%M:%S) \
  --period 300 \
  --statistics Sum

# 3. Check for errors
aws logs tail /aws/lambda/$DETECTION_ENGINE --since 1h

# 4. Verify rules exist
RULES_BUCKET=$(cat terraform-outputs.json | jq -r '.rules_bucket.value')
aws s3 ls s3://$RULES_BUCKET/rules/ --recursive

# 5. Test rule manually
aws lambda invoke \
  --function-name $DETECTION_ENGINE \
  --log-type Tail \
  response.json
```

### Queries Timing Out

```bash
# 1. Check query execution
DATABASE=$(cat terraform-outputs.json | jq -r '.database_name.value')
WORKGROUP=$(cat terraform-outputs.json | jq -r '.athena_workgroup_name.value')

# Get recent query executions
aws athena list-query-executions \
  --work-group $WORKGROUP \
  --max-results 10

# Get specific query details
QUERY_ID="abc-def-123"
aws athena get-query-execution --query-execution-id $QUERY_ID

# 2. Check data scanned
# Look for queries scanning > 1GB

# 3. Verify partitions exist
aws athena start-query-execution \
  --query-string "SHOW PARTITIONS cloudtrail" \
  --query-execution-context Database=$DATABASE \
  --work-group $WORKGROUP

# 4. Optimize rule
# Add partition filters, reduce time window
```

### High Costs

```bash
# 1. Check Athena costs
aws ce get-cost-and-usage \
  --time-period Start=2024-01-01,End=2024-01-31 \
  --granularity DAILY \
  --metrics BlendedCost \
  --filter '{"Dimensions":{"Key":"SERVICE","Values":["Amazon Athena"]}}'

# 2. Find expensive queries
# Use CloudWatch Logs Insights on detection engine logs

# 3. Optimize
# - Add partition filters to all rules
# - Convert to Parquet format
# - Reduce detection frequency
# - Disable low-value rules
```

## Backup and Recovery

### Backup Important Data

```bash
# 1. Export detection rules
aws s3 sync s3://$RULES_BUCKET/rules/ rules-backup/

# 2. Backup DynamoDB state
aws dynamodb create-backup \
  --table-name $STATE_TABLE \
  --backup-name mantissa-log-state-$(date +%Y%m%d)

# 3. Export Terraform state
cd infrastructure/aws/terraform
terraform state pull > terraform-state-backup-$(date +%Y%m%d).json

# 4. Backup secrets
aws secretsmanager list-secrets \
  --query 'SecretList[?starts_with(Name, `mantissa-log`)].Name' \
  --output text | while read SECRET; do
    aws secretsmanager get-secret-value --secret-id $SECRET > "secrets-backup/$SECRET.json"
done
```

### Disaster Recovery

**Complete environment loss:**

```bash
# 1. Restore from backups
git clone <repository-url>
cd mantissa-log-dev

# 2. Restore Terraform state
cd infrastructure/aws/terraform
terraform init
# Restore state from backup

# 3. Re-run deployment
bash scripts/deploy.sh

# 4. Restore rules
aws s3 sync rules-backup/ s3://$RULES_BUCKET/rules/

# 5. Restore secrets
for SECRET_FILE in secrets-backup/*.json; do
  SECRET_NAME=$(basename $SECRET_FILE .json)
  aws secretsmanager create-secret \
    --name $SECRET_NAME \
    --secret-string "$(jq -r '.SecretString' $SECRET_FILE)"
done
```

## Performance Optimization

### Query Optimization

```sql
-- Bad: No partition filters
SELECT * FROM cloudtrail
WHERE eventtime > '2024-01-15T00:00:00Z'

-- Good: With partition filters
SELECT * FROM cloudtrail
WHERE year = '2024'
  AND month = '01'
  AND day = '15'
  AND eventtime > '2024-01-15T00:00:00Z'
```

### Cost Optimization

- Use partition filters in all queries
- Convert logs to Parquet format
- Set S3 lifecycle policies
- Tune detection frequency
- Disable low-value rules
- Use query result reuse in Athena

### Scaling Up

See [Scaling Guide](scaling.md) for detailed scaling strategies.
