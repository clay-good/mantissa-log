# Quick Start Guide with Sample Data

Get hands-on with Mantissa Log in 15 minutes using pre-generated sample data. This tutorial walks you through deployment, data ingestion, and creating your first security detection without needing real AWS logs.

## What You'll Learn

By the end of this guide, you will:

- Deploy Mantissa Log infrastructure to AWS
- Ingest realistic sample CloudTrail data
- Run natural language queries against the data
- Create a brute force detection rule
- Configure Slack alerts with PII/PHI redaction
- Test the complete alert pipeline

**Time Required:** 15 minutes
**Cost:** < $1 for sample data testing
**Prerequisites:** AWS account, AWS CLI, Terraform, Python 3.9+

---

## Prerequisites Check

Before starting, verify you have the required tools:

```bash
# Check AWS CLI
aws --version
# Expected: aws-cli/2.x.x or higher

# Check Terraform
terraform --version
# Expected: Terraform v1.0+

# Check Python
python --version
# Expected: Python 3.9+ or 3.11+

# Check AWS credentials
aws sts get-caller-identity
# Should return your AWS account ID
```

If any tools are missing, see the [Prerequisites Guide](../deployment/prerequisites.md) for installation instructions.

---

## Step 1: Deploy Infrastructure (5 minutes)

### Clone Repository

```bash
git clone https://github.com/your-org/mantissa-log.git
cd mantissa-log
```

### Configure Terraform Backend

Create a backend configuration for Terraform state:

```bash
cd infrastructure/aws/terraform

# Create backend config
cat > backend.tf <<EOF
terraform {
  backend "s3" {
    bucket = "mantissa-log-tfstate-$(date +%s)"
    key    = "terraform.tfstate"
    region = "us-east-1"
  }
}
EOF

# Create the S3 bucket for state
aws s3 mb s3://$(grep bucket backend.tf | awk '{print $3}' | tr -d '"')
```

### Set Variables

Create `terraform.tfvars` with your configuration:

```bash
cat > terraform.tfvars <<EOF
project_name = "mantissa-log"
environment  = "dev"
aws_region   = "us-east-1"

# VPC Configuration
vpc_cidr = "10.0.0.0/16"

# Enable CloudTrail ingestion
enable_cloudtrail = true

# Cost control for testing
athena_query_result_retention_days = 7
log_retention_days                 = 30
EOF
```

### Deploy

```bash
# Initialize Terraform
terraform init

# Review the plan
terraform plan

# Deploy (takes ~5-10 minutes)
terraform apply -auto-approve
```

**What gets created:**
- S3 buckets for logs, rules, and query results
- Glue database and tables for log schema
- Athena workgroup for queries
- Lambda functions for detection engine and query handler
- DynamoDB tables for state and metadata
- EventBridge rules for scheduled detection
- IAM roles and policies

### Save Outputs

```bash
# Save outputs for later use
terraform output -json > ../../../terraform-outputs.json

# Quick reference
export LOG_BUCKET=$(terraform output -raw log_bucket)
export ATHENA_DB=$(terraform output -raw athena_database)
export ATHENA_WORKGROUP=$(terraform output -raw athena_workgroup)

echo "LOG_BUCKET=$LOG_BUCKET"
echo "ATHENA_DB=$ATHENA_DB"
echo "ATHENA_WORKGROUP=$ATHENA_WORKGROUP"
```

---

## Step 2: Generate and Ingest Sample Data (3 minutes)

We've provided a sample data generator that creates realistic CloudTrail logs including security events.

### Install Dependencies

```bash
cd ../../../scripts
pip install -r requirements.txt
```

### Generate Sample CloudTrail Logs

```bash
python generate-sample-data.py \
  --bucket $LOG_BUCKET \
  --prefix cloudtrail/ \
  --events 1000 \
  --days 7 \
  --include-threats
```

**What this creates:**

The generator produces ~1000 CloudTrail events over the last 7 days, including:

**Normal Activity (70%):**
- EC2 instance launches and terminations
- S3 bucket operations (CreateBucket, PutObject, GetObject)
- IAM policy changes and user creation
- VPC and security group modifications
- CloudWatch log operations

**Suspicious Activity (30%):**
- **Brute force attacks:** 47 failed login attempts from IP 203.0.113.42 targeting admin account
- **Privilege escalation:** IAM policy changes granting excessive permissions
- **Data exfiltration:** Large S3 GetObject operations from unusual IPs
- **Unusual regions:** API calls from regions not typically used
- **After-hours access:** Administrative actions outside business hours

### Verify Upload

```bash
aws s3 ls s3://$LOG_BUCKET/cloudtrail/ --recursive | head -10
```

Expected output:
```
2024-11-28 10:00:00   12345 cloudtrail/2024/11/28/event_001.json
2024-11-28 10:00:01   11892 cloudtrail/2024/11/28/event_002.json
...
```

### Update Glue Table Partitions

CloudTrail logs are partitioned by date. Update the Glue catalog to recognize the new partitions:

```bash
aws athena start-query-execution \
  --query-string "MSCK REPAIR TABLE cloudtrail_logs" \
  --query-execution-context "Database=$ATHENA_DB" \
  --work-group $ATHENA_WORKGROUP \
  --result-configuration "OutputLocation=s3://$LOG_BUCKET/athena-results/"
```

### Verify Data in Athena

Test that data is queryable:

```bash
# Count total events
aws athena start-query-execution \
  --query-string "SELECT COUNT(*) as event_count FROM cloudtrail_logs WHERE eventdate >= CURRENT_DATE - INTERVAL '7' DAY" \
  --query-execution-context "Database=$ATHENA_DB" \
  --work-group $ATHENA_WORKGROUP \
  --result-configuration "OutputLocation=s3://$LOG_BUCKET/athena-results/" \
  --output json > query-result.json

# Get the query execution ID
QUERY_ID=$(cat query-result.json | jq -r '.QueryExecutionId')

# Wait for query to complete (poll every 2 seconds)
while true; do
  STATUS=$(aws athena get-query-execution --query-execution-id $QUERY_ID | jq -r '.QueryExecution.Status.State')
  echo "Query status: $STATUS"

  if [ "$STATUS" = "SUCCEEDED" ]; then
    break
  elif [ "$STATUS" = "FAILED" ]; then
    echo "Query failed!"
    aws athena get-query-execution --query-execution-id $QUERY_ID | jq '.QueryExecution.Status'
    exit 1
  fi

  sleep 2
done

# Get results
aws athena get-query-results --query-execution-id $QUERY_ID
```

Expected: ~1000 events

---

## Step 3: Run Your First Query (2 minutes)

Now let's query the sample data using natural language.

### Deploy Web UI (Optional)

If you want to use the web interface:

```bash
cd ../web

# Install dependencies
npm install

# Configure environment
cat > .env <<EOF
VITE_API_ENDPOINT=https://YOUR_API_GATEWAY_URL
VITE_AWS_REGION=us-east-1
EOF

# Build
npm run build

# Deploy to S3
export WEB_BUCKET=$(cat ../terraform-outputs.json | jq -r '.web_bucket.value')
aws s3 sync dist/ s3://$WEB_BUCKET/
```

Access at: `http://$WEB_BUCKET.s3-website-us-east-1.amazonaws.com`

### Query via API

Alternatively, use the API directly:

```bash
cd ../scripts

# Get API endpoint from outputs
API_ENDPOINT=$(cat ../terraform-outputs.json | jq -r '.api_endpoint.value')

# Authenticate and get token (using demo user)
# Note: In production, you'd use Cognito properly
USER_ID="demo-user"

# Ask a natural language question
curl -X POST "$API_ENDPOINT/query" \
  -H "Content-Type: application/json" \
  -d "{
    \"user_id\": \"$USER_ID\",
    \"question\": \"Show me failed login attempts in the last 24 hours\",
    \"execute\": true
  }" | jq .
```

**Expected Response:**

```json
{
  "session_id": "sess-abc123",
  "sql": "SELECT eventtime, useridentity.username as user, sourceipaddress as source_ip, awsregion as region, errorcode, errormessage FROM cloudtrail_logs WHERE eventdate >= CURRENT_DATE - INTERVAL '1' DAY AND errorcode = 'Failed authentication' ORDER BY eventtime DESC LIMIT 100",
  "results": [
    {
      "eventtime": "2024-11-28T10:15:33Z",
      "user": "admin",
      "source_ip": "203.0.113.42",
      "region": "us-east-1",
      "errorcode": "Failed authentication",
      "errormessage": "Incorrect password"
    },
    {
      "eventtime": "2024-11-28T10:14:12Z",
      "user": "admin",
      "source_ip": "203.0.113.42",
      "region": "us-east-1",
      "errorcode": "Failed authentication",
      "errormessage": "Incorrect password"
    }
  ],
  "row_count": 47,
  "cost_estimate": {
    "data_scanned_mb": 12.5,
    "estimated_cost_usd": 0.00006
  }
}
```

### Follow-up Query

The system maintains session context, so you can refine queries:

```bash
curl -X POST "$API_ENDPOINT/query" \
  -H "Content-Type: application/json" \
  -d "{
    \"user_id\": \"$USER_ID\",
    \"session_id\": \"sess-abc123\",
    \"question\": \"Group by source IP and count failures\",
    \"execute\": true
  }" | jq .
```

**Key Insights from Results:**

- IP **203.0.113.42** has 47 failed login attempts
- All targeting **admin** account
- All within a 2-minute window
- Classic **brute force** pattern!

---

## Step 4: Create Detection Rule (3 minutes)

Let's create a rule to automatically detect this brute force pattern.

### Create Rule File

```bash
cd ../rules

# Create custom rules directory
mkdir -p custom

# Create brute force detection rule
cat > custom/brute_force_detection.yaml <<'EOF'
name: brute_force_detection
display_name: Brute Force Authentication Attempts
description: Detects 10+ failed login attempts from same IP within 10 minutes
enabled: true
severity: high
category: authentication

query: |
  SELECT
    sourceipaddress,
    useridentity.username as targeted_user,
    COUNT(*) as failure_count,
    MIN(eventtime) as first_attempt,
    MAX(eventtime) as last_attempt,
    ARBITRARY(awsregion) as region
  FROM cloudtrail_logs
  WHERE eventdate >= CURRENT_DATE - INTERVAL '1' DAY
    AND errorcode = 'Failed authentication'
  GROUP BY sourceipaddress, useridentity.username
  HAVING COUNT(*) >= 10
    AND MAX(eventtime) - MIN(eventtime) <= INTERVAL '10' MINUTE

threshold:
  count: 1  # Alert on any match
  window: 5m

schedule:
  enabled: true
  interval_minutes: 5
  lookback_minutes: 15

metadata:
  mitre_attack:
    - T1110  # Brute Force
    - T1110.001  # Password Guessing
  tags:
    - authentication
    - brute-force
    - credential-access
  references:
    - https://attack.mitre.org/techniques/T1110/

alert_template:
  title: "Brute Force Attack Detected"
  description: |
    Multiple failed login attempts detected from {{sourceipaddress}}
    targeting user {{targeted_user}}.

    This indicates a potential brute force attack attempting to gain
    unauthorized access to the account.

  fields:
    - name: source_ip
      value: "{{sourceipaddress}}"
    - name: targeted_user
      value: "{{targeted_user}}"
    - name: failure_count
      value: "{{failure_count}}"
    - name: time_range
      value: "{{first_attempt}} to {{last_attempt}}"
    - name: region
      value: "{{region}}"

  recommended_actions:
    - Block source IP {{sourceipaddress}} at network perimeter
    - Reset password for user {{targeted_user}}
    - Enable MFA for the targeted account
    - Review CloudTrail logs for any successful logins from this IP
    - Check for lateral movement if credentials were compromised
EOF
```

### Validate Rule

```bash
cd ../scripts

# Validate rule syntax
python validate-rules.py ../rules/custom/brute_force_detection.yaml
```

Expected output:
```
✓ Validating ../rules/custom/brute_force_detection.yaml
✓ Schema validation passed
✓ SQL query is valid
✓ All required fields present
✓ Rule is valid!
```

### Upload Rule

```bash
# Upload to S3 rules bucket
export RULES_BUCKET=$(cat ../terraform-outputs.json | jq -r '.rules_bucket.value')

aws s3 cp ../rules/custom/brute_force_detection.yaml \
  s3://$RULES_BUCKET/rules/custom/brute_force_detection.yaml

# Verify upload
aws s3 ls s3://$RULES_BUCKET/rules/custom/
```

### Test Rule Manually

Before waiting for the scheduled run, test the rule immediately:

```bash
python test-rule.py \
  --rule-file ../rules/custom/brute_force_detection.yaml \
  --user-id demo-user \
  --verbose
```

**Expected Output:**

```
=== Testing Rule: brute_force_detection ===

Query:
------
SELECT
  sourceipaddress,
  useridentity.username as targeted_user,
  COUNT(*) as failure_count,
  MIN(eventtime) as first_attempt,
  MAX(eventtime) as last_attempt,
  ARBITRARY(awsregion) as region
FROM cloudtrail_logs
WHERE eventdate >= CURRENT_DATE - INTERVAL '1' DAY
  AND errorcode = 'Failed authentication'
GROUP BY sourceipaddress, useridentity.username
HAVING COUNT(*) >= 10
  AND MAX(eventtime) - MIN(eventtime) <= INTERVAL '10' MINUTE

Results:
--------
Row 1:
  sourceipaddress: 203.0.113.42
  targeted_user: admin
  failure_count: 47
  first_attempt: 2024-11-28 10:13:55
  last_attempt: 2024-11-28 10:15:33
  region: us-east-1

Match Count: 1
Threshold: 1
Result: ALERT TRIGGERED ✓

Alert would be generated with:
  Severity: high
  Title: Brute Force Attack Detected
  Source IP: 203.0.113.42
  Targeted User: admin
  Failure Count: 47
```

Perfect! The rule detects our simulated brute force attack.

---

## Step 5: Set Up Slack Alerts (5 minutes)

Configure Slack to receive alerts when detection rules trigger.

### Create Slack App

1. Go to [api.slack.com/apps](https://api.slack.com/apps)
2. Click **Create New App** → **From scratch**
3. App Name: **Mantissa Log Alerts**
4. Select your workspace
5. Click **Create App**

### Enable Incoming Webhooks

1. In app settings, click **Incoming Webhooks** (left sidebar)
2. Toggle **Activate Incoming Webhooks** to **On**
3. Scroll down, click **Add New Webhook to Workspace**
4. Select channel: **#security-alerts** (or create it first)
5. Click **Allow**
6. Copy the **Webhook URL** (starts with `https://hooks.slack.com/services/...`)

### Configure Integration via API

```bash
cd ../scripts

# Create integration configuration
cat > integration-config.json <<EOF
{
  "user_id": "demo-user",
  "integration_type": "slack",
  "integration_id": "slack-security-alerts",
  "config": {
    "webhook_url": "https://hooks.slack.com/services/YOUR/WEBHOOK/URL",
    "channel": "#security-alerts",
    "username": "Mantissa Log",
    "icon_emoji": ":rotating_light:"
  },
  "message_template": {
    "text": ":rotating_light: *{{severity}} Alert: {{rule_name}}*\n\n*Description:* {{description}}\n\n*Details:*\n{{alert_fields}}\n\n*Time:* {{timestamp}}\n*Rule ID:* {{rule_id}}"
  },
  "pii_redaction": {
    "enabled": true,
    "redact_emails": true,
    "redact_phones": true,
    "redact_ssn": true,
    "redact_credit_cards": true,
    "redact_ip_addresses": false
  }
}
EOF

# Upload integration config to DynamoDB
python configure-integration.py --config integration-config.json
```

**Note on PII Redaction:**

- We enabled redaction for emails, phones, SSN, and credit cards
- **IP addresses are preserved** because they provide critical security context for incident response
- Redaction only applies to alert payloads sent to Slack, NOT to stored logs

### Link Rule to Integration

Update the rule to use this Slack integration:

```bash
# Add integration to rule config
cat > rule-integration.json <<EOF
{
  "rule_id": "brute_force_detection",
  "integrations": [
    {
      "integration_id": "slack-security-alerts",
      "enabled": true
    }
  ]
}
EOF

python configure-rule-integration.py --config rule-integration.json
```

### Send Test Alert

Verify the end-to-end alert pipeline:

```bash
python test-rule.py \
  --rule-file ../rules/custom/brute_force_detection.yaml \
  --user-id demo-user \
  --send-alerts
```

**Check your Slack channel!** You should see:

```
🚨 HIGH Alert: Brute Force Authentication Attempts

Description: Detects 10+ failed login attempts from same IP within 10 minutes

Details:
• Source IP: 203.0.113.42
• Targeted User: admin
• Failure Count: 47
• Region: us-east-1
• Time Range: 2024-11-28 10:13:55 to 10:15:33

Time: 2024-11-28 10:20:15 UTC
Rule ID: brute_force_detection
```

---

## Step 6: Monitor and Verify (2 minutes)

The detection engine runs automatically every 5 minutes. Let's monitor it.

### Check Detection Engine Logs

```bash
# Tail the detection engine Lambda logs
aws logs tail /aws/lambda/mantissa-log-detection-engine --follow
```

You'll see logs like:

```
[INFO] Starting detection cycle
[INFO] Loaded 1 detection rule(s)
[INFO] Executing rule: brute_force_detection
[INFO] Query returned 1 result(s)
[INFO] Alert triggered for brute_force_detection
[INFO] Sending alert to integration: slack-security-alerts
[INFO] Alert sent successfully
[INFO] Detection cycle complete
```

### View Alert History

Query the alerts DynamoDB table:

```bash
export ALERTS_TABLE=$(cat ../terraform-outputs.json | jq -r '.alerts_table.value')

aws dynamodb query \
  --table-name $ALERTS_TABLE \
  --key-condition-expression "pk = :pk" \
  --expression-attribute-values '{":pk":{"S":"user#demo-user"}}' \
  --scan-index-forward false \
  --limit 5 | jq '.Items'
```

### Monitor Integration Health

Check the health status of your Slack integration:

```bash
# Query integration health from DynamoDB
export INTEGRATION_HEALTH_TABLE=$(cat ../terraform-outputs.json | jq -r '.integration_health_table.value')

aws dynamodb get-item \
  --table-name $INTEGRATION_HEALTH_TABLE \
  --key '{"pk":{"S":"user#demo-user"},"sk":{"S":"integration#slack-security-alerts"}}' | jq '.Item'
```

Expected response showing healthy status:
```json
{
  "status": "healthy",
  "success_rate": 100.0,
  "total_requests": 1,
  "failed_requests": 0,
  "last_success": "2024-11-28T10:20:15Z",
  "avg_response_time_ms": 234
}
```

---

## What You've Accomplished

Congratulations! In 15 minutes, you've:

- ✅ Deployed complete Mantissa Log infrastructure
- ✅ Ingested 1000 sample CloudTrail events
- ✅ Queried logs using natural language
- ✅ Created a brute force detection rule
- ✅ Configured Slack integration with PII redaction
- ✅ Tested end-to-end alert delivery
- ✅ Verified automated detection cycles

---

## Next Steps

### 1. Explore More Queries

Try these natural language questions:

```bash
# Data exfiltration indicators
"Show me large S3 GetObject operations from unusual IPs"

# Privilege escalation
"Find IAM policy changes that grant administrator access"

# After-hours activity
"Show me administrative actions outside business hours"

# Unusual regions
"List API calls from regions we don't normally use"
```

### 2. Import Pre-built Detection Rules

Mantissa Log includes a library of detection rules:

```bash
cd ../rules

# Validate all authentication rules
python ../scripts/validate-rules.py authentication/

# Upload all authentication rules
aws s3 sync authentication/ s3://$RULES_BUCKET/rules/authentication/

# List available rule categories
ls -l
```

Available categories:
- `authentication/` - Login failures, MFA bypass, unusual access
- `cloud/` - Unauthorized API calls, resource creation, config changes
- `network/` - Port scanning, data exfiltration, unusual traffic

### 3. Set Up Additional Integrations

Configure more alert destinations:

**Jira for Ticket Creation:**
- Navigate to Settings → Integrations → Add Integration → Jira
- Follow the wizard to connect to your Jira instance
- Link high-severity rules to auto-create tickets

**PagerDuty for Incident Escalation:**
- Add PagerDuty integration with your API key
- Configure escalation policies
- Link critical rules to trigger pages

**Email Notifications:**
- Add email integration with SES
- Configure email templates
- Set up distribution lists per severity

### 4. Tune Detection Rules

Reduce false positives by adjusting thresholds:

```yaml
# In brute_force_detection.yaml, adjust threshold:
threshold:
  count: 1          # Lower for more sensitive detection
  window: 10m       # Extend for fewer alerts

# Adjust HAVING clause:
HAVING COUNT(*) >= 15  # Increase threshold to reduce noise
```

### 5. Set Up Suppression Rules

Configure maintenance windows to suppress alerts:

```bash
# Create maintenance window (suppresses alerts for 2 hours)
curl -X POST "$API_ENDPOINT/alerts/suppression" \
  -H "Content-Type: application/json" \
  -d "{
    \"user_id\": \"demo-user\",
    \"start_time\": \"2024-11-28T22:00:00Z\",
    \"duration_minutes\": 120,
    \"rule_pattern\": \".*\",
    \"reason\": \"Scheduled maintenance window\"
  }"
```

### 6. Enable Real CloudTrail Ingestion

Once you're comfortable with sample data, enable real CloudTrail:

```bash
cd ../infrastructure/aws/terraform

# Update terraform.tfvars
cat >> terraform.tfvars <<EOF
enable_cloudtrail = true
cloudtrail_config = {
  enable_logging = true
  include_global_events = true
  is_multi_region = true
}
EOF

# Apply changes
terraform apply -auto-approve
```

Real CloudTrail logs will start flowing to your log bucket within minutes.

### 7. Explore Advanced Features

**Alert Deduplication:**
- Configure fingerprinting rules to prevent duplicate alerts
- Set deduplication windows (default: 60 minutes)

**Rate Limiting:**
- Limit alerts per rule to prevent alert fatigue
- Configure max alerts per time window

**Failed Alert Management:**
- View failed alerts in the Dead Letter Queue
- Manually retry failed deliveries
- Mark alerts as resolved

**Integration Health Monitoring:**
- Real-time health status with auto-refresh
- View failure statistics and recent errors
- Monitor response times and success rates

### 8. Complete Tutorials

Continue learning with detailed tutorials:

- **[End-to-End Threat Detection](end-to-end-threat-detection.md)** - Complete workflow demonstration
- **[Detection Rule Authoring](detection-rule-authoring.md)** - Advanced rule creation *(coming soon)*
- **[Alert Response Workflow](alert-response-workflow.md)** - Investigation playbooks *(coming soon)*

---

## Troubleshooting

### Issue: No data appears in Athena

**Symptoms:**
- Queries return 0 rows
- `HIVE_PARTITION_SCHEMA_MISMATCH` error

**Solution:**

```bash
# Repair table partitions
aws athena start-query-execution \
  --query-string "MSCK REPAIR TABLE cloudtrail_logs" \
  --query-execution-context "Database=$ATHENA_DB" \
  --work-group $ATHENA_WORKGROUP \
  --result-configuration "OutputLocation=s3://$LOG_BUCKET/athena-results/"

# Verify partitions exist
aws athena start-query-execution \
  --query-string "SHOW PARTITIONS cloudtrail_logs" \
  --query-execution-context "Database=$ATHENA_DB" \
  --work-group $ATHENA_WORKGROUP \
  --result-configuration "OutputLocation=s3://$LOG_BUCKET/athena-results/"
```

### Issue: Slack alerts not sending

**Symptoms:**
- No messages in Slack channel
- Integration health shows failures

**Solution:**

```bash
# Check integration health
aws dynamodb get-item \
  --table-name $INTEGRATION_HEALTH_TABLE \
  --key '{"pk":{"S":"user#demo-user"},"sk":{"S":"integration#slack-security-alerts"}}' | jq '.Item'

# Test webhook manually
curl -X POST "YOUR_WEBHOOK_URL" \
  -H "Content-Type: application/json" \
  -d '{"text": "Test message from Mantissa Log"}'

# Check Lambda logs for errors
aws logs tail /aws/lambda/mantissa-log-alert-router --follow
```

Common causes:
- Invalid webhook URL (verify no extra characters)
- Slack app permissions revoked (reinstall app)
- Network connectivity (check Lambda VPC settings if applicable)

### Issue: Detection rule not triggering

**Symptoms:**
- Rule validates but doesn't generate alerts
- No errors in logs

**Solution:**

```bash
# Test rule manually first
python test-rule.py \
  --rule-file ../rules/custom/brute_force_detection.yaml \
  --user-id demo-user \
  --verbose

# Check if data matches query conditions
aws athena start-query-execution \
  --query-string "$(cat ../rules/custom/brute_force_detection.yaml | grep -A 50 'query:' | tail -n +2)" \
  --query-execution-context "Database=$ATHENA_DB" \
  --work-group $ATHENA_WORKGROUP \
  --result-configuration "OutputLocation=s3://$LOG_BUCKET/athena-results/"

# Verify rule is uploaded and enabled
aws s3 ls s3://$RULES_BUCKET/rules/custom/
```

### Issue: High query costs

**Symptoms:**
- Athena costs higher than expected
- Large data scanned amounts

**Solution:**

```sql
-- Add partition filters to all queries
WHERE eventdate >= CURRENT_DATE - INTERVAL '1' DAY  -- Limit to recent data

-- Use specific columns instead of SELECT *
SELECT eventtime, sourceipaddress, errorcode  -- Only needed columns
FROM cloudtrail_logs

-- Check data scanned before running
-- The test-rule.py script shows estimated cost
```

**Cost optimization tips:**
1. Always use `eventdate` partition filters
2. Convert JSON logs to Parquet format (10x smaller)
3. Set S3 lifecycle policies to archive old data
4. Tune detection frequency (every 5 min → every 15 min)
5. Use Athena query result reuse (caching)

### Issue: Terraform deployment fails

**Symptoms:**
- `terraform apply` errors
- Permission denied errors

**Common Solutions:**

```bash
# Verify AWS credentials
aws sts get-caller-identity

# Check required permissions
aws iam get-user

# If using AWS profiles
export AWS_PROFILE=your-profile-name

# Clear Terraform state and retry
rm -rf .terraform .terraform.lock.hcl
terraform init
terraform apply
```

### Getting More Help

If issues persist:

1. Check [Operations Runbook](../operations/runbook.md)
2. Review [Troubleshooting Guide](../deployment/troubleshooting.md)
3. Search [GitHub Issues](https://github.com/your-org/mantissa-log/issues)
4. Open a new issue with:
   - Error messages and logs
   - Terraform/Python versions
   - Steps to reproduce

---

## Clean Up Resources

When you're done testing, clean up to avoid charges:

### Option 1: Destroy Everything

```bash
cd infrastructure/aws/terraform

# This deletes ALL resources
terraform destroy -auto-approve

# Delete Terraform state bucket
aws s3 rb s3://$(grep bucket backend.tf | awk '{print $3}' | tr -d '"') --force
```

### Option 2: Keep Infrastructure, Delete Data

```bash
# Delete sample logs only
aws s3 rm s3://$LOG_BUCKET/cloudtrail/ --recursive

# Delete query results
aws s3 rm s3://$LOG_BUCKET/athena-results/ --recursive

# Clear DynamoDB tables
aws dynamodb scan --table-name $ALERTS_TABLE | \
  jq -r '.Items[] | "aws dynamodb delete-item --table-name '$ALERTS_TABLE' --key '\''{\\"pk\\":{\\"S\\":\\"\(.pk.S)\\"},\\"sk\\":{\\"S\\":\\"\(.sk.S)\\"}}'\''"' | \
  bash
```

**Warning:** Destroying resources will delete all data. Export any important detection rules or query results before destroying.

---

## Summary

You've successfully completed the Mantissa Log Quick Start! You now know how to:

- Deploy and configure Mantissa Log infrastructure
- Generate and ingest sample security data
- Query logs using natural language and SQL
- Create detection rules for security threats
- Configure integrations with PII/PHI redaction
- Test and monitor the complete alert pipeline
- Troubleshoot common issues

**What's Next?**

Explore the [End-to-End Threat Detection Tutorial](end-to-end-threat-detection.md) to see a complete real-world investigation workflow using all of Mantissa Log's features.

Happy threat hunting! 🔍
