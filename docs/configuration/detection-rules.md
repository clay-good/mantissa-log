# Detection Rules Guide

This guide covers writing, managing, and tuning detection rules for Mantissa Log.

## Overview

Detection rules automatically scan your logs for security issues. Rules are YAML files that define:
- What to look for (SQL query)
- When to alert (threshold)
- How to classify (severity, category)
- Additional context (metadata, MITRE mappings)

## Rule Format Reference

### Basic Structure

```yaml
name: "Rule Name"
description: "Detailed description of what this rule detects"
enabled: true
severity: "critical|high|medium|low|info"
category: "access|network|data|compliance|threat"

query: |
  SELECT
    field1,
    field2,
    COUNT(*) as count
  FROM table
  WHERE condition
  GROUP BY field1, field2

threshold:
  count: 1
  window: "5m"

metadata:
  mitre_attack:
    - "TA0001"
    - "T1078"
  references:
    - "https://docs.aws.amazon.com/security/best-practices"
  tags:
    - "aws"
    - "cloudtrail"
    - "authentication"
```

### Required Fields

**name** (string)
- Short, descriptive name for the rule
- Appears in alerts
- Should be unique across all rules

**description** (string)
- Detailed explanation of what the rule detects
- Why it matters
- Expected false positive rate

**enabled** (boolean)
- `true` to run the rule
- `false` to disable without deleting

**severity** (enum)
- `critical`: Immediate action required, active compromise likely
- `high`: Significant risk, should investigate promptly
- `medium`: Notable concern, investigate when possible
- `low`: Minor issue or policy violation
- `info`: Informational, no action required

**category** (enum)
- `access`: Authentication, authorization, IAM
- `network`: Network traffic, firewall, VPC
- `data`: Data access, exfiltration, storage
- `compliance`: Policy violations, configuration issues
- `threat`: Known threats, malware, suspicious activity

**query** (SQL string)
- Athena-compatible SQL query
- Must be SELECT only (no INSERT, UPDATE, DELETE)
- Should use partition filters for performance

**threshold** (object)
- `count`: Number of query results to trigger alert
- `window`: Time window to evaluate ("5m", "1h", "24h")

### Optional Fields

**metadata** (object)
- `mitre_attack`: MITRE ATT&CK technique IDs
- `references`: URLs to documentation
- `tags`: Custom tags for organization
- `author`: Rule author
- `version`: Rule version

## Writing Detection Rules

### Step 1: Identify the Threat

Define what you want to detect:
- Root account usage
- Failed login patterns
- Unusual API calls
- Data exfiltration
- Configuration changes

### Step 2: Write the Query

Test your query in Athena console first:

```sql
-- Test in Athena
SELECT
    eventtime,
    useridentity.principalid,
    eventname,
    sourceipaddress
FROM cloudtrail
WHERE useridentity.type = 'Root'
  AND year = '2024'
  AND month = '01'
  AND day = '15'
ORDER BY eventtime DESC
```

### Step 3: Add Time Window

Make the query relative to current time:

```sql
SELECT
    eventtime,
    useridentity.principalid,
    eventname,
    sourceipaddress
FROM cloudtrail
WHERE useridentity.type = 'Root'
  AND eventtime > CAST((CURRENT_TIMESTAMP - INTERVAL '5' MINUTE) AS VARCHAR)
  AND year = CAST(YEAR(CURRENT_DATE) AS VARCHAR)
  AND month = LPAD(CAST(MONTH(CURRENT_DATE) AS VARCHAR), 2, '0')
  AND day = LPAD(CAST(DAY(CURRENT_DATE) AS VARCHAR), 2, '0')
```

### Step 4: Create Rule File

```yaml
name: "Root Account Activity"
description: "Detects any use of AWS root account credentials"
enabled: true
severity: "critical"
category: "access"

query: |
  SELECT
    eventtime,
    useridentity.principalid,
    eventname,
    sourceipaddress,
    useragent
  FROM cloudtrail
  WHERE useridentity.type = 'Root'
    AND eventtime > CAST((CURRENT_TIMESTAMP - INTERVAL '5' MINUTE) AS VARCHAR)
    AND year = CAST(YEAR(CURRENT_DATE) AS VARCHAR)
    AND month = LPAD(CAST(MONTH(CURRENT_DATE) AS VARCHAR), 2, '0')
    AND day = LPAD(CAST(DAY(CURRENT_DATE) AS VARCHAR), 2, '0')

threshold:
  count: 1
  window: "5m"

metadata:
  mitre_attack:
    - "T1078.004"  # Valid Accounts: Cloud Accounts
  references:
    - "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_root-user.html"
  tags:
    - "aws"
    - "cloudtrail"
    - "root-account"
```

### Step 5: Upload Rule

```bash
RULES_BUCKET=$(cat terraform-outputs.json | jq -r '.rules_bucket.value')
aws s3 cp root-account-activity.yaml s3://$RULES_BUCKET/rules/aws/
```

## Example Detection Rules

### Failed Login Attempts

```yaml
name: "Multiple Failed Login Attempts"
description: "Detects multiple failed console login attempts from single IP"
enabled: true
severity: "medium"
category: "access"

query: |
  SELECT
    sourceipaddress,
    useridentity.principalid,
    COUNT(*) as failure_count,
    MIN(eventtime) as first_attempt,
    MAX(eventtime) as last_attempt
  FROM cloudtrail
  WHERE eventname = 'ConsoleLogin'
    AND errorcode IS NOT NULL
    AND eventtime > CAST((CURRENT_TIMESTAMP - INTERVAL '5' MINUTE) AS VARCHAR)
    AND year = CAST(YEAR(CURRENT_DATE) AS VARCHAR)
    AND month = LPAD(CAST(MONTH(CURRENT_DATE) AS VARCHAR), 2, '0')
    AND day = LPAD(CAST(DAY(CURRENT_DATE) AS VARCHAR), 2, '0')
  GROUP BY sourceipaddress, useridentity.principalid
  HAVING COUNT(*) >= 5

threshold:
  count: 1
  window: "5m"

metadata:
  mitre_attack:
    - "T1110"  # Brute Force
  tags:
    - "authentication"
    - "brute-force"
```

### S3 Bucket Exposure

```yaml
name: "S3 Bucket Made Public"
description: "Detects S3 buckets being made publicly accessible"
enabled: true
severity: "high"
category: "data"

query: |
  SELECT
    eventtime,
    useridentity.principalid,
    requestparameters,
    resources[1].arn as bucket_arn
  FROM cloudtrail
  WHERE eventsource = 's3.amazonaws.com'
    AND eventname IN ('PutBucketAcl', 'PutBucketPolicy', 'PutBucketPublicAccessBlock')
    AND (
      requestparameters LIKE '%"AllUsers"%'
      OR requestparameters LIKE '%"AuthenticatedUsers"%'
    )
    AND eventtime > CAST((CURRENT_TIMESTAMP - INTERVAL '5' MINUTE) AS VARCHAR)
    AND year = CAST(YEAR(CURRENT_DATE) AS VARCHAR)
    AND month = LPAD(CAST(MONTH(CURRENT_DATE) AS VARCHAR), 2, '0')
    AND day = LPAD(CAST(DAY(CURRENT_DATE) AS VARCHAR), 2, '0')

threshold:
  count: 1
  window: "5m"

metadata:
  mitre_attack:
    - "T1530"  # Data from Cloud Storage Object
  tags:
    - "s3"
    - "data-exposure"
```

### IAM Policy Changes

```yaml
name: "Privileged IAM Policy Modification"
description: "Detects changes to IAM policies with admin privileges"
enabled: true
severity: "high"
category: "access"

query: |
  SELECT
    eventtime,
    useridentity.principalid,
    eventname,
    requestparameters,
    resources
  FROM cloudtrail
  WHERE eventsource = 'iam.amazonaws.com'
    AND eventname IN (
      'PutUserPolicy',
      'PutRolePolicy',
      'PutGroupPolicy',
      'AttachUserPolicy',
      'AttachRolePolicy',
      'AttachGroupPolicy'
    )
    AND (
      requestparameters LIKE '%AdministratorAccess%'
      OR requestparameters LIKE '%"Effect":"Allow"%'
         AND requestparameters LIKE '%"Action":"*"%'
         AND requestparameters LIKE '%"Resource":"*"%'
    )
    AND eventtime > CAST((CURRENT_TIMESTAMP - INTERVAL '5' MINUTE) AS VARCHAR)
    AND year = CAST(YEAR(CURRENT_DATE) AS VARCHAR)
    AND month = LPAD(CAST(MONTH(CURRENT_DATE) AS VARCHAR), 2, '0')
    AND day = LPAD(CAST(DAY(CURRENT_DATE) AS VARCHAR), 2, '0')

threshold:
  count: 1
  window: "5m"

metadata:
  mitre_attack:
    - "T1098"  # Account Manipulation
  tags:
    - "iam"
    - "privilege-escalation"
```

### Security Group Changes

```yaml
name: "Security Group Opened to Internet"
description: "Detects security groups opened to 0.0.0.0/0"
enabled: true
severity: "medium"
category: "network"

query: |
  SELECT
    eventtime,
    useridentity.principalid,
    requestparameters,
    resources[1].arn as security_group
  FROM cloudtrail
  WHERE eventsource = 'ec2.amazonaws.com'
    AND eventname IN ('AuthorizeSecurityGroupIngress', 'AuthorizeSecurityGroupEgress')
    AND requestparameters LIKE '%0.0.0.0/0%'
    AND eventtime > CAST((CURRENT_TIMESTAMP - INTERVAL '5' MINUTE) AS VARCHAR)
    AND year = CAST(YEAR(CURRENT_DATE) AS VARCHAR)
    AND month = LPAD(CAST(MONTH(CURRENT_DATE) AS VARCHAR), 2, '0')
    AND day = LPAD(CAST(DAY(CURRENT_DATE) AS VARCHAR), 2, '0')

threshold:
  count: 1
  window: "5m"

metadata:
  mitre_attack:
    - "T1562.007"  # Impair Defenses: Disable or Modify Cloud Firewall
  tags:
    - "ec2"
    - "security-group"
    - "network"
```

### Data Exfiltration

```yaml
name: "Large S3 Data Transfer"
description: "Detects unusually large S3 data transfers"
enabled: true
severity: "medium"
category: "data"

query: |
  WITH s3_transfers AS (
    SELECT
      useridentity.principalid,
      resources[1].arn as bucket,
      COUNT(*) as request_count
    FROM cloudtrail
    WHERE eventsource = 's3.amazonaws.com'
      AND eventname = 'GetObject'
      AND eventtime > CAST((CURRENT_TIMESTAMP - INTERVAL '5' MINUTE) AS VARCHAR)
      AND year = CAST(YEAR(CURRENT_DATE) AS VARCHAR)
      AND month = LPAD(CAST(MONTH(CURRENT_DATE) AS VARCHAR), 2, '0')
      AND day = LPAD(CAST(DAY(CURRENT_DATE) AS VARCHAR), 2, '0')
    GROUP BY useridentity.principalid, resources[1].arn
  )
  SELECT
    principalid,
    bucket,
    request_count
  FROM s3_transfers
  WHERE request_count > 1000

threshold:
  count: 1
  window: "5m"

metadata:
  mitre_attack:
    - "T1530"  # Data from Cloud Storage Object
  tags:
    - "s3"
    - "data-exfiltration"
```

## Best Practices

### Performance Optimization

**Always use partition filters:**
```sql
WHERE year = CAST(YEAR(CURRENT_DATE) AS VARCHAR)
  AND month = LPAD(CAST(MONTH(CURRENT_DATE) AS VARCHAR), 2, '0')
  AND day = LPAD(CAST(DAY(CURRENT_DATE) AS VARCHAR), 2, '0')
```

**Limit time window:**
```sql
AND eventtime > CAST((CURRENT_TIMESTAMP - INTERVAL '5' MINUTE) AS VARCHAR)
```

**Use aggregations wisely:**
```sql
-- Good: Aggregate before filtering large datasets
WITH aggregated AS (
  SELECT user, COUNT(*) as count
  FROM logs
  WHERE ...
  GROUP BY user
)
SELECT * FROM aggregated WHERE count > 10

-- Avoid: Filtering large result sets
SELECT * FROM logs WHERE condition
HAVING COUNT(*) > 10  -- Less efficient
```

### Accuracy

**Reduce false positives:**
- Add specific conditions
- Exclude known good patterns
- Use appropriate thresholds
- Test thoroughly before enabling

**Example:**
```sql
-- Exclude automated processes
WHERE useridentity.principalid NOT LIKE '%service%'
  AND useragent NOT LIKE '%Boto3%'
  AND sourceipaddress NOT IN ('10.0.0.0/8', '172.16.0.0/12')
```

### Maintainability

**Use descriptive names:**
```yaml
# Good
name: "Multiple Failed Console Logins from Single IP"

# Avoid
name: "Login Rule 1"
```

**Add comprehensive descriptions:**
```yaml
description: |
  Detects 5 or more failed console login attempts from a single IP
  address within a 5-minute window. This may indicate:
  - Brute force attack
  - Credential stuffing
  - Misconfigured automation

  Expected false positive rate: Low
  Recommended action: Investigate source IP, review auth logs
```

**Document assumptions:**
```yaml
metadata:
  notes: |
    This rule assumes:
    - CloudTrail is enabled in all regions
    - Login events are delivered within 5 minutes
    - Legitimate automation uses service accounts
```

## Tuning Detection Rules

### Adjusting Sensitivity

**Modify count threshold:**
```yaml
threshold:
  count: 5  # Increase to reduce alerts
  window: "5m"
```

**Modify time window:**
```yaml
threshold:
  count: 3
  window: "15m"  # Longer window for sustained activity
```

**Add filters:**
```sql
WHERE ...
  AND NOT (
    -- Exclude known patterns
    useridentity.principalid LIKE '%automation%'
    OR sourceipaddress IN ('10.1.2.3', '10.4.5.6')
  )
```

### Testing Rules

**Test query in Athena:**
```sql
-- Run query manually with recent time window
SELECT ... FROM cloudtrail
WHERE year = '2024'
  AND month = '01'
  AND day = '15'
  AND eventtime > '2024-01-15T10:00:00Z'
```

**Check for results:**
```bash
# Test rule before enabling
DATABASE=$(cat terraform-outputs.json | jq -r '.database_name.value')
WORKGROUP=$(cat terraform-outputs.json | jq -r '.athena_workgroup_name.value')

aws athena start-query-execution \
  --query-string "$(cat rules/test-rule.yaml | yq -r '.query')" \
  --query-execution-context Database=$DATABASE \
  --work-group $WORKGROUP
```

**Enable gradually:**
```yaml
# Start with low severity
severity: "info"

# After validation, increase
severity: "high"
```

## Rule Management

### Organizing Rules

```
rules/
├── aws/
│   ├── cloudtrail/
│   │   ├── root-account.yaml
│   │   ├── failed-logins.yaml
│   │   └── iam-changes.yaml
│   ├── vpc/
│   │   ├── port-scan.yaml
│   │   └── unusual-traffic.yaml
│   └── s3/
│       ├── bucket-exposure.yaml
│       └── large-transfer.yaml
├── custom/
│   └── app-specific/
│       ├── high-error-rate.yaml
│       └── slow-queries.yaml
└── compliance/
    ├── pci-dss/
    └── hipaa/
```

### Enabling/Disabling Rules

**Disable a rule:**
```yaml
enabled: false  # Change to false
```

**Or remove from S3:**
```bash
aws s3 rm s3://$RULES_BUCKET/rules/aws/old-rule.yaml
```

### Updating Rules

```bash
# Edit local file
vim rules/aws/cloudtrail/root-account.yaml

# Upload updated version
aws s3 cp rules/aws/cloudtrail/root-account.yaml \
  s3://$RULES_BUCKET/rules/aws/cloudtrail/

# Changes take effect on next detection cycle (5 minutes)
```

### Version Control

Keep rules in Git:

```bash
git add rules/
git commit -m "Add IAM policy change detection rule"
git push

# Deploy to production
aws s3 sync rules/ s3://$RULES_BUCKET/rules/ \
  --exclude "*.md" \
  --exclude "README*" \
  --delete
```

## Advanced Techniques

### Multi-Table Joins

```yaml
name: "Correlated Network and API Activity"
description: "Detects suspicious API calls correlated with network events"
query: |
  SELECT
    c.eventtime,
    c.eventname,
    c.sourceipaddress,
    v.dstaddr,
    v.dstport
  FROM cloudtrail c
  JOIN vpc_flow_logs v
    ON c.sourceipaddress = v.srcaddr
    AND DATE_DIFF('minute',
                  FROM_ISO8601_TIMESTAMP(v.start),
                  FROM_ISO8601_TIMESTAMP(c.eventtime)) <= 5
  WHERE c.eventname = 'RunInstances'
    AND v.dstport = 22
    AND c.year = CAST(YEAR(CURRENT_DATE) AS VARCHAR)
    AND v.year = CAST(YEAR(CURRENT_DATE) AS VARCHAR)
```

### Statistical Anomaly Detection

```yaml
name: "Anomalous API Call Volume"
description: "Detects unusual spikes in API calls"
query: |
  WITH current_volume AS (
    SELECT
      useridentity.principalid,
      COUNT(*) as current_count
    FROM cloudtrail
    WHERE eventtime > CAST((CURRENT_TIMESTAMP - INTERVAL '5' MINUTE) AS VARCHAR)
      AND year = CAST(YEAR(CURRENT_DATE) AS VARCHAR)
      AND month = LPAD(CAST(MONTH(CURRENT_DATE) AS VARCHAR), 2, '0')
      AND day = LPAD(CAST(DAY(CURRENT_DATE) AS VARCHAR), 2, '0')
    GROUP BY useridentity.principalid
  ),
  baseline AS (
    SELECT
      useridentity.principalid,
      AVG(count) as avg_count,
      STDDEV(count) as stddev_count
    FROM (
      SELECT
        useridentity.principalid,
        COUNT(*) as count
      FROM cloudtrail
      WHERE eventtime > CAST((CURRENT_TIMESTAMP - INTERVAL '24' HOUR) AS VARCHAR)
      GROUP BY useridentity.principalid, DATE_TRUNC('minute', FROM_ISO8601_TIMESTAMP(eventtime))
    )
    GROUP BY useridentity.principalid
  )
  SELECT
    c.principalid,
    c.current_count,
    b.avg_count,
    b.stddev_count
  FROM current_volume c
  JOIN baseline b ON c.principalid = b.principalid
  WHERE c.current_count > (b.avg_count + (3 * b.stddev_count))
```

## Troubleshooting

### Rule Not Triggering

**Check if rule is loaded:**
```bash
aws s3 ls s3://$RULES_BUCKET/rules/ --recursive | grep your-rule.yaml
```

**Check detection engine logs:**
```bash
aws logs tail /aws/lambda/mantissa-log-detection-engine --since 10m
```

**Verify query syntax:**
```bash
# Test query manually
aws athena start-query-execution \
  --query-string "SELECT COUNT(*) FROM cloudtrail WHERE year='2024'" \
  --query-execution-context Database=$DATABASE \
  --work-group $WORKGROUP
```

### Too Many Alerts

**Increase threshold:**
```yaml
threshold:
  count: 10  # Increased from 5
  window: "5m"
```

**Add exclusions:**
```sql
WHERE ...
  AND useridentity.principalid NOT IN (
    'automation-user',
    'ci-cd-service'
  )
```

**Change severity:**
```yaml
severity: "low"  # Downgrade from "high"
```

### Query Timeouts

**Add partition filters:**
```sql
WHERE year = CAST(YEAR(CURRENT_DATE) AS VARCHAR)
  AND month = LPAD(CAST(MONTH(CURRENT_DATE) AS VARCHAR), 2, '0')
  AND day = LPAD(CAST(DAY(CURRENT_DATE) AS VARCHAR), 2, '0')
```

**Reduce time window:**
```sql
AND eventtime > CAST((CURRENT_TIMESTAMP - INTERVAL '5' MINUTE) AS VARCHAR)
-- Instead of INTERVAL '1' HOUR
```

**Optimize query:**
```sql
-- Use specific fields instead of SELECT *
SELECT eventtime, eventname, useridentity.principalid
-- Instead of SELECT *
```
