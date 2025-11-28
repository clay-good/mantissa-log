# Detection Rule Authoring Tutorial

Learn how to create effective detection rules for security monitoring in Mantissa Log. This tutorial covers rule structure, query optimization, testing, and best practices.

## Table of Contents

1. [Rule Anatomy](#rule-anatomy)
2. [Writing Your First Rule](#writing-your-first-rule)
3. [Query Optimization](#query-optimization)
4. [Testing and Validation](#testing-and-validation)
5. [Advanced Techniques](#advanced-techniques)
6. [Best Practices](#best-practices)
7. [Common Patterns](#common-patterns)
8. [Troubleshooting](#troubleshooting)

---

## Rule Anatomy

A detection rule is a YAML file with specific sections that define what to detect, how often to check, and where to send alerts.

### Complete Rule Structure

```yaml
# Metadata
name: rule_identifier_lowercase
display_name: Human Readable Rule Name
description: What this rule detects and why it matters
enabled: true
severity: critical|high|medium|low|info
category: authentication|network|data|compliance|threat

# Detection Logic
query: |
  SELECT
    field1,
    field2,
    COUNT(*) as count_field
  FROM log_table
  WHERE eventdate >= CURRENT_DATE - INTERVAL '1' DAY
    AND condition = 'value'
  GROUP BY field1, field2
  HAVING COUNT(*) >= threshold_value

# Threshold Configuration
threshold:
  count: 1              # Minimum matches to trigger alert
  window: 5m            # Time window: 5m, 1h, 24h, etc.

# Schedule Configuration
schedule:
  enabled: true
  interval_minutes: 5   # How often to run (1, 5, 15, 30, 60)
  lookback_minutes: 15  # How far back to look

# Alert Template
alert_template:
  title: "Alert Title with {{variables}}"
  description: |
    Detailed description of the alert.
    Can reference query results: {{field_name}}

  fields:
    - name: display_name
      value: "{{query_field}}"

  recommended_actions:
    - Action 1 to take
    - Action 2 to take

# Metadata
metadata:
  mitre_attack:
    - T1234      # MITRE ATT&CK technique IDs
  tags:
    - tag1
    - tag2
  references:
    - https://docs.example.com/technique
```

### Required Fields

Minimum required fields for a valid rule:

```yaml
name: my_rule
description: Rule description
enabled: true
severity: high
category: authentication
query: |
  SELECT * FROM cloudtrail_logs WHERE eventdate >= CURRENT_DATE - INTERVAL '1' DAY
```

All other fields are optional with sensible defaults.

---

## Writing Your First Rule

Let's create a rule to detect root account usage step by step.

### Step 1: Define the Objective

**What are we detecting?**
- Any use of the AWS root account
- Root account should rarely be used
- Usage indicates potential security risk

**Why does this matter?**
- Root account has unrestricted access
- Compromised root credentials = complete account takeover
- Best practice: use IAM users with MFA

### Step 2: Explore the Data

Before writing a rule, understand what the data looks like:

```sql
-- Find root account activity examples
SELECT
  eventtime,
  eventname,
  useridentity.type,
  useridentity.principalid,
  useridentity.arn,
  sourceipaddress,
  useragent
FROM cloudtrail_logs
WHERE eventdate >= CURRENT_DATE - INTERVAL '7' DAY
  AND useridentity.type = 'Root'
LIMIT 10;
```

**Sample results:**

| eventtime | eventname | type | principalid | arn | sourceipaddress | useragent |
|-----------|-----------|------|-------------|-----|-----------------|-----------|
| 2024-11-28 14:32:11 | ConsoleLogin | Root | 123456789012 | arn:aws:iam::123456789012:root | 198.51.100.42 | Mozilla/5.0... |

### Step 3: Write the Detection Query

```yaml
query: |
  SELECT
    eventtime,
    eventname,
    sourceipaddress as source_ip,
    awsregion as region,
    useragent,
    useridentity.arn as user_arn
  FROM cloudtrail_logs
  WHERE eventdate >= CURRENT_DATE - INTERVAL '1' DAY
    AND useridentity.type = 'Root'
    AND eventname != 'GetAccountPasswordPolicy'  -- Exclude benign automated checks
  ORDER BY eventtime DESC
```

**Key points:**
- Use `eventdate` partition for cost efficiency
- Filter `useridentity.type = 'Root'` to find root usage
- Exclude benign events that don't indicate actual root usage
- Select fields useful for investigation

### Step 4: Set Thresholds

```yaml
threshold:
  count: 1      # Alert on ANY root usage
  window: 5m    # Within each 5-minute detection window
```

For root account usage, we want to know about every occurrence, so threshold is 1.

### Step 5: Configure Scheduling

```yaml
schedule:
  enabled: true
  interval_minutes: 5    # Check every 5 minutes
  lookback_minutes: 15   # Look back 15 minutes (3x interval for overlap)
```

**Why 15-minute lookback for 5-minute interval?**
- Prevents missing events due to timing
- Provides overlap for events at boundary times
- Deduplication prevents duplicate alerts

### Step 6: Create Alert Template

```yaml
alert_template:
  title: "AWS Root Account Usage Detected"
  description: |
    The AWS root account was used to perform: {{eventname}}

    Root account usage should be extremely rare and only for specific
    account-level operations that require root credentials. This activity
    should be investigated immediately.

  fields:
    - name: event_name
      value: "{{eventname}}"
    - name: source_ip
      value: "{{source_ip}}"
    - name: region
      value: "{{region}}"
    - name: user_agent
      value: "{{useragent}}"
    - name: time
      value: "{{eventtime}}"

  recommended_actions:
    - Verify this was an authorized user with legitimate need for root access
    - Check MFA was used for authentication
    - Review additional CloudTrail events from this source IP
    - If unauthorized, rotate root credentials immediately
    - Enable root account MFA if not already enabled
    - Consider setting up CloudWatch alarms for root account usage
```

### Step 7: Add Metadata

```yaml
metadata:
  mitre_attack:
    - T1078.004  # Valid Accounts: Cloud Accounts
  tags:
    - aws
    - root-account
    - privilege-escalation
    - critical
  references:
    - https://docs.aws.amazon.com/IAM/latest/UserGuide/id_root-user.html
    - https://attack.mitre.org/techniques/T1078/004/
```

### Complete Rule

```yaml
name: root_account_usage
display_name: AWS Root Account Usage
description: Detects any use of the AWS root account, which should be extremely rare
enabled: true
severity: critical
category: authentication

query: |
  SELECT
    eventtime,
    eventname,
    sourceipaddress as source_ip,
    awsregion as region,
    useragent,
    useridentity.arn as user_arn
  FROM cloudtrail_logs
  WHERE eventdate >= CURRENT_DATE - INTERVAL '1' DAY
    AND useridentity.type = 'Root'
    AND eventname != 'GetAccountPasswordPolicy'
  ORDER BY eventtime DESC

threshold:
  count: 1
  window: 5m

schedule:
  enabled: true
  interval_minutes: 5
  lookback_minutes: 15

alert_template:
  title: "AWS Root Account Usage Detected"
  description: |
    The AWS root account was used to perform: {{eventname}}

    Root account usage should be extremely rare and only for specific
    account-level operations that require root credentials. This activity
    should be investigated immediately.

  fields:
    - name: event_name
      value: "{{eventname}}"
    - name: source_ip
      value: "{{source_ip}}"
    - name: region
      value: "{{region}}"
    - name: user_agent
      value: "{{useragent}}"
    - name: time
      value: "{{eventtime}}"

  recommended_actions:
    - Verify this was an authorized user with legitimate need for root access
    - Check MFA was used for authentication
    - Review additional CloudTrail events from this source IP
    - If unauthorized, rotate root credentials immediately
    - Enable root account MFA if not already enabled
    - Consider setting up CloudWatch alarms for root account usage

metadata:
  mitre_attack:
    - T1078.004  # Valid Accounts: Cloud Accounts
  tags:
    - aws
    - root-account
    - privilege-escalation
    - critical
  references:
    - https://docs.aws.amazon.com/IAM/latest/UserGuide/id_root-user.html
    - https://attack.mitre.org/techniques/T1078/004/
```

Save as `rules/authentication/root_account_usage.yaml`

---

## Query Optimization

Athena charges $5 per TB scanned. Optimize queries to reduce costs.

### 1. Always Use Partition Filters

**Bad (scans entire table):**
```sql
SELECT * FROM cloudtrail_logs
WHERE eventtime >= CURRENT_TIMESTAMP - INTERVAL '1' DAY
```

**Good (scans only relevant partitions):**
```sql
SELECT * FROM cloudtrail_logs
WHERE eventdate >= CURRENT_DATE - INTERVAL '1' DAY  -- Partition filter!
  AND eventtime >= CURRENT_TIMESTAMP - INTERVAL '1' DAY
```

**Cost impact:** 30x reduction in data scanned

### 2. Select Only Needed Columns

**Bad:**
```sql
SELECT * FROM cloudtrail_logs
WHERE eventdate >= CURRENT_DATE - INTERVAL '1' DAY
```

**Good:**
```sql
SELECT
  eventtime,
  eventname,
  sourceipaddress,
  useridentity.username
FROM cloudtrail_logs
WHERE eventdate >= CURRENT_DATE - INTERVAL '1' DAY
```

**Cost impact:** 10x reduction for large tables

### 3. Push Filters Down

**Bad (filters after aggregation):**
```sql
SELECT
  sourceipaddress,
  COUNT(*) as count
FROM cloudtrail_logs
WHERE eventdate >= CURRENT_DATE - INTERVAL '1' DAY
GROUP BY sourceipaddress
HAVING count >= 10
  AND sourceipaddress NOT LIKE '10.%'  -- Filter AFTER grouping
```

**Good (filters before aggregation):**
```sql
SELECT
  sourceipaddress,
  COUNT(*) as count
FROM cloudtrail_logs
WHERE eventdate >= CURRENT_DATE - INTERVAL '1' DAY
  AND sourceipaddress NOT LIKE '10.%'  -- Filter BEFORE grouping
GROUP BY sourceipaddress
HAVING count >= 10
```

**Cost impact:** Depends on data, often 2-5x reduction

### 4. Use Appropriate Time Windows

**Bad (scans 30 days for 5-minute detection window):**
```sql
SELECT * FROM cloudtrail_logs
WHERE eventdate >= CURRENT_DATE - INTERVAL '30' DAY
```

**Good (only scans what's needed):**
```sql
-- For 5-minute interval with 15-minute lookback:
SELECT * FROM cloudtrail_logs
WHERE eventdate >= CURRENT_DATE - INTERVAL '1' DAY
  AND eventtime >= CURRENT_TIMESTAMP - INTERVAL '15' MINUTE
```

**Cost impact:** 43x reduction (30 days → ~16 hours)

### 5. Optimize JOINs

**Bad (full table scans):**
```sql
SELECT *
FROM cloudtrail_logs c
JOIN vpc_flow_logs v ON c.sourceipaddress = v.srcaddr
```

**Good (partition filters on both sides):**
```sql
SELECT
  c.eventtime,
  c.eventname,
  c.sourceipaddress,
  v.srcaddr,
  v.dstport
FROM cloudtrail_logs c
JOIN vpc_flow_logs v
  ON c.sourceipaddress = v.srcaddr
  AND v.eventdate >= CURRENT_DATE - INTERVAL '1' DAY
WHERE c.eventdate >= CURRENT_DATE - INTERVAL '1' DAY
  AND c.eventtime >= CURRENT_TIMESTAMP - INTERVAL '15' MINUTE
  AND v.eventtime >= CURRENT_TIMESTAMP - INTERVAL '15' MINUTE
```

### 6. Estimate Costs Before Deploying

Use the validation script:

```bash
python scripts/test-rule.py \
  --rule-file rules/authentication/root_account_usage.yaml \
  --estimate-cost
```

Output:
```
Estimated data scanned: 125 MB
Estimated cost per execution: $0.0006
Monthly cost (running every 5 min): $0.52
```

---

## Testing and Validation

Always test rules before deploying to production.

### Step 1: Syntax Validation

```bash
cd scripts

# Validate YAML syntax and required fields
python validate-rules.py ../rules/authentication/root_account_usage.yaml
```

Output:
```
✓ Validating ../rules/authentication/root_account_usage.yaml
✓ Schema validation passed
✓ SQL query is valid
✓ All required fields present
✓ Rule is valid!
```

### Step 2: Query Testing

Test the query against real data:

```bash
python test-rule.py \
  --rule-file ../rules/authentication/root_account_usage.yaml \
  --user-id demo-user \
  --verbose
```

Output shows:
- Generated SQL query
- Query execution time
- Data scanned
- Cost estimate
- Result rows
- Whether threshold was met

### Step 3: Dry Run

Test without sending alerts:

```bash
python test-rule.py \
  --rule-file ../rules/authentication/root_account_usage.yaml \
  --user-id demo-user \
  --dry-run
```

This executes the rule but skips alert delivery.

### Step 4: Integration Testing

Test with actual alert delivery:

```bash
python test-rule.py \
  --rule-file ../rules/authentication/root_account_usage.yaml \
  --user-id demo-user \
  --send-alerts
```

Verify alerts appear in configured integrations (Slack, Jira, etc.).

### Step 5: Load Testing

For rules that run frequently, test performance:

```bash
# Test 100 consecutive executions
for i in {1..100}; do
  python test-rule.py \
    --rule-file ../rules/authentication/root_account_usage.yaml \
    --user-id demo-user \
    --dry-run
done
```

Monitor:
- Average execution time
- Cost per execution
- Memory usage
- Error rate

---

## Advanced Techniques

### 1. Layered Detection

Combine multiple conditions for higher confidence:

```yaml
name: lateral_movement_detection
description: Detects potential lateral movement by correlating multiple signals
query: |
  WITH new_instance_access AS (
    -- Users accessing newly created EC2 instances
    SELECT
      useridentity.username as user,
      requestparameters.instanceId as instance,
      eventtime
    FROM cloudtrail_logs
    WHERE eventdate >= CURRENT_DATE - INTERVAL '1' DAY
      AND eventname = 'RunInstances'
  ),
  ssh_from_bastion AS (
    -- SSH connections from bastion host
    SELECT
      srcaddr,
      dstaddr,
      eventtime
    FROM vpc_flow_logs
    WHERE eventdate >= CURRENT_DATE - INTERVAL '1' DAY
      AND dstport = 22
      AND srcaddr IN (SELECT ip FROM bastion_hosts)
  ),
  unusual_commands AS (
    -- Unusual commands in CloudWatch Logs
    SELECT
      instance_id,
      command,
      eventtime
    FROM application_logs
    WHERE eventdate >= CURRENT_DATE - INTERVAL '1' DAY
      AND command LIKE '%wget%'
       OR command LIKE '%curl%'
       OR command LIKE '%nc -l%'
  )
  SELECT
    n.user,
    n.instance,
    s.dstaddr,
    u.command,
    'Multiple lateral movement indicators' as reason
  FROM new_instance_access n
  JOIN ssh_from_bastion s
    ON CAST(n.instance AS varchar) = CAST(s.dstaddr AS varchar)
    AND s.eventtime BETWEEN n.eventtime AND n.eventtime + INTERVAL '1' HOUR
  JOIN unusual_commands u
    ON n.instance = u.instance_id
    AND u.eventtime > s.eventtime
```

This rule correlates 3 data sources to detect lateral movement with high confidence.

### 2. Statistical Anomaly Detection

Detect deviations from baseline:

```yaml
name: unusual_s3_access_volume
description: Detects unusual spikes in S3 access compared to historical baseline
query: |
  WITH hourly_access AS (
    -- Current hour's access count
    SELECT
      useridentity.username as user,
      COUNT(*) as current_hour_count
    FROM cloudtrail_logs
    WHERE eventdate >= CURRENT_DATE - INTERVAL '1' DAY
      AND eventtime >= CURRENT_TIMESTAMP - INTERVAL '1' HOUR
      AND eventname LIKE 'GetObject%'
    GROUP BY useridentity.username
  ),
  baseline_access AS (
    -- Average for same hour of day over last 7 days
    SELECT
      useridentity.username as user,
      AVG(hour_count) as avg_count,
      STDDEV(hour_count) as stddev_count
    FROM (
      SELECT
        useridentity.username,
        date_trunc('hour', eventtime) as hour,
        COUNT(*) as hour_count
      FROM cloudtrail_logs
      WHERE eventdate >= CURRENT_DATE - INTERVAL '8' DAY
        AND eventdate < CURRENT_DATE - INTERVAL '1' DAY
        AND eventname LIKE 'GetObject%'
      GROUP BY useridentity.username, date_trunc('hour', eventtime)
    )
    GROUP BY useridentity.username
  )
  SELECT
    h.user,
    h.current_hour_count,
    b.avg_count as baseline_avg,
    b.stddev_count as baseline_stddev,
    (h.current_hour_count - b.avg_count) / NULLIF(b.stddev_count, 0) as z_score
  FROM hourly_access h
  JOIN baseline_access b ON h.user = b.user
  WHERE (h.current_hour_count - b.avg_count) / NULLIF(b.stddev_count, 0) > 3  -- 3 standard deviations
```

This uses Z-score to detect statistical anomalies.

### 3. Time-Based Patterns

Detect activity during unusual times:

```yaml
name: after_hours_administrative_activity
description: Detects administrative actions outside business hours
query: |
  SELECT
    eventtime,
    useridentity.username as user,
    eventname,
    sourceipaddress as source_ip,
    extract(hour from eventtime) as hour,
    extract(dow from eventtime) as day_of_week
  FROM cloudtrail_logs
  WHERE eventdate >= CURRENT_DATE - INTERVAL '1' DAY
    AND eventtime >= CURRENT_TIMESTAMP - INTERVAL '15' MINUTE
    -- Administrative events
    AND (
      eventname LIKE 'Create%'
      OR eventname LIKE 'Delete%'
      OR eventname LIKE 'Attach%'
      OR eventname LIKE 'Detach%'
      OR eventname LIKE 'Put%'
      OR eventname LIKE 'Update%'
    )
    -- Resources that matter
    AND (
      eventname LIKE '%IAM%'
      OR eventname LIKE '%SecurityGroup%'
      OR eventname LIKE '%Policy%'
      OR eventname LIKE '%Role%'
    )
    -- Outside business hours (6 PM - 6 AM) or weekends
    AND (
      extract(hour from eventtime) NOT BETWEEN 6 AND 18
      OR extract(dow from eventtime) IN (0, 6)  -- Sunday=0, Saturday=6
    )
```

### 4. Threat Intelligence Correlation

Correlate with known bad indicators:

```yaml
name: access_from_known_malicious_ips
description: Detects access from IPs in threat intelligence feeds
query: |
  WITH threat_ips AS (
    -- Load threat intelligence from S3
    SELECT DISTINCT ip
    FROM threat_intel_table
    WHERE feed_date >= CURRENT_DATE - INTERVAL '7' DAY
      AND confidence >= 'medium'
  )
  SELECT
    c.eventtime,
    c.eventname,
    c.sourceipaddress as malicious_ip,
    c.useridentity.username as user,
    t.feed_source,
    t.threat_category
  FROM cloudtrail_logs c
  JOIN threat_ips t
    ON c.sourceipaddress = t.ip
  WHERE c.eventdate >= CURRENT_DATE - INTERVAL '1' DAY
    AND c.eventtime >= CURRENT_TIMESTAMP - INTERVAL '15' MINUTE
```

### 5. Session Reconstruction

Track sequences of events:

```yaml
name: suspicious_iam_escalation_chain
description: Detects suspicious sequence of IAM privilege escalation actions
query: |
  WITH ranked_events AS (
    SELECT
      useridentity.username as user,
      eventtime,
      eventname,
      ROW_NUMBER() OVER (
        PARTITION BY useridentity.username
        ORDER BY eventtime
      ) as event_seq
    FROM cloudtrail_logs
    WHERE eventdate >= CURRENT_DATE - INTERVAL '1' DAY
      AND eventtime >= CURRENT_TIMESTAMP - INTERVAL '1' HOUR
      AND (
        eventname = 'CreateUser'
        OR eventname = 'AttachUserPolicy'
        OR eventname = 'PutUserPolicy'
        OR eventname = 'CreateAccessKey'
      )
  )
  SELECT
    user,
    ARRAY_AGG(eventname ORDER BY eventtime) as action_sequence,
    MIN(eventtime) as first_action,
    MAX(eventtime) as last_action,
    COUNT(*) as action_count
  FROM ranked_events
  GROUP BY user
  HAVING COUNT(*) >= 3  -- At least 3 steps in escalation chain
    AND MAX(eventtime) - MIN(eventtime) <= INTERVAL '10' MINUTE
```

---

## Best Practices

### 1. Rule Naming Conventions

**Good:**
- `brute_force_detection`
- `unusual_s3_access_volume`
- `privilege_escalation_via_iam`

**Bad:**
- `MyRule123`
- `test`
- `IMPORTANT_SECURITY_RULE`

**Guidelines:**
- Use lowercase with underscores
- Descriptive of what is detected
- No version numbers in name (use Git)

### 2. Severity Assignment

| Severity | When to Use | Example |
|----------|-------------|---------|
| **critical** | Confirmed compromise or imminent threat | Root account login from unknown IP |
| **high** | Likely malicious, needs immediate investigation | Brute force attack, data exfiltration |
| **medium** | Suspicious but needs context | After-hours admin activity, unusual API calls |
| **low** | Informational, policy violation | Missing MFA, weak password |
| **info** | Awareness, no action needed | New user created, resource tagged |

### 3. Threshold Tuning

Start conservative, then tune based on false positives:

```yaml
# Initial deployment - high threshold
threshold:
  count: 20  # Require 20 matches
  window: 5m

# After 1 week - analyze false positives, adjust
threshold:
  count: 10  # Reduced based on data
  window: 5m

# After 1 month - optimal threshold found
threshold:
  count: 15  # Sweet spot for your environment
  window: 5m
```

### 4. Documentation

Always include:

```yaml
description: |
  WHAT: What this rule detects
  WHY: Why it matters for security
  HOW: How the detection works

alert_template:
  description: |
    Clear explanation for on-call engineer who may not be familiar
    with the specific threat this detects.

  recommended_actions:
    - Step-by-step actions to investigate
    - Specific commands to run
    - Links to runbooks or documentation
```

### 5. Version Control

Track rule changes in Git:

```bash
git add rules/authentication/root_account_usage.yaml
git commit -m "feat: add root account usage detection

- Detects any use of root account
- Excludes benign automated checks
- Sends critical alerts to #security channel
- Initial threshold: any occurrence"
```

### 6. Testing Checklist

Before deploying a new rule:

- [ ] Validates with `validate-rules.py`
- [ ] Tests successfully with `test-rule.py`
- [ ] Cost estimate is acceptable (< $10/month for 5-min interval)
- [ ] Query returns results in < 30 seconds
- [ ] False positive rate is acceptable (< 10%)
- [ ] Alert template is clear and actionable
- [ ] Recommended actions are specific
- [ ] MITRE ATT&CK mapping is accurate
- [ ] Peer reviewed by another team member
- [ ] Documented in rule library README

---

## Common Patterns

### Pattern 1: Failed Attempts Followed by Success

Detects brute force or credential stuffing:

```yaml
query: |
  WITH failed_attempts AS (
    SELECT
      useridentity.username as user,
      sourceipaddress as ip,
      COUNT(*) as failures,
      MAX(eventtime) as last_failure
    FROM cloudtrail_logs
    WHERE eventdate >= CURRENT_DATE - INTERVAL '1' DAY
      AND eventtime >= CURRENT_TIMESTAMP - INTERVAL '15' MINUTE
      AND eventname = 'ConsoleLogin'
      AND errorcode IS NOT NULL
    GROUP BY useridentity.username, sourceipaddress
    HAVING COUNT(*) >= 3
  ),
  successful_logins AS (
    SELECT
      useridentity.username as user,
      sourceipaddress as ip,
      MIN(eventtime) as first_success
    FROM cloudtrail_logs
    WHERE eventdate >= CURRENT_DATE - INTERVAL '1' DAY
      AND eventtime >= CURRENT_TIMESTAMP - INTERVAL '15' MINUTE
      AND eventname = 'ConsoleLogin'
      AND errorcode IS NULL
    GROUP BY useridentity.username, sourceipaddress
  )
  SELECT
    f.user,
    f.ip,
    f.failures,
    f.last_failure,
    s.first_success,
    'Brute force followed by successful login' as reason
  FROM failed_attempts f
  JOIN successful_logins s
    ON f.user = s.user
    AND f.ip = s.ip
    AND s.first_success > f.last_failure
    AND s.first_success <= f.last_failure + INTERVAL '5' MINUTE
```

### Pattern 2: Resource Creation from Unusual Location

Detects compromised credentials:

```yaml
query: |
  WITH user_normal_regions AS (
    -- User's normal regions (90th percentile over 30 days)
    SELECT
      useridentity.username as user,
      awsregion as region,
      COUNT(*) as access_count
    FROM cloudtrail_logs
    WHERE eventdate >= CURRENT_DATE - INTERVAL '30' DAY
    GROUP BY useridentity.username, awsregion
  ),
  ranked_regions AS (
    SELECT
      user,
      region,
      access_count,
      PERCENT_RANK() OVER (PARTITION BY user ORDER BY access_count DESC) as percentile
    FROM user_normal_regions
  ),
  normal_regions AS (
    SELECT DISTINCT user, region
    FROM ranked_regions
    WHERE percentile <= 0.10  -- Top 10% of regions
  ),
  recent_resource_creation AS (
    SELECT
      useridentity.username as user,
      awsregion as region,
      eventname,
      eventtime,
      sourceipaddress
    FROM cloudtrail_logs
    WHERE eventdate >= CURRENT_DATE - INTERVAL '1' DAY
      AND eventtime >= CURRENT_TIMESTAMP - INTERVAL '15' MINUTE
      AND (eventname LIKE 'Create%' OR eventname LIKE 'Run%')
  )
  SELECT
    r.user,
    r.region as unusual_region,
    r.eventname,
    r.eventtime,
    r.sourceipaddress,
    'Resource created from unusual region' as reason
  FROM recent_resource_creation r
  LEFT JOIN normal_regions n
    ON r.user = n.user AND r.region = n.region
  WHERE n.region IS NULL  -- Not in user's normal regions
```

### Pattern 3: Privilege Escalation

Detects IAM privilege changes:

```yaml
query: |
  SELECT
    eventtime,
    useridentity.username as user,
    eventname,
    requestparameters.userName as target_user,
    requestparameters.policyArn as policy,
    sourceipaddress as source_ip
  FROM cloudtrail_logs
  WHERE eventdate >= CURRENT_DATE - INTERVAL '1' DAY
    AND eventtime >= CURRENT_TIMESTAMP - INTERVAL '15' MINUTE
    AND (
      -- Attach powerful policies
      (eventname = 'AttachUserPolicy' AND requestparameters.policyArn LIKE '%AdministratorAccess%')
      OR (eventname = 'AttachUserPolicy' AND requestparameters.policyArn LIKE '%PowerUserAccess%')
      -- Create inline policies with dangerous permissions
      OR (eventname = 'PutUserPolicy' AND requestparameters.policyDocument LIKE '%"Effect":"Allow"%' AND requestparameters.policyDocument LIKE '%"*"%')
      -- Assume role to escalate
      OR (eventname = 'AssumeRole' AND requestparameters.roleArn LIKE '%admin%')
    )
```

### Pattern 4: Data Exfiltration

Detects large data transfers:

```yaml
query: |
  WITH data_transfers AS (
    SELECT
      useridentity.username as user,
      sourceipaddress as source_ip,
      eventname,
      COUNT(*) as transfer_count,
      SUM(CAST(responseelements.contentLength AS bigint)) as total_bytes
    FROM cloudtrail_logs
    WHERE eventdate >= CURRENT_DATE - INTERVAL '1' DAY
      AND eventtime >= CURRENT_TIMESTAMP - INTERVAL '15' MINUTE
      AND eventname IN ('GetObject', 'CopyObject')
      AND responseelements.contentLength IS NOT NULL
    GROUP BY useridentity.username, sourceipaddress, eventname
  )
  SELECT
    user,
    source_ip,
    eventname,
    transfer_count,
    total_bytes,
    total_bytes / 1024 / 1024 / 1024 as total_gb,
    'Large data transfer detected' as reason
  FROM data_transfers
  WHERE total_bytes > 10737418240  -- > 10 GB
```

### Pattern 5: Persistence Mechanisms

Detects attacker establishing persistence:

```yaml
query: |
  SELECT
    eventtime,
    useridentity.username as user,
    eventname,
    sourceipaddress as source_ip,
    CASE
      WHEN eventname = 'CreateAccessKey' THEN 'New API access key created'
      WHEN eventname = 'CreateUser' THEN 'New IAM user created'
      WHEN eventname = 'PutUserPolicy' THEN 'Inline policy added to user'
      WHEN eventname = 'CreateLoginProfile' THEN 'Console access enabled for user'
      WHEN eventname = 'CreateRole' THEN 'New IAM role created'
      ELSE eventname
    END as persistence_technique
  FROM cloudtrail_logs
  WHERE eventdate >= CURRENT_DATE - INTERVAL '1' DAY
    AND eventtime >= CURRENT_TIMESTAMP - INTERVAL '15' MINUTE
    AND eventname IN (
      'CreateAccessKey',
      'CreateUser',
      'PutUserPolicy',
      'CreateLoginProfile',
      'CreateRole'
    )
    -- Exclude service roles
    AND useridentity.username NOT LIKE '%terraform%'
    AND useridentity.username NOT LIKE '%cloudformation%'
```

---

## Troubleshooting

### Issue 1: Query Times Out

**Symptoms:**
- Query execution > 60 seconds
- Athena timeout errors

**Solutions:**

1. Add partition filters:
```sql
WHERE eventdate >= CURRENT_DATE - INTERVAL '1' DAY  -- Must have this!
```

2. Reduce lookback window:
```yaml
schedule:
  lookback_minutes: 10  # Reduce from 15 to 10
```

3. Optimize JOINs:
```sql
-- Use explicit JOIN conditions with partition filters on both sides
FROM cloudtrail_logs c
JOIN other_table o
  ON c.id = o.id
  AND o.eventdate >= CURRENT_DATE - INTERVAL '1' DAY  -- Filter both sides
WHERE c.eventdate >= CURRENT_DATE - INTERVAL '1' DAY
```

### Issue 2: High Costs

**Symptoms:**
- Unexpected Athena charges
- Cost estimate > $10/month

**Solutions:**

1. Check data scanned:
```bash
python test-rule.py --rule-file RULE.yaml --estimate-cost
```

2. Add column selection:
```sql
-- Instead of SELECT *
SELECT eventtime, eventname, sourceipaddress  -- Only what you need
```

3. Increase interval:
```yaml
schedule:
  interval_minutes: 15  # Instead of 5
```

### Issue 3: False Positives

**Symptoms:**
- Too many alerts
- Alerts for known-good activity

**Solutions:**

1. Add exclusions:
```sql
WHERE eventdate >= CURRENT_DATE - INTERVAL '1' DAY
  AND useridentity.username NOT IN ('terraform', 'cloudformation')
  AND sourceipaddress NOT LIKE '10.%'  -- Exclude internal IPs
```

2. Increase threshold:
```yaml
threshold:
  count: 20  # Increase from 10
  window: 5m
```

3. Add time-based filters:
```sql
-- Exclude business hours if appropriate
WHERE extract(hour from eventtime) NOT BETWEEN 8 AND 17
```

### Issue 4: No Results When Expected

**Symptoms:**
- Rule validates but never triggers
- Manual query shows data exists

**Solutions:**

1. Check time filters:
```sql
-- Make sure both eventdate AND eventtime filters match
WHERE eventdate >= CURRENT_DATE - INTERVAL '1' DAY
  AND eventtime >= CURRENT_TIMESTAMP - INTERVAL '15' MINUTE  -- Recent data only
```

2. Verify table partitions:
```bash
aws athena start-query-execution \
  --query-string "SHOW PARTITIONS cloudtrail_logs" \
  --query-execution-context "Database=mantissa_log" \
  --work-group mantissa-log
```

3. Check for data freshness:
```bash
aws athena start-query-execution \
  --query-string "SELECT MAX(eventtime) FROM cloudtrail_logs" \
  --query-execution-context "Database=mantissa_log" \
  --work-group mantissa-log
```

### Issue 5: Syntax Errors

**Symptoms:**
- `SYNTAX_ERROR` in Athena
- Validation passes but execution fails

**Solutions:**

1. Test query directly in Athena console
2. Check for reserved keywords:
```sql
-- Bad: 'user' is reserved
SELECT user FROM cloudtrail_logs

-- Good: Use table prefix or alias
SELECT useridentity.username as user FROM cloudtrail_logs
```

3. Validate JSON paths:
```sql
-- Bad: Incorrect casing
SELECT userIdentity.UserName  -- CloudTrail uses lowercase

-- Good:
SELECT useridentity.username
```

---

## Summary

You've learned how to:

- ✅ Understand detection rule structure
- ✅ Write effective detection queries
- ✅ Optimize for cost and performance
- ✅ Test and validate rules
- ✅ Use advanced detection techniques
- ✅ Follow best practices
- ✅ Apply common detection patterns
- ✅ Troubleshoot common issues

**Next Steps:**

1. Create your first rule for your environment
2. Test thoroughly with sample data
3. Deploy to production with conservative thresholds
4. Monitor for false positives
5. Tune thresholds based on learnings
6. Share successful rules with the team

**Additional Resources:**

- [Rule Schema Reference](../configuration/detection-rules.md)
- [Query Optimization Guide](../operations/query-optimization.md)
- [Pre-built Rules Library](../../rules/)
- [End-to-End Tutorial](end-to-end-threat-detection.md)

Happy threat hunting! 🔍
