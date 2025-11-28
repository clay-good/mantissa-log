# End-to-End Threat Detection Workflow

Complete walkthrough from suspicious activity to alert delivery using all Mantissa Log features.

## Overview

This tutorial demonstrates the complete threat detection lifecycle in Mantissa Log:

1. **Discovery**: Use natural language to explore logs
2. **Analysis**: Investigate suspicious patterns with SQL
3. **Detection**: Convert query to automated detection rule
4. **Configuration**: Set up alerting and integrations
5. **Monitoring**: Receive and respond to alerts
6. **Tuning**: Refine rules based on results

**Scenario**: Detect and alert on suspicious failed login attempts from unusual locations.

## Prerequisites

- Mantissa Log deployed in AWS
- CloudTrail logs flowing to S3
- At least 24 hours of log data
- Slack workspace (for alert delivery)

## Phase 1: Discovery with Natural Language

### Step 1: Navigate to Query Interface

1. Log in to Mantissa Log web interface
2. Click **Query** in the navigation bar
3. The conversational interface appears

### Step 2: Ask Natural Language Question

**You type**:
```
Show me failed login attempts in the last 24 hours
```

**System generates SQL**:
```sql
SELECT
    eventtime,
    useridentity.principalid as user,
    sourceipaddress as source_ip,
    awsregion as region,
    errorcode,
    errormessage
FROM cloudtrail_logs
WHERE eventname = 'ConsoleLogin'
  AND errorcode IS NOT NULL
  AND eventtime >= CURRENT_TIMESTAMP - INTERVAL '24' HOUR
ORDER BY eventtime DESC
LIMIT 100
```

**System displays**:
- Query in editable SQL editor
- Cost estimate: "$0.0023 (4.7 MB scanned)"
- **Execute Query** button

### Step 3: Review Results

Click **Execute Query**. Results table shows:

| eventtime | user | source_ip | region | errorcode | errormessage |
|-----------|------|-----------|--------|-----------|--------------|
| 2024-11-28 10:15:33 | admin | 203.0.113.42 | us-east-1 | Failed authentication | Incorrect password |
| 2024-11-28 10:14:12 | admin | 203.0.113.42 | us-east-1 | Failed authentication | Incorrect password |
| 2024-11-28 10:13:55 | admin | 203.0.113.42 | us-east-1 | Failed authentication | Incorrect password |
| 2024-11-28 09:47:22 | dbadmin | 198.51.100.88 | us-west-2 | Failed authentication | Incorrect password |

**Observations**:
- Same IP (203.0.113.42) trying repeatedly
- Targeting 'admin' account
- All within 2 minutes
- Suspicious pattern!

## Phase 2: Refine Analysis

### Step 4: Follow-Up Question

**You type**:
```
Group by source IP and show counts
```

**System generates**:
```sql
SELECT
    sourceipaddress as source_ip,
    COUNT(*) as failed_attempts,
    COUNT(DISTINCT useridentity.principalid) as unique_users_targeted,
    MIN(eventtime) as first_attempt,
    MAX(eventtime) as last_attempt
FROM cloudtrail_logs
WHERE eventname = 'ConsoleLogin'
  AND errorcode IS NOT NULL
  AND eventtime >= CURRENT_TIMESTAMP - INTERVAL '24' HOUR
GROUP BY sourceipaddress
HAVING COUNT(*) > 5
ORDER BY failed_attempts DESC
```

**Results**:

| source_ip | failed_attempts | unique_users_targeted | first_attempt | last_attempt |
|-----------|-----------------|----------------------|---------------|--------------|
| 203.0.113.42 | 47 | 3 | 2024-11-28 09:30:00 | 2024-11-28 10:15:33 |
| 198.51.100.88 | 12 | 2 | 2024-11-28 09:15:00 | 2024-11-28 09:55:00 |

**Conclusion**: 203.0.113.42 is attempting brute force attack!

## Phase 3: Convert to Detection Rule

### Step 5: Save as Detection Rule

Click **Save as Detection Rule** button.

**Rule Configuration Wizard Appears**:

**Step 1: Rule Details**
- **Rule Name**: `Failed Login Brute Force`
- **Description**: `Detects 10+ failed login attempts from a single IP within 5 minutes`
- **Severity**: High
- **MITRE ATT&CK**: T1110 (Brute Force)

**Step 2: Schedule**
- **Frequency**: Every 5 minutes
- **Lookback Window**: Last 10 minutes
- **Time Zone**: UTC

**Step 3: Threshold**
- **Trigger When**: Result count > 0
- **Alert Condition**: At least 1 IP with 10+ failures

**Step 4: Cost Projection**
```
Estimated Monthly Cost:
- Query Execution: 8,640 runs/month × 4.7 MB = $0.21
- Lambda Execution: 8,640 runs × 2.3s = $0.03
- State Storage: $0.01

Total: $0.25/month
```

Click **Next**.

**Step 5: Alert Routing**

System shows configured integrations:
- ✅ Slack Security Alerts (healthy)
- ✅ Jira SEC Project (healthy)
- ✅ PagerDuty On-Call (healthy)

**Configure Routing**:
- ☑ Slack: `#security-alerts` (High, Critical)
- ☑ Jira: Create ticket (High, Critical)
- ☐ PagerDuty: (Critical only)

Click **Create Detection Rule**.

### Step 6: Review Generated Rule

System saves rule as `failed-login-brute-force.yaml`:

```yaml
name: Failed Login Brute Force
description: Detects 10+ failed login attempts from a single IP within 5 minutes
severity: high
enabled: true

metadata:
  mitre_attack:
    - T1110
  author: Your Name
  created: 2024-11-28T10:30:00Z

schedule:
  frequency: "*/5 * * * *"  # Every 5 minutes
  lookback_minutes: 10

query: |
  SELECT
      sourceipaddress as source_ip,
      COUNT(*) as failed_attempts,
      COUNT(DISTINCT useridentity.principalid) as unique_users,
      MIN(eventtime) as first_attempt,
      MAX(eventtime) as last_attempt,
      ARRAY_AGG(DISTINCT useridentity.principalid) as targeted_users
  FROM cloudtrail_logs
  WHERE eventname = 'ConsoleLogin'
    AND errorcode IS NOT NULL
    AND eventtime >= CURRENT_TIMESTAMP - INTERVAL '10' MINUTE
  GROUP BY sourceipaddress
  HAVING COUNT(*) >= 10

threshold:
  type: count
  operator: ">"
  value: 0

alert:
  title: "Brute Force Attack Detected from ${source_ip}"
  description: |
    ${failed_attempts} failed login attempts detected from IP ${source_ip}
    targeting ${unique_users} different accounts.

    Attack timeframe: ${first_attempt} to ${last_attempt}
    Targeted accounts: ${targeted_users}

routing:
  - integration: slack
    severity_filter: [high, critical]
  - integration: jira
    severity_filter: [high, critical]
```

Rule is now **active** and will run every 5 minutes!

## Phase 4: Configure PII/PHI Redaction

### Step 7: Enable Redaction

Navigate to **Settings > PII/PHI Redaction**.

**Enable Redaction**:
- ☑ Master toggle: ON
- ☑ Email Addresses
- ☑ Phone Numbers
- ☐ IP Addresses (keep for security context)

**Test Redaction**:
```
Test Input:
User john.doe@example.com from IP 203.0.113.42
Phone: 555-123-4567

Test Output:
User [EMAIL_REDACTED] from IP 203.0.113.42
Phone: [PHONE_REDACTED]
```

IP addresses preserved (unchecked) for incident response context.

Click **Save Configuration**.

## Phase 5: Set Up Integration (Slack)

### Step 8: Configure Slack Integration

Navigate to **Settings > Integrations**.

Click **Setup Wizard** for Slack.

**Slack Wizard - Step 1: Create Slack App**
1. Go to `api.slack.com/apps`
2. Create new app "Mantissa Log Security"
3. Enable Incoming Webhooks
4. Add webhook to workspace
5. Select channel: `#security-alerts`
6. Copy webhook URL

**Slack Wizard - Step 2: Enter Webhook**
- Paste webhook URL
- Channel: `#security-alerts`
- Bot name: `Mantissa Log`
- Icon: `:shield:`

**Slack Wizard - Step 3: Test**
- Click **Send Test Message**
- ✅ Success! Test message sent (234ms)

**Slack Wizard - Step 4: Configure Routing**
- ☑ Critical
- ☑ High
- ☐ Medium
- ☐ Low
- ☐ Info

**Slack Wizard - Step 5: Complete**
- Click **Complete Setup**
- Integration saved!

**Integration Health**:
```
Slack Security Alerts
Status: Healthy ✓
Success Rate: 100%
Avg Response: 234ms
Last Test: Just now
```

## Phase 6: Monitor Alert Delivery

### Step 9: Wait for Detection to Run

The detection rule runs every 5 minutes. Within 10 minutes, an alert is triggered!

### Step 10: View Alert in Dashboard

Navigate to **Alerts** page.

**Recent Alerts**:
```
┌─────────────────────────────────────────────────────────┐
│ [HIGH] Brute Force Attack Detected from 203.0.113.42   │
│                                                         │
│ 47 failed login attempts detected from IP              │
│ 203.0.113.42 targeting 3 different accounts.           │
│                                                         │
│ Attack timeframe: 2024-11-28 09:30:00 to 10:15:33      │
│ Targeted accounts: [admin, dbadmin, root]              │
│                                                         │
│ Delivered to:                                           │
│ ✓ Slack (#security-alerts) - 198ms                     │
│ ✓ Jira (SEC-1234) - 412ms                              │
│                                                         │
│ Triggered: 2 minutes ago                                │
└─────────────────────────────────────────────────────────┘
```

### Step 11: Receive Slack Notification

**Slack message appears** in `#security-alerts`:

```
:shield: Mantissa Log

[HIGH] Brute Force Attack Detected from 203.0.113.42

Severity: high
Result Count: 1

47 failed login attempts detected from IP 203.0.113.42
targeting 3 different accounts.

Attack timeframe: 2024-11-28 09:30:00 to 10:15:33
Targeted accounts: [admin, dbadmin, root]

[View Alert] [View in Mantissa Log]
```

**Notice**: Email addresses and phone numbers would be redacted if present, but IP address is preserved for security context.

### Step 12: Check Jira Ticket

**Jira ticket created automatically**:
```
Project: SEC
Issue: SEC-1234
Type: Bug
Priority: High

Title: [HIGH] Brute Force Attack Detected from 203.0.113.42

Description:
47 failed login attempts detected from IP 203.0.113.42
targeting 3 different accounts.

Attack timeframe: 2024-11-28 09:30:00 to 10:15:33
Targeted accounts: [admin, dbadmin, root]

Labels: mantissa-log, brute-force, high-severity
```

## Phase 7: Incident Response

### Step 13: Investigate in Mantissa Log

From alert, click **View Results** to see query data:

| source_ip | failed_attempts | unique_users | targeted_users |
|-----------|-----------------|--------------|----------------|
| 203.0.113.42 | 47 | 3 | [admin, dbadmin, root] |

### Step 14: Follow-Up Investigation

**Ask natural language question**:
```
Show me all activity from IP 203.0.113.42 in the last 7 days
```

System generates:
```sql
SELECT
    eventtime,
    eventname,
    useridentity.principalid as user,
    errorcode,
    CASE
        WHEN errorcode IS NULL THEN 'Success'
        ELSE 'Failed'
    END as status
FROM cloudtrail_logs
WHERE sourceipaddress = '203.0.113.42'
  AND eventtime >= CURRENT_TIMESTAMP - INTERVAL '7' DAY
ORDER BY eventtime ASC
```

**Results show**:
- First appearance: 2024-11-28 09:30
- Only failed login attempts (no successful logins)
- Targeting privileged accounts
- **Verdict**: External attack, not compromised account

### Step 15: Block IP Address

Take action:
1. Add 203.0.113.42 to AWS WAF block list
2. Update NACL to deny traffic
3. Document in Jira ticket SEC-1234

## Phase 8: Fine-Tuning

### Step 16: Create Suppression Rule

To avoid alert fatigue during testing:

Navigate to **Settings > Alert Suppression**.

**Create Maintenance Window**:
- Start Time: 2024-11-29 02:00 UTC
- Duration: 2 hours
- Suppress Rules: `failed-login-brute-force`
- Severity: All
- Reason: Planned security testing

During this window, the rule still runs but alerts are suppressed.

### Step 17: Adjust Threshold

After 1 week of monitoring, you notice:
- 10 failures = too sensitive (some false positives)
- 20 failures = more accurate

**Edit Detection Rule**:
```yaml
query: |
  ...
  HAVING COUNT(*) >= 20  # Increased from 10
```

Save changes. Rule now triggers at higher threshold.

### Step 18: Monitor Health

Navigate to **Settings > Integrations**.

**Integration Health Dashboard**:
```
Slack Security Alerts
━━━━━━━━━━━━━━━━━━━━━
Status: Healthy ✓
Success Rate: 98.5% (67/68 delivered)
Avg Response: 245ms
Last 24h: 67 attempts, 67 success, 1 failed
Consecutive Failures: 0

Recent Failures (1):
- 2024-11-28 15:23:12: Connection timeout (retried successfully)
```

## Phase 9: Advanced Workflows

### Step 19: Create Related Detection

**You ask**:
```
Also alert if there are successful logins from IPs with previous failed attempts
```

System creates new rule: `suspicious-successful-login.yaml`

```yaml
name: Suspicious Successful Login After Failures
severity: medium

query: |
  WITH failed_ips AS (
    SELECT DISTINCT sourceipaddress
    FROM cloudtrail_logs
    WHERE eventname = 'ConsoleLogin'
      AND errorcode IS NOT NULL
      AND eventtime >= CURRENT_TIMESTAMP - INTERVAL '1' HOUR
  )
  SELECT
      f.sourceipaddress,
      s.useridentity.principalid as user,
      s.eventtime
  FROM failed_ips f
  JOIN cloudtrail_logs s
    ON f.sourceipaddress = s.sourceipaddress
  WHERE s.eventname = 'ConsoleLogin'
    AND s.errorcode IS NULL
    AND s.eventtime >= CURRENT_TIMESTAMP - INTERVAL '10' MINUTE

threshold:
  type: count
  operator: ">"
  value: 0
```

Now you have **layered detection**:
1. Brute force attempts → High severity
2. Successful login after failures → Medium severity (possible compromise)

### Step 20: Set Up Escalation

Configure severity-based routing:

**Medium Severity**:
- Slack: #security-alerts
- Jira: Create ticket

**High Severity**:
- Slack: #security-alerts (with @oncall mention)
- Jira: Create ticket
- PagerDuty: Page on-call engineer

**Critical Severity**:
- Slack: #security-alerts + #incident-response
- Jira: Create incident
- PagerDuty: Page on-call + manager

## Key Takeaways

### What You Learned

1. **Natural Language to Detection**: Start with questions, end with automated rules
2. **Cost Visibility**: Every query shows cost before execution
3. **Iterative Refinement**: Adjust thresholds based on real alerts
4. **Multi-Channel Alerting**: Route to appropriate systems by severity
5. **PII Protection**: Automatic redaction in external integrations
6. **Health Monitoring**: Track integration reliability
7. **Failure Handling**: Dead letter queue for failed alerts

### Workflow Summary

```
Question → SQL → Results → Analysis
              ↓
        Detection Rule
              ↓
        Scheduled Execution
              ↓
         Alert Triggered
              ↓
    ┌────────┼────────┐
    ↓        ↓        ↓
  Slack    Jira   PagerDuty
    ↓        ↓        ↓
  Incident Response
    ↓
  Block Threat
    ↓
  Tune Detection
    ↓
  Monitor Health
```

### Cost Analysis

**Monthly Costs for This Workflow**:
- Detection Rule Execution: $0.25
- Alert Storage: $0.05
- Integration Delivery: $0.00 (Slack/Jira free)
- Health Monitoring: $0.02

**Total**: ~$0.32/month for automated brute force detection!

Compare to: Datadog SIEM @ $150,000/year = $12,500/month

## Next Steps

### Expand Detection Coverage

1. Create rules for other MITRE ATT&CK techniques
2. Import community rules from `rules/` directory
3. Customize rules for your environment

### Integrate More Sources

1. Add VPC Flow Logs
2. Add application logs
3. Add container logs (ECS, EKS)

### Build Dashboards

1. Create executive summary dashboard
2. Track MTTR (Mean Time to Response)
3. Monitor detection coverage

### Automate Response

1. Trigger Lambda functions from alerts
2. Automatically block IPs
3. Quarantine compromised accounts

## Resources

### Documentation

- [Detection Rule Reference](../configuration/detection-rules.md)
- [Alert Configuration](../configuration/alerts.md)
- [Integration Setup](../features/integration-wizards.md)
- [PII/PHI Redaction](../features/pii-phi-redaction.md)

### Example Rules

- Browse `rules/` directory for 50+ pre-built detections
- Categories: authentication, network, cloud, data access

### Community

- GitHub Discussions: Share rules and ask questions
- Slack Community: Real-time help and collaboration

---

**You've now completed a full end-to-end threat detection workflow in Mantissa Log!** 🎉

From natural language exploration to automated alerting with health monitoring and PII protection, you've experienced the complete platform capabilities.

The same workflow applies to any security use case:
- Data exfiltration detection
- Privilege escalation monitoring
- Anomalous API usage
- Compliance violations
- Insider threat detection

Start exploring your logs and building your detection library!
