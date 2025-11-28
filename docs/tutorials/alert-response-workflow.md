# Alert Response Workflow

A practical guide to triaging, investigating, and responding to security alerts from Mantissa Log. This tutorial provides step-by-step playbooks for common alert scenarios.

## Table of Contents

1. [Alert Response Lifecycle](#alert-response-lifecycle)
2. [Initial Triage](#initial-triage)
3. [Investigation Playbooks](#investigation-playbooks)
4. [Escalation and Communication](#escalation-and-communication)
5. [Remediation Actions](#remediation-actions)
6. [Post-Incident Activities](#post-incident-activities)
7. [Tools and Commands](#tools-and-commands)

---

## Alert Response Lifecycle

Understanding the complete workflow from alert to resolution:

```
Alert Received
    ↓
Initial Triage (5 min)
    ↓
Severity Assessment
    ↓
Investigation (15-60 min)
    ↓
Containment (if needed)
    ↓
Remediation
    ↓
Documentation
    ↓
Tuning/Learning
```

### Time Targets by Severity

| Severity | Acknowledgment | Initial Triage | Full Investigation |
|----------|----------------|----------------|-------------------|
| Critical | 5 minutes | 15 minutes | 1 hour |
| High | 15 minutes | 30 minutes | 4 hours |
| Medium | 1 hour | 4 hours | 24 hours |
| Low | 4 hours | 24 hours | 3 days |
| Info | Best effort | Best effort | Best effort |

---

## Initial Triage

### Step 1: Acknowledge Alert (< 2 minutes)

When an alert arrives in Slack/PagerDuty/Email:

**Immediately capture:**
1. Alert ID
2. Timestamp
3. Severity
4. Affected resource/user

**Example Slack Alert:**
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
Alert ID: alert-abc123xyz
```

**Acknowledge in incident channel:**
```
🔍 Investigating alert-abc123xyz
Assigned to: @your-name
Status: Triaging
```

### Step 2: Initial Assessment (< 5 minutes)

Answer these key questions:

**1. Is this a real threat or false positive?**

Check for known patterns:
```bash
# Check if IP is in allow list
grep "203.0.113.42" known-good-ips.txt

# Check if this is expected maintenance
cat maintenance-windows.txt | grep "2024-11-28 10:"

# Check if user is known to have issues
grep "admin" frequently-locked-users.txt
```

**2. Is it still active?**

```bash
# Check for continued activity in last 5 minutes
cd scripts

python query.py --question "Show me failed login attempts from 203.0.113.42 in the last 5 minutes"
```

**3. Has this happened before?**

```bash
# Check alert history
python query.py --question "Show me all alerts for rule brute_force_detection in the last 7 days"
```

### Step 3: Severity Validation

Verify the assigned severity is appropriate:

**Upgrade severity if:**
- Successful login occurred after failed attempts
- Privileged account targeted (root, admin, service accounts)
- Source IP has other suspicious indicators
- Multiple users/resources affected
- Active data exfiltration detected

**Downgrade severity if:**
- Confirmed false positive
- Expected activity during change window
- Low-privilege account with no sensitive access
- Isolated incident with no other indicators

### Decision Point: Escalate or Investigate?

**Immediately escalate if:**
- Critical severity
- Confirmed compromise
- Active data exfiltration
- Privilege escalation detected
- Multiple simultaneous alerts

**Proceed to investigation if:**
- High/Medium severity
- Unclear if malicious
- Need more context
- Isolated event

---

## Investigation Playbooks

### Playbook 1: Brute Force Authentication

**Alert Type:** Failed login attempts from single source
**Severity:** High
**Investigation Time:** 15-30 minutes

#### Step 1: Gather Context (5 min)

```bash
cd scripts

# Get all activity from source IP
python query.py --question "Show me all CloudTrail events from IP 203.0.113.42 in the last 24 hours"

# Check for successful logins
python query.py --question "Show me successful logins from 203.0.113.42 in the last 24 hours"

# Check if IP is known
python query.py --question "Has IP 203.0.113.42 appeared in our logs in the last 30 days?"
```

**Key Questions:**
- How many failed attempts total?
- Were any attempts successful?
- Is this a new or known IP?
- What user accounts were targeted?

#### Step 2: Assess Impact (5 min)

```bash
# If successful login occurred, check what they did
python query.py --question "Show me all actions by user admin from IP 203.0.113.42 after the successful login"

# Check for privilege escalation
python query.py --question "Show me any IAM policy changes by user admin in the last hour"

# Check for resource creation
python query.py --question "Show me any EC2, Lambda, or IAM resources created by admin in the last hour"
```

**Impact Levels:**
- **None:** Only failed attempts, no successful access
- **Low:** Successful login but no actions taken
- **Medium:** Successful login with read operations
- **High:** Successful login with write operations
- **Critical:** Privilege escalation or resource creation

#### Step 3: Investigate Source (5 min)

```bash
# Geolocate IP
curl "https://ipapi.co/203.0.113.42/json/"

# Check threat intelligence
curl "https://www.abuseipdb.com/check/203.0.113.42/json?key=YOUR_API_KEY"

# Check VPN/Proxy services
# (Many attackers use VPNs)
```

**Red flags:**
- IP from high-risk country
- Known malicious IP in threat intel
- VPN/Proxy service (could indicate hiding)
- Hosting provider (not corporate network)

#### Step 4: Timeline Reconstruction (10 min)

```bash
# Build complete timeline
python query.py --question "Show me all events related to user admin from 1 hour before first failed login to now, ordered by time"
```

Create timeline document:
```
2024-11-28 10:05:00 - Normal admin activity from 192.0.2.100 (known office IP)
2024-11-28 10:10:00 - Admin logged out
2024-11-28 10:13:55 - First failed login from 203.0.113.42 (unknown IP)
2024-11-28 10:14:12 - Failed login #2
...
2024-11-28 10:15:33 - Failed login #47
2024-11-28 10:16:45 - No further activity
```

#### Step 5: Determine Next Action

**If no successful login:**
1. Block IP at network perimeter
2. Notify user to reset password
3. Enable MFA if not already enabled
4. Monitor for continued attempts
5. Document as attempted compromise

**If successful login occurred:**
1. **Immediate:** Disable user account
2. **Immediate:** Terminate all user sessions
3. **Immediate:** Delete any access keys created
4. **Immediate:** Block source IP
5. **Next:** Full forensic investigation
6. **Next:** Check for lateral movement
7. **Next:** Review CloudTrail for all actions taken

---

### Playbook 2: Privilege Escalation

**Alert Type:** IAM permission changes
**Severity:** Critical
**Investigation Time:** 30-60 minutes

#### Step 1: Identify What Changed (5 min)

```bash
# Get the specific policy change
python query.py --question "Show me IAM policy changes in the last hour with full request parameters"

# Identify the policy that was attached/created
python query.py --question "Show me the exact policy document that was created or attached"
```

**Capture:**
- Who made the change (user/role)
- Which user/role was granted permissions
- What permissions were granted
- When the change occurred
- Source IP of the change

#### Step 2: Assess Permissions Granted (5 min)

```bash
# Download the policy document
aws iam get-policy-version \
  --policy-arn arn:aws:iam::123456789012:policy/SuspiciousPolicy \
  --version-id v1 \
  --query 'PolicyVersion.Document' | jq .
```

**Dangerous permissions to look for:**
```json
{
  "Effect": "Allow",
  "Action": [
    "iam:*",              // Full IAM control
    "*",                  // Full AWS access
    "sts:AssumeRole",     // Can assume any role
    "iam:CreateAccessKey", // Can create keys
    "iam:AttachUserPolicy" // Can escalate further
  ],
  "Resource": "*"         // Applies to everything
}
```

**Impact:**
- **Critical:** Full admin access (`*` on `*`)
- **High:** IAM management permissions
- **Medium:** Specific service admin (EC2:*, S3:*)
- **Low:** Read-only permissions

#### Step 3: Check for Exploitation (10 min)

```bash
# Did the elevated user use the new permissions?
python query.py --question "Show me all actions by user <ELEVATED_USER> after the policy was attached"

# Look for common post-exploitation activities
python query.py --question "Show me any access key creation, user creation, or EC2 launches by <ELEVATED_USER> after the policy change"

# Check for AssumeRole attempts
python query.py --question "Show me AssumeRole events by <ELEVATED_USER> in the last hour"
```

**Red flags:**
- Immediate use of new permissions
- Creation of new access keys
- Creation of new IAM users
- Launch of EC2 instances
- AssumeRole to other accounts

#### Step 4: Identify Root Cause (10 min)

**Scenarios:**

**Scenario A: Legitimate Admin**
```
User: john.smith (DevOps team)
IP: 192.0.2.50 (Office network)
Time: During business hours
Action: Attached policy to service account
Ticket: JIRA-1234 "Setup new deployment pipeline"
```
**Verdict:** Likely legitimate, verify with ticket

**Scenario B: Compromised Credentials**
```
User: john.smith
IP: 203.0.113.42 (Unknown, foreign country)
Time: 3 AM local time
Action: Attached AdministratorAccess to own user
No ticket or change request
```
**Verdict:** Compromise, immediate response needed

**Scenario C: Insider Threat**
```
User: departed.employee
IP: 192.0.2.75 (Office network)
Action: Attached policies to personal user account
Employee departed 2 weeks ago but account still active
```
**Verdict:** Unauthorized access, immediate termination

#### Step 5: Containment (Immediate)

**For compromised credentials:**

```bash
# 1. Disable the user immediately
aws iam update-user \
  --user-name john.smith \
  --no-password-reset-required

# 2. Delete all access keys
aws iam list-access-keys --user-name john.smith | \
  jq -r '.AccessKeyMetadata[].AccessKeyId' | \
  xargs -I {} aws iam delete-access-key --user-name john.smith --access-key-id {}

# 3. Detach all policies
aws iam list-attached-user-policies --user-name john.smith | \
  jq -r '.AttachedPolicies[].PolicyArn' | \
  xargs -I {} aws iam detach-user-policy --user-name john.smith --policy-arn {}

# 4. Remove from all groups
aws iam list-groups-for-user --user-name john.smith | \
  jq -r '.Groups[].GroupName' | \
  xargs -I {} aws iam remove-user-from-group --user-name john.smith --group-name {}

# 5. Block source IP
aws ec2 revoke-security-group-ingress \
  --group-id sg-xxxxxx \
  --ip-permissions IpProtocol=tcp,FromPort=443,ToPort=443,IpRanges='[{CidrIp=203.0.113.42/32}]'
```

#### Step 6: Rollback Malicious Changes (15 min)

```bash
# Identify all changes made during compromise window
python query.py --question "Show me all IAM changes in the last 2 hours ordered by time"

# Detach malicious policies
aws iam detach-user-policy \
  --user-name <TARGET_USER> \
  --policy-arn arn:aws:iam::123456789012:policy/SuspiciousPolicy

# Delete created users
aws iam delete-user --user-name malicious-user

# Delete created access keys
aws iam delete-access-key \
  --user-name <TARGET_USER> \
  --access-key-id AKIAIOSFODNN7EXAMPLE

# Terminate created EC2 instances
aws ec2 terminate-instances --instance-ids i-1234567890abcdef0
```

---

### Playbook 3: Data Exfiltration

**Alert Type:** Unusual data transfer volume
**Severity:** Critical
**Investigation Time:** 30-60 minutes

#### Step 1: Quantify Data Transfer (5 min)

```bash
# Get total data transferred
python query.py --question "Show me all S3 GetObject operations by user <USER> in the last hour with file sizes"

# Identify specific objects accessed
python query.py --question "List all S3 objects accessed by user <USER> in the last hour with bucket names"

# Calculate total
python query.py --question "What is the total data transferred by user <USER> in the last hour?"
```

**Severity based on volume:**
- < 1 GB: Low (unless highly sensitive)
- 1-10 GB: Medium
- 10-100 GB: High
- \> 100 GB: Critical

#### Step 2: Classify Data Sensitivity (10 min)

```bash
# Check bucket classifications
aws s3api get-bucket-tagging --bucket BUCKET_NAME

# Check object metadata
aws s3api head-object --bucket BUCKET_NAME --key path/to/object

# List all buckets accessed
python query.py --question "Which S3 buckets did user <USER> access in the last hour?"
```

**Data classification levels:**
- **Public:** No impact
- **Internal:** Low impact
- **Confidential:** Medium impact
- **Restricted/PII:** High impact
- **Regulated/PHI:** Critical impact

#### Step 3: Determine Destination (10 min)

```bash
# Where was data sent?
python query.py --question "Show me all S3 PutObject or CopyObject events by user <USER> to external buckets"

# Check for data egress to internet
python query.py --question "Show me network flow logs from <USER_IP> to external IPs with large data transfer"

# Look for exfil methods
python query.py --question "Show me any SendEmail, PublishMessage, or PutObject events by <USER> in the last hour"
```

**Common exfiltration methods:**
- S3 CopyObject to external account
- EC2 instance with internet access
- Email with attachments
- SNS/SQS to external endpoints
- Direct download via GetObject

#### Step 4: Assess Legitimacy (5 min)

**Legitimate scenarios:**
- Scheduled backup job
- Data migration during change window
- Analytics export
- Compliance audit request

**Check for:**
```bash
# Is this a known service account?
grep "<USER>" service-accounts.txt

# Is there a change ticket?
jira issue get --issue JIRA-XXXX

# Is this a regular pattern?
python query.py --question "Show me historical S3 access patterns for user <USER> over the last 30 days"
```

#### Step 5: Immediate Response (10 min)

**If confirmed exfiltration:**

```bash
# 1. Block user immediately
aws iam update-user --user-name <USER> --no-password-reset-required

# 2. Delete all access keys
aws iam list-access-keys --user-name <USER> | \
  jq -r '.AccessKeyMetadata[].AccessKeyId' | \
  xargs -I {} aws iam delete-access-key --user-name <USER> --access-key-id {}

# 3. Revoke active sessions
aws iam delete-login-profile --user-name <USER>

# 4. Block source IP
# (Add to WAF rules or Security Group deny rules)

# 5. Enable S3 Block Public Access on affected buckets
aws s3api put-public-access-block \
  --bucket BUCKET_NAME \
  --public-access-block-configuration \
    "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true"

# 6. Delete any externally shared objects
aws s3api delete-object --bucket BUCKET_NAME --key path/to/exfiltrated/object
```

#### Step 6: Forensic Preservation (15 min)

```bash
# Export CloudTrail logs for forensic analysis
aws athena start-query-execution \
  --query-string "SELECT * FROM cloudtrail_logs WHERE useridentity.username = '<USER>' AND eventdate >= CURRENT_DATE - INTERVAL '7' DAY" \
  --result-configuration "OutputLocation=s3://forensics-bucket/case-123/"

# Snapshot affected S3 buckets
aws s3 sync s3://affected-bucket s3://forensics-bucket/case-123/bucket-snapshot/

# Export VPC Flow Logs
aws logs create-export-task \
  --log-group-name /aws/vpc/flowlogs \
  --from 1700000000000 \
  --to 1700100000000 \
  --destination forensics-bucket \
  --destination-prefix case-123/flowlogs/
```

---

## Escalation and Communication

### When to Escalate

**Immediate escalation required:**
- Confirmed data breach
- Ransomware detected
- Privilege escalation by unknown actor
- Multiple simultaneous critical alerts
- Active ongoing attack
- Regulatory requirements (GDPR, HIPAA, PCI-DSS)

### Escalation Paths

```
On-Call Engineer
    ↓ (Critical alerts)
Security Team Lead
    ↓ (Confirmed incidents)
Security Manager
    ↓ (Data breach/Major incident)
CISO + Legal + PR
```

### Communication Templates

**Internal Update (Every 30 min during active incident):**

```
Incident: alert-abc123xyz
Status: Active Investigation
Severity: Critical
Started: 2024-11-28 10:20 UTC
Last Update: 2024-11-28 11:00 UTC

Summary:
Detected brute force attack from 203.0.113.42 targeting admin account.
Successful login achieved. User performed privilege escalation.

Current Status:
- User account disabled
- Source IP blocked
- Reviewing actions taken during compromise window
- No evidence of data exfiltration yet

Next Steps:
- Complete timeline reconstruction
- Full credential rotation
- Forensic analysis of affected systems

Point of Contact: @security-oncall
```

**Executive Summary (For leadership):**

```
SECURITY INCIDENT SUMMARY

Incident ID: alert-abc123xyz
Date: 2024-11-28
Severity: CRITICAL

WHAT HAPPENED:
Unauthorized access to admin account following brute force attack.
Attacker escalated privileges and created new access keys.

BUSINESS IMPACT:
- 1 compromised administrative account
- Potential unauthorized access for 15 minutes
- No confirmed data loss at this time

ACTIONS TAKEN:
- Compromised account disabled
- Malicious access keys deleted
- Source IP blocked
- Full audit of actions during compromise window

CURRENT STATUS:
- Threat contained
- Forensic investigation ongoing
- No evidence of ongoing unauthorized access

ESTIMATED RESOLUTION:
4 hours for full investigation and remediation

POC: security-team@company.com
```

---

## Remediation Actions

### Credential Compromise

**Immediate (< 30 min):**
1. Disable affected user account
2. Delete all access keys
3. Terminate active sessions
4. Block source IP

**Short-term (< 24 hours):**
5. Force password reset for all users
6. Rotate all API keys and secrets
7. Enable MFA for all accounts
8. Review and revoke suspicious sessions

**Long-term (< 1 week):**
9. Implement least-privilege policies
10. Enable CloudTrail in all regions
11. Set up GuardDuty
12. Implement AWS SSO with MFA enforcement

### Privilege Escalation

**Immediate:**
1. Revoke escalated permissions
2. Disable affected account
3. Delete created resources
4. Block source IP

**Short-term:**
5. Audit all IAM policies
6. Remove overly permissive policies
7. Implement SCPs for guardrails
8. Enable IAM Access Analyzer

**Long-term:**
9. Implement policy-as-code with review process
10. Automated compliance scanning
11. Regular access reviews
12. Implement just-in-time access

### Data Exfiltration

**Immediate:**
1. Block user and source IP
2. Enable S3 Block Public Access
3. Delete external copies if possible
4. Preserve logs for forensics

**Short-term:**
5. Classify all S3 buckets
6. Implement S3 Object Lock for sensitive data
7. Enable S3 Access Logging
8. Review and remove unnecessary external shares

**Long-term:**
9. Implement DLP controls
10. Data classification program
11. Regular access audits
12. Encryption at rest for all sensitive data

---

## Post-Incident Activities

### Documentation

Create incident report with:

1. **Timeline**
   - First detection
   - Each investigation step
   - Containment actions
   - Resolution

2. **Root Cause Analysis**
   - How did attacker gain access?
   - What controls failed?
   - Why wasn't it detected earlier?

3. **Impact Assessment**
   - Systems affected
   - Data accessed/exfiltrated
   - Duration of unauthorized access
   - Business impact

4. **Remediation Actions**
   - Immediate actions taken
   - Short-term fixes
   - Long-term improvements

5. **Lessons Learned**
   - What went well?
   - What could be improved?
   - Training needs identified?

### Rule Tuning

After investigating false positives or true positives:

**For false positives:**

```yaml
# Add exclusions to rule
query: |
  SELECT ...
  FROM cloudtrail_logs
  WHERE eventdate >= CURRENT_DATE - INTERVAL '1' DAY
    -- Exclude known-good patterns
    AND useridentity.username NOT IN ('terraform', 'cloudformation')
    AND sourceipaddress NOT LIKE '10.%'  -- Internal network
```

**For true positives:**

```yaml
# Lower threshold for earlier detection
threshold:
  count: 5  # Previously 10
  window: 5m

# Or reduce detection interval
schedule:
  interval_minutes: 5  # Previously 15
```

### Continuous Improvement

Schedule regular reviews:

**Weekly:**
- Alert volume and false positive rate
- Mean time to detect (MTTD)
- Mean time to respond (MTTR)

**Monthly:**
- Rule effectiveness review
- Update threat intel feeds
- Training on new attack techniques

**Quarterly:**
- Tabletop exercises
- Update runbooks
- Review and update escalation procedures

---

## Tools and Commands

### Quick Reference

**Check current activity:**
```bash
# Real-time failed logins
python query.py --question "Show me failed login attempts in the last 5 minutes"

# Recent privilege changes
python query.py --question "Show me IAM policy changes in the last hour"

# Large data transfers
python query.py --question "Show me S3 GetObject operations > 1GB in the last hour"
```

**User investigation:**
```bash
# All activity by user
python query.py --question "Show me all actions by user <USERNAME> in the last 24 hours"

# User's normal behavior baseline
python query.py --question "Show me typical activity patterns for user <USERNAME> over last 30 days"

# Privilege level
aws iam list-attached-user-policies --user-name <USERNAME>
aws iam list-user-policies --user-name <USERNAME>
```

**IP investigation:**
```bash
# All activity from IP
python query.py --question "Show me all CloudTrail events from IP <IP_ADDRESS> in the last 24 hours"

# Geolocate
curl "https://ipapi.co/<IP_ADDRESS>/json/"

# Check threat intel
curl "https://www.abuseipdb.com/check/<IP_ADDRESS>/json?key=YOUR_KEY"
```

**Resource investigation:**
```bash
# Who accessed this S3 bucket?
python query.py --question "Show me all access to S3 bucket <BUCKET_NAME> in the last 7 days"

# Who created this EC2 instance?
python query.py --question "Show me RunInstances events for instance <INSTANCE_ID>"

# What did this instance do?
python query.py --question "Show me all API calls from instance <INSTANCE_ID>"
```

---

## Summary

You've learned:

- ✅ Complete alert response lifecycle
- ✅ Initial triage procedures
- ✅ Investigation playbooks for common scenarios
- ✅ Escalation and communication procedures
- ✅ Remediation actions for different threat types
- ✅ Post-incident activities and continuous improvement
- ✅ Useful tools and commands for investigations

**Next Steps:**

1. Practice with sample alerts from test environment
2. Customize playbooks for your organization
3. Schedule tabletop exercises
4. Update escalation contacts
5. Create investigation checklists

**Additional Resources:**

- [Quick Start Guide](quick-start-with-samples.md)
- [Detection Rule Authoring](detection-rule-authoring.md)
- [End-to-End Tutorial](end-to-end-threat-detection.md)
- [Operations Runbook](../operations/runbook.md)

Stay vigilant! 🛡️
