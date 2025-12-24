# Insider Threat Response Plan

## Overview

This incident response plan outlines the procedures for responding to insider threat indicators, including policy violations, unauthorized access attempts, privilege abuse, and suspicious employee behavior patterns.

## Trigger Conditions

- Medium to critical severity alerts
- Rule patterns matching: insider_threat, privilege_abuse, policy_violation, unauthorized_access
- User behavior analytics (UBA) anomaly alerts
- HR-flagged employee risk indicators

## Response Steps

### Step 1: Silent Monitoring Enhancement

**Priority: Immediate**
**Note: Do not alert the user**

Increase monitoring and logging for the suspected insider without tipping them off.

- Action: Run query / Custom action
- Type: Enable enhanced logging
- Target: User account and associated endpoints
- Scope: All activity - authentication, file access, email, cloud apps
- Duration: 30 days or until investigation complete
- Stealth: Yes - no user notification

### Step 2: Preserve Current Evidence

**Priority: High**

Capture and preserve all available evidence before any containment actions.

- Action: Run query
- Queries:
  - All authentication events for user (90 days)
  - All file access events (90 days)
  - All email activity (90 days)
  - All cloud app usage (90 days)
  - Badge access logs (90 days)
  - VPN connection logs (90 days)
- Output: Forensics archive with chain of custody

### Step 3: Assess Risk Level

**Priority: High**

Determine the risk level based on user role and access.

- Action: Run query
- Query: Enumerate all user privileges, group memberships, and sensitive data access
- Evaluate:
  - Access to financial systems
  - Access to customer data
  - Access to intellectual property
  - Admin privileges
  - Departure risk (resignation, PIP, etc.)

### Step 4: Create Confidential Incident Ticket

**Priority: High**

Create a restricted-access incident ticket.

- Action: Create ticket
- System: Jira
- Project: SEC-CONFIDENTIAL
- Type: Investigation
- Priority: High
- Summary: Insider Threat Investigation - [case_number]
- Description: Sanitized summary - no employee name in description
- Security Level: Confidential - Security and Legal only
- Labels: insider-threat, confidential, investigation

### Step 5: Notify Security Leadership

**Priority: High**

Alert security leadership through secure channels.

- Action: Send notification
- Method: Encrypted email or secure messaging
- Recipients: CISO, Security Director, HR Security Liaison
- Do NOT use: Regular Slack channels, unencrypted email
- Include: Case number, risk assessment, recommended actions

### Step 6: Coordinate with HR and Legal

**Priority: High**

Engage HR and Legal for guidance on employment and legal implications.

- Action: Create ticket
- System: Jira
- Project: HR-CONFIDENTIAL
- Type: Consultation
- Summary: Security consultation request - [case_number]
- Description: Request HR/Legal guidance on employee investigation
- Assignee: HR Security Liaison

### Step 7: Implement Graduated Controls

**Priority: Medium**
**Requires Approval: Yes (CISO + HR + Legal)**

Based on risk level, implement appropriate controls without full account disable.

Graduated options (select based on risk):

Level 1 - Low Risk:
- Action: Modify permissions
- Remove: Sensitive group memberships
- Retain: Basic access for job function

Level 2 - Medium Risk:
- Action: Restrict access
- Remove: VPN access, remote access
- Require: On-premises only access

Level 3 - High Risk:
- Action: Disable account
- Coordinate: HR for administrative leave
- Preserve: All data and access logs

### Step 8: Monitor for Escalation

**Priority: Medium**

Set up alerts for any escalating behavior.

- Action: Custom detection rule
- Watch for:
  - Bulk downloads or file access
  - Access outside normal hours
  - Access from unusual locations
  - Attempts to access restricted resources
  - Deletion or modification of files
- Alert: Security team immediately

### Step 9: Prepare for Confrontation/Termination

**Priority: Low**
**Trigger: HR decision to confront or terminate**

Prepare technical controls for employee confrontation or termination scenario.

- Action: Prepare (do not execute)
- Prepare:
  - Account disable script
  - Badge deactivation request
  - Device collection list
  - Data preservation verification
  - Access revocation checklist

### Step 10: Post-Resolution Actions

**Priority: Low**
**Trigger: Investigation complete**

Clean up and document lessons learned.

- Action: Create ticket
- System: Jira
- Project: SEC
- Type: Task
- Summary: Insider Threat Case Closure - [case_number]
- Tasks:
  - Archive investigation materials
  - Update insider threat detection rules
  - Document lessons learned
  - Brief security team (sanitized)

### Error Handling

This playbook handles sensitive employment matters. Errors should be handled carefully:

If monitoring enhancement fails:
1. Do not retry automatically
2. Notify Security Director only
3. Use alternative monitoring methods

If evidence preservation fails:
1. Attempt backup preservation methods
2. Document what was and wasn't captured
3. Consult Legal on implications

## Approval Requirements

This playbook has elevated approval requirements due to employment law implications:

- Enhanced monitoring: Security Director
- Graduated controls: CISO + HR Director + Legal
- Account disable: CISO + HR Director + Legal + (Executive sponsor for senior employees)
- All actions must be documented for potential legal proceedings

## Legal and Privacy Considerations

- All monitoring must comply with local employment law
- Some jurisdictions require employee notification of monitoring
- Union employees may have additional protections
- Preserve chain of custody for all evidence
- Document decision-making rationale
- Consult Legal before any confrontation

## Confidentiality

- This investigation type is HIGHLY CONFIDENTIAL
- Limit knowledge to essential personnel only
- Use secure communication channels
- Do not discuss in open Slack channels
- All documentation should be access-restricted

## Tags

- insider-threat
- confidential
- hr-coordination
- legal-coordination
- investigation
