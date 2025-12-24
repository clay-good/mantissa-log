# Data Exfiltration Response Plan

## Overview

This incident response plan outlines the procedures for responding to suspected data exfiltration incidents, including unusual data transfers, bulk downloads, and unauthorized cloud storage uploads.

## Trigger Conditions

- High or critical severity alerts
- Rule patterns matching: data_exfiltration, bulk_download, unusual_transfer, dlp_violation
- Data loss prevention (DLP) tagged alerts
- Unusually large outbound data transfers

## Response Steps

### Step 1: Block Destination IP/Domain

**Priority: Immediate**

Block the destination IP address or domain where data is being exfiltrated.

- Action: Block IP
- Target: Destination IP from alert metadata
- Duration: Indefinite (until investigation complete)
- Scope: All egress points

### Step 2: Terminate User Sessions

**Priority: Immediate**

End all active sessions for the user involved in the data transfer.

- Action: Terminate sessions
- Target: User performing the transfer
- Reason: Suspected data exfiltration investigation

### Step 3: Revoke API Tokens

**Priority: High**

Revoke all OAuth tokens and API keys associated with the user account.

- Action: Revoke tokens
- Target: Affected user
- Scope: All applications and integrations
- Force re-authentication: Yes

### Step 4: Isolate Source Host

**Priority: High**
**Requires Approval: Yes (Security Analyst)**

If the exfiltration is happening from a specific endpoint, isolate it from the network.

- Action: Network isolation
- Target: Source host (by hostname or IP)
- Method: EDR containment or network ACL
- Preserve: Connection to security tools for investigation

### Step 5: Preserve Evidence

**Priority: High**

Capture forensic evidence of the data transfer activity.

- Action: Run query
- Query type: Log preservation
- Time range: 24 hours before alert to present
- Sources: Proxy logs, firewall logs, DLP logs, endpoint logs
- Destination: Forensics archive

### Step 6: Assess Data Impact

**Priority: High**

Run queries to understand the scope of data potentially exfiltrated.

- Action: Run query
- Query: Identify files accessed and transferred by user in last 7 days
- Output: File names, sizes, classifications, destinations

### Step 7: Disable User Account

**Priority: Medium**
**Requires Approval: Yes (Security Manager, HR, Legal)**

If data exfiltration is confirmed, disable the user account pending investigation.

- Action: Disable account
- Target: Suspected user
- Reason: Data exfiltration investigation - account suspended pending review
- Coordinate with: HR, Legal

### Step 8: Create Incident Ticket

**Priority: High**

Create an incident ticket for tracking and compliance purposes.

- Action: Create ticket
- System: Jira
- Project: SEC
- Type: Incident
- Priority: Critical
- Summary: Data Exfiltration - [user_email] - [data_classification]
- Description: Include volume transferred, destinations, data types, timeline
- Labels: security-incident, data-exfiltration, dlp, compliance

### Step 9: Notify Stakeholders

**Priority: High**

Notify relevant stakeholders based on data classification.

- Action: Send notifications
- If PII/PHI involved:
  - Channel: #privacy-incidents
  - Notify: Privacy Officer, Legal
- If financial data:
  - Channel: #finance-security
  - Notify: CFO, Compliance
- All incidents:
  - Channel: #security-critical
  - Notify: CISO, Security Team

### Step 10: External Communication Preparation

**Priority: Medium**

If required by regulations, prepare for external notification.

- Action: Create ticket
- System: Jira
- Project: LEGAL
- Type: Task
- Summary: Breach Notification Assessment - [incident_id]
- Description: Data exfiltration incident requires breach notification assessment
- Assignee: Legal team

### Error Handling

If IP blocking fails:
1. Escalate to network operations
2. Attempt blocking at DNS level
3. Contact upstream provider if necessary

If user account disable requires additional approval:
1. Implement temporary controls (session termination, token revocation)
2. Expedite approval through security management chain

## Approval Requirements

- Host isolation requires approval from: Security Analyst
- Account disable requires approval from: Security Manager + HR + Legal
- Approval timeout: 2 hours for host isolation, 4 hours for account disable

## Compliance Considerations

- GDPR: 72-hour breach notification requirement
- HIPAA: 60-day breach notification requirement
- SOX: Immediate notification for financial data
- Preserve all evidence for potential legal proceedings

## Tags

- data-exfiltration
- dlp
- compliance
- insider-threat
- critical
