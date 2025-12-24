# Credential Compromise Response Plan

## Overview

This incident response plan outlines the procedures for responding to credential compromise incidents, including brute force attacks, credential stuffing, impossible travel detections, and password spraying attempts.

## Trigger Conditions

- High or critical severity alerts
- Rule patterns matching: credential, brute_force, impossible_travel, password_spray
- Identity-tagged alerts

## Response Steps

### Step 1: Terminate Active Sessions

**Priority: Immediate**

When a credential compromise is detected, immediately terminate all active sessions for the affected user to prevent further unauthorized access.

- Action: Kill all active sessions
- Target: Affected user (identified by email or user ID)
- Reason: Security incident - credential compromise detected
- Expected outcome: All active sessions terminated, user logged out everywhere

### Step 2: Force Password Reset

**Priority: High**
**Requires Approval: Yes (Security Analyst or Manager)**

After terminating sessions, force a password reset for the user account. This ensures any compromised credentials cannot be reused.

- Action: Force password reset
- Target: Affected user
- Notify user: Yes
- Message: "Your password has been reset due to a security incident. Please contact IT if you did not request this change."

### Step 3: Create Incident Ticket

**Priority: High**

Create an incident ticket in Jira to track the investigation and response.

- Action: Create ticket
- System: Jira
- Project: SEC
- Type: Incident
- Priority: High
- Summary: Include user email and alert title
- Description: Include all relevant alert details, source IP, location, user agent
- Labels: security-incident, credential-compromise, automated-response

### Step 4: Notify Security Team

**Priority: Medium**

Send a notification to the security team Slack channel with incident details and actions taken.

- Action: Send Slack notification
- Channel: #security-alerts
- Include: User email, alert title, severity, actions taken, ticket link

### Error Handling

If any step fails, send an error notification to the security team with:
- Failed step details
- Error message
- Request for manual intervention

## Approval Requirements

- Password reset requires approval from: Security Analyst, Security Manager, or SOC Tier 2
- Approval timeout: 1 hour

## Tags

- credential
- identity
- itdr
- automated
- high-priority
