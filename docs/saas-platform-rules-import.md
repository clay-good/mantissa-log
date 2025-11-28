# SaaS and Cloud-Native Platform Rules Import

## Overview

Imported 223 additional Sigma detection rules from SigmaHQ repository covering SaaS platforms and cloud-native services beyond AWS. Total rule count increased from 48 to 271 rules across 17 logsource types.

## Import Statistics

**Total Rules**: 271 Sigma-format detection rules
- AWS: 48 rules (42 CloudTrail + 6 VPC Flow)
- Azure: 130 rules
- GCP: 23 rules (16 audit + 7 Google Workspace)
- Microsoft 365: 18 rules
- Okta: 21 rules
- Kubernetes: 15 rules
- GitHub: 15 rules
- Duo Security: 1 rule

**Platform Coverage**: 17 unique logsource types
- AWS: cloudtrail, vpcflowlogs, guardduty
- Azure: activitylogs, auditlogs, signinlogs, pim, riskdetection
- GCP: gcp.audit, google_workspace.admin
- M365: audit, exchange, threat_detection, threat_management
- Identity: okta, cisco duo
- Applications: kubernetes audit, github audit

## Rules by Platform

### Azure (130 rules)

**Activity Logs (42 rules)**
- Resource management operations
- VM lifecycle events
- Network security group changes
- Storage account modifications
- Policy assignments
- Role assignments and permissions

**Audit Logs (38 rules)**
- Azure AD user management
- Group membership changes
- Application registrations
- Service principal modifications
- Directory role assignments
- Conditional access policy changes

**Sign-in Logs (24 rules)**
- Failed authentication attempts
- MFA bypass attempts
- Suspicious sign-in patterns
- Token-based authentication
- Legacy authentication protocols
- Conditional access failures

**Privileged Identity Management (14 rules)**
- PIM role activations
- Permanent role assignments
- Privilege escalation detection
- Admin role abuse

**Identity Protection (12 rules)**
- Risk detection events
- Compromised account indicators
- Anomalous behavior patterns
- Leaked credentials detection

### GCP (23 rules)

**GCP Audit Logs (16 rules)**
- IAM policy modifications
- Service account key creation
- Firewall rule changes
- Storage bucket permission changes
- Compute instance creation/deletion
- Cloud SQL database modifications
- GKE cluster operations
- Logging sink tampering

**Google Workspace (7 rules)**
- Admin privilege changes
- User account creation/deletion
- 2FA disable events
- OAuth application installations
- Google Drive external sharing
- Gmail delegation rules
- Workspace API access

### Microsoft 365 (18 rules)

**Exchange Online**
- Mailbox forwarding rules
- Email delegation
- Mailbox export requests
- Transport rule modifications

**Threat Detection**
- Malware detection events
- Phishing attempts
- Suspicious email patterns
- File detonation events

**Threat Management**
- Security alert manipulation
- Threat policy modifications
- Safe attachments bypass
- Safe links policy changes

**Audit**
- eDiscovery operations
- Compliance search activities
- Retention policy changes

### Okta (21 rules)

**Authentication Events**
- Brute force attempts
- Password spraying
- Credential stuffing
- MFA fatigue attacks
- API token abuse

**User Management**
- Account takeover indicators
- Privilege escalation
- User deactivation
- Password resets

**Application Security**
- Unauthorized API access
- Application assignment changes
- SSO configuration tampering
- OAuth grant modifications

**Admin Activity**
- Policy modifications
- Network zone changes
- Factor enrollment changes
- Admin privilege assignment

### Kubernetes (15 rules)

**Cluster Security**
- Anonymous requests to API server
- Unauthenticated requests
- Default service account usage
- Privileged pod creation
- HostPath volume mounts
- HostNetwork usage

**RBAC Events**
- ClusterRole binding abuse
- ServiceAccount token access
- Secret access attempts
- ConfigMap modifications

**Resource Management**
- Pod exec commands
- Container image pulls
- Namespace creation
- CronJob creation

### GitHub (15 rules)

**Repository Security**
- Repository made public
- Branch protection disabled
- Code scanning disabled
- Secret scanning bypass

**User Management**
- Organization member added
- Admin privilege granted
- Team access changes
- Outside collaborator added

**Security Events**
- Personal access token created
- Deploy key added
- Webhook created
- OAuth app access
- Two-factor authentication disabled

### Duo Security (1 rule)

**MFA Bypass**
- Duo bypass code usage detection

## Field Mappings Added

### Azure
- **Activity Logs**: eventName, eventSource, operationName, properties.message
- **Audit Logs**: activityType, additionalDetails.additionalInfo, targetResources.type
- **Sign-in Logs**: conditionalAccessStatus, userAgent
- **PIM**: riskEventType
- **Risk Detection**: riskEventType

### GCP
- **Audit**: data.protoPayload.* nested fields (authorizationInfo, methodName, serviceName, resource.type)
- **Google Workspace**: eventName, eventService

### M365
- **Exchange/Threat Detection/Management**: eventName, eventSource (common fields)

### Okta
- **System Logs**: actor.alternateid, debugContext.*, outcome.*, securityContext.*, target.displayname

### Kubernetes
- **Audit**: apiGroup, hostPath, objectRef.*, responseStatus.code

## Table Mappings Added

Created table mappings for 14 new logsource types:

```python
# Azure
("azure", "activitylogs"): "azure_activity_logs"
("azure", "auditlogs"): "azure_audit_logs"
("azure", "signinlogs"): "azure_signin_logs"
("azure", "pim"): "azure_pim_logs"
("azure", "riskdetection"): "azure_risk_detection"

# GCP
("gcp", "google_workspace.admin"): "google_workspace_admin_logs"

# M365
("m365", "audit"): "m365_audit_logs"
("m365", "exchange"): "m365_exchange_logs"
("m365", "threat_detection"): "m365_threat_detection"
("m365", "threat_management"): "m365_threat_management"

# Identity
("cisco", "duo"): "duo_auth_logs"

# Applications
("github", "audit"): "github_audit_logs"
```

## Files Modified

### Pipeline Configuration
- `src/shared/detection/sigma_pipeline.py`
  - Added 10 new field mapping dictionaries
  - Extended TABLE_MAPPINGS with 14 new logsources
  - Updated create_pipeline() to include all platforms
  - Extended get_field_mapping() with full platform support

### Rule Directories
- `rules/sigma/azure/` - 130 rules across 5 log types
- `rules/sigma/gcp/audit/` - 16 GCP audit rules
- `rules/sigma/gcp/gworkspace/` - 7 Google Workspace rules
- `rules/sigma/m365/` - 18 rules across 4 service types
- `rules/sigma/okta/` - 21 Okta system log rules
- `rules/sigma/kubernetes/audit/` - 15 K8s audit rules
- `rules/sigma/github/` - 15 GitHub audit rules
- `rules/sigma/duo/` - 1 Duo MFA bypass rule

## Coverage by MITRE ATT&CK

### Tactics Covered
- **Initial Access**: Phishing, valid accounts, external remote services
- **Persistence**: Account manipulation, create account, modify authentication
- **Privilege Escalation**: Valid accounts, domain policy modification
- **Defense Evasion**: Impair defenses, modify cloud compute infrastructure, indicator removal
- **Credential Access**: Brute force, password spraying, MFA request generation
- **Discovery**: Account discovery, permission groups discovery, cloud infrastructure discovery
- **Lateral Movement**: Use alternate authentication material, internal spearphishing
- **Collection**: Email collection, data from information repositories
- **Exfiltration**: Transfer data to cloud account, exfiltration over web service
- **Impact**: Account access removal, data destruction, defacement

### Technique Coverage Highlights
- T1078: Valid Accounts (50+ rules)
- T1110: Brute Force (15+ rules)
- T1556: Modify Authentication Process (12+ rules)
- T1098: Account Manipulation (20+ rules)
- T1562: Impair Defenses (18+ rules)
- T1136: Create Account (10+ rules)
- T1087: Account Discovery (8+ rules)
- T1114: Email Collection (6+ rules)
- T1537: Transfer Data to Cloud Account (8+ rules)

## Parser Requirements

These rules are ready for use when the following data source parsers are implemented:

**High Priority** (Security-Critical):
1. Okta System Log API integration
2. Google Workspace Reports API integration
3. Kubernetes audit webhook to S3
4. Microsoft 365 Management API integration

**Medium Priority** (Broad Coverage):
5. Azure Activity Logs forwarding
6. Azure AD Audit/Sign-in Logs streaming
7. GitHub Enterprise Audit Log API
8. GCP Cloud Audit Logs export to BigQuery

**Low Priority** (Specialized):
9. Duo Admin API integration

## Next Steps

1. **Parser Development** (per SAAS AND CLOUD-NATIVE DATA SOURCE EXPANSION roadmap)
   - Implement API collectors for each platform
   - Normalize log formats to match table schemas
   - Set up scheduled ingestion (5-30 minute intervals)

2. **Schema Creation**
   - Design table schemas for each logsource
   - Define partitioning strategy (by date/platform)
   - Create Athena tables and Glue catalog entries

3. **Testing and Validation**
   - Validate SQL conversion for all platforms
   - Test rules against sample data
   - Tune false positive rates

4. **Documentation**
   - Per-platform integration guides
   - Field mapping reference
   - Sample queries for each rule type

## Platform-Specific Notes

### Azure
- Requires Azure Event Hub or Log Analytics Workspace integration
- Activity Logs use different schema than Audit Logs
- Sign-in Logs available in Azure AD Premium P1/P2 only
- PIM logs require Azure AD Premium P2

### GCP
- Audit Logs use nested protoPayload structure
- Google Workspace requires domain-wide delegation
- Workspace logs have 180-day retention limit
- Some events have 24-hour delay

### Microsoft 365
- Requires E5 license or standalone license for advanced features
- Management API has throttling limits
- Audit log search can have delays up to 24 hours
- Unified Audit Log must be enabled

### Okta
- System Log API free tier has 30-day retention
- Rate limits: 1000 requests per minute
- Event types vary by Okta edition
- Requires API token with okta.logs.read scope

### Kubernetes
- Audit policy must be configured on API server
- High volume can impact cluster performance
- Webhook backend recommended for streaming
- Consider log level (Metadata vs Request vs RequestResponse)

### GitHub
- Audit log API requires GitHub Enterprise
- 90-day retention for all events
- Rate limit: 5000 requests per hour
- Requires personal access token with admin:org scope

## References

- SigmaHQ Repository: https://github.com/SigmaHQ/sigma
- Azure Monitor Logs: https://docs.microsoft.com/azure/azure-monitor/
- GCP Audit Logs: https://cloud.google.com/logging/docs/audit
- M365 Management API: https://docs.microsoft.com/office/office-365-management-api/
- Okta System Log: https://developer.okta.com/docs/reference/api/system-log/
- Kubernetes Audit: https://kubernetes.io/docs/tasks/debug/debug-cluster/audit/
- GitHub Audit Log: https://docs.github.com/enterprise-cloud@latest/rest/orgs/orgs#get-the-audit-log-for-an-organization
