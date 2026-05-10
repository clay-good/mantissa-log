#!/usr/bin/env python3
"""
One-shot generator for the destructive-event Sigma rule pack.

Produces ``rules/sigma/destructive/dest_*.yml`` from a single in-file
inventory. Re-runnable: idempotent, overwrites existing files.

The inventory captures the shape of each rule:

  - product / service          (Sigma logsource)
  - detection selection        (event names or operation strings)
  - paging metadata            (evidence_query in particular)
  - MITRE ATT&CK tags

The generated YAML uses the same field-name conventions as the existing
rule packs under ``rules/sigma/`` so the validator and converter pick
them up without modification.
"""

from __future__ import annotations

from pathlib import Path
from textwrap import dedent

OUT_DIR = Path(__file__).resolve().parent.parent / "rules" / "sigma" / "destructive"
OUT_DIR.mkdir(parents=True, exist_ok=True)

COMMON_FOOTER = dedent("""\
    falsepositives:
      - Approved emergency-access procedures with prior change-ticket reference
      - Documented break-glass account use during incident response
    level: critical
    paging: true
    paging_destinations:
      - pagerduty
      - slack
      - teams
""")


RULES: list[dict] = [
    # ---- identity / privilege escalation -----------------------------------
    {
        "filename": "dest_gws_super_admin_granted.yml",
        "title": "Google Workspace Super Admin Role Granted",
        "id": "d1000001-0000-4000-8000-000000000001",
        "description": "Detects assignment of the Workspace Super Admin role, which grants full tenant control.",
        "product": "google_workspace",
        "service": "admin",
        "selection": {
            "event.action": ["ASSIGN_ROLE", "DELEGATE_ADMIN_PRIVILEGES"],
            "google_workspace.events.parameters.ROLE_NAME": ["_SEED_ADMIN_ROLE", "Super Admin"],
        },
        "fields": ["actor.email", "@timestamp", "source.ip",
                   "google_workspace.events.parameters.USER_EMAIL",
                   "google_workspace.events.parameters.ROLE_NAME"],
        "evidence_query": (
            "SELECT actor.email, event.action, source.ip, @timestamp "
            "FROM gws_admin "
            "WHERE actor.email = '{actor.email}' "
            "AND @timestamp BETWEEN '{when}'::timestamp - INTERVAL '60' MINUTE "
            "                    AND '{when}'::timestamp + INTERVAL '10' MINUTE "
            "ORDER BY @timestamp DESC"
        ),
        "tags": ["attack.privilege_escalation", "attack.t1098", "attack.persistence"],
    },
    {
        "filename": "dest_m365_global_admin_granted.yml",
        "title": "Microsoft 365 Global Administrator Role Granted",
        "id": "d1000002-0000-4000-8000-000000000002",
        "description": "Detects assignment of the Entra Global Administrator (Company Administrator) role.",
        "product": "microsoft365",
        "service": "azureactivedirectory",
        "selection": {
            "event.action": ["Add member to role", "Add member to role completed"],
            "microsoft365.modified_properties.NewValue": ["Global Administrator", "Company Administrator"],
        },
        "fields": ["user.email", "@timestamp", "source.ip",
                   "microsoft365.operation", "microsoft365.target"],
        "evidence_query": (
            "SELECT user.email, microsoft365.operation, source.ip, @timestamp "
            "FROM m365_aad "
            "WHERE user.email = '{user.email}' "
            "AND @timestamp BETWEEN '{when}'::timestamp - INTERVAL '60' MINUTE "
            "                    AND '{when}'::timestamp + INTERVAL '10' MINUTE "
            "ORDER BY @timestamp DESC"
        ),
        "tags": ["attack.privilege_escalation", "attack.t1098"],
    },
    {
        "filename": "dest_okta_super_admin_granted.yml",
        "title": "Okta Super Administrator Role Granted",
        "id": "d1000003-0000-4000-8000-000000000003",
        "description": "Detects assignment of Okta SUPER_ADMIN to a user or group.",
        "product": "okta",
        "service": "system",
        "selection": {
            "event.action": ["user.account.privilege.grant", "group.privilege.grant"],
            "okta.target.type": ["AdminRole"],
            "okta.target.detail.role": ["SUPER_ADMIN"],
        },
        "fields": ["actor.email", "@timestamp", "source.ip",
                   "okta.target.alternate_id", "okta.target.detail.role"],
        "evidence_query": (
            "SELECT actor.email, event.action, okta.target.alternate_id, @timestamp "
            "FROM okta_system "
            "WHERE actor.email = '{actor.email}' "
            "AND @timestamp BETWEEN '{when}'::timestamp - INTERVAL '60' MINUTE "
            "                    AND '{when}'::timestamp + INTERVAL '10' MINUTE "
            "ORDER BY @timestamp DESC"
        ),
        "tags": ["attack.privilege_escalation", "attack.t1098"],
    },
    {
        "filename": "dest_aws_root_used.yml",
        "title": "AWS Root Account Used",
        "id": "d1000004-0000-4000-8000-000000000004",
        "description": "Detects activity by the AWS root account, which should be locked away after initial setup.",
        "product": "aws",
        "service": "cloudtrail",
        "selection": {
            "aws.cloudtrail.user_identity.type": ["Root"],
        },
        "fields": ["aws.cloudtrail.user_identity.arn", "event.action", "source.ip", "@timestamp"],
        "evidence_query": (
            "SELECT event.action, source.ip, aws.cloudtrail.event_source, @timestamp "
            "FROM aws_cloudtrail "
            "WHERE aws.cloudtrail.user_identity.type = 'Root' "
            "AND @timestamp BETWEEN '{when}'::timestamp - INTERVAL '60' MINUTE "
            "                    AND '{when}'::timestamp + INTERVAL '10' MINUTE "
            "ORDER BY @timestamp DESC"
        ),
        "tags": ["attack.privilege_escalation", "attack.t1078.004"],
    },
    {
        "filename": "dest_gcp_org_admin_granted.yml",
        "title": "GCP Organization Administrator Role Granted",
        "id": "d1000005-0000-4000-8000-000000000005",
        "description": "Detects grant of roles/resourcemanager.organizationAdmin or owner at the organization scope.",
        "product": "gcp",
        "service": "iam",
        "selection": {
            "event.action": ["SetIamPolicy"],
            "gcp.audit.method_name": ["google.cloud.resourcemanager.v1.Organizations.SetIamPolicy",
                                       "SetOrgPolicy"],
            "gcp.audit.iam_binding.role": ["roles/resourcemanager.organizationAdmin",
                                            "roles/owner"],
        },
        "fields": ["actor.email", "@timestamp", "gcp.audit.method_name",
                   "gcp.audit.iam_binding.role", "gcp.audit.resource.name"],
        "evidence_query": (
            "SELECT actor.email, gcp.audit.method_name, gcp.audit.iam_binding.role, @timestamp "
            "FROM gcp_audit "
            "WHERE actor.email = '{actor.email}' "
            "AND @timestamp BETWEEN '{when}'::timestamp - INTERVAL '60' MINUTE "
            "                    AND '{when}'::timestamp + INTERVAL '10' MINUTE "
            "ORDER BY @timestamp DESC"
        ),
        "tags": ["attack.privilege_escalation", "attack.t1098"],
    },
    {
        "filename": "dest_azure_owner_granted_subscription.yml",
        "title": "Azure Owner Role Granted at Subscription Scope",
        "id": "d1000006-0000-4000-8000-000000000006",
        "description": "Detects assignment of the Owner role at the subscription scope.",
        "product": "azure",
        "service": "activity",
        "selection": {
            "event.action": ["Microsoft.Authorization/roleAssignments/write"],
            "azure.role_definition.name": ["Owner"],
            "azure.scope_kind": ["subscription"],
        },
        "fields": ["user.email", "@timestamp", "azure.role_definition.name", "azure.scope"],
        "evidence_query": (
            "SELECT user.email, azure.role_definition.name, azure.scope, @timestamp "
            "FROM azure_activity "
            "WHERE user.email = '{user.email}' "
            "AND @timestamp BETWEEN '{when}'::timestamp - INTERVAL '60' MINUTE "
            "                    AND '{when}'::timestamp + INTERVAL '10' MINUTE "
            "ORDER BY @timestamp DESC"
        ),
        "tags": ["attack.privilege_escalation", "attack.t1098"],
    },

    # ---- MFA / authentication tampering ------------------------------------
    {
        "filename": "dest_gws_2fa_disabled_org.yml",
        "title": "Google Workspace Org-Wide 2-Step Verification Disabled",
        "id": "d1000007-0000-4000-8000-000000000007",
        "description": "Detects when org-wide 2-Step Verification enforcement is turned off.",
        "product": "google_workspace",
        "service": "admin",
        "selection": {
            "event.action": ["ENFORCE_STRONG_AUTHENTICATION",
                             "CHANGE_TWO_STEP_VERIFICATION_ENROLLMENT_SETTING",
                             "WEAK_PROGRAMMATIC_LOGIN_SETTINGS_CHANGED"],
            "google_workspace.events.parameters.NEW_VALUE": ["false", "DISABLED"],
        },
        "fields": ["actor.email", "@timestamp", "source.ip",
                   "google_workspace.events.parameters.NEW_VALUE",
                   "google_workspace.events.parameters.OLD_VALUE"],
        "evidence_query": (
            "SELECT actor.email, event.action, source.ip, @timestamp "
            "FROM gws_admin "
            "WHERE actor.email = '{actor.email}' "
            "AND @timestamp BETWEEN '{when}'::timestamp - INTERVAL '60' MINUTE "
            "                    AND '{when}'::timestamp + INTERVAL '10' MINUTE "
            "ORDER BY @timestamp DESC"
        ),
        "tags": ["attack.defense_evasion", "attack.persistence", "attack.t1556"],
    },
    {
        "filename": "dest_m365_security_defaults_disabled.yml",
        "title": "Microsoft 365 Security Defaults Disabled",
        "id": "d1000008-0000-4000-8000-000000000008",
        "description": "Detects when Entra Security Defaults are turned off.",
        "product": "microsoft365",
        "service": "azureactivedirectory",
        "selection": {
            "event.action": ["Set Company Information", "Set IsEnabled"],
            "microsoft365.target_resource": ["Identity Security Defaults"],
            "microsoft365.modified_properties.NewValue": ["false", "False", "Disabled"],
        },
        "fields": ["user.email", "@timestamp", "source.ip",
                   "microsoft365.modified_properties"],
        "evidence_query": (
            "SELECT user.email, microsoft365.operation, source.ip, @timestamp "
            "FROM m365_aad "
            "WHERE user.email = '{user.email}' "
            "AND @timestamp BETWEEN '{when}'::timestamp - INTERVAL '60' MINUTE "
            "                    AND '{when}'::timestamp + INTERVAL '10' MINUTE "
            "ORDER BY @timestamp DESC"
        ),
        "tags": ["attack.defense_evasion", "attack.t1556"],
    },
    {
        "filename": "dest_m365_conditional_access_disabled.yml",
        "title": "Microsoft 365 Conditional Access Policy Disabled or Deleted",
        "id": "d1000009-0000-4000-8000-000000000009",
        "description": "Detects disabling or deletion of a Conditional Access policy.",
        "product": "microsoft365",
        "service": "azureactivedirectory",
        "selection": {
            "event.action": ["Update conditional access policy",
                             "Delete conditional access policy",
                             "Disable conditional access policy"],
        },
        "fields": ["user.email", "@timestamp", "microsoft365.target_resource",
                   "microsoft365.modified_properties"],
        "evidence_query": (
            "SELECT user.email, microsoft365.operation, microsoft365.target_resource, @timestamp "
            "FROM m365_aad "
            "WHERE user.email = '{user.email}' "
            "AND @timestamp BETWEEN '{when}'::timestamp - INTERVAL '60' MINUTE "
            "                    AND '{when}'::timestamp + INTERVAL '10' MINUTE "
            "ORDER BY @timestamp DESC"
        ),
        "tags": ["attack.defense_evasion", "attack.t1556"],
    },
    {
        "filename": "dest_okta_mfa_factor_reset_for_admin.yml",
        "title": "Okta MFA Factor Reset on Privileged Account",
        "id": "d1000010-0000-4000-8000-000000000010",
        "description": "Detects MFA factor reset performed on an account holding administrative roles.",
        "product": "okta",
        "service": "system",
        "selection": {
            "event.action": ["user.mfa.factor.reset_all", "user.mfa.factor.deactivate"],
            "okta.target.detail.is_admin": [True, "true"],
        },
        "fields": ["actor.email", "okta.target.alternate_id", "@timestamp", "source.ip"],
        "evidence_query": (
            "SELECT actor.email, okta.target.alternate_id, event.action, @timestamp "
            "FROM okta_system "
            "WHERE okta.target.alternate_id = '{okta.target.alternate_id}' "
            "AND @timestamp BETWEEN '{when}'::timestamp - INTERVAL '60' MINUTE "
            "                    AND '{when}'::timestamp + INTERVAL '10' MINUTE "
            "ORDER BY @timestamp DESC"
        ),
        "tags": ["attack.credential_access", "attack.t1556"],
    },

    # ---- mass data egress / destruction ------------------------------------
    {
        "filename": "dest_gws_drive_mass_download.yml",
        "title": "Google Workspace Drive Mass Download",
        "id": "d1000011-0000-4000-8000-000000000011",
        "description": "Detects when a single user downloads an unusually large number of Drive files in a short window.",
        "product": "google_workspace",
        "service": "drive",
        "selection": {
            "event.action": ["download"],
        },
        "threshold": {"field": "actor.email", "operator": ">=", "value": 100, "window_minutes": 10},
        "fields": ["actor.email", "@timestamp", "source.ip",
                   "google_workspace.events.parameters.doc_id"],
        "evidence_query": (
            "SELECT @timestamp, event.action, "
            "       google_workspace.events.parameters.doc_id, "
            "       google_workspace.events.parameters.doc_title "
            "FROM gws_drive "
            "WHERE actor.email = '{actor.email}' AND event.action = 'download' "
            "AND @timestamp BETWEEN '{when}'::timestamp - INTERVAL '30' MINUTE "
            "                    AND '{when}'::timestamp + INTERVAL '10' MINUTE "
            "ORDER BY @timestamp DESC"
        ),
        "tags": ["attack.exfiltration", "attack.t1530"],
    },
    {
        "filename": "dest_gws_drive_mass_delete.yml",
        "title": "Google Workspace Drive Mass Delete",
        "id": "d1000012-0000-4000-8000-000000000012",
        "description": "Detects bulk file deletion by a single user.",
        "product": "google_workspace",
        "service": "drive",
        "selection": {
            "event.action": ["delete", "trash"],
        },
        "threshold": {"field": "actor.email", "operator": ">=", "value": 50, "window_minutes": 10},
        "fields": ["actor.email", "@timestamp",
                   "google_workspace.events.parameters.doc_id"],
        "evidence_query": (
            "SELECT @timestamp, event.action, "
            "       google_workspace.events.parameters.doc_id, "
            "       google_workspace.events.parameters.doc_title "
            "FROM gws_drive "
            "WHERE actor.email = '{actor.email}' AND event.action IN ('delete', 'trash') "
            "AND @timestamp BETWEEN '{when}'::timestamp - INTERVAL '30' MINUTE "
            "                    AND '{when}'::timestamp + INTERVAL '10' MINUTE "
            "ORDER BY @timestamp DESC"
        ),
        "tags": ["attack.impact", "attack.t1485"],
    },
    {
        "filename": "dest_m365_sharepoint_mass_download.yml",
        "title": "Microsoft 365 SharePoint Mass Download",
        "id": "d1000013-0000-4000-8000-000000000013",
        "description": "Detects bulk file downloads from SharePoint or OneDrive by a single user.",
        "product": "microsoft365",
        "service": "sharepoint",
        "selection": {
            "event.action": ["FileDownloaded", "FileSyncDownloadedFull"],
        },
        "threshold": {"field": "user.email", "operator": ">=", "value": 100, "window_minutes": 10},
        "fields": ["user.email", "@timestamp", "microsoft365.target", "microsoft365.site_url"],
        "evidence_query": (
            "SELECT @timestamp, microsoft365.operation, microsoft365.target, microsoft365.site_url "
            "FROM m365_sharepoint "
            "WHERE user.email = '{user.email}' AND microsoft365.operation IN ('FileDownloaded','FileSyncDownloadedFull') "
            "AND @timestamp BETWEEN '{when}'::timestamp - INTERVAL '30' MINUTE "
            "                    AND '{when}'::timestamp + INTERVAL '10' MINUTE "
            "ORDER BY @timestamp DESC"
        ),
        "tags": ["attack.exfiltration", "attack.t1530"],
    },
    {
        "filename": "dest_m365_mailbox_mass_export.yml",
        "title": "Microsoft 365 Mailbox Mass Export",
        "id": "d1000014-0000-4000-8000-000000000014",
        "description": "Detects export of mailbox contents at scale (eDiscovery, PST export, or compliance search).",
        "product": "microsoft365",
        "service": "exchange",
        "selection": {
            "event.action": ["New-ComplianceSearchAction", "Export mailbox", "Start-MailboxExportRequest"],
        },
        "fields": ["user.email", "@timestamp", "microsoft365.operation", "microsoft365.target"],
        "evidence_query": (
            "SELECT user.email, microsoft365.operation, microsoft365.target, @timestamp "
            "FROM m365_exchange "
            "WHERE user.email = '{user.email}' "
            "AND @timestamp BETWEEN '{when}'::timestamp - INTERVAL '60' MINUTE "
            "                    AND '{when}'::timestamp + INTERVAL '10' MINUTE "
            "ORDER BY @timestamp DESC"
        ),
        "tags": ["attack.exfiltration", "attack.collection", "attack.t1114"],
    },
    {
        "filename": "dest_aws_s3_bucket_made_public.yml",
        "title": "AWS S3 Bucket Made Public",
        "id": "d1000015-0000-4000-8000-000000000015",
        "description": "Detects an S3 bucket being granted public access (ACL or policy).",
        "product": "aws",
        "service": "cloudtrail",
        "selection": {
            "event.action": ["PutBucketAcl", "PutBucketPolicy", "PutPublicAccessBlock",
                             "DeletePublicAccessBlock"],
            "aws.cloudtrail.request_parameters.access_control_policy.grants.grantee.uri":
                ["http://acs.amazonaws.com/groups/global/AllUsers",
                 "http://acs.amazonaws.com/groups/global/AuthenticatedUsers"],
        },
        "fields": ["aws.cloudtrail.user_identity.arn", "@timestamp",
                   "aws.cloudtrail.request_parameters.bucket_name"],
        "evidence_query": (
            "SELECT aws.cloudtrail.user_identity.arn, event.action, "
            "       aws.cloudtrail.request_parameters.bucket_name, @timestamp "
            "FROM aws_cloudtrail "
            "WHERE aws.cloudtrail.user_identity.arn = '{aws.cloudtrail.user_identity.arn}' "
            "AND @timestamp BETWEEN '{when}'::timestamp - INTERVAL '60' MINUTE "
            "                    AND '{when}'::timestamp + INTERVAL '10' MINUTE "
            "ORDER BY @timestamp DESC"
        ),
        "tags": ["attack.exfiltration", "attack.impact", "attack.t1567"],
    },
    {
        "filename": "dest_aws_s3_mass_delete_or_lifecycle_purge.yml",
        "title": "AWS S3 Mass Delete or Lifecycle Purge",
        "id": "d1000016-0000-4000-8000-000000000016",
        "description": "Detects DeleteObjects/Lifecycle expiration that removes objects at scale.",
        "product": "aws",
        "service": "cloudtrail",
        "selection": {
            "event.action": ["DeleteObjects", "DeleteBucket", "PutBucketLifecycleConfiguration"],
        },
        "threshold": {"field": "aws.cloudtrail.user_identity.arn", "operator": ">=",
                      "value": 500, "window_minutes": 10},
        "fields": ["aws.cloudtrail.user_identity.arn", "@timestamp",
                   "aws.cloudtrail.request_parameters.bucket_name"],
        "evidence_query": (
            "SELECT aws.cloudtrail.user_identity.arn, event.action, "
            "       aws.cloudtrail.request_parameters.bucket_name, @timestamp "
            "FROM aws_cloudtrail "
            "WHERE aws.cloudtrail.user_identity.arn = '{aws.cloudtrail.user_identity.arn}' "
            "AND @timestamp BETWEEN '{when}'::timestamp - INTERVAL '30' MINUTE "
            "                    AND '{when}'::timestamp + INTERVAL '10' MINUTE "
            "ORDER BY @timestamp DESC"
        ),
        "tags": ["attack.impact", "attack.t1485"],
    },
    {
        "filename": "dest_github_repo_made_public_or_deleted.yml",
        "title": "GitHub Repository Made Public or Deleted",
        "id": "d1000017-0000-4000-8000-000000000017",
        "description": "Detects a private repo being flipped to public, or any repository deletion.",
        "product": "github",
        "service": "audit",
        "selection": {
            "event.action": ["repo.access", "repo.destroy", "repo.transfer",
                             "repository.visibility_changed"],
            "github.visibility": ["public"],
        },
        "fields": ["actor.email", "@timestamp", "github.repo", "github.visibility"],
        "evidence_query": (
            "SELECT actor.email, event.action, github.repo, github.visibility, @timestamp "
            "FROM github_audit "
            "WHERE actor.email = '{actor.email}' "
            "AND @timestamp BETWEEN '{when}'::timestamp - INTERVAL '60' MINUTE "
            "                    AND '{when}'::timestamp + INTERVAL '10' MINUTE "
            "ORDER BY @timestamp DESC"
        ),
        "tags": ["attack.exfiltration", "attack.impact", "attack.t1485"],
    },

    # ---- OAuth / app trust -------------------------------------------------
    {
        "filename": "dest_gws_oauth_high_risk_scope_granted.yml",
        "title": "Google Workspace OAuth High-Risk Scope Granted",
        "id": "d1000018-0000-4000-8000-000000000018",
        "description": "Detects third-party OAuth grants of Drive or Gmail full scopes.",
        "product": "google_workspace",
        "service": "token",
        "selection": {
            "event.action": ["authorize"],
            "google_workspace.events.parameters.scope":
                ["https://www.googleapis.com/auth/drive",
                 "https://mail.google.com/",
                 "https://www.googleapis.com/auth/gmail.modify"],
        },
        "fields": ["actor.email", "@timestamp",
                   "google_workspace.events.parameters.client_id",
                   "google_workspace.events.parameters.scope",
                   "google_workspace.events.parameters.app_name"],
        "evidence_query": (
            "SELECT actor.email, "
            "       google_workspace.events.parameters.app_name, "
            "       google_workspace.events.parameters.scope, "
            "       google_workspace.events.parameters.client_id, @timestamp "
            "FROM gws_token "
            "WHERE actor.email = '{actor.email}' "
            "AND @timestamp BETWEEN '{when}'::timestamp - INTERVAL '60' MINUTE "
            "                    AND '{when}'::timestamp + INTERVAL '10' MINUTE "
            "ORDER BY @timestamp DESC"
        ),
        "tags": ["attack.persistence", "attack.t1098.001"],
    },
    {
        "filename": "dest_m365_high_privilege_consent.yml",
        "title": "Microsoft 365 High-Privilege App Consent",
        "id": "d1000019-0000-4000-8000-000000000019",
        "description": "Detects admin consent grants to apps requesting high-privilege Graph scopes.",
        "product": "microsoft365",
        "service": "azureactivedirectory",
        "selection": {
            "event.action": ["Consent to application", "Add app role assignment grant to user"],
            "microsoft365.modified_properties.NewValue":
                ["Mail.ReadWrite", "Mail.Send", "Files.ReadWrite.All",
                 "Sites.FullControl.All", "Directory.ReadWrite.All",
                 "AppRoleAssignment.ReadWrite.All", "RoleManagement.ReadWrite.Directory"],
        },
        "fields": ["user.email", "@timestamp", "microsoft365.target",
                   "microsoft365.modified_properties"],
        "evidence_query": (
            "SELECT user.email, microsoft365.operation, microsoft365.target, @timestamp "
            "FROM m365_aad "
            "WHERE user.email = '{user.email}' "
            "AND @timestamp BETWEEN '{when}'::timestamp - INTERVAL '60' MINUTE "
            "                    AND '{when}'::timestamp + INTERVAL '10' MINUTE "
            "ORDER BY @timestamp DESC"
        ),
        "tags": ["attack.persistence", "attack.t1098.001"],
    },

    # ---- logging / audit tampering -----------------------------------------
    {
        "filename": "dest_aws_cloudtrail_disabled_or_deleted.yml",
        "title": "AWS CloudTrail Disabled or Deleted",
        "id": "d1000020-0000-4000-8000-000000000020",
        "description": "Detects CloudTrail trail being stopped, deleted, or having logging disabled.",
        "product": "aws",
        "service": "cloudtrail",
        "selection": {
            "event.action": ["StopLogging", "DeleteTrail", "UpdateTrail", "PutEventSelectors"],
            "aws.cloudtrail.event_source": ["cloudtrail.amazonaws.com"],
        },
        "fields": ["aws.cloudtrail.user_identity.arn", "@timestamp",
                   "aws.cloudtrail.request_parameters.name"],
        "evidence_query": (
            "SELECT aws.cloudtrail.user_identity.arn, event.action, "
            "       aws.cloudtrail.request_parameters.name, @timestamp "
            "FROM aws_cloudtrail "
            "WHERE aws.cloudtrail.user_identity.arn = '{aws.cloudtrail.user_identity.arn}' "
            "AND @timestamp BETWEEN '{when}'::timestamp - INTERVAL '60' MINUTE "
            "                    AND '{when}'::timestamp + INTERVAL '10' MINUTE "
            "ORDER BY @timestamp DESC"
        ),
        "tags": ["attack.defense_evasion", "attack.t1562.008"],
    },
    {
        "filename": "dest_gcp_audit_log_sink_deleted.yml",
        "title": "GCP Audit Log Sink Deleted",
        "id": "d1000021-0000-4000-8000-000000000021",
        "description": "Detects deletion or disabling of a Logging sink that exports audit logs.",
        "product": "gcp",
        "service": "logging",
        "selection": {
            "event.action": ["google.logging.v2.ConfigServiceV2.DeleteSink",
                             "google.logging.v2.ConfigServiceV2.UpdateSink"],
        },
        "fields": ["actor.email", "@timestamp", "gcp.audit.resource.name", "gcp.audit.method_name"],
        "evidence_query": (
            "SELECT actor.email, gcp.audit.method_name, gcp.audit.resource.name, @timestamp "
            "FROM gcp_audit "
            "WHERE actor.email = '{actor.email}' "
            "AND @timestamp BETWEEN '{when}'::timestamp - INTERVAL '60' MINUTE "
            "                    AND '{when}'::timestamp + INTERVAL '10' MINUTE "
            "ORDER BY @timestamp DESC"
        ),
        "tags": ["attack.defense_evasion", "attack.t1562.008"],
    },
    {
        "filename": "dest_m365_audit_log_disabled.yml",
        "title": "Microsoft 365 Unified Audit Log Disabled",
        "id": "d1000022-0000-4000-8000-000000000022",
        "description": "Detects when the Unified Audit Log is disabled at the tenant level.",
        "product": "microsoft365",
        "service": "exchange",
        "selection": {
            "event.action": ["Set-AdminAuditLogConfig"],
            "microsoft365.modified_properties.UnifiedAuditLogIngestionEnabled":
                ["False", "false"],
        },
        "fields": ["user.email", "@timestamp", "microsoft365.modified_properties"],
        "evidence_query": (
            "SELECT user.email, microsoft365.operation, microsoft365.modified_properties, @timestamp "
            "FROM m365_exchange "
            "WHERE user.email = '{user.email}' "
            "AND @timestamp BETWEEN '{when}'::timestamp - INTERVAL '60' MINUTE "
            "                    AND '{when}'::timestamp + INTERVAL '10' MINUTE "
            "ORDER BY @timestamp DESC"
        ),
        "tags": ["attack.defense_evasion", "attack.t1562.008"],
    },
]


def render_selection(sel: dict) -> str:
    lines = ["  selection:"]
    for key, values in sel.items():
        if isinstance(values, list):
            lines.append(f"    {key}:")
            for v in values:
                lines.append(f"      - {repr(v) if isinstance(v, str) else str(v).lower()}")
        else:
            lines.append(f"    {key}: {values}")
    return "\n".join(lines)


def render_threshold(threshold: dict) -> str:
    return (
        "threshold:\n"
        f"  field: {threshold['field']}\n"
        f"  operator: '{threshold['operator']}'\n"
        f"  value: {threshold['value']}\n"
        f"  window_minutes: {threshold['window_minutes']}\n"
    )


def _quote_field(name: str) -> str:
    """YAML doesn't allow unquoted tokens starting with '@'. Quote them."""
    if name.startswith("@"):
        return f"'{name}'"
    return name


def render(rule: dict) -> str:
    selection = render_selection(rule["selection"])
    threshold_block = ""
    if "threshold" in rule:
        threshold_block = "\n" + render_threshold(rule["threshold"])
    fields = "\n".join(f"  - {_quote_field(f)}" for f in rule["fields"])
    tags = "\n".join(f"  - {t}" for t in rule["tags"])
    return (
        f"title: {rule['title']}\n"
        f"id: {rule['id']}\n"
        f"status: experimental\n"
        f"description: {rule['description']}\n"
        f"author: Mantissa Log Destructive-Event Pack\n"
        f"date: 2026-05-10\n"
        f"modified: 2026-05-10\n"
        f"\n"
        f"logsource:\n"
        f"  product: {rule['product']}\n"
        f"  service: {rule['service']}\n"
        f"\n"
        f"detection:\n"
        f"{selection}\n"
        f"  condition: selection\n"
        f"{threshold_block}\n"
        f"fields:\n"
        f"{fields}\n"
        f"\n"
        f"tags:\n"
        f"{tags}\n"
        f"\n"
        f"evidence_query: |\n"
        + "\n".join("  " + line for line in rule["evidence_query"].splitlines())
        + "\n\n"
        f"{COMMON_FOOTER}"
    )


def main() -> int:
    for rule in RULES:
        path = OUT_DIR / rule["filename"]
        path.write_text(render(rule))
        print(f"wrote {path.name}")
    print(f"\ngenerated {len(RULES)} destructive-event rules in {OUT_DIR}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
