"""Identity-specific alert templates for ITDR module.

Provides structured templates for rendering identity alerts with
relevant context and actionable information.
"""

import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Protocol


class AlertProtocol(Protocol):
    """Protocol for Alert objects."""

    id: str
    rule_id: str
    rule_name: str
    severity: str
    title: str
    description: str
    timestamp: datetime
    results: List[Dict[str, Any]]
    metadata: Dict[str, Any]


@dataclass
class AlertTemplate:
    """Template for rendering an identity alert.

    Attributes:
        alert_type: Type of identity alert (brute_force, credential_stuffing, etc.)
        title_template: Format string for alert title
        body_template: Markdown format string for alert body
        severity_colors: Mapping of severity to color codes
        action_buttons: List of action button definitions
        investigation_links: List of investigation link templates
        mitre_technique: MITRE ATT&CK technique ID
        recommended_actions: List of recommended response actions
    """

    alert_type: str
    title_template: str
    body_template: str
    severity_colors: Dict[str, str] = field(default_factory=dict)
    action_buttons: List[Dict[str, str]] = field(default_factory=list)
    investigation_links: List[Dict[str, str]] = field(default_factory=list)
    mitre_technique: Optional[str] = None
    recommended_actions: List[str] = field(default_factory=list)

    def __post_init__(self):
        """Set default severity colors if not provided."""
        if not self.severity_colors:
            self.severity_colors = {
                "critical": "#FF0000",  # Red
                "high": "#FF6600",  # Orange
                "medium": "#FFCC00",  # Yellow
                "low": "#00CC00",  # Green
                "info": "#0066FF",  # Blue
            }


@dataclass
class RenderedAlert:
    """A fully rendered alert ready for output.

    Attributes:
        alert_id: Original alert ID
        alert_type: Type of identity alert
        severity: Alert severity
        severity_color: Color code for severity
        title: Rendered title
        body_markdown: Rendered body in markdown
        body_html: Rendered body in HTML (if applicable)
        action_buttons: Rendered action buttons
        investigation_links: Rendered investigation links
        recommended_actions: List of recommended actions
        rendered_at: When alert was rendered
        metadata: Additional metadata
    """

    alert_id: str
    alert_type: str
    severity: str
    severity_color: str
    title: str
    body_markdown: str
    body_html: Optional[str] = None
    action_buttons: List[Dict[str, str]] = field(default_factory=list)
    investigation_links: List[Dict[str, str]] = field(default_factory=list)
    recommended_actions: List[str] = field(default_factory=list)
    rendered_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "alert_id": self.alert_id,
            "alert_type": self.alert_type,
            "severity": self.severity,
            "severity_color": self.severity_color,
            "title": self.title,
            "body_markdown": self.body_markdown,
            "body_html": self.body_html,
            "action_buttons": self.action_buttons,
            "investigation_links": self.investigation_links,
            "recommended_actions": self.recommended_actions,
            "rendered_at": self.rendered_at.isoformat(),
            "metadata": self.metadata,
        }


class IdentityAlertTemplates:
    """Collection of templates for identity-specific alerts.

    Provides pre-defined templates for common identity attack types
    with relevant context fields and recommended actions.
    """

    def __init__(self, base_url: str = ""):
        """Initialize alert templates.

        Args:
            base_url: Base URL for investigation links
        """
        self.base_url = base_url.rstrip("/")
        self._templates = self._create_templates()

    def _create_templates(self) -> Dict[str, AlertTemplate]:
        """Create all identity alert templates."""
        return {
            "brute_force": self._brute_force_template(),
            "credential_stuffing": self._credential_stuffing_template(),
            "password_spray": self._password_spray_template(),
            "mfa_fatigue": self._mfa_fatigue_template(),
            "mfa_bypass": self._mfa_bypass_template(),
            "impossible_travel": self._impossible_travel_template(),
            "privilege_escalation": self._privilege_escalation_template(),
            "session_hijack": self._session_hijack_template(),
            "dormant_account": self._dormant_account_template(),
            "token_theft": self._token_theft_template(),
            "unusual_login_time": self._unusual_login_time_template(),
            "new_device": self._new_device_template(),
            "new_location": self._new_location_template(),
            "account_takeover": self._account_takeover_template(),
        }

    def _brute_force_template(self) -> AlertTemplate:
        """Template for brute force attack alerts."""
        return AlertTemplate(
            alert_type="brute_force",
            title_template="Brute Force Attack Detected: {user_email}",
            body_template="""## Alert Summary
{failure_count} failed login attempts detected for **{user_email}** from {source_ip} ({source_country}) in {time_window}.

## User Context
- **Department:** {user_department}
- **Job Title:** {user_title}
- **Normal Login Times:** {typical_login_hours}
- **Risk Score:** {risk_score}/100

## Attack Details
| Field | Value |
|-------|-------|
| First Attempt | {first_attempt_time} |
| Last Attempt | {last_attempt_time} |
| Total Attempts | {failure_count} |
| Source IP | {source_ip} |
| Source Location | {source_city}, {source_country} |
| Failure Reasons | {failure_reasons} |

## Provider Details
- **Identity Provider:** {provider}
- **Application:** {target_application}

## Recommended Actions
1. Verify account status and check for successful authentication after failures
2. Consider temporarily blocking source IP: `{source_ip}`
3. Notify user of the attack attempt
4. Review user's recent activity for signs of compromise
""",
            action_buttons=[
                {"id": "investigate", "label": "Investigate", "style": "primary"},
                {"id": "block_ip", "label": "Block IP", "style": "danger"},
                {"id": "notify_user", "label": "Notify User", "style": "default"},
                {"id": "dismiss", "label": "Dismiss", "style": "default"},
            ],
            investigation_links=[
                {"label": "View User Activity", "url": "{base_url}/users/{user_id}/activity"},
                {"label": "IP Reputation", "url": "{base_url}/threat-intel/ip/{source_ip}"},
                {"label": "Alert Timeline", "url": "{base_url}/alerts/{alert_id}/timeline"},
            ],
            mitre_technique="T1110.001",
            recommended_actions=[
                "Verify account status",
                "Block source IP if attack is ongoing",
                "Notify user of attempt",
                "Check for successful logins after failed attempts",
            ],
        )

    def _credential_stuffing_template(self) -> AlertTemplate:
        """Template for credential stuffing attack alerts."""
        return AlertTemplate(
            alert_type="credential_stuffing",
            title_template="Credential Stuffing Attack Detected: {target_count} Users Targeted",
            body_template="""## Alert Summary
Credential stuffing attack detected targeting **{target_count} users** from {unique_ip_count} unique IP addresses in {time_window}.

## Attack Overview
| Metric | Value |
|--------|-------|
| Total Attempts | {total_attempts} |
| Unique Users Targeted | {target_count} |
| Unique Source IPs | {unique_ip_count} |
| Success Rate | {success_rate}% |
| Time Window | {time_window} |

## Top Source IPs
{top_source_ips}

## Targeted Users
{targeted_users}

## Attack Indicators
- **Pattern:** {attack_pattern}
- **Credential Source:** Likely from data breach
- **Automation Detected:** {is_automated}

## Recommended Actions
1. Block top attacking IPs at perimeter
2. Force password reset for any compromised accounts
3. Enable enhanced monitoring for targeted users
4. Review for successful authentications
""",
            action_buttons=[
                {"id": "investigate", "label": "Investigate", "style": "primary"},
                {"id": "block_ips", "label": "Block All IPs", "style": "danger"},
                {"id": "force_reset", "label": "Force Password Reset", "style": "warning"},
                {"id": "dismiss", "label": "Dismiss", "style": "default"},
            ],
            investigation_links=[
                {"label": "View Attack Details", "url": "{base_url}/incidents/{incident_id}"},
                {"label": "IP Analysis", "url": "{base_url}/threat-intel/bulk-ip"},
                {"label": "User Impact Report", "url": "{base_url}/reports/user-impact/{incident_id}"},
            ],
            mitre_technique="T1110.004",
            recommended_actions=[
                "Block attacking IPs at perimeter",
                "Force password reset for compromised accounts",
                "Enable enhanced monitoring",
                "Review breach databases for credential matches",
            ],
        )

    def _password_spray_template(self) -> AlertTemplate:
        """Template for password spray attack alerts."""
        return AlertTemplate(
            alert_type="password_spray",
            title_template="Password Spray Attack Detected: {target_count} Users",
            body_template="""## Alert Summary
Password spray attack detected targeting **{target_count} users** with {password_count} common passwords in {time_window}.

## Attack Characteristics
| Metric | Value |
|--------|-------|
| Users Targeted | {target_count} |
| Passwords Tested | {password_count} |
| Total Attempts | {total_attempts} |
| Attempts per User | ~{attempts_per_user} |
| Source IPs | {unique_ip_count} |

## Attack Pattern
- **Spray Velocity:** {spray_velocity} attempts/minute
- **Password Pattern:** {password_pattern}
- **Target Selection:** {target_selection}

## Top Targeted Users
{targeted_users}

## Source Information
| IP Address | Location | Attempts |
|------------|----------|----------|
{source_ip_table}

## Recommended Actions
1. Implement account lockout for targeted users
2. Force MFA enrollment for users without it
3. Block source IPs if attack is ongoing
4. Review password policy compliance
""",
            action_buttons=[
                {"id": "investigate", "label": "Investigate", "style": "primary"},
                {"id": "lockout", "label": "Lock Accounts", "style": "danger"},
                {"id": "force_mfa", "label": "Force MFA", "style": "warning"},
                {"id": "dismiss", "label": "Dismiss", "style": "default"},
            ],
            investigation_links=[
                {"label": "Attack Timeline", "url": "{base_url}/incidents/{incident_id}/timeline"},
                {"label": "User List", "url": "{base_url}/incidents/{incident_id}/users"},
            ],
            mitre_technique="T1110.003",
            recommended_actions=[
                "Implement temporary account lockouts",
                "Force MFA enrollment",
                "Block attacking IPs",
                "Review and strengthen password policy",
            ],
        )

    def _mfa_fatigue_template(self) -> AlertTemplate:
        """Template for MFA fatigue attack alerts."""
        return AlertTemplate(
            alert_type="mfa_fatigue",
            title_template="MFA Fatigue Attack Detected: {user_email}",
            body_template="""## Alert Summary
MFA fatigue attack (push bombing) detected for **{user_email}** with {push_count} push notifications in {time_window}.

## User Context
- **Department:** {user_department}
- **Risk Score:** {risk_score}/100
- **Normal MFA Rate:** {normal_mfa_rate} challenges/day

## Attack Details
| Field | Value |
|-------|-------|
| Total Push Notifications | {push_count} |
| Time Window | {time_window} |
| Push Rate | {push_rate}/minute |
| Denials | {denial_count} |
| Final Approval | {was_approved} |

## Attack Timeline
{attack_timeline}

## Source Information
- **IP Address:** {source_ip}
- **Location:** {source_city}, {source_country}
- **Device:** {source_device}

## Recommended Actions
1. {"**URGENT:** Account may be compromised - approved after repeated denials" if was_approved else "User successfully resisted attack"}
2. Contact user to verify if they approved any prompts
3. Consider requiring number matching for MFA
4. Block source IP if attack is ongoing
""",
            action_buttons=[
                {"id": "investigate", "label": "Investigate", "style": "primary"},
                {"id": "revoke_sessions", "label": "Revoke Sessions", "style": "danger"},
                {"id": "contact_user", "label": "Contact User", "style": "warning"},
                {"id": "dismiss", "label": "Dismiss", "style": "default"},
            ],
            investigation_links=[
                {"label": "User Sessions", "url": "{base_url}/users/{user_id}/sessions"},
                {"label": "MFA History", "url": "{base_url}/users/{user_id}/mfa-history"},
            ],
            mitre_technique="T1621",
            recommended_actions=[
                "Contact user immediately to verify",
                "Revoke all active sessions if compromised",
                "Enable number matching for MFA",
                "Consider phishing-resistant MFA",
            ],
        )

    def _mfa_bypass_template(self) -> AlertTemplate:
        """Template for MFA bypass alerts."""
        return AlertTemplate(
            alert_type="mfa_bypass",
            title_template="MFA Bypass Detected: {user_email}",
            body_template="""## Alert Summary
MFA bypass detected for **{user_email}**. User authenticated without expected MFA challenge.

## User Context
- **Department:** {user_department}
- **Normal MFA Rate:** {normal_mfa_rate}%
- **MFA Methods:** {typical_mfa_methods}

## Bypass Details
| Field | Value |
|-------|-------|
| Authentication Time | {auth_time} |
| Expected MFA | Yes |
| MFA Completed | No |
| Bypass Method | {bypass_method} |

## Session Information
- **Source IP:** {source_ip}
- **Location:** {source_city}, {source_country}
- **Device:** {device_info}
- **Application:** {target_application}

## Recommended Actions
1. Investigate how MFA was bypassed
2. Review conditional access policies
3. Check for session token theft
4. Verify no MFA exceptions were added
""",
            action_buttons=[
                {"id": "investigate", "label": "Investigate", "style": "primary"},
                {"id": "revoke_sessions", "label": "Revoke Sessions", "style": "danger"},
                {"id": "force_mfa", "label": "Force MFA", "style": "warning"},
                {"id": "dismiss", "label": "Dismiss", "style": "default"},
            ],
            investigation_links=[
                {"label": "Policy Audit", "url": "{base_url}/policies/audit"},
                {"label": "Session Details", "url": "{base_url}/sessions/{session_id}"},
            ],
            mitre_technique="T1556.006",
            recommended_actions=[
                "Investigate bypass mechanism",
                "Revoke active sessions",
                "Review conditional access policies",
                "Check for unauthorized MFA exceptions",
            ],
        )

    def _impossible_travel_template(self) -> AlertTemplate:
        """Template for impossible travel alerts."""
        return AlertTemplate(
            alert_type="impossible_travel",
            title_template="Impossible Travel Detected: {user_email}",
            body_template="""## Alert Summary
Impossible travel detected for **{user_email}**. User authenticated from two locations that are geographically impossible to travel between in the given time.

## Travel Analysis
| Metric | Value |
|--------|-------|
| Distance | {distance_km} km ({distance_miles} miles) |
| Time Between Logins | {time_between} |
| Required Speed | {required_speed_kmh} km/h |
| Maximum Possible Speed | {max_travel_speed} km/h |

## First Location
- **Time:** {first_login_time}
- **IP:** {first_ip}
- **City:** {first_city}
- **Country:** {first_country}
- **Coordinates:** {first_coords}

## Second Location
- **Time:** {second_login_time}
- **IP:** {second_ip}
- **City:** {second_city}
- **Country:** {second_country}
- **Coordinates:** {second_coords}

## User Context
- **Known Locations:** {known_locations}
- **VPN Usage:** {uses_vpn}
- **Risk Score:** {risk_score}/100

## Recommended Actions
1. Verify with user which login was legitimate
2. Check if VPN or proxy was used
3. Review session activity from both locations
4. Consider revoking session from suspicious location
""",
            action_buttons=[
                {"id": "investigate", "label": "Investigate", "style": "primary"},
                {"id": "revoke_second", "label": "Revoke 2nd Session", "style": "danger"},
                {"id": "contact_user", "label": "Contact User", "style": "warning"},
                {"id": "dismiss", "label": "Mark as VPN", "style": "default"},
            ],
            investigation_links=[
                {"label": "Location History", "url": "{base_url}/users/{user_id}/locations"},
                {"label": "Session Comparison", "url": "{base_url}/sessions/compare/{session1_id}/{session2_id}"},
            ],
            mitre_technique="T1078",
            recommended_actions=[
                "Contact user to verify",
                "Check for VPN or proxy usage",
                "Review activity from both sessions",
                "Revoke suspicious session",
            ],
        )

    def _privilege_escalation_template(self) -> AlertTemplate:
        """Template for privilege escalation alerts."""
        return AlertTemplate(
            alert_type="privilege_escalation",
            title_template="Privilege Escalation Detected: {user_email}",
            body_template="""## Alert Summary
Privilege escalation detected for **{user_email}**. User gained elevated privileges through {escalation_method}.

## Escalation Details
| Field | Value |
|-------|-------|
| Previous Role | {previous_role} |
| New Role | {new_role} |
| Escalation Type | {escalation_type} |
| Granted By | {granted_by} |
| Time | {escalation_time} |

## New Permissions
{new_permissions}

## User Context
- **Department:** {user_department}
- **Normal Privilege Level:** {typical_privilege_level}
- **Risk Score:** {risk_score}/100

## Change Context
- **Approved Change:** {is_approved_change}
- **Change Ticket:** {change_ticket}
- **Business Justification:** {justification}

## Recommended Actions
1. Verify privilege change was authorized
2. Review who granted the privileges
3. Check for subsequent suspicious activity
4. Audit recent actions with new privileges
""",
            action_buttons=[
                {"id": "investigate", "label": "Investigate", "style": "primary"},
                {"id": "revoke_privs", "label": "Revoke Privileges", "style": "danger"},
                {"id": "verify_change", "label": "Verify Change", "style": "warning"},
                {"id": "approve", "label": "Approve", "style": "default"},
            ],
            investigation_links=[
                {"label": "Permission Audit", "url": "{base_url}/users/{user_id}/permissions"},
                {"label": "Change History", "url": "{base_url}/audit/privilege-changes"},
            ],
            mitre_technique="T1078.004",
            recommended_actions=[
                "Verify change was authorized",
                "Review granter's authorization",
                "Audit activity with new privileges",
                "Check for lateral movement",
            ],
        )

    def _session_hijack_template(self) -> AlertTemplate:
        """Template for session hijacking alerts."""
        return AlertTemplate(
            alert_type="session_hijack",
            title_template="Session Hijacking Detected: {user_email}",
            body_template="""## Alert Summary
Possible session hijacking detected for **{user_email}**. Session token appears to be used from an unauthorized location or device.

## Hijacking Indicators
| Indicator | Original | Current |
|-----------|----------|---------|
| IP Address | {original_ip} | {current_ip} |
| Location | {original_location} | {current_location} |
| Device | {original_device} | {current_device} |
| User Agent | {original_ua} | {current_ua} |

## Session Details
- **Session ID:** {session_id}
- **Created:** {session_created}
- **Last Activity:** {last_activity}
- **Anomaly Detected:** {anomaly_time}

## Detection Reason
{detection_reason}

## Risk Assessment
- **Confidence:** {confidence}%
- **Risk Score:** {risk_score}/100
- **Potential Impact:** {potential_impact}

## Recommended Actions
1. **Immediately revoke the session**
2. Force re-authentication for user
3. Investigate how token was obtained
4. Review for data exfiltration
""",
            action_buttons=[
                {"id": "revoke_now", "label": "Revoke Session NOW", "style": "danger"},
                {"id": "investigate", "label": "Investigate", "style": "primary"},
                {"id": "contact_user", "label": "Contact User", "style": "warning"},
                {"id": "dismiss", "label": "Dismiss", "style": "default"},
            ],
            investigation_links=[
                {"label": "Session Activity", "url": "{base_url}/sessions/{session_id}/activity"},
                {"label": "Token Analysis", "url": "{base_url}/security/token-analysis/{session_id}"},
            ],
            mitre_technique="T1550.004",
            recommended_actions=[
                "Immediately revoke session",
                "Force user re-authentication",
                "Investigate token theft vector",
                "Check for data exfiltration",
            ],
        )

    def _dormant_account_template(self) -> AlertTemplate:
        """Template for dormant account activation alerts."""
        return AlertTemplate(
            alert_type="dormant_account",
            title_template="Dormant Account Activated: {user_email}",
            body_template="""## Alert Summary
Previously dormant account **{user_email}** has become active after {dormancy_period} of inactivity.

## Account Details
| Field | Value |
|-------|-------|
| Last Previous Activity | {last_activity} |
| Dormancy Period | {dormancy_period} |
| Account Type | {account_type} |
| Department | {department} |

## Activation Details
- **Activation Time:** {activation_time}
- **Source IP:** {source_ip}
- **Location:** {source_location}
- **Device:** {device_info}

## Activity After Activation
{recent_activity}

## Risk Indicators
- **Employee Status:** {employee_status}
- **Account Status:** {account_status}
- **Expected Reactivation:** {is_expected}

## Recommended Actions
1. Verify user's current employment status
2. Confirm account owner initiated the login
3. Review activity performed after activation
4. Check if account should remain active
""",
            action_buttons=[
                {"id": "investigate", "label": "Investigate", "style": "primary"},
                {"id": "disable_account", "label": "Disable Account", "style": "danger"},
                {"id": "contact_hr", "label": "Contact HR", "style": "warning"},
                {"id": "approve", "label": "Approve", "style": "default"},
            ],
            investigation_links=[
                {"label": "Account History", "url": "{base_url}/users/{user_id}/history"},
                {"label": "HR Status", "url": "{base_url}/hr/employee/{user_id}"},
            ],
            mitre_technique="T1078.001",
            recommended_actions=[
                "Verify current employment status",
                "Confirm with account owner",
                "Review post-activation activity",
                "Decide if account should remain active",
            ],
        )

    def _token_theft_template(self) -> AlertTemplate:
        """Template for token theft alerts."""
        return AlertTemplate(
            alert_type="token_theft",
            title_template="Token Theft Detected: {user_email}",
            body_template="""## Alert Summary
Access token theft detected for **{user_email}**. Token is being used in a suspicious manner indicating possible theft.

## Token Details
| Field | Value |
|-------|-------|
| Token Type | {token_type} |
| Token Scope | {token_scope} |
| Issued | {token_issued} |
| Expires | {token_expires} |

## Theft Indicators
{theft_indicators}

## Usage Anomalies
- **Original Context:** {original_context}
- **Suspicious Context:** {suspicious_context}
- **API Calls Made:** {api_calls_count}

## Accessed Resources
{accessed_resources}

## Recommended Actions
1. **Immediately revoke the token**
2. Revoke all refresh tokens for user
3. Investigate theft vector (phishing, malware, etc.)
4. Review data accessed with stolen token
""",
            action_buttons=[
                {"id": "revoke_token", "label": "Revoke Token NOW", "style": "danger"},
                {"id": "revoke_all", "label": "Revoke All Tokens", "style": "danger"},
                {"id": "investigate", "label": "Investigate", "style": "primary"},
                {"id": "dismiss", "label": "Dismiss", "style": "default"},
            ],
            investigation_links=[
                {"label": "Token Usage Log", "url": "{base_url}/security/tokens/{token_id}/usage"},
                {"label": "Data Access Audit", "url": "{base_url}/audit/data-access/{user_id}"},
            ],
            mitre_technique="T1528",
            recommended_actions=[
                "Immediately revoke stolen token",
                "Revoke all user tokens",
                "Investigate theft vector",
                "Audit data access",
            ],
        )

    def _unusual_login_time_template(self) -> AlertTemplate:
        """Template for unusual login time alerts."""
        return AlertTemplate(
            alert_type="unusual_login_time",
            title_template="Unusual Login Time: {user_email}",
            body_template="""## Alert Summary
Unusual login time detected for **{user_email}**. User authenticated at {login_time} which is outside their normal working hours.

## Login Details
- **Login Time:** {login_time} ({timezone})
- **Day of Week:** {day_of_week}
- **Source IP:** {source_ip}
- **Location:** {source_location}

## User's Normal Pattern
- **Typical Hours:** {typical_hours}
- **Typical Days:** {typical_days}
- **Time Zone:** {user_timezone}

## Deviation Analysis
- **Hours Outside Normal:** {hours_deviation}
- **Statistical Deviation:** {std_deviation} standard deviations
- **Previous Off-Hours Logins:** {previous_offhours_count}

## Recommended Actions
1. Verify login was intentional
2. Check for concurrent sessions from normal locations
3. Review activity during this session
""",
            action_buttons=[
                {"id": "investigate", "label": "Investigate", "style": "primary"},
                {"id": "contact_user", "label": "Contact User", "style": "warning"},
                {"id": "approve", "label": "Mark as Expected", "style": "default"},
            ],
            investigation_links=[
                {"label": "Login History", "url": "{base_url}/users/{user_id}/logins"},
            ],
            mitre_technique="T1078",
            recommended_actions=[
                "Verify login was intentional",
                "Check session activity",
                "Update baseline if legitimate",
            ],
        )

    def _new_device_template(self) -> AlertTemplate:
        """Template for new device alerts."""
        return AlertTemplate(
            alert_type="new_device",
            title_template="New Device Login: {user_email}",
            body_template="""## Alert Summary
Login from new device detected for **{user_email}**.

## New Device Details
- **Device Type:** {device_type}
- **Operating System:** {device_os}
- **Browser:** {browser}
- **Device Fingerprint:** {device_fingerprint}

## Login Context
- **Time:** {login_time}
- **Source IP:** {source_ip}
- **Location:** {source_location}

## User's Known Devices
{known_devices}

## Risk Factors
- **First Time Device:** Yes
- **Location Matches Known:** {location_matches}
- **After Failed Attempts:** {after_failures}

## Recommended Actions
1. Confirm with user if this is their device
2. Review login context for other anomalies
3. Add to trusted devices if confirmed
""",
            action_buttons=[
                {"id": "investigate", "label": "Investigate", "style": "primary"},
                {"id": "trust_device", "label": "Trust Device", "style": "default"},
                {"id": "block_device", "label": "Block Device", "style": "danger"},
            ],
            investigation_links=[
                {"label": "Device History", "url": "{base_url}/users/{user_id}/devices"},
            ],
            mitre_technique="T1078",
            recommended_actions=[
                "Confirm with user",
                "Review login context",
                "Add to trusted devices if legitimate",
            ],
        )

    def _new_location_template(self) -> AlertTemplate:
        """Template for new location alerts."""
        return AlertTemplate(
            alert_type="new_location",
            title_template="New Location Login: {user_email}",
            body_template="""## Alert Summary
Login from new location detected for **{user_email}**.

## New Location Details
- **City:** {new_city}
- **Country:** {new_country}
- **IP Address:** {source_ip}
- **ISP:** {isp}

## Login Context
- **Time:** {login_time}
- **Device:** {device_info}
- **Application:** {application}

## User's Known Locations
{known_locations}

## Risk Assessment
- **Distance from Nearest Known:** {distance_km} km
- **Country Change:** {is_country_change}
- **Travel Possible:** {travel_possible}

## Recommended Actions
1. Verify with user if they are traveling
2. Check if VPN is being used
3. Review session activity
""",
            action_buttons=[
                {"id": "investigate", "label": "Investigate", "style": "primary"},
                {"id": "trust_location", "label": "Trust Location", "style": "default"},
                {"id": "revoke", "label": "Revoke Session", "style": "danger"},
            ],
            investigation_links=[
                {"label": "Location History", "url": "{base_url}/users/{user_id}/locations"},
            ],
            mitre_technique="T1078",
            recommended_actions=[
                "Verify if user is traveling",
                "Check for VPN usage",
                "Review session activity",
            ],
        )

    def _account_takeover_template(self) -> AlertTemplate:
        """Template for account takeover alerts."""
        return AlertTemplate(
            alert_type="account_takeover",
            title_template="Account Takeover Detected: {user_email}",
            body_template="""## Alert Summary
**CRITICAL:** Account takeover detected for **{user_email}**. Multiple indicators suggest the account has been compromised.

## Takeover Indicators
{takeover_indicators}

## Attack Timeline
{attack_timeline}

## Compromised Session Details
- **Session Started:** {session_start}
- **Source IP:** {source_ip}
- **Location:** {source_location}
- **Device:** {device_info}

## Malicious Activity Detected
{malicious_activity}

## Impact Assessment
- **Data Accessed:** {data_accessed}
- **Changes Made:** {changes_made}
- **Lateral Movement:** {lateral_movement}

## Recommended Actions
1. **IMMEDIATELY disable the account**
2. Revoke all active sessions and tokens
3. Reset credentials and MFA
4. Investigate scope of compromise
5. Notify user through alternate channel
6. Initiate incident response procedure
""",
            action_buttons=[
                {"id": "disable_account", "label": "DISABLE ACCOUNT", "style": "danger"},
                {"id": "revoke_all", "label": "Revoke All Sessions", "style": "danger"},
                {"id": "investigate", "label": "Investigate", "style": "primary"},
                {"id": "create_incident", "label": "Create Incident", "style": "warning"},
            ],
            investigation_links=[
                {"label": "Full Activity Log", "url": "{base_url}/users/{user_id}/activity?full=true"},
                {"label": "Data Access Audit", "url": "{base_url}/audit/data-access/{user_id}"},
                {"label": "Incident Playbook", "url": "{base_url}/playbooks/account-takeover"},
            ],
            mitre_technique="T1078",
            recommended_actions=[
                "IMMEDIATELY disable account",
                "Revoke all sessions and tokens",
                "Reset credentials and MFA",
                "Investigate compromise scope",
                "Notify user via alternate channel",
                "Initiate incident response",
            ],
        )

    def get_template(self, alert_type: str) -> Optional[AlertTemplate]:
        """Get template for a specific alert type.

        Args:
            alert_type: Type of identity alert

        Returns:
            AlertTemplate if found, None otherwise
        """
        return self._templates.get(alert_type.lower().replace("-", "_"))

    def list_template_types(self) -> List[str]:
        """Get list of available template types.

        Returns:
            List of alert type names
        """
        return list(self._templates.keys())

    def render_alert(
        self,
        alert: AlertProtocol,
        template: Optional[AlertTemplate] = None,
        context: Optional[Dict[str, Any]] = None,
    ) -> RenderedAlert:
        """Render an alert using its template.

        Args:
            alert: Alert to render
            template: Optional template override
            context: Additional context for rendering

        Returns:
            RenderedAlert with filled template
        """
        # Determine alert type and get template
        alert_type = self._determine_alert_type(alert)

        if template is None:
            template = self.get_template(alert_type)

        if template is None:
            # Use default template
            template = self._default_template()

        # Build context for template rendering
        render_context = self._build_render_context(alert, context or {})

        # Render title
        title = self._safe_format(template.title_template, render_context)

        # Render body
        body_markdown = self._safe_format(template.body_template, render_context)

        # Get severity color
        severity_color = template.severity_colors.get(
            alert.severity.lower(), "#808080"
        )

        # Render action buttons
        action_buttons = self._render_action_buttons(
            template.action_buttons, render_context
        )

        # Render investigation links
        investigation_links = self._render_investigation_links(
            template.investigation_links, render_context
        )

        return RenderedAlert(
            alert_id=alert.id,
            alert_type=alert_type,
            severity=alert.severity,
            severity_color=severity_color,
            title=title,
            body_markdown=body_markdown,
            action_buttons=action_buttons,
            investigation_links=investigation_links,
            recommended_actions=template.recommended_actions,
            metadata={
                "mitre_technique": template.mitre_technique,
                "original_title": alert.title,
                "original_description": alert.description,
            },
        )

    def _determine_alert_type(self, alert: AlertProtocol) -> str:
        """Determine alert type from alert data.

        Args:
            alert: Alert to analyze

        Returns:
            Alert type string
        """
        # Check metadata for explicit type
        if alert.metadata:
            if "alert_type" in alert.metadata:
                return alert.metadata["alert_type"]
            if "identity_alert_type" in alert.metadata:
                return alert.metadata["identity_alert_type"]

        # Infer from rule name
        rule_lower = alert.rule_name.lower()

        type_keywords = {
            "brute_force": ["brute", "bruteforce"],
            "credential_stuffing": ["credential", "stuffing"],
            "password_spray": ["spray", "password spray"],
            "mfa_fatigue": ["fatigue", "push bomb", "mfa bomb"],
            "mfa_bypass": ["mfa bypass", "bypass mfa"],
            "impossible_travel": ["impossible", "travel"],
            "privilege_escalation": ["privilege", "escalat"],
            "session_hijack": ["hijack", "session theft"],
            "dormant_account": ["dormant", "inactive account"],
            "token_theft": ["token theft", "stolen token"],
            "unusual_login_time": ["unusual time", "off hours"],
            "new_device": ["new device", "unknown device"],
            "new_location": ["new location", "unknown location"],
            "account_takeover": ["takeover", "compromised account"],
        }

        for alert_type, keywords in type_keywords.items():
            for keyword in keywords:
                if keyword in rule_lower:
                    return alert_type

        return "generic"

    def _build_render_context(
        self,
        alert: AlertProtocol,
        additional_context: Dict[str, Any],
    ) -> Dict[str, Any]:
        """Build context dictionary for template rendering.

        Args:
            alert: Alert data
            additional_context: Additional context values

        Returns:
            Complete context dictionary
        """
        context = {
            "alert_id": alert.id,
            "rule_id": alert.rule_id,
            "rule_name": alert.rule_name,
            "severity": alert.severity,
            "timestamp": alert.timestamp.isoformat(),
            "base_url": self.base_url,
        }

        # Add results data (flatten first result if available)
        if alert.results:
            first_result = alert.results[0]
            for key, value in first_result.items():
                context[key] = value

        # Add metadata
        if alert.metadata:
            # Add enrichment data if available
            enrichment = alert.metadata.get("enrichment", {})
            for key, value in enrichment.items():
                context[f"enrichment_{key}"] = value

            # Add other metadata
            for key, value in alert.metadata.items():
                if key != "enrichment":
                    context[key] = value

        # Add additional context (overrides)
        context.update(additional_context)

        # Add common defaults for missing fields
        defaults = {
            "user_email": "unknown",
            "user_department": "Unknown",
            "user_title": "Unknown",
            "source_ip": "Unknown",
            "source_country": "Unknown",
            "source_city": "Unknown",
            "source_location": "Unknown",
            "risk_score": 0,
            "typical_login_hours": "Not established",
            "failure_count": 0,
            "time_window": "Unknown",
            "provider": "Unknown",
            "target_application": "Unknown",
        }

        for key, default in defaults.items():
            if key not in context or context[key] is None:
                context[key] = default

        return context

    def _safe_format(self, template: str, context: Dict[str, Any]) -> str:
        """Safely format template string with context.

        Args:
            template: Template string with {placeholders}
            context: Context values

        Returns:
            Formatted string with missing placeholders replaced with "N/A"
        """
        # Find all placeholders
        placeholders = re.findall(r"\{([^}]+)\}", template)

        # Build safe context with defaults
        safe_context = {}
        for placeholder in placeholders:
            # Handle nested keys like source_geo.country
            if "." in placeholder:
                parts = placeholder.split(".")
                value = context
                for part in parts:
                    if isinstance(value, dict):
                        value = value.get(part, "N/A")
                    else:
                        value = "N/A"
                        break
                safe_context[placeholder] = value
            else:
                safe_context[placeholder] = context.get(placeholder, "N/A")

        # Format template
        try:
            return template.format(**safe_context)
        except (KeyError, ValueError):
            # Fallback: replace unresolved placeholders
            result = template
            for placeholder in placeholders:
                pattern = "{" + placeholder + "}"
                if pattern in result:
                    result = result.replace(pattern, str(safe_context.get(placeholder, "N/A")))
            return result

    def _render_action_buttons(
        self,
        buttons: List[Dict[str, str]],
        context: Dict[str, Any],
    ) -> List[Dict[str, str]]:
        """Render action buttons with context.

        Args:
            buttons: Button definitions
            context: Render context

        Returns:
            Rendered button list
        """
        rendered = []
        for button in buttons:
            rendered_button = {}
            for key, value in button.items():
                if isinstance(value, str):
                    rendered_button[key] = self._safe_format(value, context)
                else:
                    rendered_button[key] = value
            rendered.append(rendered_button)
        return rendered

    def _render_investigation_links(
        self,
        links: List[Dict[str, str]],
        context: Dict[str, Any],
    ) -> List[Dict[str, str]]:
        """Render investigation links with context.

        Args:
            links: Link definitions
            context: Render context

        Returns:
            Rendered link list
        """
        rendered = []
        for link in links:
            rendered_link = {}
            for key, value in link.items():
                if isinstance(value, str):
                    rendered_link[key] = self._safe_format(value, context)
                else:
                    rendered_link[key] = value
            rendered.append(rendered_link)
        return rendered

    def _default_template(self) -> AlertTemplate:
        """Create a default template for unknown alert types.

        Returns:
            Generic alert template
        """
        return AlertTemplate(
            alert_type="generic",
            title_template="{rule_name}: {title}",
            body_template="""## Alert Summary
{description}

## Details
- **Severity:** {severity}
- **Time:** {timestamp}
- **Rule:** {rule_name}

## Recommended Actions
1. Review the alert details
2. Investigate affected resources
3. Take appropriate action
""",
            action_buttons=[
                {"id": "investigate", "label": "Investigate", "style": "primary"},
                {"id": "dismiss", "label": "Dismiss", "style": "default"},
            ],
            investigation_links=[
                {"label": "Alert Details", "url": "{base_url}/alerts/{alert_id}"},
            ],
            recommended_actions=[
                "Review alert details",
                "Investigate affected resources",
                "Take appropriate action",
            ],
        )
