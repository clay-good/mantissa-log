"""Privilege escalation detection for identity events.

Provides cross-provider detection of privilege escalation patterns including:
- Admin role grants to non-admin users
- Self-privilege grants (user granting themselves elevated access)
- Privilege grant chains (multiple escalations in sequence)
- Unusual privilege grants (from new locations, outside hours)
- Privilege grants by newly-created admins
"""

import logging
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Set

logger = logging.getLogger(__name__)


class PrivilegeGrantType(Enum):
    """Types of privilege grant detections."""

    ADMIN_GRANT = "admin_grant"  # Admin role assigned to user
    SELF_GRANT = "self_grant"  # User granted themselves privileges
    PRIVILEGE_CHAIN = "privilege_chain"  # Multiple privilege escalations
    UNUSUAL_GRANT = "unusual_grant"  # Grant with anomalies
    NEW_ADMIN_GRANT = "new_admin_grant"  # Grant by newly-created admin


@dataclass
class PrivilegeAlert:
    """Alert generated for detected privilege escalation.

    Attributes:
        alert_id: Unique identifier for this alert
        alert_type: Type of privilege escalation
        severity: Alert severity (critical, high, medium, low)
        title: Human-readable alert title
        description: Detailed description of the escalation
        actor_email: Email of user who granted the privilege
        target_email: Email of user receiving the privilege
        role_granted: Name of the role or privilege granted
        provider: Identity provider where grant occurred
        source_ip: IP address of the actor
        source_country: Country of the actor
        event_time: When the grant occurred
        evidence: Additional evidence data
        mitre_techniques: Associated MITRE ATT&CK techniques
        recommended_actions: Suggested response actions
    """

    alert_id: str
    alert_type: PrivilegeGrantType
    severity: str
    title: str
    description: str
    actor_email: str = ""
    target_email: str = ""
    role_granted: str = ""
    provider: str = ""
    source_ip: str = ""
    source_country: str = ""
    event_time: Optional[datetime] = None
    evidence: Dict[str, Any] = field(default_factory=dict)
    mitre_techniques: List[str] = field(default_factory=list)
    recommended_actions: List[str] = field(default_factory=list)
    detected_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "alert_id": self.alert_id,
            "alert_type": self.alert_type.value,
            "severity": self.severity,
            "title": self.title,
            "description": self.description,
            "actor_email": self.actor_email,
            "target_email": self.target_email,
            "role_granted": self.role_granted,
            "provider": self.provider,
            "source_ip": self.source_ip,
            "source_country": self.source_country,
            "event_time": self.event_time.isoformat() if self.event_time else None,
            "evidence": self.evidence,
            "mitre_techniques": self.mitre_techniques,
            "recommended_actions": self.recommended_actions,
            "detected_at": self.detected_at.isoformat(),
        }


@dataclass
class PrivilegeChain:
    """Represents a chain of privilege escalations for a user.

    Attributes:
        user_email: The user who received privileges
        grants: List of privilege grants in chronological order
        initial_privilege_level: Privilege level before chain
        final_privilege_level: Privilege level after chain
        chain_duration_hours: Time span of the escalation chain
        unique_granters: Number of different users who granted privileges
        is_suspicious: Whether the chain pattern is suspicious
    """

    user_email: str
    grants: List[Dict[str, Any]] = field(default_factory=list)
    initial_privilege_level: str = "user"
    final_privilege_level: str = "user"
    chain_duration_hours: float = 0.0
    unique_granters: int = 0
    is_suspicious: bool = False

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "user_email": self.user_email,
            "grants": self.grants,
            "initial_privilege_level": self.initial_privilege_level,
            "final_privilege_level": self.final_privilege_level,
            "chain_duration_hours": self.chain_duration_hours,
            "unique_granters": self.unique_granters,
            "is_suspicious": self.is_suspicious,
        }


class PrivilegeDetector:
    """Detects privilege escalation attacks across identity providers.

    Implements detection for:
    1. Admin role grants to non-admin users
    2. Self-privilege grants (always critical)
    3. Privilege grant chains (multiple escalations)
    4. Unusual privilege grants (combined with anomalies)
    5. Privilege grants by newly-created admins

    Attributes:
        query_executor: Executor for querying identity events
        baseline_store: Store for user baselines
        HIGH_PRIVILEGE_ROLES: Set of high-privilege role names
        PROVIDER_ROLE_MAPPING: Mapping of provider-specific roles to normalized levels
    """

    # High-privilege roles across providers (normalized names)
    HIGH_PRIVILEGE_ROLES: Set[str] = {
        # Generic
        "Global Administrator",
        "Super Admin",
        "org_admin",
        "Security Administrator",
        "Exchange Administrator",
        # Okta
        "SUPER_ADMIN",
        "ORG_ADMIN",
        "APP_ADMIN",
        "USER_ADMIN",
        "GROUP_ADMIN",
        "REPORT_ADMIN",
        "API_ACCESS_MANAGEMENT_ADMIN",
        "MOBILE_ADMIN",
        # Azure AD / Entra ID
        "Company Administrator",  # Legacy Global Admin name
        "Privileged Role Administrator",
        "Privileged Authentication Administrator",
        "Application Administrator",
        "Cloud Application Administrator",
        "Authentication Administrator",
        "User Administrator",
        "Helpdesk Administrator",
        # Google Workspace
        "_SUPER_ADMIN",
        "_ADMIN",
        "_SECURITY_ADMIN",
        "_USER_MANAGEMENT_ADMIN",
        "_SERVICES_ADMIN",
        "_GROUPS_ADMIN",
        # Microsoft 365
        "Organization Management",
        "Compliance Administrator",
        "eDiscovery Manager",
        "Security Reader",
        # Duo
        "Owner",
        "Administrator",
    }

    # Critical roles that warrant immediate attention
    CRITICAL_ROLES: Set[str] = {
        "Global Administrator",
        "Super Admin",
        "SUPER_ADMIN",
        "_SUPER_ADMIN",
        "Company Administrator",
        "Privileged Role Administrator",
        "Owner",
        "org_admin",
        "Organization Management",
    }

    # Provider-specific role to privilege level mapping
    PROVIDER_ROLE_MAPPING: Dict[str, Dict[str, str]] = {
        "okta": {
            "SUPER_ADMIN": "critical",
            "ORG_ADMIN": "critical",
            "APP_ADMIN": "high",
            "USER_ADMIN": "high",
            "GROUP_ADMIN": "medium",
            "REPORT_ADMIN": "low",
            "READ_ONLY_ADMIN": "low",
            "API_ACCESS_MANAGEMENT_ADMIN": "high",
            "MOBILE_ADMIN": "medium",
            "HELP_DESK_ADMIN": "low",
        },
        "azure": {
            "Global Administrator": "critical",
            "Company Administrator": "critical",
            "Privileged Role Administrator": "critical",
            "Privileged Authentication Administrator": "critical",
            "Security Administrator": "high",
            "Application Administrator": "high",
            "Cloud Application Administrator": "high",
            "User Administrator": "high",
            "Authentication Administrator": "medium",
            "Helpdesk Administrator": "low",
            "Directory Readers": "low",
        },
        "google_workspace": {
            "_SUPER_ADMIN": "critical",
            "_ADMIN": "high",
            "_SECURITY_ADMIN": "critical",
            "_USER_MANAGEMENT_ADMIN": "high",
            "_SERVICES_ADMIN": "high",
            "_GROUPS_ADMIN": "medium",
            "_HELP_DESK_ADMIN": "low",
        },
        "microsoft365": {
            "Organization Management": "critical",
            "Security Administrator": "critical",
            "Compliance Administrator": "high",
            "Exchange Administrator": "high",
            "SharePoint Administrator": "high",
            "Teams Administrator": "high",
            "eDiscovery Manager": "high",
            "Security Reader": "low",
        },
        "duo": {
            "Owner": "critical",
            "Administrator": "high",
            "Application Manager": "medium",
            "User Manager": "medium",
            "Help Desk": "low",
            "Read-only": "low",
        },
    }

    # Default window for detection
    DEFAULT_WINDOW_HOURS = 24

    # Threshold for "new admin" (hours since becoming admin)
    NEW_ADMIN_THRESHOLD_HOURS = 72

    def __init__(
        self,
        query_executor: Any,
        baseline_store: Any = None,
        identity_events_table: str = "identity_events",
    ):
        """Initialize the privilege detector.

        Args:
            query_executor: Executor for querying the data lake
            baseline_store: Optional store for user baselines
            identity_events_table: Name of the identity events table
        """
        self.query_executor = query_executor
        self.baseline_store = baseline_store
        self.identity_events_table = identity_events_table

    def detect_privilege_grants(
        self,
        window_hours: int = None,
    ) -> List[PrivilegeAlert]:
        """Detect all privilege grants of high-privilege roles.

        Finds PRIVILEGE_GRANT events where high-privilege roles were assigned.
        Higher severity for grants to new users, outside business hours, or
        from potentially compromised accounts.

        Args:
            window_hours: Detection window in hours

        Returns:
            List of PrivilegeAlert for each detected grant
        """
        window = window_hours or self.DEFAULT_WINDOW_HOURS
        alerts = []

        cutoff = datetime.now(timezone.utc) - timedelta(hours=window)
        cutoff_str = cutoff.strftime("%Y-%m-%d %H:%M:%S")

        query = f"""
            SELECT
                actor_email,
                target_email,
                role_name,
                provider,
                source_ip,
                source_geo_country,
                event_timestamp,
                event_action,
                raw_data
            FROM {self.identity_events_table}
            WHERE event_type = 'PRIVILEGE_GRANT'
              AND event_timestamp >= TIMESTAMP '{cutoff_str}'
            ORDER BY event_timestamp DESC
            LIMIT 500
        """

        try:
            result = self.query_executor.execute_query(query, timeout_seconds=120)

            for row in result.rows:
                role_name = row.get("role_name", "")
                if self._is_high_privilege_role(role_name):
                    alert = self._create_admin_grant_alert(row)
                    alerts.append(alert)

        except Exception as e:
            logger.error(f"Error detecting privilege grants: {e}")

        return alerts

    def detect_self_privilege_grant(
        self,
        window_hours: int = None,
    ) -> List[PrivilegeAlert]:
        """Detect when users grant themselves elevated privileges.

        Self-privilege grants should never occur in normal operations.
        Always critical severity as this indicates compromise or insider threat.

        Args:
            window_hours: Detection window in hours

        Returns:
            List of PrivilegeAlert for each self-grant detected
        """
        window = window_hours or self.DEFAULT_WINDOW_HOURS
        alerts = []

        cutoff = datetime.now(timezone.utc) - timedelta(hours=window)
        cutoff_str = cutoff.strftime("%Y-%m-%d %H:%M:%S")

        query = f"""
            SELECT
                actor_email,
                target_email,
                role_name,
                provider,
                source_ip,
                source_geo_country,
                event_timestamp,
                event_action,
                raw_data
            FROM {self.identity_events_table}
            WHERE event_type = 'PRIVILEGE_GRANT'
              AND event_timestamp >= TIMESTAMP '{cutoff_str}'
              AND LOWER(actor_email) = LOWER(target_email)
            ORDER BY event_timestamp DESC
            LIMIT 100
        """

        try:
            result = self.query_executor.execute_query(query, timeout_seconds=120)

            for row in result.rows:
                alert = self._create_self_grant_alert(row)
                alerts.append(alert)

        except Exception as e:
            logger.error(f"Error detecting self-privilege grants: {e}")

        return alerts

    def detect_privilege_grant_chain(
        self,
        user_email: str,
        window_hours: int = None,
    ) -> List[PrivilegeAlert]:
        """Detect when a user receives multiple privilege grants.

        Multiple privilege grants in a short period could indicate
        an escalation path being exploited.

        Args:
            user_email: Email of user to check
            window_hours: Detection window in hours

        Returns:
            List of PrivilegeAlert if chain detected
        """
        window = window_hours or self.DEFAULT_WINDOW_HOURS
        alerts = []

        cutoff = datetime.now(timezone.utc) - timedelta(hours=window)
        cutoff_str = cutoff.strftime("%Y-%m-%d %H:%M:%S")

        query = f"""
            SELECT
                actor_email,
                target_email,
                role_name,
                provider,
                source_ip,
                source_geo_country,
                event_timestamp,
                event_action
            FROM {self.identity_events_table}
            WHERE event_type = 'PRIVILEGE_GRANT'
              AND event_timestamp >= TIMESTAMP '{cutoff_str}'
              AND LOWER(target_email) = LOWER('{user_email}')
            ORDER BY event_timestamp ASC
        """

        try:
            result = self.query_executor.execute_query(query, timeout_seconds=120)

            if len(result.rows) >= 2:
                # Multiple grants - analyze the chain
                chain = self._analyze_grant_chain(user_email, result.rows)

                if chain.is_suspicious:
                    alert = self._create_chain_alert(chain)
                    alerts.append(alert)

        except Exception as e:
            logger.error(f"Error detecting privilege grant chain: {e}")

        return alerts

    def detect_unusual_privilege_grant(
        self,
        window_hours: int = None,
    ) -> List[PrivilegeAlert]:
        """Detect privilege grants with additional anomaly indicators.

        Flags grants that occur:
        - From new/unusual locations for the granter
        - Outside business hours
        - To dormant accounts
        - Combined with other suspicious activity

        Args:
            window_hours: Detection window in hours

        Returns:
            List of PrivilegeAlert for unusual grants
        """
        window = window_hours or self.DEFAULT_WINDOW_HOURS
        alerts = []

        cutoff = datetime.now(timezone.utc) - timedelta(hours=window)
        cutoff_str = cutoff.strftime("%Y-%m-%d %H:%M:%S")

        query = f"""
            SELECT
                actor_email,
                target_email,
                role_name,
                provider,
                source_ip,
                source_geo_country,
                source_geo_city,
                event_timestamp,
                event_action,
                raw_data
            FROM {self.identity_events_table}
            WHERE event_type = 'PRIVILEGE_GRANT'
              AND event_timestamp >= TIMESTAMP '{cutoff_str}'
            ORDER BY event_timestamp DESC
            LIMIT 500
        """

        try:
            result = self.query_executor.execute_query(query, timeout_seconds=120)

            for row in result.rows:
                anomalies = self._check_grant_anomalies(row)

                if anomalies:
                    alert = self._create_unusual_grant_alert(row, anomalies)
                    alerts.append(alert)

        except Exception as e:
            logger.error(f"Error detecting unusual privilege grants: {e}")

        return alerts

    def detect_privilege_grant_by_new_admin(
        self,
        window_hours: int = None,
    ) -> List[PrivilegeAlert]:
        """Detect privilege grants made by recently-created admins.

        If an admin was recently granted admin access and is already
        granting others, this could indicate the new admin is compromised.

        Args:
            window_hours: Detection window in hours

        Returns:
            List of PrivilegeAlert for grants by new admins
        """
        window = window_hours or self.DEFAULT_WINDOW_HOURS
        alerts = []

        cutoff = datetime.now(timezone.utc) - timedelta(hours=window)
        cutoff_str = cutoff.strftime("%Y-%m-%d %H:%M:%S")

        # First, find recent privilege grants
        query = f"""
            SELECT
                actor_email,
                target_email,
                role_name,
                provider,
                source_ip,
                source_geo_country,
                event_timestamp,
                event_action
            FROM {self.identity_events_table}
            WHERE event_type = 'PRIVILEGE_GRANT'
              AND event_timestamp >= TIMESTAMP '{cutoff_str}'
            ORDER BY event_timestamp DESC
            LIMIT 500
        """

        try:
            result = self.query_executor.execute_query(query, timeout_seconds=120)

            for row in result.rows:
                actor_email = row.get("actor_email", "")
                if actor_email and self._is_new_admin(actor_email):
                    alert = self._create_new_admin_grant_alert(row)
                    alerts.append(alert)

        except Exception as e:
            logger.error(f"Error detecting grants by new admins: {e}")

        return alerts

    def analyze_privilege_chain(
        self,
        user_email: str,
    ) -> Dict[str, Any]:
        """Get full history of privilege changes for a user.

        Provides complete privilege timeline for investigation,
        including who granted, when, and what.

        Args:
            user_email: Email of user to analyze

        Returns:
            Dictionary containing privilege chain analysis
        """
        # Look back 90 days for full history
        cutoff = datetime.now(timezone.utc) - timedelta(days=90)
        cutoff_str = cutoff.strftime("%Y-%m-%d %H:%M:%S")

        query = f"""
            SELECT
                actor_email,
                target_email,
                role_name,
                provider,
                source_ip,
                source_geo_country,
                event_timestamp,
                event_action,
                event_type
            FROM {self.identity_events_table}
            WHERE (LOWER(target_email) = LOWER('{user_email}')
                   OR LOWER(actor_email) = LOWER('{user_email}'))
              AND event_type IN ('PRIVILEGE_GRANT', 'PRIVILEGE_REVOKE', 'ROLE_CHANGE')
              AND event_timestamp >= TIMESTAMP '{cutoff_str}'
            ORDER BY event_timestamp ASC
        """

        try:
            result = self.query_executor.execute_query(query, timeout_seconds=120)

            # Build timeline
            grants_received = []
            grants_given = []
            revocations = []

            for row in result.rows:
                event = {
                    "actor": row.get("actor_email", ""),
                    "target": row.get("target_email", ""),
                    "role": row.get("role_name", ""),
                    "provider": row.get("provider", ""),
                    "timestamp": row.get("event_timestamp"),
                    "action": row.get("event_action", ""),
                    "event_type": row.get("event_type", ""),
                    "source_ip": row.get("source_ip", ""),
                    "country": row.get("source_geo_country", ""),
                }

                target = row.get("target_email", "").lower()
                actor = row.get("actor_email", "").lower()
                user = user_email.lower()

                if target == user:
                    if row.get("event_type") == "PRIVILEGE_REVOKE":
                        revocations.append(event)
                    else:
                        grants_received.append(event)
                elif actor == user:
                    grants_given.append(event)

            # Analyze patterns
            current_roles = self._get_current_roles(grants_received, revocations)
            privilege_level = self._calculate_privilege_level(current_roles)

            return {
                "user_email": user_email,
                "analysis_period_days": 90,
                "grants_received": grants_received,
                "grants_given": grants_given,
                "revocations": revocations,
                "current_roles": current_roles,
                "current_privilege_level": privilege_level,
                "total_grants_received": len(grants_received),
                "total_grants_given": len(grants_given),
                "unique_granters": len(set(g["actor"] for g in grants_received)),
                "providers_involved": list(set(g["provider"] for g in grants_received)),
                "is_admin": privilege_level in ("critical", "high"),
                "first_admin_grant": self._find_first_admin_grant(grants_received),
            }

        except Exception as e:
            logger.error(f"Error analyzing privilege chain: {e}")
            return {
                "user_email": user_email,
                "error": str(e),
            }

    def run_all_detections(
        self,
        window_hours: int = None,
    ) -> List[PrivilegeAlert]:
        """Run all privilege escalation detection methods.

        Args:
            window_hours: Detection window in hours

        Returns:
            Combined and deduplicated list of alerts
        """
        window = window_hours or self.DEFAULT_WINDOW_HOURS
        all_alerts = []

        # Run detection methods
        admin_grants = self.detect_privilege_grants(window_hours=window)
        all_alerts.extend(admin_grants)

        self_grants = self.detect_self_privilege_grant(window_hours=window)
        all_alerts.extend(self_grants)

        unusual_grants = self.detect_unusual_privilege_grant(window_hours=window)
        all_alerts.extend(unusual_grants)

        new_admin_grants = self.detect_privilege_grant_by_new_admin(window_hours=window)
        all_alerts.extend(new_admin_grants)

        # Deduplicate
        deduplicated = self._deduplicate_alerts(all_alerts)

        # Sort by severity
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        deduplicated.sort(
            key=lambda a: (severity_order.get(a.severity, 4), a.event_time or datetime.min)
        )

        return deduplicated

    def _is_high_privilege_role(self, role_name: str) -> bool:
        """Check if a role is considered high privilege.

        Args:
            role_name: Name of the role to check

        Returns:
            True if the role is high privilege
        """
        if not role_name:
            return False

        # Direct match
        if role_name in self.HIGH_PRIVILEGE_ROLES:
            return True

        # Case-insensitive partial match for admin-type roles
        role_lower = role_name.lower()
        admin_keywords = ["admin", "super", "global", "owner", "organization", "security"]

        for keyword in admin_keywords:
            if keyword in role_lower:
                return True

        return False

    def _is_critical_role(self, role_name: str) -> bool:
        """Check if a role is critical (highest privilege).

        Args:
            role_name: Name of the role to check

        Returns:
            True if the role is critical
        """
        if not role_name:
            return False

        if role_name in self.CRITICAL_ROLES:
            return True

        role_lower = role_name.lower()
        critical_keywords = ["global", "super", "owner", "organization management"]

        for keyword in critical_keywords:
            if keyword in role_lower:
                return True

        return False

    def _get_role_severity(self, role_name: str, provider: str = "") -> str:
        """Get severity level for a specific role.

        Args:
            role_name: Name of the role
            provider: Identity provider (optional)

        Returns:
            Severity level (critical, high, medium, low)
        """
        # Check provider-specific mapping first
        if provider and provider.lower() in self.PROVIDER_ROLE_MAPPING:
            provider_map = self.PROVIDER_ROLE_MAPPING[provider.lower()]
            if role_name in provider_map:
                return provider_map[role_name]

        # Check against critical roles
        if self._is_critical_role(role_name):
            return "critical"

        # Check against high privilege roles
        if self._is_high_privilege_role(role_name):
            return "high"

        # Default to medium for any admin-type role
        if "admin" in role_name.lower():
            return "medium"

        return "low"

    def _is_new_admin(self, actor_email: str) -> bool:
        """Check if an actor is a recently-created admin.

        Args:
            actor_email: Email of the actor to check

        Returns:
            True if the actor became admin within threshold period
        """
        threshold = datetime.now(timezone.utc) - timedelta(
            hours=self.NEW_ADMIN_THRESHOLD_HOURS
        )
        threshold_str = threshold.strftime("%Y-%m-%d %H:%M:%S")

        query = f"""
            SELECT event_timestamp
            FROM {self.identity_events_table}
            WHERE event_type = 'PRIVILEGE_GRANT'
              AND LOWER(target_email) = LOWER('{actor_email}')
              AND event_timestamp >= TIMESTAMP '{threshold_str}'
            ORDER BY event_timestamp ASC
            LIMIT 1
        """

        try:
            result = self.query_executor.execute_query(query, timeout_seconds=30)
            return len(result.rows) > 0
        except Exception as e:
            logger.error(f"Error checking if new admin: {e}")
            return False

    def _check_grant_anomalies(self, row: Dict[str, Any]) -> List[str]:
        """Check for anomalies associated with a privilege grant.

        Args:
            row: Event data row

        Returns:
            List of anomaly descriptions
        """
        anomalies = []
        event_time = row.get("event_timestamp")

        # Check for outside business hours (basic check)
        if event_time:
            if isinstance(event_time, str):
                event_time = datetime.fromisoformat(event_time.replace("Z", "+00:00"))

            hour = event_time.hour
            if hour < 6 or hour > 20:
                anomalies.append("outside_business_hours")

            # Weekend check
            if event_time.weekday() >= 5:
                anomalies.append("weekend_grant")

        # Check for new location (if baseline available)
        actor_email = row.get("actor_email", "")
        source_country = row.get("source_geo_country", "")

        if self.baseline_store and actor_email and source_country:
            try:
                baseline = self.baseline_store.get_baseline(actor_email)
                if baseline and source_country not in baseline.known_countries:
                    anomalies.append("new_location_for_granter")
            except Exception:
                pass

        # Check if target is dormant (no activity in 30+ days)
        target_email = row.get("target_email", "")
        if target_email and self._is_dormant_account(target_email):
            anomalies.append("dormant_account_activated")

        return anomalies

    def _is_dormant_account(self, user_email: str, dormant_days: int = 30) -> bool:
        """Check if an account is dormant (no recent activity).

        Args:
            user_email: Email to check
            dormant_days: Days of inactivity to consider dormant

        Returns:
            True if account is dormant
        """
        cutoff = datetime.now(timezone.utc) - timedelta(days=dormant_days)
        cutoff_str = cutoff.strftime("%Y-%m-%d %H:%M:%S")

        query = f"""
            SELECT COUNT(*) as activity_count
            FROM {self.identity_events_table}
            WHERE LOWER(user_email) = LOWER('{user_email}')
              AND event_timestamp >= TIMESTAMP '{cutoff_str}'
        """

        try:
            result = self.query_executor.execute_query(query, timeout_seconds=30)
            if result.rows:
                return result.rows[0].get("activity_count", 0) == 0
        except Exception as e:
            logger.error(f"Error checking dormant account: {e}")

        return False

    def _analyze_grant_chain(
        self,
        user_email: str,
        rows: List[Dict[str, Any]],
    ) -> PrivilegeChain:
        """Analyze a chain of privilege grants for a user.

        Args:
            user_email: User receiving the grants
            rows: List of grant events

        Returns:
            PrivilegeChain analysis
        """
        grants = []
        granters = set()
        first_time = None
        last_time = None

        for row in rows:
            event_time = row.get("event_timestamp")
            if isinstance(event_time, str):
                event_time = datetime.fromisoformat(event_time.replace("Z", "+00:00"))

            if first_time is None:
                first_time = event_time
            last_time = event_time

            granters.add(row.get("actor_email", ""))
            grants.append({
                "actor": row.get("actor_email", ""),
                "role": row.get("role_name", ""),
                "provider": row.get("provider", ""),
                "timestamp": event_time.isoformat() if event_time else None,
                "source_ip": row.get("source_ip", ""),
            })

        # Calculate duration
        duration_hours = 0.0
        if first_time and last_time:
            duration_hours = (last_time - first_time).total_seconds() / 3600

        # Determine privilege levels
        roles = [g["role"] for g in grants]
        final_level = max(
            (self._get_role_severity(r) for r in roles),
            key=lambda x: {"critical": 4, "high": 3, "medium": 2, "low": 1}.get(x, 0),
            default="user"
        )

        # Determine if suspicious
        is_suspicious = (
            len(grants) >= 3  # Multiple grants
            or (len(granters) >= 2 and duration_hours <= 1)  # Multiple granters quickly
            or any(self._is_critical_role(g["role"]) for g in grants)  # Critical role
        )

        return PrivilegeChain(
            user_email=user_email,
            grants=grants,
            initial_privilege_level="user",
            final_privilege_level=final_level,
            chain_duration_hours=duration_hours,
            unique_granters=len(granters),
            is_suspicious=is_suspicious,
        )

    def _get_current_roles(
        self,
        grants: List[Dict[str, Any]],
        revocations: List[Dict[str, Any]],
    ) -> List[str]:
        """Determine current roles from grant/revocation history.

        Args:
            grants: List of grant events
            revocations: List of revocation events

        Returns:
            List of current role names
        """
        revoked_roles = set()
        for rev in revocations:
            revoked_roles.add(rev.get("role", ""))

        current = []
        for grant in grants:
            role = grant.get("role", "")
            if role and role not in revoked_roles:
                current.append(role)

        return list(set(current))

    def _calculate_privilege_level(self, roles: List[str]) -> str:
        """Calculate overall privilege level from roles.

        Args:
            roles: List of role names

        Returns:
            Highest privilege level
        """
        if not roles:
            return "user"

        levels = []
        for role in roles:
            severity = self._get_role_severity(role)
            levels.append(severity)

        level_order = {"critical": 4, "high": 3, "medium": 2, "low": 1}
        max_level = max(levels, key=lambda x: level_order.get(x, 0), default="low")

        return max_level

    def _find_first_admin_grant(
        self,
        grants: List[Dict[str, Any]],
    ) -> Optional[Dict[str, Any]]:
        """Find the first admin grant in a list.

        Args:
            grants: List of grant events

        Returns:
            First admin grant or None
        """
        for grant in grants:
            role = grant.get("role", "")
            if self._is_high_privilege_role(role):
                return grant
        return None

    def _create_admin_grant_alert(self, row: Dict[str, Any]) -> PrivilegeAlert:
        """Create alert for admin role grant.

        Args:
            row: Event data row

        Returns:
            PrivilegeAlert
        """
        role_name = row.get("role_name", "Unknown Role")
        actor_email = row.get("actor_email", "unknown")
        target_email = row.get("target_email", "unknown")
        provider = row.get("provider", "unknown")

        severity = self._get_role_severity(role_name, provider)

        return PrivilegeAlert(
            alert_id=str(uuid.uuid4()),
            alert_type=PrivilegeGrantType.ADMIN_GRANT,
            severity=severity,
            title=f"Admin Role Granted: {role_name} to {target_email}",
            description=(
                f"User {actor_email} granted the {role_name} role to "
                f"{target_email} on {provider}. This is a high-privilege "
                f"role that should be carefully controlled."
            ),
            actor_email=actor_email,
            target_email=target_email,
            role_granted=role_name,
            provider=provider,
            source_ip=row.get("source_ip", ""),
            source_country=row.get("source_geo_country", ""),
            event_time=self._parse_timestamp(row.get("event_timestamp")),
            evidence={
                "event_action": row.get("event_action", ""),
                "role_severity": severity,
            },
            mitre_techniques=["T1078.004", "T1098", "T1098.001"],
            recommended_actions=[
                f"Verify {actor_email} is authorized to grant admin roles",
                f"Confirm {target_email} has legitimate need for {role_name}",
                "Review if this was part of approved change process",
                "Check source IP and location for anomalies",
            ],
        )

    def _create_self_grant_alert(self, row: Dict[str, Any]) -> PrivilegeAlert:
        """Create alert for self-privilege grant.

        Args:
            row: Event data row

        Returns:
            PrivilegeAlert (always critical)
        """
        role_name = row.get("role_name", "Unknown Role")
        actor_email = row.get("actor_email", "unknown")
        provider = row.get("provider", "unknown")

        return PrivilegeAlert(
            alert_id=str(uuid.uuid4()),
            alert_type=PrivilegeGrantType.SELF_GRANT,
            severity="critical",  # Always critical
            title=f"CRITICAL: Self-Privilege Grant by {actor_email}",
            description=(
                f"User {actor_email} granted themselves the {role_name} role "
                f"on {provider}. Self-privilege grants should NEVER occur in "
                f"normal operations and indicate account compromise or insider threat."
            ),
            actor_email=actor_email,
            target_email=actor_email,
            role_granted=role_name,
            provider=provider,
            source_ip=row.get("source_ip", ""),
            source_country=row.get("source_geo_country", ""),
            event_time=self._parse_timestamp(row.get("event_timestamp")),
            evidence={
                "event_action": row.get("event_action", ""),
                "self_grant": True,
            },
            mitre_techniques=["T1078.004", "T1098", "T1548"],
            recommended_actions=[
                f"IMMEDIATELY lock the account {actor_email}",
                "Revoke all active sessions and tokens",
                "Remove the self-granted role",
                "Audit all actions by this user in past 24 hours",
                "Contact user through verified out-of-band channel",
                "Consider security incident declaration",
            ],
        )

    def _create_chain_alert(self, chain: PrivilegeChain) -> PrivilegeAlert:
        """Create alert for privilege escalation chain.

        Args:
            chain: PrivilegeChain analysis

        Returns:
            PrivilegeAlert
        """
        severity = chain.final_privilege_level
        if chain.unique_granters >= 2 and chain.chain_duration_hours <= 1:
            severity = "critical"  # Rapid multi-granter escalation

        return PrivilegeAlert(
            alert_id=str(uuid.uuid4()),
            alert_type=PrivilegeGrantType.PRIVILEGE_CHAIN,
            severity=severity,
            title=f"Privilege Escalation Chain: {chain.user_email}",
            description=(
                f"User {chain.user_email} received {len(chain.grants)} privilege "
                f"grants from {chain.unique_granters} different users within "
                f"{chain.chain_duration_hours:.1f} hours. Escalated from "
                f"{chain.initial_privilege_level} to {chain.final_privilege_level}."
            ),
            actor_email="multiple",
            target_email=chain.user_email,
            role_granted=", ".join(g["role"] for g in chain.grants),
            provider=", ".join(set(g["provider"] for g in chain.grants)),
            event_time=self._parse_timestamp(
                chain.grants[-1]["timestamp"] if chain.grants else None
            ),
            evidence={
                "grant_count": len(chain.grants),
                "unique_granters": chain.unique_granters,
                "duration_hours": chain.chain_duration_hours,
                "grants": chain.grants,
            },
            mitre_techniques=["T1078.004", "T1098", "T1548"],
            recommended_actions=[
                f"Review all {len(chain.grants)} privilege grants to {chain.user_email}",
                "Verify each grant was properly authorized",
                "Check if target user has legitimate need for all roles",
                "Audit actions of all users who granted privileges",
            ],
        )

    def _create_unusual_grant_alert(
        self,
        row: Dict[str, Any],
        anomalies: List[str],
    ) -> PrivilegeAlert:
        """Create alert for privilege grant with anomalies.

        Args:
            row: Event data row
            anomalies: List of detected anomalies

        Returns:
            PrivilegeAlert
        """
        role_name = row.get("role_name", "Unknown Role")
        actor_email = row.get("actor_email", "unknown")
        target_email = row.get("target_email", "unknown")
        provider = row.get("provider", "unknown")

        # Higher severity for more anomalies
        base_severity = self._get_role_severity(role_name, provider)
        if len(anomalies) >= 2 or "dormant_account_activated" in anomalies:
            severity = "critical"
        elif len(anomalies) >= 1:
            severity = "high" if base_severity != "critical" else "critical"
        else:
            severity = base_severity

        anomaly_desc = ", ".join(a.replace("_", " ") for a in anomalies)

        return PrivilegeAlert(
            alert_id=str(uuid.uuid4()),
            alert_type=PrivilegeGrantType.UNUSUAL_GRANT,
            severity=severity,
            title=f"Unusual Privilege Grant: {role_name} to {target_email}",
            description=(
                f"User {actor_email} granted {role_name} to {target_email} "
                f"on {provider} with unusual characteristics: {anomaly_desc}."
            ),
            actor_email=actor_email,
            target_email=target_email,
            role_granted=role_name,
            provider=provider,
            source_ip=row.get("source_ip", ""),
            source_country=row.get("source_geo_country", ""),
            event_time=self._parse_timestamp(row.get("event_timestamp")),
            evidence={
                "anomalies": anomalies,
                "event_action": row.get("event_action", ""),
            },
            mitre_techniques=["T1078.004", "T1098"],
            recommended_actions=[
                f"Verify the unusual circumstances: {anomaly_desc}",
                f"Contact {actor_email} to confirm authorization",
                "Review if this matches normal change management",
                "Check for other suspicious activity from same source",
            ],
        )

    def _create_new_admin_grant_alert(self, row: Dict[str, Any]) -> PrivilegeAlert:
        """Create alert for privilege grant by newly-created admin.

        Args:
            row: Event data row

        Returns:
            PrivilegeAlert
        """
        role_name = row.get("role_name", "Unknown Role")
        actor_email = row.get("actor_email", "unknown")
        target_email = row.get("target_email", "unknown")
        provider = row.get("provider", "unknown")

        return PrivilegeAlert(
            alert_id=str(uuid.uuid4()),
            alert_type=PrivilegeGrantType.NEW_ADMIN_GRANT,
            severity="high",
            title=f"New Admin Granting Privileges: {actor_email}",
            description=(
                f"User {actor_email}, who became an admin within the last "
                f"{self.NEW_ADMIN_THRESHOLD_HOURS} hours, is already granting "
                f"privileges ({role_name}) to {target_email}. This could indicate "
                f"the new admin account is compromised."
            ),
            actor_email=actor_email,
            target_email=target_email,
            role_granted=role_name,
            provider=provider,
            source_ip=row.get("source_ip", ""),
            source_country=row.get("source_geo_country", ""),
            event_time=self._parse_timestamp(row.get("event_timestamp")),
            evidence={
                "event_action": row.get("event_action", ""),
                "new_admin_threshold_hours": self.NEW_ADMIN_THRESHOLD_HOURS,
            },
            mitre_techniques=["T1078.004", "T1098"],
            recommended_actions=[
                f"Verify {actor_email} is a legitimate new admin",
                "Check how and when this account became admin",
                "Review all actions by this admin since elevation",
                "Confirm grants are part of authorized onboarding",
            ],
        )

    def _deduplicate_alerts(
        self,
        alerts: List[PrivilegeAlert],
    ) -> List[PrivilegeAlert]:
        """Deduplicate alerts with overlapping events.

        Args:
            alerts: List of alerts to deduplicate

        Returns:
            Deduplicated list
        """
        if not alerts:
            return []

        # Group by target email and role
        seen = {}
        for alert in alerts:
            key = (alert.target_email, alert.role_granted, alert.provider)

            if key not in seen:
                seen[key] = alert
            else:
                # Keep higher severity
                existing = seen[key]
                severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
                if severity_order.get(alert.severity, 4) < severity_order.get(
                    existing.severity, 4
                ):
                    seen[key] = alert

        return list(seen.values())

    def _parse_timestamp(self, ts: Any) -> Optional[datetime]:
        """Parse timestamp from query result.

        Args:
            ts: Timestamp value (string, datetime, or None)

        Returns:
            Parsed datetime or None
        """
        if ts is None:
            return None
        if isinstance(ts, datetime):
            return ts
        if isinstance(ts, str):
            try:
                return datetime.fromisoformat(ts.replace("Z", "+00:00"))
            except ValueError:
                return None
        return None
