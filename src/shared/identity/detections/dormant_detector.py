"""Dormant account activation detection for identity events.

Provides detection of dormant account activity including:
- Accounts inactive for 30+ days becoming active
- Dormant accounts using admin/privileged access
- Service accounts being reactivated
- Proactive dormant account listing for cleanup
"""

import logging
import re
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Set

logger = logging.getLogger(__name__)


class DormantAlertType(Enum):
    """Types of dormant account detections."""

    DORMANT_ACTIVATION = "dormant_activation"  # Inactive account became active
    DORMANT_PRIVILEGE = "dormant_privilege"  # Dormant account used privileges
    SERVICE_REACTIVATION = "service_reactivation"  # Service account reactivated


@dataclass
class DormantAlert:
    """Alert generated for detected dormant account activity.

    Attributes:
        alert_id: Unique identifier for this alert
        alert_type: Type of dormant account alert
        severity: Alert severity (critical, high, medium, low)
        title: Human-readable alert title
        description: Detailed description of the activity
        user_email: User/account email
        days_inactive: Number of days the account was inactive
        last_activity: Timestamp of last activity before dormancy
        current_activity: Timestamp of current activity
        provider: Identity provider
        source_ip: IP address of current activity
        source_country: Country of current activity
        is_service_account: Whether this is a service account
        is_admin_account: Whether this is an admin account
        event_time: When the event occurred
        evidence: Additional evidence data
        mitre_techniques: Associated MITRE ATT&CK techniques
        recommended_actions: Suggested response actions
    """

    alert_id: str
    alert_type: DormantAlertType
    severity: str
    title: str
    description: str
    user_email: str = ""
    days_inactive: int = 0
    last_activity: Optional[datetime] = None
    current_activity: Optional[datetime] = None
    provider: str = ""
    source_ip: str = ""
    source_country: str = ""
    is_service_account: bool = False
    is_admin_account: bool = False
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
            "user_email": self.user_email,
            "days_inactive": self.days_inactive,
            "last_activity": self.last_activity.isoformat() if self.last_activity else None,
            "current_activity": self.current_activity.isoformat() if self.current_activity else None,
            "provider": self.provider,
            "source_ip": self.source_ip,
            "source_country": self.source_country,
            "is_service_account": self.is_service_account,
            "is_admin_account": self.is_admin_account,
            "event_time": self.event_time.isoformat() if self.event_time else None,
            "evidence": self.evidence,
            "mitre_techniques": self.mitre_techniques,
            "recommended_actions": self.recommended_actions,
            "detected_at": self.detected_at.isoformat(),
        }


class DormantAccountDetector:
    """Detects dormant account activation across identity providers.

    Implements detection for:
    1. Dormant account activation (30+ days inactive)
    2. Dormant accounts using privileged access
    3. Service account reactivation
    4. Proactive dormant account listing

    Attributes:
        query_executor: Executor for querying identity events
        baseline_store: Store for user baselines
        DORMANT_THRESHOLD_DAYS: Default dormancy threshold
    """

    # Default dormancy thresholds
    DORMANT_THRESHOLD_DAYS = 30
    ADMIN_DORMANT_THRESHOLD_DAYS = 14
    SERVICE_ACCOUNT_DORMANT_DAYS = 7

    # Service account naming patterns
    SERVICE_ACCOUNT_PATTERNS: List[str] = [
        r"^svc[_\-]",
        r"^service[_\-]",
        r"^srv[_\-]",
        r"^bot[_\-]",
        r"automation",
        r"^system@",
        r"noreply",
        r"^api[_\-]",
        r"^app[_\-]",
        r"@service\.",
        r"^scheduled[_\-]",
        r"^cron[_\-]",
        r"^batch[_\-]",
    ]

    # Admin account indicators
    ADMIN_INDICATORS: Set[str] = {
        "admin",
        "administrator",
        "root",
        "superuser",
        "operator",
        "sysadmin",
    }

    def __init__(
        self,
        query_executor: Any,
        baseline_store: Any = None,
        identity_events_table: str = "identity_events",
        dormant_threshold_days: int = None,
    ):
        """Initialize the dormant account detector.

        Args:
            query_executor: Executor for querying the data lake
            baseline_store: Optional store for user baselines
            identity_events_table: Name of the identity events table
            dormant_threshold_days: Override for dormancy threshold
        """
        self.query_executor = query_executor
        self.baseline_store = baseline_store
        self.identity_events_table = identity_events_table

        if dormant_threshold_days is not None:
            self.DORMANT_THRESHOLD_DAYS = dormant_threshold_days

        # Compile service account patterns
        self._service_patterns = [
            re.compile(pattern, re.IGNORECASE)
            for pattern in self.SERVICE_ACCOUNT_PATTERNS
        ]

    def detect_dormant_activation(
        self,
        window_hours: int = 24,
    ) -> List[DormantAlert]:
        """Detect dormant accounts that have become active.

        Finds all successful authentications in the window and checks
        if the account was dormant (no activity for threshold days).

        Args:
            window_hours: Detection window in hours

        Returns:
            List of DormantAlert for activated dormant accounts
        """
        alerts = []

        cutoff = datetime.now(timezone.utc) - timedelta(hours=window_hours)
        cutoff_str = cutoff.strftime("%Y-%m-%d %H:%M:%S")

        # Get all successful authentications in window
        query = f"""
            SELECT DISTINCT
                user_email,
                source_ip,
                source_geo_country,
                source_geo_city,
                device_fingerprint,
                user_agent,
                provider,
                MIN(event_timestamp) as first_activity
            FROM {self.identity_events_table}
            WHERE event_type = 'AUTH_SUCCESS'
              AND event_timestamp >= TIMESTAMP '{cutoff_str}'
              AND user_email IS NOT NULL
              AND user_email != ''
            GROUP BY user_email, source_ip, source_geo_country, source_geo_city,
                     device_fingerprint, user_agent, provider
            ORDER BY first_activity ASC
            LIMIT 1000
        """

        try:
            result = self.query_executor.execute_query(query, timeout_seconds=120)

            # Check each user for dormancy
            checked_users = set()
            for row in result.rows:
                user_email = row.get("user_email", "")

                # Skip if already checked
                if user_email.lower() in checked_users:
                    continue
                checked_users.add(user_email.lower())

                # Get last activity before the current window
                last_activity = self.get_last_activity(user_email, cutoff)

                if last_activity is None:
                    # Never seen before - treat as dormant (first time access)
                    # But with lower confidence
                    continue

                # Calculate days inactive
                days_inactive = (cutoff - last_activity).days

                # Determine appropriate threshold
                is_service = self._is_service_account(user_email)
                is_admin = self._is_admin_account(user_email)

                if is_service:
                    threshold = self.SERVICE_ACCOUNT_DORMANT_DAYS
                elif is_admin:
                    threshold = self.ADMIN_DORMANT_THRESHOLD_DAYS
                else:
                    threshold = self.DORMANT_THRESHOLD_DAYS

                if days_inactive >= threshold:
                    # Account is dormant - generate alert
                    current_time = row.get("first_activity")
                    if isinstance(current_time, str):
                        current_time = datetime.fromisoformat(
                            current_time.replace("Z", "+00:00")
                        )

                    alert = self._create_dormant_activation_alert(
                        row, days_inactive, last_activity, current_time,
                        is_service, is_admin
                    )
                    alerts.append(alert)

        except Exception as e:
            logger.error(f"Error detecting dormant activation: {e}")

        return alerts

    def get_last_activity(
        self,
        user_email: str,
        before_time: datetime = None,
    ) -> Optional[datetime]:
        """Get the most recent activity for a user before a given time.

        Args:
            user_email: User email to check
            before_time: Only look for activity before this time

        Returns:
            Timestamp of last activity or None if never seen
        """
        if before_time is None:
            before_time = datetime.now(timezone.utc)

        before_str = before_time.strftime("%Y-%m-%d %H:%M:%S")

        query = f"""
            SELECT MAX(event_timestamp) as last_activity
            FROM {self.identity_events_table}
            WHERE LOWER(user_email) = LOWER('{user_email}')
              AND event_timestamp < TIMESTAMP '{before_str}'
        """

        try:
            result = self.query_executor.execute_query(query, timeout_seconds=30)

            if result.rows and result.rows[0].get("last_activity"):
                last = result.rows[0]["last_activity"]
                if isinstance(last, str):
                    return datetime.fromisoformat(last.replace("Z", "+00:00"))
                return last

        except Exception as e:
            logger.error(f"Error getting last activity for {user_email}: {e}")

        return None

    def is_dormant_account(
        self,
        user_email: str,
        threshold_days: int = None,
    ) -> bool:
        """Check if an account qualifies as dormant.

        Args:
            user_email: User email to check
            threshold_days: Override for dormancy threshold

        Returns:
            True if account is dormant
        """
        threshold = threshold_days or self.DORMANT_THRESHOLD_DAYS

        # Adjust threshold based on account type
        if self._is_service_account(user_email):
            threshold = min(threshold, self.SERVICE_ACCOUNT_DORMANT_DAYS)
        elif self._is_admin_account(user_email):
            threshold = min(threshold, self.ADMIN_DORMANT_THRESHOLD_DAYS)

        last_activity = self.get_last_activity(user_email)

        if last_activity is None:
            # Never seen - could be new or truly dormant
            return False  # Conservative: don't flag unknown accounts

        days_inactive = (datetime.now(timezone.utc) - last_activity).days
        return days_inactive >= threshold

    def detect_dormant_account_privilege_use(
        self,
        window_hours: int = 24,
    ) -> List[DormantAlert]:
        """Detect dormant accounts using admin/privileged access.

        This is critical severity - dormant accounts should not
        suddenly need privileged access.

        Args:
            window_hours: Detection window in hours

        Returns:
            List of DormantAlert for privileged dormant account usage
        """
        alerts = []

        cutoff = datetime.now(timezone.utc) - timedelta(hours=window_hours)
        cutoff_str = cutoff.strftime("%Y-%m-%d %H:%M:%S")

        # Look for privilege-related events
        query = f"""
            SELECT
                user_email,
                event_type,
                event_action,
                role_name,
                source_ip,
                source_geo_country,
                provider,
                event_timestamp
            FROM {self.identity_events_table}
            WHERE event_type IN ('PRIVILEGE_GRANT', 'ADMIN_ACTION', 'PRIVILEGE_USE',
                                 'ROLE_CHANGE', 'POLICY_CHANGE')
              AND event_timestamp >= TIMESTAMP '{cutoff_str}'
              AND user_email IS NOT NULL
              AND user_email != ''
            ORDER BY event_timestamp DESC
            LIMIT 500
        """

        try:
            result = self.query_executor.execute_query(query, timeout_seconds=120)

            checked_users = set()
            for row in result.rows:
                user_email = row.get("user_email", "")

                if user_email.lower() in checked_users:
                    continue
                checked_users.add(user_email.lower())

                # Check if account was dormant
                last_activity = self.get_last_activity(user_email, cutoff)

                if last_activity is None:
                    continue

                days_inactive = (cutoff - last_activity).days

                if days_inactive >= self.DORMANT_THRESHOLD_DAYS:
                    current_time = row.get("event_timestamp")
                    if isinstance(current_time, str):
                        current_time = datetime.fromisoformat(
                            current_time.replace("Z", "+00:00")
                        )

                    alert = self._create_dormant_privilege_alert(
                        row, days_inactive, last_activity, current_time
                    )
                    alerts.append(alert)

        except Exception as e:
            logger.error(f"Error detecting dormant privilege use: {e}")

        return alerts

    def detect_service_account_reactivation(
        self,
        window_hours: int = 24,
    ) -> List[DormantAlert]:
        """Detect service accounts being reactivated after dormancy.

        Service accounts have predictable patterns - unexpected
        reactivation may indicate lateral movement.

        Args:
            window_hours: Detection window in hours

        Returns:
            List of DormantAlert for reactivated service accounts
        """
        alerts = []

        cutoff = datetime.now(timezone.utc) - timedelta(hours=window_hours)
        cutoff_str = cutoff.strftime("%Y-%m-%d %H:%M:%S")

        # Get activity from service accounts
        query = f"""
            SELECT DISTINCT
                user_email,
                source_ip,
                source_geo_country,
                provider,
                event_type,
                event_action,
                application_name,
                MIN(event_timestamp) as first_activity
            FROM {self.identity_events_table}
            WHERE event_type IN ('AUTH_SUCCESS', 'API_CALL', 'TOKEN_USED')
              AND event_timestamp >= TIMESTAMP '{cutoff_str}'
              AND user_email IS NOT NULL
              AND user_email != ''
            GROUP BY user_email, source_ip, source_geo_country, provider,
                     event_type, event_action, application_name
            ORDER BY first_activity ASC
            LIMIT 1000
        """

        try:
            result = self.query_executor.execute_query(query, timeout_seconds=120)

            checked_users = set()
            for row in result.rows:
                user_email = row.get("user_email", "")

                # Only check service accounts
                if not self._is_service_account(user_email):
                    continue

                if user_email.lower() in checked_users:
                    continue
                checked_users.add(user_email.lower())

                # Check for dormancy
                last_activity = self.get_last_activity(user_email, cutoff)

                if last_activity is None:
                    continue

                days_inactive = (cutoff - last_activity).days

                if days_inactive >= self.SERVICE_ACCOUNT_DORMANT_DAYS:
                    current_time = row.get("first_activity")
                    if isinstance(current_time, str):
                        current_time = datetime.fromisoformat(
                            current_time.replace("Z", "+00:00")
                        )

                    alert = self._create_service_reactivation_alert(
                        row, days_inactive, last_activity, current_time
                    )
                    alerts.append(alert)

        except Exception as e:
            logger.error(f"Error detecting service account reactivation: {e}")

        return alerts

    def get_dormant_accounts_list(
        self,
        threshold_days: int = None,
    ) -> List[str]:
        """Get list of all dormant accounts for proactive review.

        Returns all accounts that have not had activity within
        the threshold period. Useful for account cleanup.

        Args:
            threshold_days: Override for dormancy threshold

        Returns:
            List of dormant account emails
        """
        threshold = threshold_days or self.DORMANT_THRESHOLD_DAYS
        cutoff = datetime.now(timezone.utc) - timedelta(days=threshold)
        cutoff_str = cutoff.strftime("%Y-%m-%d %H:%M:%S")

        # Find users with activity, then invert
        # Get all known users and their last activity
        query = f"""
            SELECT
                user_email,
                MAX(event_timestamp) as last_activity
            FROM {self.identity_events_table}
            WHERE user_email IS NOT NULL
              AND user_email != ''
            GROUP BY user_email
            HAVING MAX(event_timestamp) < TIMESTAMP '{cutoff_str}'
            ORDER BY last_activity ASC
            LIMIT 10000
        """

        dormant_accounts = []

        try:
            result = self.query_executor.execute_query(query, timeout_seconds=180)

            for row in result.rows:
                user_email = row.get("user_email", "")
                if user_email:
                    dormant_accounts.append(user_email)

        except Exception as e:
            logger.error(f"Error getting dormant accounts list: {e}")

        return dormant_accounts

    def get_dormant_accounts_details(
        self,
        threshold_days: int = None,
    ) -> List[Dict[str, Any]]:
        """Get detailed information about dormant accounts.

        Args:
            threshold_days: Override for dormancy threshold

        Returns:
            List of dictionaries with dormant account details
        """
        threshold = threshold_days or self.DORMANT_THRESHOLD_DAYS
        cutoff = datetime.now(timezone.utc) - timedelta(days=threshold)
        cutoff_str = cutoff.strftime("%Y-%m-%d %H:%M:%S")

        query = f"""
            SELECT
                user_email,
                MAX(event_timestamp) as last_activity,
                COUNT(*) as total_events,
                ARRAY_AGG(DISTINCT provider) as providers
            FROM {self.identity_events_table}
            WHERE user_email IS NOT NULL
              AND user_email != ''
            GROUP BY user_email
            HAVING MAX(event_timestamp) < TIMESTAMP '{cutoff_str}'
            ORDER BY last_activity ASC
            LIMIT 1000
        """

        dormant_details = []

        try:
            result = self.query_executor.execute_query(query, timeout_seconds=180)

            now = datetime.now(timezone.utc)

            for row in result.rows:
                user_email = row.get("user_email", "")
                last_activity = row.get("last_activity")

                if isinstance(last_activity, str):
                    last_activity = datetime.fromisoformat(
                        last_activity.replace("Z", "+00:00")
                    )

                days_inactive = (now - last_activity).days if last_activity else 0

                dormant_details.append({
                    "user_email": user_email,
                    "last_activity": last_activity.isoformat() if last_activity else None,
                    "days_inactive": days_inactive,
                    "total_events": row.get("total_events", 0),
                    "providers": row.get("providers", []),
                    "is_service_account": self._is_service_account(user_email),
                    "is_admin_account": self._is_admin_account(user_email),
                })

        except Exception as e:
            logger.error(f"Error getting dormant account details: {e}")

        return dormant_details

    def run_all_detections(
        self,
        window_hours: int = 24,
    ) -> List[DormantAlert]:
        """Run all dormant account detection methods.

        Args:
            window_hours: Detection window in hours

        Returns:
            Combined list of all alerts
        """
        all_alerts = []

        # Dormant activation detection
        activation_alerts = self.detect_dormant_activation(window_hours)
        all_alerts.extend(activation_alerts)

        # Dormant privilege use detection
        privilege_alerts = self.detect_dormant_account_privilege_use(window_hours)
        all_alerts.extend(privilege_alerts)

        # Service account reactivation
        service_alerts = self.detect_service_account_reactivation(window_hours)
        all_alerts.extend(service_alerts)

        # Deduplicate by user email
        seen_users = set()
        unique_alerts = []
        for alert in all_alerts:
            key = (alert.user_email, alert.alert_type.value)
            if key not in seen_users:
                seen_users.add(key)
                unique_alerts.append(alert)

        # Sort by severity
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        unique_alerts.sort(
            key=lambda a: (severity_order.get(a.severity, 4), -a.days_inactive)
        )

        return unique_alerts

    def _is_service_account(self, email: str) -> bool:
        """Check if an email appears to be a service account.

        Args:
            email: Email to check

        Returns:
            True if appears to be service account
        """
        if not email:
            return False

        for pattern in self._service_patterns:
            if pattern.search(email):
                return True

        return False

    def _is_admin_account(self, email: str) -> bool:
        """Check if an email appears to be an admin account.

        Args:
            email: Email to check

        Returns:
            True if appears to be admin account
        """
        if not email:
            return False

        email_lower = email.lower()
        for indicator in self.ADMIN_INDICATORS:
            if indicator in email_lower:
                return True

        return False

    def _create_dormant_activation_alert(
        self,
        row: Dict[str, Any],
        days_inactive: int,
        last_activity: datetime,
        current_activity: datetime,
        is_service: bool,
        is_admin: bool,
    ) -> DormantAlert:
        """Create alert for dormant account activation.

        Args:
            row: Event data row
            days_inactive: Days of inactivity
            last_activity: Last activity timestamp
            current_activity: Current activity timestamp
            is_service: Whether service account
            is_admin: Whether admin account

        Returns:
            DormantAlert
        """
        user_email = row.get("user_email", "unknown")

        # Determine severity
        if is_admin or is_service:
            severity = "critical"
        elif days_inactive >= 90:
            severity = "critical"
        elif days_inactive >= 60:
            severity = "high"
        else:
            severity = "high"

        account_type = "Service account" if is_service else (
            "Admin account" if is_admin else "Account"
        )

        return DormantAlert(
            alert_id=str(uuid.uuid4()),
            alert_type=DormantAlertType.DORMANT_ACTIVATION,
            severity=severity,
            title=f"Dormant {account_type} Activated: {user_email}",
            description=(
                f"{account_type} {user_email} became active after {days_inactive} days "
                f"of inactivity. Last seen on {last_activity.strftime('%Y-%m-%d')}. "
                f"Current activity from {row.get('source_geo_country', 'unknown')} "
                f"({row.get('source_ip', 'unknown')})."
            ),
            user_email=user_email,
            days_inactive=days_inactive,
            last_activity=last_activity,
            current_activity=current_activity,
            provider=row.get("provider", "unknown"),
            source_ip=row.get("source_ip", ""),
            source_country=row.get("source_geo_country", ""),
            is_service_account=is_service,
            is_admin_account=is_admin,
            event_time=current_activity,
            evidence={
                "source_city": row.get("source_geo_city"),
                "device_fingerprint": row.get("device_fingerprint"),
                "user_agent": row.get("user_agent"),
            },
            mitre_techniques=["T1078", "T1078.004"],
            recommended_actions=[
                f"Verify {user_email} through out-of-band communication",
                "Check if user returned from leave or had reason for inactivity",
                "Review source IP and location for anomalies",
                "Check device fingerprint against known devices",
                "If unverified, suspend account immediately",
                "Force password reset before re-enabling",
            ],
        )

    def _create_dormant_privilege_alert(
        self,
        row: Dict[str, Any],
        days_inactive: int,
        last_activity: datetime,
        current_activity: datetime,
    ) -> DormantAlert:
        """Create alert for dormant account privilege use.

        Args:
            row: Event data row
            days_inactive: Days of inactivity
            last_activity: Last activity timestamp
            current_activity: Current activity timestamp

        Returns:
            DormantAlert (always critical)
        """
        user_email = row.get("user_email", "unknown")

        return DormantAlert(
            alert_id=str(uuid.uuid4()),
            alert_type=DormantAlertType.DORMANT_PRIVILEGE,
            severity="critical",  # Always critical
            title=f"CRITICAL: Dormant Account Using Privileges: {user_email}",
            description=(
                f"Account {user_email} was dormant for {days_inactive} days and "
                f"is now using privileged access. Event: {row.get('event_action', 'unknown')}. "
                f"This is a critical indicator of compromise."
            ),
            user_email=user_email,
            days_inactive=days_inactive,
            last_activity=last_activity,
            current_activity=current_activity,
            provider=row.get("provider", "unknown"),
            source_ip=row.get("source_ip", ""),
            source_country=row.get("source_geo_country", ""),
            is_admin_account=True,  # Using privileges implies admin context
            event_time=current_activity,
            evidence={
                "event_type": row.get("event_type"),
                "event_action": row.get("event_action"),
                "role_name": row.get("role_name"),
            },
            mitre_techniques=["T1078", "T1078.004", "T1098"],
            recommended_actions=[
                "IMMEDIATELY suspend the account",
                "Terminate all active sessions",
                "Audit all actions taken by the account",
                "Check for privilege grants or policy changes",
                "Review for data exfiltration",
                "Initiate incident response procedures",
            ],
        )

    def _create_service_reactivation_alert(
        self,
        row: Dict[str, Any],
        days_inactive: int,
        last_activity: datetime,
        current_activity: datetime,
    ) -> DormantAlert:
        """Create alert for service account reactivation.

        Args:
            row: Event data row
            days_inactive: Days of inactivity
            last_activity: Last activity timestamp
            current_activity: Current activity timestamp

        Returns:
            DormantAlert
        """
        user_email = row.get("user_email", "unknown")

        # Critical if from unexpected IP
        severity = "high"
        if days_inactive >= 30:
            severity = "critical"

        return DormantAlert(
            alert_id=str(uuid.uuid4()),
            alert_type=DormantAlertType.SERVICE_REACTIVATION,
            severity=severity,
            title=f"Service Account Reactivated: {user_email}",
            description=(
                f"Service account {user_email} reactivated after {days_inactive} days. "
                f"Activity from {row.get('source_ip', 'unknown')} "
                f"({row.get('source_geo_country', 'unknown')}). "
                f"Application: {row.get('application_name', 'unknown')}."
            ),
            user_email=user_email,
            days_inactive=days_inactive,
            last_activity=last_activity,
            current_activity=current_activity,
            provider=row.get("provider", "unknown"),
            source_ip=row.get("source_ip", ""),
            source_country=row.get("source_geo_country", ""),
            is_service_account=True,
            event_time=current_activity,
            evidence={
                "event_type": row.get("event_type"),
                "event_action": row.get("event_action"),
                "application_name": row.get("application_name"),
            },
            mitre_techniques=["T1078.001", "T1078.004"],
            recommended_actions=[
                "Identify the service account owner/team",
                "Verify if reactivation is expected",
                "Check if source IP matches known infrastructure",
                "Review operations performed",
                "If unexpected, disable immediately",
                "Rotate service account credentials",
            ],
        )
