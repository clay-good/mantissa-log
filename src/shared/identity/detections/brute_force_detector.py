"""Brute force attack detection for identity events.

Provides cross-provider detection of brute force attacks including:
- Single user brute force (targeted attack)
- Distributed brute force / password spray (multiple users from same IP)
- Cross-provider brute force (same user targeted across multiple IdPs)
"""

import logging
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


class BruteForceType(Enum):
    """Types of brute force attacks detected."""

    SINGLE_USER = "single_user"  # Targeted attack on one user
    DISTRIBUTED = "distributed"  # Password spray across many users
    CROSS_PROVIDER = "cross_provider"  # Attack spanning multiple IdPs


@dataclass
class BruteForceAlert:
    """Alert generated for detected brute force attack.

    Attributes:
        alert_id: Unique identifier for this alert
        alert_type: Type of brute force attack
        severity: Alert severity (critical, high, medium, low)
        title: Human-readable alert title
        description: Detailed description of the attack
        user_emails: List of targeted user email addresses
        source_ips: List of source IP addresses involved
        providers: List of identity providers involved
        failure_count: Total number of failed authentication attempts
        time_window_minutes: Detection time window
        first_event_time: Timestamp of first event in window
        last_event_time: Timestamp of last event in window
        evidence: Additional evidence data
        mitre_techniques: Associated MITRE ATT&CK techniques
        recommended_actions: Suggested response actions
    """

    alert_id: str
    alert_type: BruteForceType
    severity: str
    title: str
    description: str
    user_emails: List[str] = field(default_factory=list)
    source_ips: List[str] = field(default_factory=list)
    providers: List[str] = field(default_factory=list)
    failure_count: int = 0
    time_window_minutes: int = 15
    first_event_time: Optional[datetime] = None
    last_event_time: Optional[datetime] = None
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
            "user_emails": self.user_emails,
            "source_ips": self.source_ips,
            "providers": self.providers,
            "failure_count": self.failure_count,
            "time_window_minutes": self.time_window_minutes,
            "first_event_time": self.first_event_time.isoformat() if self.first_event_time else None,
            "last_event_time": self.last_event_time.isoformat() if self.last_event_time else None,
            "evidence": self.evidence,
            "mitre_techniques": self.mitre_techniques,
            "recommended_actions": self.recommended_actions,
            "detected_at": self.detected_at.isoformat(),
        }


class BruteForceDetector:
    """Detects brute force attacks across identity providers.

    Implements three detection methods:
    1. Single user brute force: 5+ failures for same user in 15 minutes
    2. Distributed brute force: 10+ users from same IP in 15 minutes
    3. Cross-provider brute force: 3+ failures across 2+ providers in 15 minutes

    Attributes:
        query_executor: Executor for querying identity events
        SINGLE_USER_THRESHOLD: Minimum failures to trigger single user alert
        DISTRIBUTED_THRESHOLD: Minimum unique users for distributed alert
        CROSS_PROVIDER_THRESHOLD: Minimum failures for cross-provider alert
        DEFAULT_WINDOW_MINUTES: Default time window for detection
    """

    # Detection thresholds
    SINGLE_USER_THRESHOLD = 5
    DISTRIBUTED_THRESHOLD = 10
    CROSS_PROVIDER_THRESHOLD = 3
    CROSS_PROVIDER_MIN_PROVIDERS = 2
    DEFAULT_WINDOW_MINUTES = 15

    def __init__(
        self,
        query_executor: Any,
        identity_events_table: str = "identity_events",
        single_user_threshold: int = None,
        distributed_threshold: int = None,
        cross_provider_threshold: int = None,
    ):
        """Initialize the brute force detector.

        Args:
            query_executor: Executor for querying the data lake
            identity_events_table: Name of the identity events table
            single_user_threshold: Override for single user threshold
            distributed_threshold: Override for distributed threshold
            cross_provider_threshold: Override for cross-provider threshold
        """
        self.query_executor = query_executor
        self.identity_events_table = identity_events_table

        if single_user_threshold is not None:
            self.SINGLE_USER_THRESHOLD = single_user_threshold
        if distributed_threshold is not None:
            self.DISTRIBUTED_THRESHOLD = distributed_threshold
        if cross_provider_threshold is not None:
            self.CROSS_PROVIDER_THRESHOLD = cross_provider_threshold

    def detect_single_user_brute_force(
        self,
        user_email: str = None,
        window_minutes: int = None,
    ) -> List[BruteForceAlert]:
        """Detect brute force attacks targeting individual users.

        Finds users with failure count above threshold within the time window.
        If user_email is provided, checks only that specific user.

        Args:
            user_email: Optional specific user to check
            window_minutes: Detection window in minutes

        Returns:
            List of BruteForceAlert for each user above threshold
        """
        window = window_minutes or self.DEFAULT_WINDOW_MINUTES
        alerts = []

        cutoff = datetime.now(timezone.utc) - timedelta(minutes=window)
        cutoff_str = cutoff.strftime("%Y-%m-%d %H:%M:%S")

        # Build query
        user_filter = ""
        if user_email:
            user_filter = f"AND user_email = '{user_email}'"

        query = f"""
            SELECT
                user_email,
                COUNT(*) as failure_count,
                ARRAY_AGG(DISTINCT source_ip) as source_ips,
                ARRAY_AGG(DISTINCT provider) as providers,
                MIN(event_timestamp) as first_event,
                MAX(event_timestamp) as last_event,
                ARRAY_AGG(DISTINCT failure_reason) as failure_reasons
            FROM {self.identity_events_table}
            WHERE event_type = 'AUTH_FAILURE'
              AND event_timestamp >= TIMESTAMP '{cutoff_str}'
              {user_filter}
            GROUP BY user_email
            HAVING COUNT(*) >= {self.SINGLE_USER_THRESHOLD}
            ORDER BY failure_count DESC
            LIMIT 100
        """

        try:
            result = self.query_executor.execute_query(query, timeout_seconds=120)

            for row in result.rows:
                alert = self._create_single_user_alert(row, window)
                alerts.append(alert)

        except Exception as e:
            logger.error(f"Error detecting single user brute force: {e}")

        return alerts

    def detect_distributed_brute_force(
        self,
        window_minutes: int = None,
    ) -> List[BruteForceAlert]:
        """Detect password spray attacks targeting multiple users from same IP.

        Finds IPs that have attempted authentication for many different users,
        which indicates a password spray attack.

        Args:
            window_minutes: Detection window in minutes

        Returns:
            List of BruteForceAlert for each IP above threshold
        """
        window = window_minutes or self.DEFAULT_WINDOW_MINUTES
        alerts = []

        cutoff = datetime.now(timezone.utc) - timedelta(minutes=window)
        cutoff_str = cutoff.strftime("%Y-%m-%d %H:%M:%S")

        query = f"""
            SELECT
                source_ip,
                COUNT(DISTINCT user_email) as unique_users,
                COUNT(*) as total_attempts,
                ARRAY_AGG(DISTINCT user_email) as user_emails,
                ARRAY_AGG(DISTINCT provider) as providers,
                MIN(event_timestamp) as first_event,
                MAX(event_timestamp) as last_event
            FROM {self.identity_events_table}
            WHERE event_type = 'AUTH_FAILURE'
              AND event_timestamp >= TIMESTAMP '{cutoff_str}'
              AND source_ip IS NOT NULL
              AND source_ip != ''
            GROUP BY source_ip
            HAVING COUNT(DISTINCT user_email) >= {self.DISTRIBUTED_THRESHOLD}
            ORDER BY unique_users DESC
            LIMIT 100
        """

        try:
            result = self.query_executor.execute_query(query, timeout_seconds=120)

            for row in result.rows:
                alert = self._create_distributed_alert(row, window)
                alerts.append(alert)

        except Exception as e:
            logger.error(f"Error detecting distributed brute force: {e}")

        return alerts

    def detect_cross_provider_brute_force(
        self,
        window_minutes: int = None,
    ) -> List[BruteForceAlert]:
        """Detect brute force attacks spanning multiple identity providers.

        Finds users with authentication failures across 2+ providers,
        indicating an attacker is trying the same credentials across systems.

        Args:
            window_minutes: Detection window in minutes

        Returns:
            List of BruteForceAlert for each cross-provider attack
        """
        window = window_minutes or self.DEFAULT_WINDOW_MINUTES
        alerts = []

        cutoff = datetime.now(timezone.utc) - timedelta(minutes=window)
        cutoff_str = cutoff.strftime("%Y-%m-%d %H:%M:%S")

        query = f"""
            SELECT
                user_email,
                COUNT(*) as failure_count,
                COUNT(DISTINCT provider) as provider_count,
                ARRAY_AGG(DISTINCT provider) as providers,
                ARRAY_AGG(DISTINCT source_ip) as source_ips,
                MIN(event_timestamp) as first_event,
                MAX(event_timestamp) as last_event
            FROM {self.identity_events_table}
            WHERE event_type = 'AUTH_FAILURE'
              AND event_timestamp >= TIMESTAMP '{cutoff_str}'
            GROUP BY user_email
            HAVING COUNT(DISTINCT provider) >= {self.CROSS_PROVIDER_MIN_PROVIDERS}
               AND COUNT(*) >= {self.CROSS_PROVIDER_THRESHOLD}
            ORDER BY provider_count DESC, failure_count DESC
            LIMIT 100
        """

        try:
            result = self.query_executor.execute_query(query, timeout_seconds=120)

            for row in result.rows:
                alert = self._create_cross_provider_alert(row, window)
                alerts.append(alert)

        except Exception as e:
            logger.error(f"Error detecting cross-provider brute force: {e}")

        return alerts

    def run_all_detections(
        self,
        window_minutes: int = None,
    ) -> List[BruteForceAlert]:
        """Run all brute force detection methods.

        Executes single user, distributed, and cross-provider detection,
        then deduplicates overlapping alerts.

        Args:
            window_minutes: Detection window in minutes

        Returns:
            Combined and deduplicated list of alerts
        """
        window = window_minutes or self.DEFAULT_WINDOW_MINUTES
        all_alerts = []

        # Run all detection methods
        single_user_alerts = self.detect_single_user_brute_force(
            window_minutes=window
        )
        all_alerts.extend(single_user_alerts)

        distributed_alerts = self.detect_distributed_brute_force(
            window_minutes=window
        )
        all_alerts.extend(distributed_alerts)

        cross_provider_alerts = self.detect_cross_provider_brute_force(
            window_minutes=window
        )
        all_alerts.extend(cross_provider_alerts)

        # Deduplicate by user/IP overlap
        deduplicated = self._deduplicate_alerts(all_alerts)

        # Sort by severity
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        deduplicated.sort(
            key=lambda a: (severity_order.get(a.severity, 4), -a.failure_count)
        )

        return deduplicated

    def _create_single_user_alert(
        self, row: Dict[str, Any], window_minutes: int
    ) -> BruteForceAlert:
        """Create alert for single user brute force detection.

        Args:
            row: Query result row
            window_minutes: Detection window

        Returns:
            BruteForceAlert
        """
        user_email = row.get("user_email", "unknown")
        failure_count = row.get("failure_count", 0)
        source_ips = row.get("source_ips", [])
        providers = row.get("providers", [])
        failure_reasons = row.get("failure_reasons", [])

        # Determine severity based on failure count
        if failure_count >= 20:
            severity = "critical"
        elif failure_count >= 10:
            severity = "high"
        else:
            severity = "medium"

        return BruteForceAlert(
            alert_id=str(uuid.uuid4()),
            alert_type=BruteForceType.SINGLE_USER,
            severity=severity,
            title=f"Brute Force Attack: {failure_count} failures for {user_email}",
            description=(
                f"Detected {failure_count} authentication failures for user "
                f"{user_email} within {window_minutes} minutes. "
                f"Source IPs: {', '.join(source_ips[:5])}. "
                f"This may indicate a targeted credential attack."
            ),
            user_emails=[user_email],
            source_ips=source_ips if isinstance(source_ips, list) else [source_ips],
            providers=providers if isinstance(providers, list) else [providers],
            failure_count=failure_count,
            time_window_minutes=window_minutes,
            first_event_time=self._parse_timestamp(row.get("first_event")),
            last_event_time=self._parse_timestamp(row.get("last_event")),
            evidence={
                "failure_reasons": failure_reasons,
                "unique_ips": len(source_ips) if isinstance(source_ips, list) else 1,
            },
            mitre_techniques=["T1110.001"],  # Password Guessing
            recommended_actions=[
                f"Review account status for {user_email}",
                "Check source IPs against threat intelligence",
                "Consider temporary account lockout",
                "Verify if attack coincides with known credential leaks",
            ],
        )

    def _create_distributed_alert(
        self, row: Dict[str, Any], window_minutes: int
    ) -> BruteForceAlert:
        """Create alert for distributed brute force / password spray detection.

        Args:
            row: Query result row
            window_minutes: Detection window

        Returns:
            BruteForceAlert
        """
        source_ip = row.get("source_ip", "unknown")
        unique_users = row.get("unique_users", 0)
        total_attempts = row.get("total_attempts", 0)
        user_emails = row.get("user_emails", [])
        providers = row.get("providers", [])

        return BruteForceAlert(
            alert_id=str(uuid.uuid4()),
            alert_type=BruteForceType.DISTRIBUTED,
            severity="critical",  # Password spray is always critical
            title=f"Password Spray Attack: {unique_users} users from {source_ip}",
            description=(
                f"Detected password spray attack from IP {source_ip} targeting "
                f"{unique_users} unique user accounts with {total_attempts} total "
                f"attempts in {window_minutes} minutes. This is a critical threat "
                f"indicating automated credential testing."
            ),
            user_emails=user_emails if isinstance(user_emails, list) else [user_emails],
            source_ips=[source_ip],
            providers=providers if isinstance(providers, list) else [providers],
            failure_count=total_attempts,
            time_window_minutes=window_minutes,
            first_event_time=self._parse_timestamp(row.get("first_event")),
            last_event_time=self._parse_timestamp(row.get("last_event")),
            evidence={
                "unique_users_targeted": unique_users,
                "total_attempts": total_attempts,
            },
            mitre_techniques=["T1110.003"],  # Password Spraying
            recommended_actions=[
                f"Block IP {source_ip} immediately at firewall/WAF",
                "Review all targeted accounts for compromise",
                "Check if any authentications succeeded from this IP",
                "Report IP to threat intelligence sharing communities",
                "Force password reset for targeted high-value accounts",
            ],
        )

    def _create_cross_provider_alert(
        self, row: Dict[str, Any], window_minutes: int
    ) -> BruteForceAlert:
        """Create alert for cross-provider brute force detection.

        Args:
            row: Query result row
            window_minutes: Detection window

        Returns:
            BruteForceAlert
        """
        user_email = row.get("user_email", "unknown")
        failure_count = row.get("failure_count", 0)
        provider_count = row.get("provider_count", 0)
        providers = row.get("providers", [])
        source_ips = row.get("source_ips", [])

        return BruteForceAlert(
            alert_id=str(uuid.uuid4()),
            alert_type=BruteForceType.CROSS_PROVIDER,
            severity="critical",  # Cross-provider is always critical
            title=(
                f"Cross-Provider Attack: {user_email} targeted across "
                f"{provider_count} identity providers"
            ),
            description=(
                f"Detected authentication failures for user {user_email} across "
                f"{provider_count} different identity providers ({', '.join(providers)}) "
                f"within {window_minutes} minutes. This indicates an attacker is "
                f"testing stolen credentials across multiple systems."
            ),
            user_emails=[user_email],
            source_ips=source_ips if isinstance(source_ips, list) else [source_ips],
            providers=providers if isinstance(providers, list) else [providers],
            failure_count=failure_count,
            time_window_minutes=window_minutes,
            first_event_time=self._parse_timestamp(row.get("first_event")),
            last_event_time=self._parse_timestamp(row.get("last_event")),
            evidence={
                "provider_count": provider_count,
                "providers": providers,
            },
            mitre_techniques=["T1110.004", "T1078"],  # Credential Stuffing, Valid Accounts
            recommended_actions=[
                f"Force password reset for {user_email} across all systems",
                "Verify user hasn't been compromised",
                "Check for successful logins across all providers",
                "Review if credentials may have been leaked",
                "Enable MFA on all accounts if not already enabled",
            ],
        )

    def _deduplicate_alerts(
        self, alerts: List[BruteForceAlert]
    ) -> List[BruteForceAlert]:
        """Deduplicate alerts with overlapping users or IPs.

        When the same user appears in both single-user and cross-provider
        alerts, keep the more severe/specific one.

        Args:
            alerts: List of alerts to deduplicate

        Returns:
            Deduplicated list
        """
        if not alerts:
            return []

        # Group by primary identifier
        user_alerts: Dict[str, List[BruteForceAlert]] = {}
        ip_alerts: Dict[str, List[BruteForceAlert]] = {}

        for alert in alerts:
            # Index by user
            for user in alert.user_emails:
                if user not in user_alerts:
                    user_alerts[user] = []
                user_alerts[user].append(alert)

            # Index by IP (for distributed alerts)
            for ip in alert.source_ips:
                if ip not in ip_alerts:
                    ip_alerts[ip] = []
                ip_alerts[ip].append(alert)

        # Keep highest severity alert per user
        kept_alerts = set()
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}

        for user, user_alert_list in user_alerts.items():
            if len(user_alert_list) > 1:
                # Keep the most severe
                best = min(
                    user_alert_list,
                    key=lambda a: (severity_order.get(a.severity, 4), -a.failure_count)
                )
                kept_alerts.add(best.alert_id)
            else:
                kept_alerts.add(user_alert_list[0].alert_id)

        # Keep all distributed alerts (they're IP-based, not user-based)
        for alert in alerts:
            if alert.alert_type == BruteForceType.DISTRIBUTED:
                kept_alerts.add(alert.alert_id)

        return [a for a in alerts if a.alert_id in kept_alerts]

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
