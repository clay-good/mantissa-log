"""MFA bypass and fatigue attack detection for identity events.

Provides detection of MFA-related attacks including:
- MFA fatigue (push bombing): repeated notifications to tire user into approving
- MFA bypass: methods to circumvent MFA requirements
- MFA method changes: potential SIM swap or account takeover indicators
- Unusual MFA from new devices
"""

import logging
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


class MFAAlertType(Enum):
    """Types of MFA-related alerts."""

    FATIGUE = "mfa_fatigue"  # Push bombing attack
    BYPASS = "mfa_bypass"  # MFA circumvented
    METHOD_CHANGE = "mfa_method_change"  # Factor changed (SIM swap indicator)
    NEW_DEVICE = "mfa_new_device"  # MFA from unseen device


class MFAMethod(Enum):
    """MFA method types with security ratings."""

    PUSH = "push"  # Push notification (Okta Verify, MS Authenticator)
    TOTP = "totp"  # Time-based OTP
    HOTP = "hotp"  # HMAC-based OTP
    SMS = "sms"  # SMS (weak)
    VOICE = "voice"  # Voice call (weak)
    EMAIL = "email"  # Email (weak)
    FIDO2 = "fido2"  # Hardware key (strong)
    BIOMETRIC = "biometric"  # Fingerprint/Face (strong)
    BACKUP = "backup"  # Backup codes


# Security ratings for MFA methods (higher is stronger)
MFA_METHOD_STRENGTH = {
    MFAMethod.FIDO2: 5,
    MFAMethod.BIOMETRIC: 4,
    MFAMethod.PUSH: 3,
    MFAMethod.TOTP: 3,
    MFAMethod.HOTP: 2,
    MFAMethod.SMS: 1,
    MFAMethod.VOICE: 1,
    MFAMethod.EMAIL: 1,
    MFAMethod.BACKUP: 0,
}


@dataclass
class MFATimelineEvent:
    """Single event in MFA fatigue timeline.

    Attributes:
        timestamp: When the event occurred
        event_type: Type of MFA event (challenge, success, failure)
        source_ip: Source IP of the event
        user_agent: User agent string
        location: Geographic location
        result: Result of the MFA attempt
    """

    timestamp: datetime
    event_type: str
    source_ip: str = ""
    user_agent: str = ""
    location: str = ""
    result: str = ""

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "timestamp": self.timestamp.isoformat(),
            "event_type": self.event_type,
            "source_ip": self.source_ip,
            "user_agent": self.user_agent,
            "location": self.location,
            "result": self.result,
        }


@dataclass
class MFAFatigueAnalysis:
    """Analysis results for MFA fatigue timeline.

    Attributes:
        user_email: User being attacked
        total_challenges: Number of MFA challenges in window
        denied_count: Number of denials
        success_count: Number of successes
        fraud_reported: Whether user reported fraud
        user_gave_in: Whether user eventually approved after denials
        breaking_point_time: When user approved after denials
        time_to_break_seconds: Time from first challenge to approval
        avg_interval_seconds: Average time between challenges
        source_ips: Unique source IPs involved
        timeline: Detailed timeline of events
    """

    user_email: str
    total_challenges: int = 0
    denied_count: int = 0
    success_count: int = 0
    fraud_reported: bool = False
    user_gave_in: bool = False
    breaking_point_time: Optional[datetime] = None
    time_to_break_seconds: float = 0.0
    avg_interval_seconds: float = 0.0
    source_ips: List[str] = field(default_factory=list)
    timeline: List[MFATimelineEvent] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "user_email": self.user_email,
            "total_challenges": self.total_challenges,
            "denied_count": self.denied_count,
            "success_count": self.success_count,
            "fraud_reported": self.fraud_reported,
            "user_gave_in": self.user_gave_in,
            "breaking_point_time": (
                self.breaking_point_time.isoformat()
                if self.breaking_point_time
                else None
            ),
            "time_to_break_seconds": self.time_to_break_seconds,
            "avg_interval_seconds": self.avg_interval_seconds,
            "source_ips": self.source_ips,
            "timeline": [e.to_dict() for e in self.timeline],
        }


@dataclass
class MFAAlert:
    """Alert generated for MFA-related attacks.

    Attributes:
        alert_id: Unique identifier for this alert
        alert_type: Type of MFA attack
        severity: Alert severity (critical, high, medium, low)
        title: Human-readable alert title
        description: Detailed description of the attack
        user_email: Targeted user
        challenge_count: Number of MFA challenges
        success_after_failures: Whether success occurred after failures
        time_window_minutes: Detection time window
        first_event_time: Timestamp of first event
        last_event_time: Timestamp of last event
        fatigue_analysis: Detailed fatigue analysis (if applicable)
        source_ips: Source IPs involved
        providers: Identity providers involved
        is_high_value_target: Whether user is admin/executive
        evidence: Additional evidence data
        mitre_techniques: Associated MITRE ATT&CK techniques
        recommended_actions: Suggested response actions
    """

    alert_id: str
    alert_type: MFAAlertType
    severity: str
    title: str
    description: str
    user_email: str
    challenge_count: int = 0
    success_after_failures: bool = False
    time_window_minutes: int = 5
    first_event_time: Optional[datetime] = None
    last_event_time: Optional[datetime] = None
    fatigue_analysis: Optional[MFAFatigueAnalysis] = None
    source_ips: List[str] = field(default_factory=list)
    providers: List[str] = field(default_factory=list)
    is_high_value_target: bool = False
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
            "challenge_count": self.challenge_count,
            "success_after_failures": self.success_after_failures,
            "time_window_minutes": self.time_window_minutes,
            "first_event_time": (
                self.first_event_time.isoformat() if self.first_event_time else None
            ),
            "last_event_time": (
                self.last_event_time.isoformat() if self.last_event_time else None
            ),
            "fatigue_analysis": (
                self.fatigue_analysis.to_dict() if self.fatigue_analysis else None
            ),
            "source_ips": self.source_ips,
            "providers": self.providers,
            "is_high_value_target": self.is_high_value_target,
            "evidence": self.evidence,
            "mitre_techniques": self.mitre_techniques,
            "recommended_actions": self.recommended_actions,
            "detected_at": self.detected_at.isoformat(),
        }


class MFADetector:
    """Detects MFA-related attacks across identity providers.

    Implements detection for:
    - MFA fatigue (push bombing): repeated challenges to tire user
    - MFA bypass: circumventing MFA requirements
    - MFA method changes: potential SIM swap indicators
    - MFA from new devices

    Attributes:
        query_executor: Executor for querying identity events
        MFA_FATIGUE_THRESHOLD: Minimum challenges to trigger fatigue alert
        MFA_FATIGUE_WINDOW_MINUTES: Time window for fatigue detection
    """

    # Detection thresholds
    MFA_FATIGUE_THRESHOLD = 5
    MFA_FATIGUE_WINDOW_MINUTES = 5

    # High-value target patterns (admins, executives)
    HIGH_VALUE_PATTERNS = [
        "admin",
        "administrator",
        "root",
        "superuser",
        "ceo",
        "cfo",
        "cto",
        "ciso",
        "president",
        "vp",
        "director",
        "exec",
        "it-admin",
        "sysadmin",
        "secops",
        "security",
    ]

    def __init__(
        self,
        query_executor: Any,
        identity_events_table: str = "identity_events",
        mfa_fatigue_threshold: int = None,
        mfa_fatigue_window_minutes: int = None,
    ):
        """Initialize the MFA detector.

        Args:
            query_executor: Executor for querying the data lake
            identity_events_table: Name of the identity events table
            mfa_fatigue_threshold: Override for fatigue threshold
            mfa_fatigue_window_minutes: Override for fatigue window
        """
        self.query_executor = query_executor
        self.identity_events_table = identity_events_table

        if mfa_fatigue_threshold is not None:
            self.MFA_FATIGUE_THRESHOLD = mfa_fatigue_threshold
        if mfa_fatigue_window_minutes is not None:
            self.MFA_FATIGUE_WINDOW_MINUTES = mfa_fatigue_window_minutes

    def detect_mfa_fatigue(
        self,
        window_minutes: int = None,
    ) -> List[MFAAlert]:
        """Detect MFA fatigue (push bombing) attacks.

        Finds users with excessive MFA challenges in short time window.
        Critical if success occurs after multiple failures (user gave in).

        Args:
            window_minutes: Detection window in minutes

        Returns:
            List of MFAAlert for each suspected fatigue attack
        """
        window = window_minutes or self.MFA_FATIGUE_WINDOW_MINUTES
        alerts = []

        cutoff = datetime.now(timezone.utc) - timedelta(minutes=window)
        cutoff_str = cutoff.strftime("%Y-%m-%d %H:%M:%S")

        query = f"""
            SELECT
                user_email,
                COUNT(*) as challenge_count,
                COUNT(*) FILTER (WHERE event_type = 'MFA_SUCCESS') as success_count,
                COUNT(*) FILTER (WHERE event_type = 'MFA_FAILURE') as failure_count,
                COUNT(*) FILTER (WHERE event_type = 'MFA_CHALLENGE') as pending_count,
                MAX(CASE WHEN event_type = 'MFA_SUCCESS' THEN event_timestamp END) as success_time,
                MIN(event_timestamp) as first_event,
                MAX(event_timestamp) as last_event,
                ARRAY_AGG(DISTINCT source_ip) as source_ips,
                ARRAY_AGG(DISTINCT provider) as providers
            FROM {self.identity_events_table}
            WHERE event_type IN ('MFA_CHALLENGE', 'MFA_SUCCESS', 'MFA_FAILURE')
              AND event_timestamp >= TIMESTAMP '{cutoff_str}'
            GROUP BY user_email
            HAVING COUNT(*) >= {self.MFA_FATIGUE_THRESHOLD}
            ORDER BY challenge_count DESC
            LIMIT 100
        """

        try:
            result = self.query_executor.execute_query(query, timeout_seconds=120)

            for row in result.rows:
                user_email = row.get("user_email")

                # Analyze the fatigue timeline
                fatigue_analysis = self.analyze_mfa_fatigue_timeline(
                    user_email=user_email,
                    window_minutes=window,
                )

                # Generate alert
                alert = self._create_fatigue_alert(
                    row=row,
                    fatigue_analysis=fatigue_analysis,
                    window_minutes=window,
                )
                alerts.append(alert)

        except Exception as e:
            logger.error(f"Error detecting MFA fatigue: {e}")

        return alerts

    def detect_mfa_bypass(
        self,
        window_hours: int = 24,
    ) -> List[MFAAlert]:
        """Detect MFA bypass attempts.

        Finds logins without MFA that should have had it, or MFA
        disabled before login.

        Args:
            window_hours: Detection window in hours

        Returns:
            List of MFAAlert for each suspected bypass
        """
        alerts = []

        cutoff = datetime.now(timezone.utc) - timedelta(hours=window_hours)
        cutoff_str = cutoff.strftime("%Y-%m-%d %H:%M:%S")

        # Find MFA disable events followed by successful logins
        query = f"""
            SELECT
                user_email,
                'mfa_disabled' as bypass_type,
                disable_time,
                login_time,
                source_ip,
                provider
            FROM (
                SELECT
                    d.user_email,
                    d.event_timestamp as disable_time,
                    MIN(l.event_timestamp) as login_time,
                    l.source_ip,
                    l.provider
                FROM {self.identity_events_table} d
                JOIN {self.identity_events_table} l
                  ON d.user_email = l.user_email
                  AND l.event_type = 'AUTH_SUCCESS'
                  AND l.event_timestamp > d.event_timestamp
                  AND l.event_timestamp < d.event_timestamp + INTERVAL '2 hours'
                WHERE d.event_type = 'MFA_DISABLED'
                  AND d.event_timestamp >= TIMESTAMP '{cutoff_str}'
                GROUP BY d.user_email, d.event_timestamp, l.source_ip, l.provider
            ) bypass_events
            LIMIT 100
        """

        try:
            result = self.query_executor.execute_query(query, timeout_seconds=120)

            for row in result.rows:
                alert = self._create_bypass_alert(
                    row=row,
                    window_hours=window_hours,
                )
                alerts.append(alert)

        except Exception as e:
            logger.error(f"Error detecting MFA bypass: {e}")

        return alerts

    def detect_mfa_method_change(
        self,
        window_hours: int = 24,
    ) -> List[MFAAlert]:
        """Detect suspicious MFA method changes.

        Finds users who changed MFA methods, especially to weaker types
        or added new phone numbers (SIM swap indicator).

        Args:
            window_hours: Detection window in hours

        Returns:
            List of MFAAlert for each suspicious change
        """
        alerts = []

        cutoff = datetime.now(timezone.utc) - timedelta(hours=window_hours)
        cutoff_str = cutoff.strftime("%Y-%m-%d %H:%M:%S")

        query = f"""
            SELECT
                user_email,
                event_type,
                event_timestamp,
                source_ip,
                provider,
                raw_event
            FROM {self.identity_events_table}
            WHERE event_type IN ('MFA_ENROLLED', 'MFA_CHANGED', 'MFA_REMOVED')
              AND event_timestamp >= TIMESTAMP '{cutoff_str}'
            ORDER BY user_email, event_timestamp
            LIMIT 500
        """

        try:
            result = self.query_executor.execute_query(query, timeout_seconds=120)

            # Group by user
            user_changes: Dict[str, List[Dict]] = {}
            for row in result.rows:
                user = row.get("user_email")
                if user not in user_changes:
                    user_changes[user] = []
                user_changes[user].append(row)

            # Analyze each user's changes
            for user_email, changes in user_changes.items():
                # Check for suspicious patterns
                is_suspicious = self._analyze_mfa_changes(changes)
                if is_suspicious:
                    alert = self._create_method_change_alert(
                        user_email=user_email,
                        changes=changes,
                        window_hours=window_hours,
                    )
                    alerts.append(alert)

        except Exception as e:
            logger.error(f"Error detecting MFA method changes: {e}")

        return alerts

    def detect_mfa_from_new_device(
        self,
        window_hours: int = 24,
    ) -> List[MFAAlert]:
        """Detect MFA success from previously unseen devices.

        Compares device to user's baseline to identify new devices.

        Args:
            window_hours: Detection window in hours

        Returns:
            List of MFAAlert for each new device MFA
        """
        alerts = []

        cutoff = datetime.now(timezone.utc) - timedelta(hours=window_hours)
        cutoff_str = cutoff.strftime("%Y-%m-%d %H:%M:%S")

        # This requires baseline comparison - query recent MFA successes
        # and compare to historical device fingerprints
        query = f"""
            SELECT
                user_email,
                device_fingerprint,
                user_agent,
                source_ip,
                event_timestamp,
                provider
            FROM {self.identity_events_table}
            WHERE event_type = 'MFA_SUCCESS'
              AND event_timestamp >= TIMESTAMP '{cutoff_str}'
              AND device_fingerprint IS NOT NULL
            ORDER BY user_email, event_timestamp
            LIMIT 500
        """

        try:
            result = self.query_executor.execute_query(query, timeout_seconds=120)

            # Group by user
            user_devices: Dict[str, List[Dict]] = {}
            for row in result.rows:
                user = row.get("user_email")
                if user not in user_devices:
                    user_devices[user] = []
                user_devices[user].append(row)

            # Check each user for new devices
            for user_email, events in user_devices.items():
                new_device_events = self._identify_new_devices(user_email, events)
                for event in new_device_events:
                    alert = self._create_new_device_alert(
                        user_email=user_email,
                        event=event,
                        window_hours=window_hours,
                    )
                    alerts.append(alert)

        except Exception as e:
            logger.error(f"Error detecting MFA from new devices: {e}")

        return alerts

    def analyze_mfa_fatigue_timeline(
        self,
        user_email: str,
        window_minutes: int = None,
    ) -> MFAFatigueAnalysis:
        """Get detailed timeline of MFA events for a user.

        Calculates timing patterns and identifies the "breaking point"
        if user eventually approved after denials.

        Args:
            user_email: User to analyze
            window_minutes: Detection window in minutes

        Returns:
            MFAFatigueAnalysis with detailed timeline
        """
        window = window_minutes or self.MFA_FATIGUE_WINDOW_MINUTES
        analysis = MFAFatigueAnalysis(user_email=user_email)

        cutoff = datetime.now(timezone.utc) - timedelta(minutes=window)
        cutoff_str = cutoff.strftime("%Y-%m-%d %H:%M:%S")

        query = f"""
            SELECT
                event_type,
                event_timestamp,
                source_ip,
                user_agent,
                raw_event
            FROM {self.identity_events_table}
            WHERE user_email = '{user_email}'
              AND event_type IN ('MFA_CHALLENGE', 'MFA_SUCCESS', 'MFA_FAILURE', 'MFA_FRAUD')
              AND event_timestamp >= TIMESTAMP '{cutoff_str}'
            ORDER BY event_timestamp ASC
            LIMIT 200
        """

        try:
            result = self.query_executor.execute_query(query, timeout_seconds=60)

            if not result.rows:
                return analysis

            timeline = []
            source_ips = set()
            denied_count = 0
            success_count = 0
            fraud_reported = False
            first_event_time = None
            success_time = None

            for row in result.rows:
                ts = self._parse_timestamp(row.get("event_timestamp"))
                if not ts:
                    continue

                if first_event_time is None:
                    first_event_time = ts

                event_type = row.get("event_type")
                source_ip = row.get("source_ip", "")

                if source_ip:
                    source_ips.add(source_ip)

                timeline.append(
                    MFATimelineEvent(
                        timestamp=ts,
                        event_type=event_type,
                        source_ip=source_ip,
                        user_agent=row.get("user_agent", ""),
                        result=event_type,
                    )
                )

                if event_type == "MFA_FAILURE":
                    denied_count += 1
                elif event_type == "MFA_SUCCESS":
                    success_count += 1
                    if success_time is None:
                        success_time = ts
                elif event_type == "MFA_FRAUD":
                    fraud_reported = True

            # Calculate analysis
            analysis.total_challenges = len(timeline)
            analysis.denied_count = denied_count
            analysis.success_count = success_count
            analysis.fraud_reported = fraud_reported
            analysis.source_ips = list(source_ips)
            analysis.timeline = timeline

            # Check if user gave in (success after denials)
            if denied_count > 0 and success_count > 0 and success_time:
                analysis.user_gave_in = True
                analysis.breaking_point_time = success_time
                if first_event_time:
                    analysis.time_to_break_seconds = (
                        success_time - first_event_time
                    ).total_seconds()

            # Calculate average interval
            if len(timeline) >= 2:
                intervals = []
                for i in range(1, len(timeline)):
                    delta = (
                        timeline[i].timestamp - timeline[i - 1].timestamp
                    ).total_seconds()
                    intervals.append(delta)
                if intervals:
                    analysis.avg_interval_seconds = sum(intervals) / len(intervals)

        except Exception as e:
            logger.error(f"Error analyzing MFA fatigue timeline: {e}")

        return analysis

    def is_high_value_target(self, user_email: str) -> bool:
        """Check if user is a high-value target (admin, executive).

        Args:
            user_email: User email to check

        Returns:
            True if user matches high-value patterns
        """
        if not user_email:
            return False

        email_lower = user_email.lower()
        for pattern in self.HIGH_VALUE_PATTERNS:
            if pattern in email_lower:
                return True

        return False

    def _create_fatigue_alert(
        self,
        row: Dict[str, Any],
        fatigue_analysis: MFAFatigueAnalysis,
        window_minutes: int,
    ) -> MFAAlert:
        """Create alert for MFA fatigue detection.

        Args:
            row: Query result row
            fatigue_analysis: Detailed fatigue analysis
            window_minutes: Detection window used

        Returns:
            MFAAlert
        """
        user_email = row.get("user_email", "unknown")
        challenge_count = row.get("challenge_count", 0)
        success_count = row.get("success_count", 0)
        failure_count = row.get("failure_count", 0)
        source_ips = row.get("source_ips", [])
        providers = row.get("providers", [])

        is_hvt = self.is_high_value_target(user_email)
        user_gave_in = fatigue_analysis.user_gave_in

        # Determine severity
        if fatigue_analysis.fraud_reported:
            severity = "critical"
        elif user_gave_in:
            severity = "critical"
        elif is_hvt:
            severity = "critical"
        else:
            severity = "high"

        # Build description
        description_parts = [
            f"Detected MFA fatigue attack against {user_email}.",
            f"{challenge_count} MFA challenges in {window_minutes} minutes.",
        ]

        if user_gave_in:
            description_parts.append(
                f"CRITICAL: User approved after {failure_count} denials!"
            )
        if fatigue_analysis.fraud_reported:
            description_parts.append("User reported fraud - attack confirmed!")
        if is_hvt:
            description_parts.append("Target is a high-value account!")

        # Build recommended actions
        actions = [
            f"Contact {user_email} immediately through verified channel",
        ]

        if user_gave_in or fatigue_analysis.fraud_reported:
            actions.extend(
                [
                    "Revoke all active sessions immediately",
                    "Force password reset",
                    "Review audit logs for post-compromise activity",
                ]
            )

        actions.extend(
            [
                "Enable number matching for push notifications",
                "Consider phishing-resistant MFA (FIDO2)",
                "Review and strengthen MFA policies",
            ]
        )

        return MFAAlert(
            alert_id=str(uuid.uuid4()),
            alert_type=MFAAlertType.FATIGUE,
            severity=severity,
            title=f"MFA Fatigue: {challenge_count} challenges for {user_email}",
            description=" ".join(description_parts),
            user_email=user_email,
            challenge_count=challenge_count,
            success_after_failures=user_gave_in,
            time_window_minutes=window_minutes,
            first_event_time=self._parse_timestamp(row.get("first_event")),
            last_event_time=self._parse_timestamp(row.get("last_event")),
            fatigue_analysis=fatigue_analysis,
            source_ips=source_ips if isinstance(source_ips, list) else [source_ips],
            providers=providers if isinstance(providers, list) else [providers],
            is_high_value_target=is_hvt,
            evidence={
                "success_count": success_count,
                "failure_count": failure_count,
                "user_gave_in": user_gave_in,
                "fraud_reported": fatigue_analysis.fraud_reported,
                "avg_interval_seconds": fatigue_analysis.avg_interval_seconds,
            },
            mitre_techniques=["T1621"],  # MFA Request Generation
            recommended_actions=actions,
        )

    def _create_bypass_alert(
        self,
        row: Dict[str, Any],
        window_hours: int,
    ) -> MFAAlert:
        """Create alert for MFA bypass detection.

        Args:
            row: Query result row
            window_hours: Detection window used

        Returns:
            MFAAlert
        """
        user_email = row.get("user_email", "unknown")
        bypass_type = row.get("bypass_type", "unknown")
        source_ip = row.get("source_ip", "")
        provider = row.get("provider", "")

        is_hvt = self.is_high_value_target(user_email)

        description = (
            f"MFA bypass detected for {user_email}. "
            f"MFA was disabled followed by successful login. "
            f"This may indicate account compromise."
        )

        return MFAAlert(
            alert_id=str(uuid.uuid4()),
            alert_type=MFAAlertType.BYPASS,
            severity="critical",
            title=f"MFA Bypass: {user_email}",
            description=description,
            user_email=user_email,
            time_window_minutes=window_hours * 60,
            first_event_time=self._parse_timestamp(row.get("disable_time")),
            last_event_time=self._parse_timestamp(row.get("login_time")),
            source_ips=[source_ip] if source_ip else [],
            providers=[provider] if provider else [],
            is_high_value_target=is_hvt,
            evidence={
                "bypass_type": bypass_type,
            },
            mitre_techniques=["T1556.006"],  # Modify Auth Process: MFA
            recommended_actions=[
                f"Verify MFA disable was authorized for {user_email}",
                "Revoke active sessions",
                "Force password reset and MFA re-enrollment",
                "Review audit logs for unauthorized activity",
                "Check if admin account was used to disable MFA",
            ],
        )

    def _create_method_change_alert(
        self,
        user_email: str,
        changes: List[Dict],
        window_hours: int,
    ) -> MFAAlert:
        """Create alert for suspicious MFA method change.

        Args:
            user_email: User who changed MFA
            changes: List of change events
            window_hours: Detection window used

        Returns:
            MFAAlert
        """
        is_hvt = self.is_high_value_target(user_email)

        change_types = [c.get("event_type") for c in changes]
        source_ips = list(set(c.get("source_ip") for c in changes if c.get("source_ip")))
        providers = list(set(c.get("provider") for c in changes if c.get("provider")))

        description = (
            f"Suspicious MFA method changes for {user_email}. "
            f"Changes: {', '.join(change_types)}. "
            f"This may indicate SIM swap or account takeover."
        )

        return MFAAlert(
            alert_id=str(uuid.uuid4()),
            alert_type=MFAAlertType.METHOD_CHANGE,
            severity="high",
            title=f"MFA Method Change: {user_email}",
            description=description,
            user_email=user_email,
            time_window_minutes=window_hours * 60,
            source_ips=source_ips,
            providers=providers,
            is_high_value_target=is_hvt,
            evidence={
                "change_types": change_types,
                "change_count": len(changes),
            },
            mitre_techniques=["T1556.006", "T1078"],
            recommended_actions=[
                f"Verify MFA changes were authorized by {user_email}",
                "Contact user through non-phone verified channel",
                "Check for SIM swap indicators",
                "Review if phone number was changed",
                "Force re-verification of identity",
            ],
        )

    def _create_new_device_alert(
        self,
        user_email: str,
        event: Dict,
        window_hours: int,
    ) -> MFAAlert:
        """Create alert for MFA from new device.

        Args:
            user_email: User with new device
            event: MFA event from new device
            window_hours: Detection window used

        Returns:
            MFAAlert
        """
        is_hvt = self.is_high_value_target(user_email)
        device_fp = event.get("device_fingerprint", "unknown")
        source_ip = event.get("source_ip", "")
        provider = event.get("provider", "")

        description = (
            f"MFA success from new device for {user_email}. "
            f"Device fingerprint: {device_fp}. "
            f"Verify this is a legitimate new device."
        )

        return MFAAlert(
            alert_id=str(uuid.uuid4()),
            alert_type=MFAAlertType.NEW_DEVICE,
            severity="medium",
            title=f"MFA from New Device: {user_email}",
            description=description,
            user_email=user_email,
            time_window_minutes=window_hours * 60,
            first_event_time=self._parse_timestamp(event.get("event_timestamp")),
            source_ips=[source_ip] if source_ip else [],
            providers=[provider] if provider else [],
            is_high_value_target=is_hvt,
            evidence={
                "device_fingerprint": device_fp,
                "user_agent": event.get("user_agent", ""),
            },
            mitre_techniques=["T1078"],
            recommended_actions=[
                f"Verify new device is legitimate for {user_email}",
                "Check if user recently got new phone/computer",
                "Review login location for anomalies",
            ],
        )

    def _analyze_mfa_changes(self, changes: List[Dict]) -> bool:
        """Analyze MFA changes for suspicious patterns.

        Args:
            changes: List of MFA change events

        Returns:
            True if changes are suspicious
        """
        if not changes:
            return False

        # Suspicious patterns:
        # 1. MFA removed without re-enrollment
        # 2. Multiple changes in short time
        # 3. Changed to weaker method

        has_removal = any(c.get("event_type") == "MFA_REMOVED" for c in changes)
        change_count = len(changes)

        # Multiple changes or removal is suspicious
        if change_count >= 3 or has_removal:
            return True

        return False

    def _identify_new_devices(
        self,
        user_email: str,
        events: List[Dict],
    ) -> List[Dict]:
        """Identify MFA events from new devices.

        Args:
            user_email: User to check
            events: List of MFA events

        Returns:
            List of events from new devices
        """
        # This would typically compare against stored baseline
        # For now, return empty as this requires baseline lookup
        # In production, query user's baseline for known devices
        return []

    def run_all_detections(
        self,
        include_new_device: bool = True,
    ) -> List[MFAAlert]:
        """Run all MFA detection methods.

        Args:
            include_new_device: Whether to include new device detection

        Returns:
            Combined list of alerts from all detection methods
        """
        all_alerts = []

        # MFA fatigue (most critical)
        fatigue_alerts = self.detect_mfa_fatigue()
        all_alerts.extend(fatigue_alerts)

        # MFA bypass
        bypass_alerts = self.detect_mfa_bypass()
        all_alerts.extend(bypass_alerts)

        # MFA method changes
        method_alerts = self.detect_mfa_method_change()
        all_alerts.extend(method_alerts)

        # New device (optional, may be noisy)
        if include_new_device:
            device_alerts = self.detect_mfa_from_new_device()
            all_alerts.extend(device_alerts)

        # Sort by severity
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        all_alerts.sort(key=lambda a: severity_order.get(a.severity, 4))

        return all_alerts

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
