"""Password spray attack detection for identity events.

Provides detection of password spray attacks where attackers try common
passwords against many accounts while staying below lockout thresholds.
Key characteristics:
- Low attempts per user (below lockout threshold)
- Many unique users targeted
- May span hours or days (low-and-slow)
- Evenly distributed timing
"""

import logging
import statistics
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


@dataclass
class SprayTimingAnalysis:
    """Analysis results for spray timing patterns.

    Attributes:
        is_evenly_distributed: Whether attempts are evenly spaced (smart spray)
        timing_variance_seconds: Variance in seconds between attempts
        timing_mean_seconds: Mean time between attempts in seconds
        attempts_per_hour: Average attempts per hour
        time_span_hours: Total time span of observed attempts
        evidence: Additional evidence details
    """

    is_evenly_distributed: bool = False
    timing_variance_seconds: float = 0.0
    timing_mean_seconds: float = 0.0
    attempts_per_hour: float = 0.0
    time_span_hours: float = 0.0
    evidence: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "is_evenly_distributed": self.is_evenly_distributed,
            "timing_variance_seconds": self.timing_variance_seconds,
            "timing_mean_seconds": self.timing_mean_seconds,
            "attempts_per_hour": self.attempts_per_hour,
            "time_span_hours": self.time_span_hours,
            "evidence": self.evidence,
        }


@dataclass
class CompromisedAccount:
    """Account with successful login after spray targeting.

    Attributes:
        user_email: Email of the compromised account
        source_ip: IP that compromised the account
        failure_time: Time of the spray failure
        success_time: Time of the subsequent success
        time_delta_seconds: Time between failure and success
    """

    user_email: str
    source_ip: str
    failure_time: Optional[datetime] = None
    success_time: Optional[datetime] = None
    time_delta_seconds: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "user_email": self.user_email,
            "source_ip": self.source_ip,
            "failure_time": (
                self.failure_time.isoformat() if self.failure_time else None
            ),
            "success_time": (
                self.success_time.isoformat() if self.success_time else None
            ),
            "time_delta_seconds": self.time_delta_seconds,
        }


@dataclass
class PasswordSprayAlert:
    """Alert generated for detected password spray attack.

    Attributes:
        alert_id: Unique identifier for this alert
        severity: Alert severity (critical, high, medium, low)
        title: Human-readable alert title
        description: Detailed description of the attack
        source_ip: Source IP address of the attack
        users_targeted: Number of unique users targeted
        total_attempts: Total number of authentication attempts
        avg_attempts_per_user: Average attempts per user
        max_attempts_per_user: Maximum attempts on any single user
        time_window_minutes: Detection time window
        first_event_time: Timestamp of first event in window
        last_event_time: Timestamp of last event in window
        timing_analysis: Results of timing pattern analysis
        targeted_users: List of targeted user email addresses
        compromised_accounts: Users with successful login after targeting
        providers: List of identity providers involved
        evidence: Additional evidence data
        mitre_techniques: Associated MITRE ATT&CK techniques
        recommended_actions: Suggested response actions
    """

    alert_id: str
    severity: str
    title: str
    description: str
    source_ip: str
    users_targeted: int = 0
    total_attempts: int = 0
    avg_attempts_per_user: float = 0.0
    max_attempts_per_user: int = 0
    time_window_minutes: int = 60
    first_event_time: Optional[datetime] = None
    last_event_time: Optional[datetime] = None
    timing_analysis: Optional[SprayTimingAnalysis] = None
    targeted_users: List[str] = field(default_factory=list)
    compromised_accounts: List[CompromisedAccount] = field(default_factory=list)
    providers: List[str] = field(default_factory=list)
    evidence: Dict[str, Any] = field(default_factory=dict)
    mitre_techniques: List[str] = field(default_factory=list)
    recommended_actions: List[str] = field(default_factory=list)
    detected_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "alert_id": self.alert_id,
            "severity": self.severity,
            "title": self.title,
            "description": self.description,
            "source_ip": self.source_ip,
            "users_targeted": self.users_targeted,
            "total_attempts": self.total_attempts,
            "avg_attempts_per_user": self.avg_attempts_per_user,
            "max_attempts_per_user": self.max_attempts_per_user,
            "time_window_minutes": self.time_window_minutes,
            "first_event_time": (
                self.first_event_time.isoformat() if self.first_event_time else None
            ),
            "last_event_time": (
                self.last_event_time.isoformat() if self.last_event_time else None
            ),
            "timing_analysis": (
                self.timing_analysis.to_dict() if self.timing_analysis else None
            ),
            "targeted_users": self.targeted_users,
            "compromised_accounts": [c.to_dict() for c in self.compromised_accounts],
            "providers": self.providers,
            "evidence": self.evidence,
            "mitre_techniques": self.mitre_techniques,
            "recommended_actions": self.recommended_actions,
            "detected_at": self.detected_at.isoformat(),
        }


class PasswordSprayDetector:
    """Detects password spray attacks across identity providers.

    Password spray attacks try common passwords against many accounts
    while staying below lockout thresholds. Detection focuses on:
    - Many unique users from single IP with few attempts each
    - Time-distributed attempts (below rate limits)
    - Evenly spaced timing patterns

    Attributes:
        query_executor: Executor for querying identity events
        MIN_USERS_TARGETED: Minimum unique users to trigger detection
        MAX_ATTEMPTS_PER_USER: Maximum attempts per user for spray pattern
        TIME_WINDOW_MINUTES: Default time window for detection
    """

    # Detection thresholds
    MIN_USERS_TARGETED = 10
    MAX_ATTEMPTS_PER_USER = 3
    TIME_WINDOW_MINUTES = 60

    # Longer window for slow sprays
    SLOW_SPRAY_WINDOW_HOURS = 24
    SLOW_SPRAY_MIN_USERS = 20

    # Evenly distributed timing threshold (coefficient of variation)
    EVEN_TIMING_CV_THRESHOLD = 0.3

    # SSO/legitimate patterns to exclude
    SSO_USER_AGENT_PATTERNS = [
        "SAML",
        "OIDC",
        "Azure AD Connect",
        "Google Apps",
        "Okta Browser Plugin",
    ]

    def __init__(
        self,
        query_executor: Any,
        identity_events_table: str = "identity_events",
        min_users_targeted: int = None,
        max_attempts_per_user: int = None,
        time_window_minutes: int = None,
    ):
        """Initialize the password spray detector.

        Args:
            query_executor: Executor for querying the data lake
            identity_events_table: Name of the identity events table
            min_users_targeted: Override for minimum users threshold
            max_attempts_per_user: Override for max attempts per user
            time_window_minutes: Override for time window
        """
        self.query_executor = query_executor
        self.identity_events_table = identity_events_table

        if min_users_targeted is not None:
            self.MIN_USERS_TARGETED = min_users_targeted
        if max_attempts_per_user is not None:
            self.MAX_ATTEMPTS_PER_USER = max_attempts_per_user
        if time_window_minutes is not None:
            self.TIME_WINDOW_MINUTES = time_window_minutes

    def detect_password_spray(
        self,
        window_minutes: int = None,
    ) -> List[PasswordSprayAlert]:
        """Detect password spray attacks.

        Finds IPs with spray pattern: many users, few attempts each.
        Distinguishes from legitimate SSO patterns.

        Args:
            window_minutes: Detection window in minutes

        Returns:
            List of PasswordSprayAlert for each suspicious IP
        """
        window = window_minutes or self.TIME_WINDOW_MINUTES
        alerts = []

        cutoff = datetime.now(timezone.utc) - timedelta(minutes=window)
        cutoff_str = cutoff.strftime("%Y-%m-%d %H:%M:%S")

        # Nested query to get per-user attempt counts, then aggregate by IP
        query = f"""
            SELECT
                source_ip,
                COUNT(DISTINCT user_email) as users_targeted,
                SUM(attempts_per_user) as total_attempts,
                AVG(attempts_per_user) as avg_per_user,
                MAX(attempts_per_user) as max_per_user,
                MIN(first_attempt) as first_event,
                MAX(last_attempt) as last_event,
                ARRAY_AGG(DISTINCT user_email) as user_emails,
                ARRAY_AGG(DISTINCT provider) as providers
            FROM (
                SELECT
                    source_ip,
                    user_email,
                    provider,
                    COUNT(*) as attempts_per_user,
                    MIN(event_timestamp) as first_attempt,
                    MAX(event_timestamp) as last_attempt
                FROM {self.identity_events_table}
                WHERE event_type = 'AUTH_FAILURE'
                  AND event_timestamp >= TIMESTAMP '{cutoff_str}'
                  AND source_ip IS NOT NULL
                  AND source_ip != ''
                GROUP BY source_ip, user_email, provider
            ) per_user
            GROUP BY source_ip
            HAVING COUNT(DISTINCT user_email) >= {self.MIN_USERS_TARGETED}
               AND AVG(attempts_per_user) <= {self.MAX_ATTEMPTS_PER_USER}
            ORDER BY users_targeted DESC
            LIMIT 100
        """

        try:
            result = self.query_executor.execute_query(query, timeout_seconds=120)

            for row in result.rows:
                source_ip = row.get("source_ip")

                # Analyze timing patterns
                timing_analysis = self.analyze_spray_timing(
                    source_ip=source_ip,
                    window_minutes=window,
                )

                # Get targeted users
                targeted_users = self.identify_targeted_users(
                    source_ip=source_ip,
                    window_minutes=window,
                )

                # Check for successful logins after spray
                compromised = self.check_for_success_after_spray(
                    source_ip=source_ip,
                    user_list=targeted_users,
                    window_minutes=window,
                )

                # Generate alert
                alert = self._create_spray_alert(
                    ip_data=row,
                    timing_analysis=timing_analysis,
                    targeted_users=targeted_users,
                    compromised_accounts=compromised,
                    window_minutes=window,
                )
                alerts.append(alert)

        except Exception as e:
            logger.error(f"Error detecting password spray: {e}")

        return alerts

    def detect_time_distributed_spray(
        self,
        window_hours: int = None,
    ) -> List[PasswordSprayAlert]:
        """Detect slow, time-distributed password spray attacks.

        Same pattern as regular spray but over longer time window
        to catch sophisticated slow-and-low attacks.

        Args:
            window_hours: Detection window in hours

        Returns:
            List of PasswordSprayAlert for each suspicious IP
        """
        window = window_hours or self.SLOW_SPRAY_WINDOW_HOURS
        window_minutes = window * 60
        alerts = []

        cutoff = datetime.now(timezone.utc) - timedelta(hours=window)
        cutoff_str = cutoff.strftime("%Y-%m-%d %H:%M:%S")

        # Similar query but with longer window and higher user threshold
        query = f"""
            SELECT
                source_ip,
                COUNT(DISTINCT user_email) as users_targeted,
                SUM(attempts_per_user) as total_attempts,
                AVG(attempts_per_user) as avg_per_user,
                MAX(attempts_per_user) as max_per_user,
                MIN(first_attempt) as first_event,
                MAX(last_attempt) as last_event,
                ARRAY_AGG(DISTINCT user_email) as user_emails,
                ARRAY_AGG(DISTINCT provider) as providers
            FROM (
                SELECT
                    source_ip,
                    user_email,
                    provider,
                    COUNT(*) as attempts_per_user,
                    MIN(event_timestamp) as first_attempt,
                    MAX(event_timestamp) as last_attempt
                FROM {self.identity_events_table}
                WHERE event_type = 'AUTH_FAILURE'
                  AND event_timestamp >= TIMESTAMP '{cutoff_str}'
                  AND source_ip IS NOT NULL
                  AND source_ip != ''
                GROUP BY source_ip, user_email, provider
            ) per_user
            GROUP BY source_ip
            HAVING COUNT(DISTINCT user_email) >= {self.SLOW_SPRAY_MIN_USERS}
               AND AVG(attempts_per_user) <= {self.MAX_ATTEMPTS_PER_USER}
            ORDER BY users_targeted DESC
            LIMIT 100
        """

        try:
            result = self.query_executor.execute_query(query, timeout_seconds=180)

            for row in result.rows:
                source_ip = row.get("source_ip")

                timing_analysis = self.analyze_spray_timing(
                    source_ip=source_ip,
                    window_minutes=window_minutes,
                )

                targeted_users = self.identify_targeted_users(
                    source_ip=source_ip,
                    window_minutes=window_minutes,
                )

                compromised = self.check_for_success_after_spray(
                    source_ip=source_ip,
                    user_list=targeted_users,
                    window_minutes=window_minutes,
                )

                alert = self._create_spray_alert(
                    ip_data=row,
                    timing_analysis=timing_analysis,
                    targeted_users=targeted_users,
                    compromised_accounts=compromised,
                    window_minutes=window_minutes,
                    is_slow_spray=True,
                )
                alerts.append(alert)

        except Exception as e:
            logger.error(f"Error detecting time-distributed spray: {e}")

        return alerts

    def analyze_spray_timing(
        self,
        source_ip: str,
        window_minutes: int = None,
    ) -> SprayTimingAnalysis:
        """Analyze timing distribution of spray attempts.

        Calculates if attempts are evenly spaced (smart spray).
        Even timing is more suspicious as it indicates automation.

        Args:
            source_ip: IP address to analyze
            window_minutes: Detection window in minutes

        Returns:
            SprayTimingAnalysis with timing patterns
        """
        window = window_minutes or self.TIME_WINDOW_MINUTES
        analysis = SprayTimingAnalysis()

        cutoff = datetime.now(timezone.utc) - timedelta(minutes=window)
        cutoff_str = cutoff.strftime("%Y-%m-%d %H:%M:%S")

        query = f"""
            SELECT event_timestamp
            FROM {self.identity_events_table}
            WHERE source_ip = '{source_ip}'
              AND event_type = 'AUTH_FAILURE'
              AND event_timestamp >= TIMESTAMP '{cutoff_str}'
            ORDER BY event_timestamp ASC
            LIMIT 1000
        """

        try:
            result = self.query_executor.execute_query(query, timeout_seconds=60)

            if len(result.rows) < 2:
                return analysis

            timestamps = []
            for row in result.rows:
                ts = self._parse_timestamp(row.get("event_timestamp"))
                if ts:
                    timestamps.append(ts)

            if len(timestamps) >= 2:
                # Calculate inter-event intervals
                intervals_seconds = []
                for i in range(1, len(timestamps)):
                    delta = (timestamps[i] - timestamps[i - 1]).total_seconds()
                    intervals_seconds.append(delta)

                if intervals_seconds:
                    analysis.timing_mean_seconds = statistics.mean(intervals_seconds)
                    if len(intervals_seconds) >= 2:
                        analysis.timing_variance_seconds = statistics.variance(
                            intervals_seconds
                        )
                        stdev = statistics.stdev(intervals_seconds)
                        if analysis.timing_mean_seconds > 0:
                            cv = stdev / analysis.timing_mean_seconds
                            analysis.is_evenly_distributed = (
                                cv < self.EVEN_TIMING_CV_THRESHOLD
                            )

                # Calculate time span and rate
                time_span = (timestamps[-1] - timestamps[0]).total_seconds()
                analysis.time_span_hours = time_span / 3600
                if time_span > 0:
                    analysis.attempts_per_hour = len(timestamps) / (time_span / 3600)

                analysis.evidence = {
                    "total_events": len(timestamps),
                    "interval_count": len(intervals_seconds),
                    "min_interval_seconds": min(intervals_seconds) if intervals_seconds else 0,
                    "max_interval_seconds": max(intervals_seconds) if intervals_seconds else 0,
                }

        except Exception as e:
            logger.error(f"Error analyzing spray timing: {e}")

        return analysis

    def identify_targeted_users(
        self,
        source_ip: str,
        window_minutes: int = None,
    ) -> List[str]:
        """Get list of all users targeted by suspected spray.

        Args:
            source_ip: IP address of the spray attack
            window_minutes: Detection window in minutes

        Returns:
            List of targeted user email addresses
        """
        window = window_minutes or self.TIME_WINDOW_MINUTES
        users = []

        cutoff = datetime.now(timezone.utc) - timedelta(minutes=window)
        cutoff_str = cutoff.strftime("%Y-%m-%d %H:%M:%S")

        query = f"""
            SELECT DISTINCT user_email
            FROM {self.identity_events_table}
            WHERE source_ip = '{source_ip}'
              AND event_type = 'AUTH_FAILURE'
              AND event_timestamp >= TIMESTAMP '{cutoff_str}'
            LIMIT 1000
        """

        try:
            result = self.query_executor.execute_query(query, timeout_seconds=60)
            users = [row.get("user_email") for row in result.rows if row.get("user_email")]
        except Exception as e:
            logger.error(f"Error identifying targeted users: {e}")

        return users

    def check_for_success_after_spray(
        self,
        source_ip: str,
        user_list: List[str],
        window_minutes: int = None,
    ) -> List[CompromisedAccount]:
        """Check if any targeted users had successful login from spray IP.

        This is a critical finding - indicates account compromise.

        Args:
            source_ip: IP address of the spray attack
            user_list: List of targeted user emails
            window_minutes: Detection window in minutes

        Returns:
            List of CompromisedAccount for each compromised user
        """
        if not user_list:
            return []

        window = window_minutes or self.TIME_WINDOW_MINUTES
        compromised = []

        cutoff = datetime.now(timezone.utc) - timedelta(minutes=window)
        cutoff_str = cutoff.strftime("%Y-%m-%d %H:%M:%S")

        # Build user list for IN clause
        user_in_clause = ", ".join([f"'{email}'" for email in user_list[:100]])

        query = f"""
            SELECT
                user_email,
                MIN(CASE WHEN event_type = 'AUTH_FAILURE' THEN event_timestamp END) as failure_time,
                MIN(CASE WHEN event_type = 'AUTH_SUCCESS' THEN event_timestamp END) as success_time
            FROM {self.identity_events_table}
            WHERE source_ip = '{source_ip}'
              AND user_email IN ({user_in_clause})
              AND event_timestamp >= TIMESTAMP '{cutoff_str}'
            GROUP BY user_email
            HAVING MIN(CASE WHEN event_type = 'AUTH_SUCCESS' THEN event_timestamp END) IS NOT NULL
        """

        try:
            result = self.query_executor.execute_query(query, timeout_seconds=60)

            for row in result.rows:
                failure_time = self._parse_timestamp(row.get("failure_time"))
                success_time = self._parse_timestamp(row.get("success_time"))

                # Only count as compromised if success came after failure
                if failure_time and success_time and success_time > failure_time:
                    delta = (success_time - failure_time).total_seconds()
                    compromised.append(
                        CompromisedAccount(
                            user_email=row.get("user_email"),
                            source_ip=source_ip,
                            failure_time=failure_time,
                            success_time=success_time,
                            time_delta_seconds=delta,
                        )
                    )

        except Exception as e:
            logger.error(f"Error checking for success after spray: {e}")

        return compromised

    def _create_spray_alert(
        self,
        ip_data: Dict[str, Any],
        timing_analysis: SprayTimingAnalysis,
        targeted_users: List[str],
        compromised_accounts: List[CompromisedAccount],
        window_minutes: int,
        is_slow_spray: bool = False,
    ) -> PasswordSprayAlert:
        """Create alert for password spray detection.

        Args:
            ip_data: Query result data for the source IP
            timing_analysis: Timing pattern analysis results
            targeted_users: List of targeted user emails
            compromised_accounts: Users with successful login after targeting
            window_minutes: Detection window used
            is_slow_spray: Whether this is a slow/distributed spray

        Returns:
            PasswordSprayAlert with full evidence
        """
        source_ip = ip_data.get("source_ip", "unknown")
        users_targeted = ip_data.get("users_targeted", 0)
        total_attempts = ip_data.get("total_attempts", 0)
        avg_per_user = ip_data.get("avg_per_user", 0)
        max_per_user = ip_data.get("max_per_user", 0)
        providers = ip_data.get("providers", [])

        # Severity is critical, elevated to critical if compromised accounts found
        severity = "critical"

        # Build description
        spray_type = "time-distributed " if is_slow_spray else ""
        description_parts = [
            f"Detected {spray_type}password spray attack from IP {source_ip}.",
            f"Targeted {users_targeted} unique users with {total_attempts} total attempts.",
            f"Average {avg_per_user:.1f} attempts per user (max {max_per_user}).",
        ]

        if timing_analysis.is_evenly_distributed:
            description_parts.append(
                "Evenly distributed timing indicates automated attack."
            )

        if compromised_accounts:
            description_parts.append(
                f"CRITICAL: {len(compromised_accounts)} accounts may be compromised!"
            )

        # Build recommended actions
        actions = [
            f"Block IP {source_ip} immediately at firewall/WAF",
        ]

        if compromised_accounts:
            compromised_emails = [c.user_email for c in compromised_accounts]
            actions.extend(
                [
                    f"URGENT: Force password reset for compromised accounts: {', '.join(compromised_emails[:5])}",
                    "Investigate compromised accounts for post-access activity",
                    "Review audit logs for data exfiltration",
                ]
            )

        actions.extend(
            [
                "Review all targeted accounts for additional compromise indicators",
                "Check IP against threat intelligence feeds",
                "Implement smart lockout policies if not already enabled",
                "Consider requiring MFA for all targeted users",
            ]
        )

        return PasswordSprayAlert(
            alert_id=str(uuid.uuid4()),
            severity=severity,
            title=f"Password Spray: {users_targeted} users from {source_ip}",
            description=" ".join(description_parts),
            source_ip=source_ip,
            users_targeted=users_targeted,
            total_attempts=total_attempts,
            avg_attempts_per_user=avg_per_user,
            max_attempts_per_user=max_per_user,
            time_window_minutes=window_minutes,
            first_event_time=self._parse_timestamp(ip_data.get("first_event")),
            last_event_time=self._parse_timestamp(ip_data.get("last_event")),
            timing_analysis=timing_analysis,
            targeted_users=targeted_users[:100],
            compromised_accounts=compromised_accounts,
            providers=providers if isinstance(providers, list) else [providers],
            evidence={
                "is_slow_spray": is_slow_spray,
                "is_evenly_distributed": timing_analysis.is_evenly_distributed,
                "timing_variance_seconds": timing_analysis.timing_variance_seconds,
                "compromised_count": len(compromised_accounts),
            },
            mitre_techniques=["T1110.003"],  # Password Spraying
            recommended_actions=actions,
        )

    def run_all_detections(
        self,
        include_slow_spray: bool = True,
    ) -> List[PasswordSprayAlert]:
        """Run all password spray detection methods.

        Args:
            include_slow_spray: Whether to include 24-hour slow spray detection

        Returns:
            Combined list of alerts from all detection methods
        """
        all_alerts = []

        # Standard 1-hour spray detection
        standard_alerts = self.detect_password_spray()
        all_alerts.extend(standard_alerts)

        # Optional slow spray detection
        if include_slow_spray:
            slow_alerts = self.detect_time_distributed_spray()
            # Filter out slow spray alerts that overlap with standard detections
            standard_ips = {a.source_ip for a in standard_alerts}
            slow_alerts = [a for a in slow_alerts if a.source_ip not in standard_ips]
            all_alerts.extend(slow_alerts)

        # Sort by compromised accounts first, then by users targeted
        all_alerts.sort(
            key=lambda a: (-len(a.compromised_accounts), -a.users_targeted)
        )

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
