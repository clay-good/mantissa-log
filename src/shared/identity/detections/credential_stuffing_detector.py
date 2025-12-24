"""Credential stuffing attack detection for identity events.

Provides detection of credential stuffing attacks where attackers use
leaked credentials from breaches to attempt logins. Key characteristics:
- High volume of unique users from limited IPs
- Automation patterns (consistent timing, same user agent)
- Mix of successes and failures (valid leaked creds)
"""

import logging
import re
import statistics
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


@dataclass
class AutomationAnalysis:
    """Analysis results for automation pattern detection.

    Attributes:
        is_automated: Whether the traffic appears automated
        confidence_score: Confidence level (0.0-1.0) that traffic is automated
        timing_variance_ms: Variance in milliseconds between requests
        timing_mean_ms: Mean time between requests in milliseconds
        user_agent_count: Number of unique user agents observed
        has_bot_signature: Whether known bot signatures were detected
        bot_signatures_found: List of bot signatures detected
        evidence: Additional evidence details
    """

    is_automated: bool = False
    confidence_score: float = 0.0
    timing_variance_ms: float = 0.0
    timing_mean_ms: float = 0.0
    user_agent_count: int = 0
    has_bot_signature: bool = False
    bot_signatures_found: List[str] = field(default_factory=list)
    evidence: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "is_automated": self.is_automated,
            "confidence_score": self.confidence_score,
            "timing_variance_ms": self.timing_variance_ms,
            "timing_mean_ms": self.timing_mean_ms,
            "user_agent_count": self.user_agent_count,
            "has_bot_signature": self.has_bot_signature,
            "bot_signatures_found": self.bot_signatures_found,
            "evidence": self.evidence,
        }


@dataclass
class CredentialStuffingAlert:
    """Alert generated for detected credential stuffing attack.

    Attributes:
        alert_id: Unique identifier for this alert
        severity: Alert severity (critical, high, medium, low)
        title: Human-readable alert title
        description: Detailed description of the attack
        source_ip: Source IP address of the attack
        unique_user_count: Number of unique users targeted
        success_count: Number of successful authentications
        failure_count: Number of failed authentications
        success_rate: Percentage of successful attempts
        user_agents: List of user agents observed
        time_window_minutes: Detection time window
        first_event_time: Timestamp of first event in window
        last_event_time: Timestamp of last event in window
        automation_analysis: Results of automation pattern analysis
        targeted_users: List of targeted user email addresses
        successful_users: List of users with successful logins
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
    unique_user_count: int = 0
    success_count: int = 0
    failure_count: int = 0
    success_rate: float = 0.0
    user_agents: List[str] = field(default_factory=list)
    time_window_minutes: int = 10
    first_event_time: Optional[datetime] = None
    last_event_time: Optional[datetime] = None
    automation_analysis: Optional[AutomationAnalysis] = None
    targeted_users: List[str] = field(default_factory=list)
    successful_users: List[str] = field(default_factory=list)
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
            "unique_user_count": self.unique_user_count,
            "success_count": self.success_count,
            "failure_count": self.failure_count,
            "success_rate": self.success_rate,
            "user_agents": self.user_agents,
            "time_window_minutes": self.time_window_minutes,
            "first_event_time": (
                self.first_event_time.isoformat() if self.first_event_time else None
            ),
            "last_event_time": (
                self.last_event_time.isoformat() if self.last_event_time else None
            ),
            "automation_analysis": (
                self.automation_analysis.to_dict()
                if self.automation_analysis
                else None
            ),
            "targeted_users": self.targeted_users,
            "successful_users": self.successful_users,
            "providers": self.providers,
            "evidence": self.evidence,
            "mitre_techniques": self.mitre_techniques,
            "recommended_actions": self.recommended_actions,
            "detected_at": self.detected_at.isoformat(),
        }


class CredentialStuffingDetector:
    """Detects credential stuffing attacks across identity providers.

    Credential stuffing uses leaked credentials from data breaches to
    attempt logins. Detection focuses on:
    - High volume of unique users from single IP
    - Automation patterns (consistent timing, user agents)
    - Mix of successes and failures indicating valid leaked credentials

    Attributes:
        query_executor: Executor for querying identity events
        UNIQUE_USER_THRESHOLD: Minimum unique users to trigger detection
        TIME_WINDOW_MINUTES: Default time window for detection
        AUTOMATION_TIMING_VARIANCE_MS: Threshold for automation detection
        SUCCESS_THRESHOLD: Minimum successes for mixed attack detection
        FAILURE_THRESHOLD: Minimum failures for mixed attack detection
    """

    # Detection thresholds
    UNIQUE_USER_THRESHOLD = 20
    TIME_WINDOW_MINUTES = 10
    AUTOMATION_TIMING_VARIANCE_MS = 500  # Suspicious if timing variance is below this
    SUCCESS_THRESHOLD = 5
    FAILURE_THRESHOLD = 10

    # Known bot/automation user agent patterns
    BOT_USER_AGENT_PATTERNS = [
        # Headless browsers
        r"HeadlessChrome",
        r"PhantomJS",
        r"Puppeteer",
        r"Playwright",
        r"Selenium",
        r"WebDriver",
        r"Headless",
        # Python libraries
        r"python-requests",
        r"Python-urllib",
        r"aiohttp",
        r"httpx",
        r"mechanize",
        # HTTP clients
        r"curl/",
        r"wget/",
        r"libwww-perl",
        r"Java/",
        r"Apache-HttpClient",
        r"okhttp",
        r"Go-http-client",
        r"node-fetch",
        r"axios/",
        # Security/attack tools
        r"sqlmap",
        r"nikto",
        r"nmap",
        r"Burp Suite",
        r"OWASP ZAP",
        r"w3af",
        r"Hydra",
        r"Medusa",
        r"gobuster",
        # Generic bot patterns
        r"bot",
        r"crawler",
        r"spider",
        r"scraper",
        # Empty or suspicious patterns
        r"^-$",
        r"^$",
        r"null",
        r"undefined",
    ]

    # Compiled regex patterns for efficiency
    _compiled_patterns: List[re.Pattern] = []

    def __init__(
        self,
        query_executor: Any,
        identity_events_table: str = "identity_events",
        unique_user_threshold: int = None,
        time_window_minutes: int = None,
        automation_timing_variance_ms: float = None,
    ):
        """Initialize the credential stuffing detector.

        Args:
            query_executor: Executor for querying the data lake
            identity_events_table: Name of the identity events table
            unique_user_threshold: Override for unique user threshold
            time_window_minutes: Override for time window
            automation_timing_variance_ms: Override for automation threshold
        """
        self.query_executor = query_executor
        self.identity_events_table = identity_events_table

        if unique_user_threshold is not None:
            self.UNIQUE_USER_THRESHOLD = unique_user_threshold
        if time_window_minutes is not None:
            self.TIME_WINDOW_MINUTES = time_window_minutes
        if automation_timing_variance_ms is not None:
            self.AUTOMATION_TIMING_VARIANCE_MS = automation_timing_variance_ms

        # Compile regex patterns once
        if not self._compiled_patterns:
            self._compiled_patterns = [
                re.compile(pattern, re.IGNORECASE)
                for pattern in self.BOT_USER_AGENT_PATTERNS
            ]

    def detect_credential_stuffing(
        self,
        window_minutes: int = None,
    ) -> List[CredentialStuffingAlert]:
        """Detect credential stuffing attacks.

        Finds IPs with high unique user count within the time window.
        Also checks for mixed success/failure patterns.

        Args:
            window_minutes: Detection window in minutes

        Returns:
            List of CredentialStuffingAlert for each suspicious IP
        """
        window = window_minutes or self.TIME_WINDOW_MINUTES
        alerts = []

        cutoff = datetime.now(timezone.utc) - timedelta(minutes=window)
        cutoff_str = cutoff.strftime("%Y-%m-%d %H:%M:%S")

        # Query for high-volume IPs
        query = f"""
            SELECT
                source_ip,
                COUNT(DISTINCT user_email) as unique_users,
                COUNT(*) as total_attempts,
                COUNT(*) FILTER (WHERE event_type = 'AUTH_SUCCESS') as successes,
                COUNT(*) FILTER (WHERE event_type = 'AUTH_FAILURE') as failures,
                ARRAY_AGG(DISTINCT user_agent) as user_agents,
                ARRAY_AGG(DISTINCT user_email) as user_emails,
                ARRAY_AGG(DISTINCT provider) as providers,
                ARRAY_AGG(user_email) FILTER (WHERE event_type = 'AUTH_SUCCESS')
                    as successful_users,
                MIN(event_timestamp) as first_event,
                MAX(event_timestamp) as last_event
            FROM {self.identity_events_table}
            WHERE event_timestamp >= TIMESTAMP '{cutoff_str}'
              AND source_ip IS NOT NULL
              AND source_ip != ''
            GROUP BY source_ip
            HAVING COUNT(DISTINCT user_email) >= {self.UNIQUE_USER_THRESHOLD}
               OR (COUNT(*) FILTER (WHERE event_type = 'AUTH_SUCCESS') >= {self.SUCCESS_THRESHOLD}
                   AND COUNT(*) FILTER (WHERE event_type = 'AUTH_FAILURE') >= {self.FAILURE_THRESHOLD})
            ORDER BY unique_users DESC
            LIMIT 100
        """

        try:
            result = self.query_executor.execute_query(query, timeout_seconds=120)

            for row in result.rows:
                source_ip = row.get("source_ip")

                # Analyze automation patterns for this IP
                automation_analysis = self.detect_automation_patterns(
                    source_ip=source_ip,
                    window_minutes=window,
                )

                # Generate alert
                alert = self.generate_stuffing_alert(
                    ip_data=row,
                    automation_analysis=automation_analysis,
                    window_minutes=window,
                )
                alerts.append(alert)

        except Exception as e:
            logger.error(f"Error detecting credential stuffing: {e}")

        return alerts

    def detect_automation_patterns(
        self,
        source_ip: str,
        window_minutes: int = None,
    ) -> AutomationAnalysis:
        """Analyze timing patterns to detect automation.

        Calculates inter-event timing variance to identify bot behavior.
        Human users have high variance; bots have consistent timing.

        Args:
            source_ip: IP address to analyze
            window_minutes: Detection window in minutes

        Returns:
            AutomationAnalysis with confidence score and evidence
        """
        window = window_minutes or self.TIME_WINDOW_MINUTES
        analysis = AutomationAnalysis()

        cutoff = datetime.now(timezone.utc) - timedelta(minutes=window)
        cutoff_str = cutoff.strftime("%Y-%m-%d %H:%M:%S")

        # Get ordered events with timestamps
        query = f"""
            SELECT
                event_timestamp,
                user_agent
            FROM {self.identity_events_table}
            WHERE source_ip = '{source_ip}'
              AND event_timestamp >= TIMESTAMP '{cutoff_str}'
            ORDER BY event_timestamp ASC
            LIMIT 1000
        """

        try:
            result = self.query_executor.execute_query(query, timeout_seconds=60)

            if len(result.rows) < 2:
                return analysis

            # Extract timestamps and user agents
            timestamps = []
            user_agents = set()

            for row in result.rows:
                ts = self._parse_timestamp(row.get("event_timestamp"))
                if ts:
                    timestamps.append(ts)
                ua = row.get("user_agent")
                if ua:
                    user_agents.add(ua)

            # Calculate inter-event timing
            if len(timestamps) >= 2:
                intervals_ms = []
                for i in range(1, len(timestamps)):
                    delta = (timestamps[i] - timestamps[i - 1]).total_seconds() * 1000
                    intervals_ms.append(delta)

                if intervals_ms:
                    analysis.timing_mean_ms = statistics.mean(intervals_ms)
                    if len(intervals_ms) >= 2:
                        analysis.timing_variance_ms = statistics.variance(intervals_ms)
                    else:
                        analysis.timing_variance_ms = 0.0

            # Check user agents
            analysis.user_agent_count = len(user_agents)

            # Check for bot signatures
            for ua in user_agents:
                if ua and self.check_known_bot_signatures(ua):
                    analysis.has_bot_signature = True
                    analysis.bot_signatures_found.append(ua)

            # Calculate automation confidence score
            confidence = 0.0

            # Low timing variance indicates automation
            if analysis.timing_variance_ms < self.AUTOMATION_TIMING_VARIANCE_MS:
                confidence += 0.4

            # Single user agent for many requests indicates automation
            if analysis.user_agent_count == 1:
                confidence += 0.2

            # Bot signatures are strong indicators
            if analysis.has_bot_signature:
                confidence += 0.4

            # Very consistent timing (near-zero variance) is highly suspicious
            if analysis.timing_variance_ms < 100:  # Under 100ms variance
                confidence += 0.2

            analysis.confidence_score = min(confidence, 1.0)
            analysis.is_automated = confidence >= 0.5

            analysis.evidence = {
                "event_count": len(timestamps),
                "time_span_seconds": (
                    (timestamps[-1] - timestamps[0]).total_seconds()
                    if len(timestamps) >= 2
                    else 0
                ),
                "unique_user_agents": list(user_agents)[:10],
            }

        except Exception as e:
            logger.error(f"Error analyzing automation patterns: {e}")

        return analysis

    def check_known_bot_signatures(self, user_agent: str) -> bool:
        """Check if user agent matches known bot patterns.

        Args:
            user_agent: User agent string to check

        Returns:
            True if matches known bot pattern
        """
        if not user_agent:
            return True  # Empty user agent is suspicious

        for pattern in self._compiled_patterns:
            if pattern.search(user_agent):
                return True

        return False

    def generate_stuffing_alert(
        self,
        ip_data: Dict[str, Any],
        automation_analysis: AutomationAnalysis,
        window_minutes: int,
    ) -> CredentialStuffingAlert:
        """Generate comprehensive alert for credential stuffing attack.

        Combines IP activity data with automation analysis into alert.

        Args:
            ip_data: Query result data for the source IP
            automation_analysis: Automation pattern analysis results
            window_minutes: Detection window used

        Returns:
            CredentialStuffingAlert with full evidence
        """
        source_ip = ip_data.get("source_ip", "unknown")
        unique_users = ip_data.get("unique_users", 0)
        total_attempts = ip_data.get("total_attempts", 0)
        successes = ip_data.get("successes", 0)
        failures = ip_data.get("failures", 0)
        user_agents = ip_data.get("user_agents", [])
        user_emails = ip_data.get("user_emails", [])
        providers = ip_data.get("providers", [])
        successful_users = ip_data.get("successful_users", [])

        # Calculate success rate
        success_rate = (successes / total_attempts * 100) if total_attempts > 0 else 0

        # Determine severity
        severity = "critical"  # Credential stuffing is always critical

        # Build description
        description_parts = [
            f"Detected credential stuffing attack from IP {source_ip}.",
            f"Targeted {unique_users} unique users with {total_attempts} attempts.",
            f"Success rate: {success_rate:.1f}% ({successes} successes, {failures} failures).",
        ]

        if automation_analysis.is_automated:
            description_parts.append(
                f"Automation confidence: {automation_analysis.confidence_score:.0%}."
            )
        if automation_analysis.has_bot_signature:
            description_parts.append("Known bot signatures detected in user agent.")

        # Build recommended actions
        actions = [
            f"Block IP {source_ip} immediately at firewall/WAF",
        ]

        if successes > 0:
            actions.extend(
                [
                    f"Force password reset for {successes} users with successful logins",
                    "Review successful accounts for post-compromise activity",
                ]
            )

        actions.extend(
            [
                "Check IP against threat intelligence feeds",
                "Review user agents for attack tool signatures",
                "Consider implementing rate limiting by IP",
            ]
        )

        # De-duplicate successful users
        unique_successful_users = list(set(successful_users)) if successful_users else []

        return CredentialStuffingAlert(
            alert_id=str(uuid.uuid4()),
            severity=severity,
            title=f"Credential Stuffing: {unique_users} users from {source_ip}",
            description=" ".join(description_parts),
            source_ip=source_ip,
            unique_user_count=unique_users,
            success_count=successes,
            failure_count=failures,
            success_rate=success_rate,
            user_agents=user_agents if isinstance(user_agents, list) else [user_agents],
            time_window_minutes=window_minutes,
            first_event_time=self._parse_timestamp(ip_data.get("first_event")),
            last_event_time=self._parse_timestamp(ip_data.get("last_event")),
            automation_analysis=automation_analysis,
            targeted_users=(
                user_emails[:100] if isinstance(user_emails, list) else [user_emails]
            ),
            successful_users=unique_successful_users[:50],
            providers=providers if isinstance(providers, list) else [providers],
            evidence={
                "total_attempts": total_attempts,
                "unique_user_agents": len(user_agents) if user_agents else 0,
                "automation_score": automation_analysis.confidence_score,
                "timing_variance_ms": automation_analysis.timing_variance_ms,
            },
            mitre_techniques=["T1110.004"],  # Credential Stuffing
            recommended_actions=actions,
        )

    def run_detection(
        self,
        window_minutes: int = None,
    ) -> List[CredentialStuffingAlert]:
        """Run credential stuffing detection.

        Main entry point that runs detection and returns alerts.

        Args:
            window_minutes: Detection window in minutes

        Returns:
            List of CredentialStuffingAlert
        """
        return self.detect_credential_stuffing(window_minutes=window_minutes)

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
