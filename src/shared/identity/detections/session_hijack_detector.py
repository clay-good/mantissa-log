"""Session hijacking detection for identity events.

Provides detection of session-based attacks including:
- IP address changes mid-session
- Device/user agent changes mid-session
- Concurrent session usage from multiple locations
- Session token replay after logout
- Impossible travel within sessions
"""

import logging
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Set
import hashlib
import re

logger = logging.getLogger(__name__)


class SessionHijackType(Enum):
    """Types of session hijacking detections."""

    IP_CHANGE = "ip_change"  # IP changed mid-session
    DEVICE_CHANGE = "device_change"  # Device changed mid-session
    CONCURRENT_USAGE = "concurrent_usage"  # Same session from multiple IPs
    TOKEN_REPLAY = "token_replay"  # Session used after logout
    IMPOSSIBLE_TRAVEL = "impossible_travel"  # Geographic impossibility in session


@dataclass
class SessionHijackAlert:
    """Alert generated for detected session hijacking.

    Attributes:
        alert_id: Unique identifier for this alert
        alert_type: Type of session hijacking
        severity: Alert severity (critical, high, medium, low)
        title: Human-readable alert title
        description: Detailed description of the hijacking
        session_id: Session ID affected
        user_email: User whose session was hijacked
        original_ip: Original session IP
        new_ip: New/suspicious IP
        original_device: Original device fingerprint
        new_device: New device fingerprint
        provider: Identity provider
        detected_at: When detection occurred
        evidence: Additional evidence data
        mitre_techniques: Associated MITRE ATT&CK techniques
        recommended_actions: Suggested response actions
    """

    alert_id: str
    alert_type: SessionHijackType
    severity: str
    title: str
    description: str
    session_id: str = ""
    user_email: str = ""
    original_ip: str = ""
    new_ip: str = ""
    original_device: str = ""
    new_device: str = ""
    provider: str = ""
    detected_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    evidence: Dict[str, Any] = field(default_factory=dict)
    mitre_techniques: List[str] = field(default_factory=list)
    recommended_actions: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "alert_id": self.alert_id,
            "alert_type": self.alert_type.value,
            "severity": self.severity,
            "title": self.title,
            "description": self.description,
            "session_id": self.session_id,
            "user_email": self.user_email,
            "original_ip": self.original_ip,
            "new_ip": self.new_ip,
            "original_device": self.original_device,
            "new_device": self.new_device,
            "provider": self.provider,
            "detected_at": self.detected_at.isoformat(),
            "evidence": self.evidence,
            "mitre_techniques": self.mitre_techniques,
            "recommended_actions": self.recommended_actions,
        }


@dataclass
class SessionIntegrity:
    """Result of session integrity validation.

    Attributes:
        session_id: Session ID validated
        user_email: User email
        is_valid: Whether session passed all integrity checks
        anomalies: List of detected anomalies
        risk_score: Calculated risk score (0-100)
        recommendation: Recommended action
    """

    session_id: str
    user_email: str
    is_valid: bool
    anomalies: List[Dict[str, Any]] = field(default_factory=list)
    risk_score: float = 0.0
    recommendation: str = "No action needed"

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "session_id": self.session_id,
            "user_email": self.user_email,
            "is_valid": self.is_valid,
            "anomalies": self.anomalies,
            "risk_score": self.risk_score,
            "recommendation": self.recommendation,
        }


class SessionHijackDetector:
    """Detects session hijacking attacks across identity providers.

    Implements detection for:
    1. IP address changes within a session
    2. Device fingerprint changes within a session
    3. Concurrent session usage from multiple IPs
    4. Session token replay after logout
    5. Impossible travel within sessions

    Attributes:
        session_store: Store for session data
        query_executor: Executor for querying identity events
        alert_generator: Optional custom alert generator
    """

    # Known VPN/proxy ASN patterns (partial list)
    KNOWN_VPN_ASNS: Set[str] = {
        "AS9009",   # M247 - VPN provider
        "AS20473",  # Vultr - Cloud/VPN
        "AS14061",  # DigitalOcean
        "AS16509",  # Amazon AWS
        "AS15169",  # Google Cloud
        "AS8075",   # Microsoft Azure
    }

    # Mobile carrier patterns that may legitimately change IPs
    MOBILE_CARRIER_PATTERNS: Set[str] = {
        "verizon", "t-mobile", "att", "sprint", "vodafone",
        "o2", "ee", "three", "orange", "telefonica",
    }

    # Grace period for token replay detection (seconds)
    TOKEN_REPLAY_GRACE_SECONDS = 30

    # Concurrent usage detection window (minutes)
    CONCURRENT_WINDOW_MINUTES = 5

    def __init__(
        self,
        session_store: Any,
        query_executor: Any,
        alert_generator: Any = None,
        identity_events_table: str = "identity_events",
    ):
        """Initialize the session hijack detector.

        Args:
            session_store: Store for managing session data
            query_executor: Executor for querying the data lake
            alert_generator: Optional custom alert generator
            identity_events_table: Name of the identity events table
        """
        self.session_store = session_store
        self.query_executor = query_executor
        self.alert_generator = alert_generator
        self.identity_events_table = identity_events_table

    def detect_session_hijacking(
        self,
        window_hours: int = 24,
    ) -> List[SessionHijackAlert]:
        """Detect all types of session hijacking in active sessions.

        Gets all active sessions and checks for:
        - IP changes
        - Device changes
        - Location changes (impossible travel)

        Args:
            window_hours: Detection window in hours

        Returns:
            List of SessionHijackAlert for detected issues
        """
        alerts = []

        cutoff = datetime.now(timezone.utc) - timedelta(hours=window_hours)
        cutoff_str = cutoff.strftime("%Y-%m-%d %H:%M:%S")

        # Query for session events with changes
        query = f"""
            SELECT
                session_id,
                user_email,
                source_ip,
                source_geo_country,
                source_geo_city,
                device_fingerprint,
                user_agent,
                provider,
                event_type,
                event_timestamp
            FROM {self.identity_events_table}
            WHERE session_id IS NOT NULL
              AND session_id != ''
              AND event_timestamp >= TIMESTAMP '{cutoff_str}'
            ORDER BY session_id, event_timestamp ASC
        """

        try:
            result = self.query_executor.execute_query(query, timeout_seconds=180)

            # Group events by session
            sessions: Dict[str, List[Dict[str, Any]]] = {}
            for row in result.rows:
                session_id = row.get("session_id", "")
                if session_id:
                    if session_id not in sessions:
                        sessions[session_id] = []
                    sessions[session_id].append(row)

            # Analyze each session
            for session_id, events in sessions.items():
                if len(events) < 2:
                    continue  # Need at least 2 events to detect changes

                # Check for IP changes
                ip_alert = self._check_ip_changes(session_id, events)
                if ip_alert:
                    alerts.append(ip_alert)

                # Check for device changes
                device_alert = self._check_device_changes(session_id, events)
                if device_alert:
                    alerts.append(device_alert)

        except Exception as e:
            logger.error(f"Error detecting session hijacking: {e}")

        return alerts

    def detect_ip_change_in_session(
        self,
        session: Any,
    ) -> Optional[SessionHijackAlert]:
        """Detect IP address changes within a specific session.

        Args:
            session: UserSession object to check

        Returns:
            SessionHijackAlert if suspicious IP change detected
        """
        if not session or not session.session_id:
            return None

        # Get all events for this session
        query = f"""
            SELECT
                source_ip,
                source_geo_country,
                source_geo_city,
                event_timestamp,
                event_type,
                user_agent
            FROM {self.identity_events_table}
            WHERE session_id = '{session.session_id}'
            ORDER BY event_timestamp ASC
        """

        try:
            result = self.query_executor.execute_query(query, timeout_seconds=60)

            if len(result.rows) < 2:
                return None

            events = list(result.rows)
            return self._check_ip_changes(session.session_id, events)

        except Exception as e:
            logger.error(f"Error detecting IP change in session: {e}")
            return None

    def detect_device_change_in_session(
        self,
        session: Any,
    ) -> Optional[SessionHijackAlert]:
        """Detect device fingerprint changes within a specific session.

        Device changes mid-session should never occur and are
        a critical indicator of session token theft.

        Args:
            session: UserSession object to check

        Returns:
            SessionHijackAlert if device change detected
        """
        if not session or not session.session_id:
            return None

        query = f"""
            SELECT
                device_fingerprint,
                user_agent,
                source_ip,
                event_timestamp,
                event_type
            FROM {self.identity_events_table}
            WHERE session_id = '{session.session_id}'
            ORDER BY event_timestamp ASC
        """

        try:
            result = self.query_executor.execute_query(query, timeout_seconds=60)

            if len(result.rows) < 2:
                return None

            events = list(result.rows)
            return self._check_device_changes(session.session_id, events)

        except Exception as e:
            logger.error(f"Error detecting device change in session: {e}")
            return None

    def detect_concurrent_session_usage(
        self,
        user_email: str,
    ) -> Optional[SessionHijackAlert]:
        """Detect same session ID used from multiple IPs simultaneously.

        This is definitive evidence of session theft - a single session
        cannot legitimately exist in two places at once.

        Args:
            user_email: User email to check

        Returns:
            SessionHijackAlert if concurrent usage detected
        """
        window = datetime.now(timezone.utc) - timedelta(
            minutes=self.CONCURRENT_WINDOW_MINUTES
        )
        window_str = window.strftime("%Y-%m-%d %H:%M:%S")

        query = f"""
            SELECT
                session_id,
                source_ip,
                source_geo_country,
                source_geo_city,
                device_fingerprint,
                user_agent,
                event_timestamp,
                provider
            FROM {self.identity_events_table}
            WHERE LOWER(user_email) = LOWER('{user_email}')
              AND session_id IS NOT NULL
              AND session_id != ''
              AND event_timestamp >= TIMESTAMP '{window_str}'
            ORDER BY session_id, event_timestamp DESC
        """

        try:
            result = self.query_executor.execute_query(query, timeout_seconds=60)

            # Group by session and check for multiple IPs
            sessions: Dict[str, Dict[str, List[Dict[str, Any]]]] = {}

            for row in result.rows:
                session_id = row.get("session_id", "")
                source_ip = row.get("source_ip", "")

                if session_id and source_ip:
                    if session_id not in sessions:
                        sessions[session_id] = {}
                    if source_ip not in sessions[session_id]:
                        sessions[session_id][source_ip] = []
                    sessions[session_id][source_ip].append(row)

            # Check for sessions with multiple IPs
            for session_id, ip_events in sessions.items():
                unique_ips = list(ip_events.keys())

                # Filter out private IPs
                public_ips = [
                    ip for ip in unique_ips
                    if not self._is_private_ip(ip)
                ]

                if len(public_ips) >= 2:
                    # Get sample events from each IP
                    first_ip = public_ips[0]
                    second_ip = public_ips[1]
                    first_event = ip_events[first_ip][0]
                    second_event = ip_events[second_ip][0]

                    return SessionHijackAlert(
                        alert_id=str(uuid.uuid4()),
                        alert_type=SessionHijackType.CONCURRENT_USAGE,
                        severity="critical",
                        title=f"CRITICAL: Concurrent Session Usage for {user_email}",
                        description=(
                            f"Session {session_id[:16]}... is being used simultaneously "
                            f"from {len(public_ips)} different IPs: {', '.join(public_ips[:3])}. "
                            f"This is definitive evidence of session token theft."
                        ),
                        session_id=session_id,
                        user_email=user_email,
                        original_ip=first_ip,
                        new_ip=second_ip,
                        provider=first_event.get("provider", "unknown"),
                        evidence={
                            "unique_ips": public_ips,
                            "ip_count": len(public_ips),
                            "detection_window_minutes": self.CONCURRENT_WINDOW_MINUTES,
                            "first_ip_country": first_event.get("source_geo_country"),
                            "second_ip_country": second_event.get("source_geo_country"),
                        },
                        mitre_techniques=["T1539", "T1550.001"],
                        recommended_actions=[
                            "IMMEDIATELY terminate this session",
                            f"Identify the attacker IP (likely the newer one: {second_ip})",
                            "Block the attacker IP if possible",
                            "Force password reset for user",
                            "Review all session activity from both IPs",
                            "Investigate token theft vector",
                            "Declare security incident",
                        ],
                    )

        except Exception as e:
            logger.error(f"Error detecting concurrent session usage: {e}")

        return None

    def detect_session_token_replay(
        self,
        window_hours: int = 24,
    ) -> List[SessionHijackAlert]:
        """Detect session tokens being used after logout.

        Finds cases where a session continues to be used after
        a SESSION_END event was recorded.

        Args:
            window_hours: Detection window in hours

        Returns:
            List of SessionHijackAlert for token replays
        """
        alerts = []

        cutoff = datetime.now(timezone.utc) - timedelta(hours=window_hours)
        cutoff_str = cutoff.strftime("%Y-%m-%d %H:%M:%S")

        # Find sessions that ended
        end_query = f"""
            SELECT
                session_id,
                user_email,
                event_timestamp as end_time,
                source_ip as end_ip,
                provider
            FROM {self.identity_events_table}
            WHERE event_type = 'SESSION_END'
              AND session_id IS NOT NULL
              AND session_id != ''
              AND event_timestamp >= TIMESTAMP '{cutoff_str}'
        """

        try:
            end_result = self.query_executor.execute_query(end_query, timeout_seconds=60)

            for end_row in end_result.rows:
                session_id = end_row.get("session_id", "")
                end_time = end_row.get("end_time")
                user_email = end_row.get("user_email", "")

                if not session_id or not end_time:
                    continue

                if isinstance(end_time, str):
                    end_time = datetime.fromisoformat(end_time.replace("Z", "+00:00"))

                # Check for activity after logout
                grace_time = end_time + timedelta(seconds=self.TOKEN_REPLAY_GRACE_SECONDS)
                grace_str = grace_time.strftime("%Y-%m-%d %H:%M:%S")

                activity_query = f"""
                    SELECT
                        source_ip,
                        source_geo_country,
                        event_type,
                        event_timestamp,
                        device_fingerprint
                    FROM {self.identity_events_table}
                    WHERE session_id = '{session_id}'
                      AND event_type != 'SESSION_END'
                      AND event_timestamp > TIMESTAMP '{grace_str}'
                    ORDER BY event_timestamp ASC
                    LIMIT 10
                """

                activity_result = self.query_executor.execute_query(
                    activity_query, timeout_seconds=30
                )

                if activity_result.rows:
                    # Token replay detected
                    replay_event = activity_result.rows[0]
                    replay_time = replay_event.get("event_timestamp")

                    if isinstance(replay_time, str):
                        replay_time = datetime.fromisoformat(
                            replay_time.replace("Z", "+00:00")
                        )

                    delay_seconds = (replay_time - end_time).total_seconds()

                    # Determine severity based on delay
                    if delay_seconds < 60:
                        severity = "high"  # Could be race condition
                    else:
                        severity = "critical"  # Definitive theft

                    alert = SessionHijackAlert(
                        alert_id=str(uuid.uuid4()),
                        alert_type=SessionHijackType.TOKEN_REPLAY,
                        severity=severity,
                        title=f"Session Token Replay: {user_email}",
                        description=(
                            f"Session {session_id[:16]}... continued to be used "
                            f"{delay_seconds:.0f} seconds after logout. "
                            f"Activity from IP {replay_event.get('source_ip', 'unknown')}. "
                            f"This indicates token theft and replay."
                        ),
                        session_id=session_id,
                        user_email=user_email,
                        original_ip=end_row.get("end_ip", ""),
                        new_ip=replay_event.get("source_ip", ""),
                        provider=end_row.get("provider", "unknown"),
                        evidence={
                            "logout_time": end_time.isoformat(),
                            "replay_time": replay_time.isoformat() if replay_time else None,
                            "delay_seconds": delay_seconds,
                            "replay_event_count": len(activity_result.rows),
                            "replay_event_type": replay_event.get("event_type"),
                        },
                        mitre_techniques=["T1539", "T1550.001"],
                        recommended_actions=[
                            "Force invalidate the session token at IdP level",
                            "Review all activity after logout",
                            "Check for data access or exfiltration",
                            "Investigate how token was obtained",
                            "Check if refresh tokens are compromised",
                            "Force password reset",
                        ],
                    )
                    alerts.append(alert)

        except Exception as e:
            logger.error(f"Error detecting session token replay: {e}")

        return alerts

    def validate_session_integrity(
        self,
        session: Any,
    ) -> SessionIntegrity:
        """Perform full session integrity check.

        Validates all aspects of session security and returns
        a comprehensive report for investigation.

        Args:
            session: UserSession object to validate

        Returns:
            SessionIntegrity containing all findings
        """
        anomalies = []
        risk_score = 0.0

        if not session:
            return SessionIntegrity(
                session_id="",
                user_email="",
                is_valid=False,
                anomalies=[{"type": "invalid_session", "message": "Session is None"}],
                risk_score=100.0,
                recommendation="Invalid session object",
            )

        session_id = getattr(session, "session_id", "")
        user_email = getattr(session, "user_email", "")

        # Get all events for the session
        query = f"""
            SELECT
                source_ip,
                source_geo_country,
                source_geo_city,
                device_fingerprint,
                user_agent,
                event_type,
                event_timestamp
            FROM {self.identity_events_table}
            WHERE session_id = '{session_id}'
            ORDER BY event_timestamp ASC
        """

        try:
            result = self.query_executor.execute_query(query, timeout_seconds=60)
            events = list(result.rows)

            if not events:
                return SessionIntegrity(
                    session_id=session_id,
                    user_email=user_email,
                    is_valid=True,
                    anomalies=[],
                    risk_score=0.0,
                    recommendation="No events found for session",
                )

            # Check IP consistency
            ips = set(e.get("source_ip", "") for e in events if e.get("source_ip"))
            if len(ips) > 1:
                anomalies.append({
                    "type": "ip_change",
                    "severity": "high",
                    "message": f"Session used from {len(ips)} different IPs",
                    "ips": list(ips),
                })
                risk_score += 30

            # Check device consistency
            devices = set(
                e.get("device_fingerprint", "") for e in events
                if e.get("device_fingerprint")
            )
            if len(devices) > 1:
                anomalies.append({
                    "type": "device_change",
                    "severity": "critical",
                    "message": f"Session used from {len(devices)} different devices",
                    "devices": list(devices),
                })
                risk_score += 50

            # Check user agent consistency
            user_agents = set(e.get("user_agent", "") for e in events if e.get("user_agent"))
            if len(user_agents) > 1:
                # Parse and compare
                ua_signatures = set(self._get_ua_signature(ua) for ua in user_agents)
                if len(ua_signatures) > 1:
                    anomalies.append({
                        "type": "user_agent_change",
                        "severity": "high",
                        "message": "User agent changed significantly",
                        "user_agents": list(user_agents),
                    })
                    risk_score += 25

            # Check country consistency
            countries = set(
                e.get("source_geo_country", "") for e in events
                if e.get("source_geo_country")
            )
            if len(countries) > 1:
                anomalies.append({
                    "type": "country_change",
                    "severity": "critical",
                    "message": f"Session used from {len(countries)} different countries",
                    "countries": list(countries),
                })
                risk_score += 40

            # Check session duration
            if events:
                first_time = events[0].get("event_timestamp")
                last_time = events[-1].get("event_timestamp")

                if isinstance(first_time, str):
                    first_time = datetime.fromisoformat(first_time.replace("Z", "+00:00"))
                if isinstance(last_time, str):
                    last_time = datetime.fromisoformat(last_time.replace("Z", "+00:00"))

                if first_time and last_time:
                    duration_hours = (last_time - first_time).total_seconds() / 3600
                    if duration_hours > 24:
                        anomalies.append({
                            "type": "long_session",
                            "severity": "medium",
                            "message": f"Session duration: {duration_hours:.1f} hours",
                        })
                        risk_score += 10

            # Check for ended session activity
            ended_events = [e for e in events if e.get("event_type") == "SESSION_END"]
            if ended_events:
                end_time = ended_events[0].get("event_timestamp")
                later_events = [
                    e for e in events
                    if e.get("event_type") != "SESSION_END"
                    and e.get("event_timestamp") > end_time
                ]
                if later_events:
                    anomalies.append({
                        "type": "token_replay",
                        "severity": "critical",
                        "message": f"Session used {len(later_events)} times after logout",
                    })
                    risk_score += 50

            # Cap risk score at 100
            risk_score = min(risk_score, 100.0)

            # Determine recommendation
            if risk_score >= 70:
                recommendation = "TERMINATE SESSION IMMEDIATELY - High risk of compromise"
            elif risk_score >= 40:
                recommendation = "Force re-authentication and investigate"
            elif risk_score >= 20:
                recommendation = "Monitor closely and verify with user"
            else:
                recommendation = "Session appears normal"

            return SessionIntegrity(
                session_id=session_id,
                user_email=user_email,
                is_valid=(risk_score < 40),
                anomalies=anomalies,
                risk_score=risk_score,
                recommendation=recommendation,
            )

        except Exception as e:
            logger.error(f"Error validating session integrity: {e}")
            return SessionIntegrity(
                session_id=session_id,
                user_email=user_email,
                is_valid=False,
                anomalies=[{"type": "error", "message": str(e)}],
                risk_score=100.0,
                recommendation="Error during validation - treat as suspicious",
            )

    def run_all_detections(
        self,
        window_hours: int = 24,
    ) -> List[SessionHijackAlert]:
        """Run all session hijacking detection methods.

        Args:
            window_hours: Detection window in hours

        Returns:
            Combined list of all alerts
        """
        all_alerts = []

        # Main hijacking detection
        hijack_alerts = self.detect_session_hijacking(window_hours)
        all_alerts.extend(hijack_alerts)

        # Token replay detection
        replay_alerts = self.detect_session_token_replay(window_hours)
        all_alerts.extend(replay_alerts)

        # Sort by severity
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        all_alerts.sort(
            key=lambda a: (severity_order.get(a.severity, 4), a.detected_at)
        )

        return all_alerts

    def _check_ip_changes(
        self,
        session_id: str,
        events: List[Dict[str, Any]],
    ) -> Optional[SessionHijackAlert]:
        """Check for suspicious IP changes in session events.

        Args:
            session_id: Session ID
            events: List of session events in chronological order

        Returns:
            SessionHijackAlert if suspicious change detected
        """
        if not events:
            return None

        original_ip = None
        original_country = None
        user_email = events[0].get("user_email", "unknown")
        provider = events[0].get("provider", "unknown")

        for event in events:
            current_ip = event.get("source_ip", "")
            current_country = event.get("source_geo_country", "")

            if not current_ip:
                continue

            if original_ip is None:
                original_ip = current_ip
                original_country = current_country
                continue

            if current_ip != original_ip:
                # Check if this is a legitimate change
                if self._is_legitimate_ip_change(
                    original_ip, current_ip, event.get("user_agent", "")
                ):
                    continue

                # Determine severity
                if current_country and original_country and current_country != original_country:
                    severity = "critical"
                elif self._is_datacenter_ip(current_ip):
                    severity = "high"
                else:
                    severity = "high"

                return SessionHijackAlert(
                    alert_id=str(uuid.uuid4()),
                    alert_type=SessionHijackType.IP_CHANGE,
                    severity=severity,
                    title=f"Session IP Change: {user_email}",
                    description=(
                        f"Session {session_id[:16]}... changed IP from "
                        f"{original_ip} ({original_country or 'unknown'}) to "
                        f"{current_ip} ({current_country or 'unknown'}). "
                        f"This may indicate session hijacking."
                    ),
                    session_id=session_id,
                    user_email=user_email,
                    original_ip=original_ip,
                    new_ip=current_ip,
                    provider=provider,
                    evidence={
                        "original_country": original_country,
                        "new_country": current_country,
                        "event_type": event.get("event_type"),
                        "event_time": str(event.get("event_timestamp")),
                    },
                    mitre_techniques=["T1539", "T1550.001"],
                    recommended_actions=[
                        "Review the session activity",
                        "Check if IP change is geographically reasonable",
                        "Verify if user has VPN or mobile patterns",
                        "Consider terminating the session",
                    ],
                )

        return None

    def _check_device_changes(
        self,
        session_id: str,
        events: List[Dict[str, Any]],
    ) -> Optional[SessionHijackAlert]:
        """Check for device fingerprint changes in session events.

        Args:
            session_id: Session ID
            events: List of session events in chronological order

        Returns:
            SessionHijackAlert if device change detected (always critical)
        """
        if not events:
            return None

        original_device = None
        original_ua = None
        user_email = events[0].get("user_email", "unknown")
        provider = events[0].get("provider", "unknown")

        for event in events:
            current_device = event.get("device_fingerprint", "")
            current_ua = event.get("user_agent", "")

            # Use device fingerprint if available, otherwise user agent
            if original_device is None and (current_device or current_ua):
                original_device = current_device
                original_ua = current_ua
                continue

            # Check device fingerprint change
            if current_device and original_device and current_device != original_device:
                return self._create_device_change_alert(
                    session_id, user_email, provider,
                    original_device, current_device,
                    original_ua, current_ua, event
                )

            # Check user agent change (significant)
            if current_ua and original_ua:
                if not self._are_user_agents_similar(original_ua, current_ua):
                    return self._create_device_change_alert(
                        session_id, user_email, provider,
                        original_device or "unknown", current_device or "unknown",
                        original_ua, current_ua, event
                    )

        return None

    def _create_device_change_alert(
        self,
        session_id: str,
        user_email: str,
        provider: str,
        original_device: str,
        new_device: str,
        original_ua: str,
        new_ua: str,
        event: Dict[str, Any],
    ) -> SessionHijackAlert:
        """Create alert for device change detection.

        Args:
            session_id: Session ID
            user_email: User email
            provider: Identity provider
            original_device: Original device fingerprint
            new_device: New device fingerprint
            original_ua: Original user agent
            new_ua: New user agent
            event: Event that triggered detection

        Returns:
            SessionHijackAlert
        """
        return SessionHijackAlert(
            alert_id=str(uuid.uuid4()),
            alert_type=SessionHijackType.DEVICE_CHANGE,
            severity="critical",  # Device changes are always critical
            title=f"CRITICAL: Device Change in Session for {user_email}",
            description=(
                f"Session {session_id[:16]}... showed device change. "
                f"Original: {original_device[:32] if original_device else 'unknown'}... "
                f"New: {new_device[:32] if new_device else 'unknown'}... "
                f"Devices should NEVER change mid-session."
            ),
            session_id=session_id,
            user_email=user_email,
            original_device=original_device,
            new_device=new_device,
            provider=provider,
            evidence={
                "original_user_agent": original_ua,
                "new_user_agent": new_ua,
                "event_type": event.get("event_type"),
                "event_time": str(event.get("event_timestamp")),
                "source_ip": event.get("source_ip"),
            },
            mitre_techniques=["T1539", "T1550.001", "T1528"],
            recommended_actions=[
                "IMMEDIATELY terminate this session",
                "Force re-authentication for the user",
                "Review all actions after device change",
                "Check for data access or exfiltration",
                "Investigate how token was stolen",
            ],
        )

    def _is_legitimate_ip_change(
        self,
        original_ip: str,
        new_ip: str,
        user_agent: str,
    ) -> bool:
        """Check if an IP change might be legitimate.

        Args:
            original_ip: Original IP address
            new_ip: New IP address
            user_agent: User agent string

        Returns:
            True if change might be legitimate
        """
        # Check if mobile user (IP changes are common)
        if user_agent:
            ua_lower = user_agent.lower()
            if "mobile" in ua_lower or "android" in ua_lower or "iphone" in ua_lower:
                return True

        # Check if same /24 subnet (NAT rotation)
        try:
            orig_parts = original_ip.split(".")
            new_parts = new_ip.split(".")
            if len(orig_parts) == 4 and len(new_parts) == 4:
                if orig_parts[:3] == new_parts[:3]:
                    return True
        except Exception:
            pass

        return False

    def _is_private_ip(self, ip: str) -> bool:
        """Check if IP is a private/internal address.

        Args:
            ip: IP address to check

        Returns:
            True if private IP
        """
        if not ip:
            return True

        try:
            parts = ip.split(".")
            if len(parts) != 4:
                return True  # Invalid, treat as private

            first = int(parts[0])
            second = int(parts[1])

            # 10.0.0.0/8
            if first == 10:
                return True

            # 172.16.0.0/12
            if first == 172 and 16 <= second <= 31:
                return True

            # 192.168.0.0/16
            if first == 192 and second == 168:
                return True

            # 127.0.0.0/8
            if first == 127:
                return True

        except Exception:
            return True

        return False

    def _is_datacenter_ip(self, ip: str) -> bool:
        """Check if IP belongs to known datacenter/cloud provider.

        Args:
            ip: IP address to check

        Returns:
            True if datacenter IP (simplified check)
        """
        # This is a simplified check - production would use ASN lookup
        # Common datacenter IP patterns (very simplified)
        datacenter_prefixes = [
            "35.", "34.", "104.", "108.",  # Google
            "52.", "54.", "18.", "3.",      # AWS
            "13.", "20.", "40.",            # Azure
            "45.", "66.", "67.",            # Various hosting
        ]

        for prefix in datacenter_prefixes:
            if ip.startswith(prefix):
                return True

        return False

    def _are_user_agents_similar(
        self,
        ua1: str,
        ua2: str,
    ) -> bool:
        """Check if two user agents are similar (same browser/OS).

        Args:
            ua1: First user agent
            ua2: Second user agent

        Returns:
            True if user agents are similar
        """
        sig1 = self._get_ua_signature(ua1)
        sig2 = self._get_ua_signature(ua2)

        return sig1 == sig2

    def _get_ua_signature(self, user_agent: str) -> str:
        """Extract a simplified signature from user agent.

        Args:
            user_agent: User agent string

        Returns:
            Simplified signature for comparison
        """
        if not user_agent:
            return ""

        ua_lower = user_agent.lower()

        # Determine browser
        browser = "unknown"
        if "firefox" in ua_lower:
            browser = "firefox"
        elif "edg" in ua_lower:
            browser = "edge"
        elif "chrome" in ua_lower:
            browser = "chrome"
        elif "safari" in ua_lower:
            browser = "safari"

        # Determine OS
        os = "unknown"
        if "windows" in ua_lower:
            os = "windows"
        elif "mac" in ua_lower or "macos" in ua_lower:
            os = "macos"
        elif "linux" in ua_lower:
            os = "linux"
        elif "android" in ua_lower:
            os = "android"
        elif "iphone" in ua_lower or "ipad" in ua_lower:
            os = "ios"

        # Determine device type
        device = "desktop"
        if "mobile" in ua_lower or "android" in ua_lower or "iphone" in ua_lower:
            device = "mobile"
        elif "tablet" in ua_lower or "ipad" in ua_lower:
            device = "tablet"

        return f"{browser}:{os}:{device}"
