"""Session tracker for identity events.

Processes IdentityEvents and maintains session state, detecting
concurrent sessions and session anomalies.
"""

import hashlib
import logging
import math
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Optional, Tuple
import uuid

from ..models.identity_event import IdentityEvent, IdentityEventType, GeoLocation
from .session_store import (
    SessionStore,
    SessionStatus,
    UserSession,
    ConcurrentSessionAlert,
    SessionAnomaly,
    AnomalyType,
    InMemorySessionStore,
)

logger = logging.getLogger(__name__)


class SessionTracker:
    """Tracks identity sessions and detects session-based anomalies.

    Processes IdentityEvents to maintain session state and detect:
    - Concurrent sessions from different locations/devices
    - Session hijacking attempts
    - Impossible travel scenarios
    - Unusual session patterns
    """

    # Earth radius in kilometers for haversine calculation
    EARTH_RADIUS_KM = 6371

    # Maximum travel speed in km/h for impossible travel detection
    MAX_TRAVEL_SPEED_KMH = 800

    # Concurrent session thresholds
    CONCURRENT_SESSION_WINDOW_MINUTES = 5
    MAX_NORMAL_CONCURRENT_SESSIONS = 2

    # Session idle timeout
    SESSION_IDLE_TIMEOUT_MINUTES = 60

    # Risk score weights
    ANOMALY_RISK_WEIGHTS = {
        AnomalyType.IMPOSSIBLE_TRAVEL: 40.0,
        AnomalyType.CONCURRENT_SESSION: 25.0,
        AnomalyType.SESSION_HIJACK_SUSPECTED: 50.0,
        AnomalyType.NEW_IP: 15.0,
        AnomalyType.NEW_DEVICE: 15.0,
        AnomalyType.NEW_LOCATION: 20.0,
        AnomalyType.UNUSUAL_TIME: 10.0,
        AnomalyType.LONG_SESSION: 10.0,
        AnomalyType.RAPID_PROVIDER_SWITCH: 20.0,
    }

    def __init__(
        self,
        store: Optional[SessionStore] = None,
        max_concurrent_sessions: int = 2,
        session_idle_timeout_minutes: int = 60,
        session_timeout_minutes: Optional[int] = None,  # Alias
        enable_impossible_travel_detection: bool = True,
        query_executor: Optional[Any] = None,
    ):
        """Initialize SessionTracker.

        Args:
            store: Session storage backend (defaults to InMemorySessionStore)
            max_concurrent_sessions: Max concurrent sessions before alerting
            session_idle_timeout_minutes: Minutes of inactivity before session expires
            session_timeout_minutes: Alias for session_idle_timeout_minutes
            enable_impossible_travel_detection: Whether to detect impossible travel
            query_executor: Optional query executor for database operations
        """
        self.store = store or InMemorySessionStore()
        self.max_concurrent_sessions = max_concurrent_sessions
        # Handle both parameter names
        self.session_idle_timeout_minutes = session_timeout_minutes or session_idle_timeout_minutes
        self.session_timeout_minutes = self.session_idle_timeout_minutes
        self.enable_impossible_travel_detection = enable_impossible_travel_detection
        self.query_executor = query_executor

    def create_session(self, event: IdentityEvent) -> UserSession:
        """Create a new session from an identity event.

        This is the public API for tests. Internally uses _handle_session_start.

        Args:
            event: IdentityEvent to create session from

        Returns:
            Created UserSession
        """
        # Use device_id directly if available, otherwise create fingerprint
        device_id = event.device_id
        device_fingerprint = device_id or self._create_device_fingerprint(event)

        # Create new session
        session = UserSession(
            session_id=str(uuid.uuid4()),
            user_id=event.user_id or "",
            user_email=event.user_email or "",
            provider=event.provider or "",
            started_at=event.timestamp,
            last_activity=event.timestamp,
            source_ip=event.source_ip or "",
            source_geo=event.source_geo,
            device_fingerprint=device_fingerprint,
            user_agent=event.user_agent,
            application_name=event.application_name,
            is_active=True,
            risk_score=0.0,
            risk_factors=[],
            provider_session_id=event.session_id,
        )

        # Set device_id override if provided
        if device_id:
            session._device_id_override = device_id

        # Store the session
        self.store.create_session(session)

        logger.info(
            f"Created session {session.session_id} for {session.user_email} "
            f"from {session.source_ip} via {session.provider}"
        )

        return session

    def on_identity_event(self, event: IdentityEvent) -> Optional[UserSession]:
        """Process an identity event and update session state.

        Args:
            event: IdentityEvent to process

        Returns:
            Updated or created UserSession, or None if not applicable
        """
        if not event.user_email:
            logger.debug(f"Skipping event without user_email: {event.event_id}")
            return None

        # Handle event based on type
        if event.event_type in (
            IdentityEventType.AUTH_SUCCESS,
            IdentityEventType.SESSION_START,
            IdentityEventType.MFA_SUCCESS,
        ):
            return self._handle_session_start(event)

        elif event.event_type == IdentityEventType.SESSION_END:
            return self._handle_session_end(event)

        elif event.event_type in (
            IdentityEventType.AUTH_FAILURE,
            IdentityEventType.MFA_FAILURE,
        ):
            # Update existing session's last_activity if any
            return self._handle_auth_activity(event)

        else:
            # Other events - update session activity
            return self._handle_auth_activity(event)

    def _handle_session_start(self, event: IdentityEvent) -> UserSession:
        """Handle session start event."""
        # Create device fingerprint
        device_fingerprint = self._create_device_fingerprint(event)

        # Create new session
        session = UserSession(
            session_id=event.session_id or str(uuid.uuid4()),
            user_id=event.user_id,
            user_email=event.user_email,
            provider=event.provider,
            started_at=event.timestamp,
            last_activity=event.timestamp,
            source_ip=event.source_ip or "",
            source_geo=event.source_geo,
            device_fingerprint=device_fingerprint,
            user_agent=event.user_agent,
            application_name=event.application_name,
            is_active=True,
            risk_score=0.0,
            risk_factors=[],
        )

        # Check for anomalies before creating
        anomalies = self.detect_session_anomalies(session)
        if anomalies:
            session.risk_score = self.get_session_risk_score(session, anomalies)
            session.risk_factors = [a.anomaly_type.value for a in anomalies]

        # Create session
        self.store.create_session(session)

        logger.info(
            f"Created session {session.session_id} for {session.user_email} "
            f"from {session.source_ip} via {session.provider}"
        )

        return session

    def _handle_session_end(self, event: IdentityEvent) -> Optional[UserSession]:
        """Handle session end event."""
        # Try to find matching session
        session = None

        if event.session_id:
            session = self.store.get_session(event.session_id)

        if not session:
            # Try to find most recent active session for user
            active_sessions = self.store.get_active_sessions_for_user(event.user_email)
            if active_sessions:
                # Find session matching provider
                for s in active_sessions:
                    if s.provider == event.provider:
                        session = s
                        break
                # Fall back to most recent
                if not session:
                    session = max(active_sessions, key=lambda s: s.last_activity)

        if session:
            self.store.end_session(session.session_id, "logout")
            logger.info(f"Ended session {session.session_id} for {event.user_email}")
            return session

        logger.debug(f"No active session found to end for {event.user_email}")
        return None

    def _handle_auth_activity(self, event: IdentityEvent) -> Optional[UserSession]:
        """Handle authentication activity event."""
        active_sessions = self.store.get_active_sessions_for_user(event.user_email)

        if not active_sessions:
            # No active session - may be implicit session start
            if event.event_type in (
                IdentityEventType.AUTH_SUCCESS,
                IdentityEventType.MFA_SUCCESS,
            ):
                return self._handle_session_start(event)
            return None

        # Find matching session by provider/IP
        matching_session = None
        for session in active_sessions:
            if session.provider == event.provider:
                if session.source_ip == event.source_ip:
                    matching_session = session
                    break
                # Same provider, different IP - might be session update
                if not matching_session:
                    matching_session = session

        if matching_session:
            # Update last activity
            updates = {"last_activity": event.timestamp}

            # Update IP if changed (could indicate session hijack)
            if event.source_ip and event.source_ip != matching_session.source_ip:
                updates["source_ip"] = event.source_ip
                if event.source_geo:
                    updates["source_geo"] = event.source_geo.to_dict()

            self.store.update_session(matching_session.session_id, updates)

            # Refresh session
            return self.store.get_session(matching_session.session_id)

        return None

    def detect_concurrent_sessions(
        self,
        user_email: str,
        active_sessions: Optional[List[UserSession]] = None,
    ) -> Optional[ConcurrentSessionAlert]:
        """Detect concurrent active sessions for a user.

        Args:
            user_email: User's email address
            active_sessions: Pre-fetched active sessions (optional)

        Returns:
            ConcurrentSessionAlert if suspicious concurrency detected, None otherwise
            Returns True (bool) if active_sessions provided and concurrent detected
        """
        # If active_sessions provided, just check if there are multiple
        if active_sessions is not None:
            if len(active_sessions) > 1:
                return True  # type: ignore
            return None

        concurrent = self.store.get_concurrent_sessions(user_email)

        if len(concurrent) <= 1:
            return None

        # Check if concurrent sessions are from different locations/IPs
        unique_ips = set(s.source_ip for s in concurrent if s.source_ip)
        unique_providers = set(s.provider for s in concurrent)

        if len(unique_ips) <= 1 and len(unique_providers) <= 1:
            # Same IP, same provider - likely legitimate (multiple tabs)
            if len(concurrent) <= self.max_concurrent_sessions:
                return None

        # Determine risk level
        risk_level = "low"
        alert_reason = f"Multiple active sessions detected ({len(concurrent)})"

        if len(unique_ips) > 1:
            risk_level = "medium"
            alert_reason = f"Sessions from {len(unique_ips)} different IPs"

            # Check for impossible travel between sessions
            if self.enable_impossible_travel_detection:
                if self._check_impossible_travel_between_sessions(concurrent):
                    risk_level = "high"
                    alert_reason = "Impossible travel detected between concurrent sessions"

        if len(unique_providers) > 1:
            # Different providers might be okay (SSO federation)
            if risk_level == "low":
                risk_level = "medium"

        return ConcurrentSessionAlert(
            user_email=user_email,
            sessions=concurrent,
            risk_level=risk_level,
            detected_at=datetime.now(timezone.utc),
            alert_reason=alert_reason,
        )

    def detect_session_anomalies(self, session: UserSession) -> List[SessionAnomaly]:
        """Detect anomalies in a session compared to user's history.

        Args:
            session: UserSession to analyze

        Returns:
            List of detected SessionAnomaly objects
        """
        anomalies = []

        # Get user's recent session history
        recent_sessions = self.store.get_recent_sessions_for_user(
            session.user_email, hours=168  # 7 days
        )

        # Exclude the current session
        recent_sessions = [s for s in recent_sessions if s.session_id != session.session_id]

        if not recent_sessions:
            # No history - can't detect anomalies
            return anomalies

        # Check for new IP
        known_ips = set(s.source_ip for s in recent_sessions if s.source_ip)
        if session.source_ip and session.source_ip not in known_ips:
            anomalies.append(SessionAnomaly(
                session_id=session.session_id,
                anomaly_type=AnomalyType.NEW_IP,
                confidence=0.7,
                details={
                    "new_ip": session.source_ip,
                    "known_ips_count": len(known_ips),
                },
            ))

        # Check for new device
        known_fingerprints = set(s.device_fingerprint for s in recent_sessions if s.device_fingerprint)
        if session.device_fingerprint and session.device_fingerprint not in known_fingerprints:
            anomalies.append(SessionAnomaly(
                session_id=session.session_id,
                anomaly_type=AnomalyType.NEW_DEVICE,
                confidence=0.6,
                details={
                    "device_fingerprint": session.device_fingerprint,
                    "known_devices_count": len(known_fingerprints),
                },
            ))

        # Check for new location (country)
        known_countries = set()
        for s in recent_sessions:
            if s.source_geo and s.source_geo.country:
                known_countries.add(s.source_geo.country)

        if session.source_geo and session.source_geo.country:
            if session.source_geo.country not in known_countries:
                anomalies.append(SessionAnomaly(
                    session_id=session.session_id,
                    anomaly_type=AnomalyType.NEW_LOCATION,
                    confidence=0.8,
                    details={
                        "new_country": session.source_geo.country,
                        "known_countries": list(known_countries),
                    },
                ))

        # Check for impossible travel
        if self.enable_impossible_travel_detection:
            impossible_travel = self._check_impossible_travel(session, recent_sessions)
            if impossible_travel:
                anomalies.append(impossible_travel)

        # Check for unusual time
        unusual_time = self._check_unusual_time(session, recent_sessions)
        if unusual_time:
            anomalies.append(unusual_time)

        # Check for rapid provider switching
        rapid_switch = self._check_rapid_provider_switch(session, recent_sessions)
        if rapid_switch:
            anomalies.append(rapid_switch)

        return anomalies

    def get_session_risk_score(
        self, session: UserSession, anomalies: Optional[List[SessionAnomaly]] = None
    ) -> float:
        """Calculate risk score for a session based on anomalies.

        Args:
            session: UserSession to score
            anomalies: Pre-computed anomalies (will be computed if None)

        Returns:
            Risk score from 0-100
        """
        if anomalies is None:
            anomalies = self.detect_session_anomalies(session)

        if not anomalies:
            return 0.0

        total_score = 0.0

        for anomaly in anomalies:
            weight = self.ANOMALY_RISK_WEIGHTS.get(anomaly.anomaly_type, 10.0)
            total_score += weight * anomaly.confidence

        # Cap at 100
        return min(100.0, total_score)

    def _create_device_fingerprint(self, event: IdentityEvent) -> Optional[str]:
        """Create a device fingerprint from event data."""
        parts = []

        if event.device_id:
            parts.append(event.device_id)
        if event.device_type:
            parts.append(event.device_type)
        if event.user_agent:
            # Use first 100 chars of user agent
            parts.append(event.user_agent[:100])

        if not parts:
            return None

        fingerprint_data = "|".join(parts)
        return hashlib.sha256(fingerprint_data.encode()).hexdigest()[:32]

    def _check_impossible_travel(
        self, session: UserSession, recent_sessions: List[UserSession]
    ) -> Optional[SessionAnomaly]:
        """Check for impossible travel between sessions."""
        if not session.source_geo or not session.source_geo.lat:
            return None

        # Find most recent session with geo data
        most_recent = None
        for s in sorted(recent_sessions, key=lambda x: x.last_activity, reverse=True):
            if s.source_geo and s.source_geo.lat:
                most_recent = s
                break

        if not most_recent:
            return None

        # Calculate distance
        distance_km = self._haversine_distance(
            session.source_geo.lat, session.source_geo.lon,
            most_recent.source_geo.lat, most_recent.source_geo.lon
        )

        # Calculate time difference
        session_time = session.started_at
        recent_time = most_recent.last_activity

        if session_time.tzinfo is None:
            session_time = session_time.replace(tzinfo=timezone.utc)
        if recent_time.tzinfo is None:
            recent_time = recent_time.replace(tzinfo=timezone.utc)

        time_diff_hours = abs((session_time - recent_time).total_seconds() / 3600)

        if time_diff_hours == 0:
            time_diff_hours = 0.01  # Avoid division by zero

        # Calculate required speed
        required_speed_kmh = distance_km / time_diff_hours

        if required_speed_kmh > self.MAX_TRAVEL_SPEED_KMH:
            return SessionAnomaly(
                session_id=session.session_id,
                anomaly_type=AnomalyType.IMPOSSIBLE_TRAVEL,
                confidence=min(1.0, required_speed_kmh / (self.MAX_TRAVEL_SPEED_KMH * 2)),
                details={
                    "distance_km": round(distance_km, 2),
                    "time_hours": round(time_diff_hours, 2),
                    "required_speed_kmh": round(required_speed_kmh, 2),
                    "from_location": {
                        "country": most_recent.source_geo.country,
                        "city": most_recent.source_geo.city,
                    },
                    "to_location": {
                        "country": session.source_geo.country,
                        "city": session.source_geo.city,
                    },
                },
            )

        return None

    def _check_impossible_travel_between_sessions(
        self, sessions: List[UserSession]
    ) -> bool:
        """Check for impossible travel between concurrent sessions."""
        geo_sessions = [s for s in sessions if s.source_geo and s.source_geo.lat]

        if len(geo_sessions) < 2:
            return False

        for i, s1 in enumerate(geo_sessions):
            for s2 in geo_sessions[i + 1:]:
                distance_km = self._haversine_distance(
                    s1.source_geo.lat, s1.source_geo.lon,
                    s2.source_geo.lat, s2.source_geo.lon
                )

                # Calculate time difference between last activities
                time1 = s1.last_activity
                time2 = s2.last_activity
                if time1.tzinfo is None:
                    time1 = time1.replace(tzinfo=timezone.utc)
                if time2.tzinfo is None:
                    time2 = time2.replace(tzinfo=timezone.utc)

                time_diff_hours = abs((time1 - time2).total_seconds() / 3600)

                if time_diff_hours == 0:
                    time_diff_hours = 0.01

                required_speed = distance_km / time_diff_hours

                if required_speed > self.MAX_TRAVEL_SPEED_KMH:
                    return True

        return False

    def _check_unusual_time(
        self, session: UserSession, recent_sessions: List[UserSession]
    ) -> Optional[SessionAnomaly]:
        """Check if session started at unusual time for user."""
        if len(recent_sessions) < 10:
            # Not enough history
            return None

        # Get typical login hours
        typical_hours = set()
        for s in recent_sessions:
            start_time = s.started_at
            if start_time.tzinfo is None:
                start_time = start_time.replace(tzinfo=timezone.utc)
            typical_hours.add(start_time.hour)

        session_time = session.started_at
        if session_time.tzinfo is None:
            session_time = session_time.replace(tzinfo=timezone.utc)

        session_hour = session_time.hour

        if session_hour not in typical_hours:
            # Check if it's completely off-hours
            if len(typical_hours) >= 5:  # User has diverse hours, less suspicious
                return None

            return SessionAnomaly(
                session_id=session.session_id,
                anomaly_type=AnomalyType.UNUSUAL_TIME,
                confidence=0.5,
                details={
                    "session_hour": session_hour,
                    "typical_hours": sorted(typical_hours),
                },
            )

        return None

    def _check_rapid_provider_switch(
        self, session: UserSession, recent_sessions: List[UserSession]
    ) -> Optional[SessionAnomaly]:
        """Check for rapid switching between identity providers."""
        if not recent_sessions:
            return None

        # Look at sessions in last 30 minutes
        cutoff = session.started_at - timedelta(minutes=30)
        if cutoff.tzinfo is None:
            cutoff = cutoff.replace(tzinfo=timezone.utc)

        recent_providers = set()
        for s in recent_sessions:
            start_time = s.started_at
            if start_time.tzinfo is None:
                start_time = start_time.replace(tzinfo=timezone.utc)
            if start_time >= cutoff:
                recent_providers.add(s.provider)

        if session.provider not in recent_providers and len(recent_providers) >= 1:
            # New provider used within 30 minutes of using another
            return SessionAnomaly(
                session_id=session.session_id,
                anomaly_type=AnomalyType.RAPID_PROVIDER_SWITCH,
                confidence=0.6,
                details={
                    "new_provider": session.provider,
                    "recent_providers": list(recent_providers),
                    "window_minutes": 30,
                },
            )

        return None

    def _haversine_distance(
        self, lat1: float, lon1: float, lat2: float, lon2: float
    ) -> float:
        """Calculate distance between two points using Haversine formula."""
        lat1_rad = math.radians(lat1)
        lat2_rad = math.radians(lat2)
        delta_lat = math.radians(lat2 - lat1)
        delta_lon = math.radians(lon2 - lon1)

        a = (
            math.sin(delta_lat / 2) ** 2 +
            math.cos(lat1_rad) * math.cos(lat2_rad) * math.sin(delta_lon / 2) ** 2
        )
        c = 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))

        return self.EARTH_RADIUS_KM * c

    def expire_idle_sessions(self) -> int:
        """Expire sessions that have been idle too long.

        Returns:
            Number of sessions expired
        """
        # This would need to scan all active sessions
        # Implementation depends on store capabilities
        return self.store.cleanup_expired_sessions(self.session_idle_timeout_minutes // 60)

    def get_active_sessions(self, user_email: str) -> List[UserSession]:
        """Get all active sessions for a user.

        Uses query_executor if available, otherwise falls back to store.

        Args:
            user_email: User's email address

        Returns:
            List of active UserSession objects
        """
        if self.query_executor:
            # Use query executor for database-backed sessions
            results = self.query_executor.execute(
                f"SELECT * FROM sessions WHERE user_email = '{user_email}' AND status = 'active'"
            )
            sessions = []
            for row in results or []:
                session = UserSession(
                    session_id=row.get("session_id", ""),
                    user_id=row.get("user_id", ""),
                    user_email=row.get("user_email", user_email),
                    provider=row.get("provider", ""),
                    started_at=row.get("started_at", datetime.now(timezone.utc)),
                    last_activity=row.get("last_activity", datetime.now(timezone.utc)),
                    source_ip=row.get("source_ip", ""),
                    is_active=row.get("status") == "active",
                )
                sessions.append(session)
            return sessions
        return self.store.get_active_sessions_for_user(user_email)

    def expire_session(self, session: UserSession) -> UserSession:
        """Expire a specific session.

        Args:
            session: Session to expire

        Returns:
            Updated session with EXPIRED status
        """
        session._status_override = SessionStatus.EXPIRED
        session.is_active = False
        session.end_reason = "expired"
        self.store.update_session(session.session_id, {
            "status": SessionStatus.EXPIRED.value,
            "is_active": False,
        })
        return session

    def terminate_all_sessions(
        self,
        user_email: str,
        reason: str = "security_action",
    ) -> int:
        """Terminate all sessions for a user (security action).

        Args:
            user_email: User's email address
            reason: Reason for termination

        Returns:
            Number of sessions terminated
        """
        sessions = self.get_active_sessions(user_email)
        count = 0

        for session in sessions:
            session.status = SessionStatus.TERMINATED
            session.is_active = False
            self.store.end_session(session.session_id, reason)
            count += 1

        logger.info(f"Terminated {count} sessions for {user_email}: {reason}")
        return count

    def update_session(
        self,
        session: UserSession,
        event: IdentityEvent,
    ) -> UserSession:
        """Update a session with a new event.

        Args:
            session: Session to update
            event: New identity event

        Returns:
            Updated session
        """
        # Only update last_activity if the event is newer
        if event.timestamp > session.last_activity:
            session.last_activity = event.timestamp

        # Track event in history
        if not hasattr(session, 'event_history') or session.event_history is None:
            session.event_history = []
        session.event_history.append({
            "event_id": event.event_id,
            "event_type": event.event_type.value if hasattr(event.event_type, 'value') else str(event.event_type),
            "timestamp": event.timestamp.isoformat(),
            "source_ip": event.source_ip,
        })

        # Increment event count
        session.event_count = getattr(session, 'event_count', 0) + 1

        # Track applications accessed
        if event.application_name:
            if not hasattr(session, 'applications_accessed') or session.applications_accessed is None:
                session.applications_accessed = []
            if event.application_name not in session.applications_accessed:
                session.applications_accessed.append(event.application_name)

        # Update IP if changed
        if event.source_ip and event.source_ip != session.source_ip:
            session.source_ip = event.source_ip
            if event.source_geo:
                session.source_geo = event.source_geo

        # Save to store
        self.store.update_session(session.session_id, {
            "last_activity": event.timestamp,
            "source_ip": session.source_ip,
        })

        return session

    def exceeds_concurrent_limit(
        self,
        user_email: str,
        active_sessions: Optional[List[UserSession]] = None,
    ) -> bool:
        """Check if user exceeds concurrent session limit.

        Args:
            user_email: User's email address
            active_sessions: Pre-fetched active sessions (optional)

        Returns:
            True if concurrent session limit exceeded
        """
        if active_sessions is None:
            active_sessions = self.get_active_sessions(user_email)
        return len(active_sessions) > self.max_concurrent_sessions

    def is_cross_provider_concurrent(
        self,
        sessions: List[UserSession],
    ) -> bool:
        """Check if sessions span multiple providers.

        Args:
            sessions: List of sessions to check

        Returns:
            True if sessions are from different providers
        """
        providers = set(s.provider for s in sessions if s.provider)
        return len(providers) > 1

    def detect_ip_change(
        self,
        session: UserSession,
        event: IdentityEvent,
    ) -> Optional[Dict[str, Any]]:
        """Detect IP change during a session.

        Args:
            session: Current session
            event: New event

        Returns:
            Anomaly dict if IP changed, None otherwise
        """
        if not event.source_ip or event.source_ip == session.source_ip:
            return None

        return {
            "type": "session_ip_change",
            "original_ip": session.source_ip,
            "new_ip": event.source_ip,
            "session_id": session.session_id,
        }

    def detect_duration_anomaly(
        self,
        session: UserSession,
        baseline: Optional[Any] = None,
        is_service_account: bool = False,
    ) -> Optional[Dict[str, Any]]:
        """Detect unusually long session duration.

        Args:
            session: Session to check
            baseline: User baseline (optional)
            is_service_account: Whether this is a service account session

        Returns:
            Anomaly dict if duration is unusual, None otherwise
        """
        # Service accounts may have long-running sessions normally
        if is_service_account or getattr(session, 'is_service_account', False):
            return None

        if not session.last_activity or not session.start_time:
            return None

        duration = session.last_activity - session.start_time
        duration_hours = duration.total_seconds() / 3600

        # Default threshold: 8 hours
        threshold_hours = 8

        if baseline:
            # Use baseline avg session duration if available
            avg_duration = getattr(baseline, "avg_session_duration_hours", None)
            if avg_duration:
                threshold_hours = max(avg_duration * 2, 8)

        if duration_hours > threshold_hours:
            return {
                "type": "unusual_duration",
                "duration_hours": int(duration_hours),
                "threshold_hours": threshold_hours,
                "session_id": session.session_id,
            }

        return None

    def is_session_active(self, session: UserSession) -> bool:
        """Check if a session is still active based on timeout.

        Args:
            session: Session to check

        Returns:
            True if session is still active
        """
        if not session.is_active:
            return False

        now = datetime.now(timezone.utc)
        last = session.last_activity
        if last.tzinfo is None:
            last = last.replace(tzinfo=timezone.utc)

        idle_minutes = (now - last).total_seconds() / 60
        return idle_minutes <= self.session_idle_timeout_minutes

    def end_session(
        self,
        session: UserSession,
        event: IdentityEvent,
    ) -> UserSession:
        """End a session based on logout/end event.

        Args:
            session: Session to end
            event: Logout/end event

        Returns:
            Updated session with ENDED status
        """
        session.is_active = False
        session.ended_at = event.timestamp
        session.end_time = event.timestamp  # Alias for test compatibility
        session.end_reason = "logout"
        session._status_override = SessionStatus.ENDED

        self.store.end_session(session.session_id, "logout")
        return session

    def is_suspicious_concurrent(
        self,
        sessions: List[UserSession],
        check_location: bool = True,
    ) -> bool:
        """Check if concurrent sessions are suspicious.

        Args:
            sessions: List of concurrent sessions
            check_location: Whether to check geographic location

        Returns:
            True if concurrent sessions are suspicious
        """
        if len(sessions) <= 1:
            return False

        if not check_location:
            return len(sessions) > self.max_concurrent_sessions

        # Check if sessions are from different countries
        countries = set()
        for session in sessions:
            if session.source_geo and session.source_geo.country:
                countries.add(session.source_geo.country)

        # Different countries = suspicious
        if len(countries) > 1:
            return True

        # Check for impossible travel
        if self.enable_impossible_travel_detection:
            if self._check_impossible_travel_between_sessions(sessions):
                return True

        return False

    def detect_geo_change(
        self,
        session: UserSession,
        event: IdentityEvent,
    ) -> Optional[Dict[str, Any]]:
        """Detect geographic location change during a session.

        Args:
            session: Current session
            event: New event

        Returns:
            Anomaly dict if geo changed, None otherwise
        """
        if not event.source_geo or not session.source_geo:
            return None

        # Check if country changed
        if event.source_geo.country != session.source_geo.country:
            return {
                "type": "session_geo_change",
                "original_location": {
                    "country": session.source_geo.country,
                    "city": session.source_geo.city,
                },
                "new_location": {
                    "country": event.source_geo.country,
                    "city": event.source_geo.city,
                },
                "session_id": session.session_id,
            }

        # Check if city changed significantly
        if event.source_geo.city and session.source_geo.city:
            if event.source_geo.city != session.source_geo.city:
                # Calculate distance if we have coordinates
                if (event.source_geo.lat and event.source_geo.lon and
                    session.source_geo.lat and session.source_geo.lon):
                    distance = self._haversine_distance(
                        session.source_geo.lat, session.source_geo.lon,
                        event.source_geo.lat, event.source_geo.lon
                    )
                    # Only flag if distance is significant (>100km)
                    if distance > 100:
                        return {
                            "type": "session_geo_change",
                            "original_location": {
                                "country": session.source_geo.country,
                                "city": session.source_geo.city,
                            },
                            "new_location": {
                                "country": event.source_geo.country,
                                "city": event.source_geo.city,
                            },
                            "distance_km": round(distance, 2),
                            "session_id": session.session_id,
                        }

        return None

    def detect_activity_anomaly(
        self,
        session: UserSession,
        threshold_events: int = 100,
    ) -> Optional[Dict[str, Any]]:
        """Detect unusual activity patterns in a session.

        Args:
            session: Session to check
            threshold_events: Event count threshold

        Returns:
            Anomaly dict if activity is unusual, None otherwise
        """
        event_count = getattr(session, 'event_count', 0)

        if event_count > threshold_events:
            return {
                "type": "high_session_activity",
                "event_count": event_count,
                "threshold": threshold_events,
                "session_id": session.session_id,
            }

        return None

    def detect_device_change(
        self,
        session: UserSession,
        event: IdentityEvent,
    ) -> Optional[Dict[str, Any]]:
        """Detect device change during a session.

        Args:
            session: Current session
            event: New event

        Returns:
            Anomaly dict if device changed, None otherwise
        """
        if not event.device_id:
            return None

        # Get the session's device ID
        session_device = session.device_id or session.device_fingerprint

        if not session_device:
            return None

        if event.device_id != session_device:
            return {
                "type": "session_device_change",
                "original_device": session_device,
                "new_device": event.device_id,
                "new_user_agent": event.user_agent,
                "session_id": session.session_id,
            }

        return None

    def is_session_after_password_change(
        self,
        session: UserSession,
        password_change_time: datetime,
    ) -> bool:
        """Check if session started before a password change.

        Sessions that existed before a password change and are still
        active after it are suspicious.

        Args:
            session: Session to check
            password_change_time: When password was changed

        Returns:
            True if session is suspicious
        """
        # Ensure timezone awareness
        start_time = session.start_time
        if start_time.tzinfo is None:
            start_time = start_time.replace(tzinfo=timezone.utc)

        pw_time = password_change_time
        if pw_time.tzinfo is None:
            pw_time = pw_time.replace(tzinfo=timezone.utc)

        # Session started before password change = suspicious
        return start_time < pw_time and session.is_active
