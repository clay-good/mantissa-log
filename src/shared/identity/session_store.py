"""Identity session tracking store for ITDR.

Maintains active user sessions across identity providers for detecting
session-based attacks like hijacking and concurrent access.
"""

import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
import json
import uuid

from ..models.identity_event import GeoLocation

logger = logging.getLogger(__name__)


class SessionStatus(Enum):
    """Status of a user session."""

    ACTIVE = "active"
    ENDED = "ended"
    EXPIRED = "expired"
    TERMINATED = "terminated"


class AnomalyType(Enum):
    """Types of session anomalies detected."""

    NEW_IP = "new_ip"
    NEW_DEVICE = "new_device"
    NEW_LOCATION = "new_location"
    UNUSUAL_TIME = "unusual_time"
    IMPOSSIBLE_TRAVEL = "impossible_travel"
    CONCURRENT_SESSION = "concurrent_session"
    SESSION_HIJACK_SUSPECTED = "session_hijack_suspected"
    LONG_SESSION = "long_session"
    RAPID_PROVIDER_SWITCH = "rapid_provider_switch"


@dataclass
class UserSession:
    """Represents an active user session across identity providers.

    Attributes:
        session_id: Unique session identifier
        user_id: Provider-specific user ID
        user_email: Normalized user email
        provider: Identity provider (okta, azure, google_workspace, duo, microsoft365)
        started_at: Session start time
        last_activity: Last activity timestamp
        source_ip: Source IP address
        source_geo: Geographic location of source IP
        device_fingerprint: Device identifier/fingerprint
        user_agent: Browser/client user agent
        application_name: Application being accessed
        is_active: Whether session is currently active
        risk_score: Calculated risk score (0-100)
        risk_factors: List of identified risk factors
    """

    session_id: str
    user_id: str
    user_email: str
    provider: str
    started_at: datetime
    last_activity: datetime
    source_ip: str
    source_geo: Optional[GeoLocation] = None
    device_fingerprint: Optional[str] = None
    user_agent: Optional[str] = None
    application_name: Optional[str] = None
    is_active: bool = True
    risk_score: float = 0.0
    risk_factors: List[str] = field(default_factory=list)
    ended_at: Optional[datetime] = None
    end_reason: Optional[str] = None

    # Optional: provider-specific session ID
    provider_session_id: Optional[str] = None

    # Session tracking fields
    event_count: int = 0
    event_history: List[Dict[str, Any]] = field(default_factory=list)
    applications_accessed: List[str] = field(default_factory=list)
    is_service_account: bool = False

    # Internal status override
    _status_override: Optional['SessionStatus'] = field(default=None, repr=False)
    _start_time_override: Optional[datetime] = field(default=None, repr=False)
    _device_id_override: Optional[str] = field(default=None, repr=False)

    def __post_init__(self):
        """Validate and normalize fields."""
        if not self.session_id:
            self.session_id = str(uuid.uuid4())
        if self.user_email:
            self.user_email = self.user_email.lower()
        if self.provider:
            self.provider = self.provider.lower()
        # Initialize applications_accessed with current app if set
        if self.application_name and self.application_name not in self.applications_accessed:
            self.applications_accessed.append(self.application_name)

    @property
    def status(self) -> 'SessionStatus':
        """Get session status for test compatibility."""
        if self._status_override is not None:
            if isinstance(self._status_override, SessionStatus):
                return self._status_override
            # Handle string values
            if isinstance(self._status_override, str):
                return SessionStatus(self._status_override)
        if self.is_active:
            return SessionStatus.ACTIVE
        if self.end_reason == "expired":
            return SessionStatus.EXPIRED
        return SessionStatus.ENDED

    @status.setter
    def status(self, value: 'SessionStatus') -> None:
        """Set session status."""
        if isinstance(value, str):
            value = SessionStatus(value)
        self._status_override = value
        if value == SessionStatus.ACTIVE:
            self.is_active = True
        else:
            self.is_active = False

    @property
    def start_time(self) -> datetime:
        """Alias for started_at for test compatibility."""
        if self._start_time_override is not None:
            return self._start_time_override
        return self.started_at

    @start_time.setter
    def start_time(self, value: datetime) -> None:
        """Set start time."""
        self._start_time_override = value
        self.started_at = value

    @property
    def device_id(self) -> Optional[str]:
        """Alias for device_fingerprint for test compatibility."""
        if self._device_id_override is not None:
            return self._device_id_override
        return self.device_fingerprint

    @device_id.setter
    def device_id(self, value: Optional[str]) -> None:
        """Set device ID."""
        self._device_id_override = value
        self.device_fingerprint = value

    @property
    def application(self) -> Optional[str]:
        """Alias for application_name for test compatibility."""
        return self.application_name

    @property
    def end_time(self) -> Optional[datetime]:
        """Alias for ended_at for test compatibility."""
        return self.ended_at

    @end_time.setter
    def end_time(self, value: Optional[datetime]) -> None:
        """Set end time."""
        self.ended_at = value

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for storage."""
        result = {
            "session_id": self.session_id,
            "user_id": self.user_id,
            "user_email": self.user_email,
            "provider": self.provider,
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "last_activity": self.last_activity.isoformat() if self.last_activity else None,
            "source_ip": self.source_ip,
            "device_fingerprint": self.device_fingerprint,
            "user_agent": self.user_agent,
            "application_name": self.application_name,
            "is_active": self.is_active,
            "risk_score": self.risk_score,
            "risk_factors": self.risk_factors,
        }

        if self.source_geo:
            result["source_geo"] = self.source_geo.to_dict()

        if self.ended_at:
            result["ended_at"] = self.ended_at.isoformat()
        if self.end_reason:
            result["end_reason"] = self.end_reason

        return result

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "UserSession":
        """Create UserSession from dictionary."""
        # Parse timestamps
        started_at = data.get("started_at")
        if isinstance(started_at, str):
            started_at = datetime.fromisoformat(started_at.replace("Z", "+00:00"))
        elif started_at is None:
            started_at = datetime.now(timezone.utc)

        last_activity = data.get("last_activity")
        if isinstance(last_activity, str):
            last_activity = datetime.fromisoformat(last_activity.replace("Z", "+00:00"))
        elif last_activity is None:
            last_activity = started_at

        ended_at = data.get("ended_at")
        if isinstance(ended_at, str):
            ended_at = datetime.fromisoformat(ended_at.replace("Z", "+00:00"))

        # Parse geo location
        source_geo = None
        if "source_geo" in data and data["source_geo"]:
            source_geo = GeoLocation.from_dict(data["source_geo"])

        return cls(
            session_id=data.get("session_id", str(uuid.uuid4())),
            user_id=data.get("user_id", ""),
            user_email=data.get("user_email", ""),
            provider=data.get("provider", "unknown"),
            started_at=started_at,
            last_activity=last_activity,
            source_ip=data.get("source_ip", ""),
            source_geo=source_geo,
            device_fingerprint=data.get("device_fingerprint"),
            user_agent=data.get("user_agent"),
            application_name=data.get("application_name"),
            is_active=data.get("is_active", True),
            risk_score=float(data.get("risk_score", 0.0)),
            risk_factors=data.get("risk_factors", []),
            ended_at=ended_at,
            end_reason=data.get("end_reason"),
        )

    def get_duration_minutes(self) -> float:
        """Get session duration in minutes."""
        end_time = self.ended_at or datetime.now(timezone.utc)
        if self.started_at.tzinfo is None:
            # Assume UTC if no timezone
            start = self.started_at.replace(tzinfo=timezone.utc)
        else:
            start = self.started_at

        if end_time.tzinfo is None:
            end_time = end_time.replace(tzinfo=timezone.utc)

        return (end_time - start).total_seconds() / 60

    def is_expired(self, max_idle_minutes: int = 60) -> bool:
        """Check if session is expired due to inactivity."""
        if not self.is_active:
            return True

        now = datetime.now(timezone.utc)
        last = self.last_activity
        if last.tzinfo is None:
            last = last.replace(tzinfo=timezone.utc)

        idle_minutes = (now - last).total_seconds() / 60
        return idle_minutes > max_idle_minutes


@dataclass
class ConcurrentSessionAlert:
    """Alert for concurrent sessions detected for a user.

    Attributes:
        user_email: User with concurrent sessions
        sessions: List of concurrent sessions
        risk_level: Overall risk level (low, medium, high, critical)
        detected_at: When the concurrency was detected
        alert_reason: Why this is suspicious
    """

    user_email: str
    sessions: List[UserSession]
    risk_level: str
    detected_at: datetime
    alert_reason: str = "Multiple active sessions detected"

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "user_email": self.user_email,
            "sessions": [s.to_dict() for s in self.sessions],
            "risk_level": self.risk_level,
            "detected_at": self.detected_at.isoformat(),
            "alert_reason": self.alert_reason,
            "session_count": len(self.sessions),
        }


@dataclass
class SessionAnomaly:
    """Detected anomaly in a session.

    Attributes:
        session_id: Session where anomaly was detected
        anomaly_type: Type of anomaly from AnomalyType enum
        confidence: Confidence score (0-1)
        details: Additional details about the anomaly
        detected_at: When the anomaly was detected
    """

    session_id: str
    anomaly_type: AnomalyType
    confidence: float
    details: Dict[str, Any] = field(default_factory=dict)
    detected_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "session_id": self.session_id,
            "anomaly_type": self.anomaly_type.value,
            "confidence": self.confidence,
            "details": self.details,
            "detected_at": self.detected_at.isoformat(),
        }


class SessionStore(ABC):
    """Abstract base class for session storage.

    Implementations should handle persistence to DynamoDB, Firestore, Cosmos DB, etc.
    """

    @abstractmethod
    def create_session(self, session: UserSession) -> str:
        """Create a new session.

        Args:
            session: UserSession to create

        Returns:
            Session ID of created session
        """
        pass

    @abstractmethod
    def update_session(self, session_id: str, updates: Dict[str, Any]) -> bool:
        """Update an existing session.

        Args:
            session_id: Session to update
            updates: Dictionary of field updates

        Returns:
            True if update successful
        """
        pass

    @abstractmethod
    def get_session(self, session_id: str) -> Optional[UserSession]:
        """Get a session by ID.

        Args:
            session_id: Session ID to retrieve

        Returns:
            UserSession if found, None otherwise
        """
        pass

    @abstractmethod
    def get_active_sessions_for_user(self, user_email: str) -> List[UserSession]:
        """Get all active sessions for a user.

        Args:
            user_email: User's email address

        Returns:
            List of active sessions
        """
        pass

    @abstractmethod
    def get_recent_sessions_for_user(
        self, user_email: str, hours: int = 24
    ) -> List[UserSession]:
        """Get recent sessions for a user.

        Args:
            user_email: User's email address
            hours: Number of hours to look back

        Returns:
            List of recent sessions
        """
        pass

    @abstractmethod
    def get_concurrent_sessions(self, user_email: str) -> List[UserSession]:
        """Get concurrent active sessions for a user.

        Args:
            user_email: User's email address

        Returns:
            List of concurrent sessions (active within last 5 minutes)
        """
        pass

    @abstractmethod
    def end_session(self, session_id: str, reason: str) -> bool:
        """End/terminate a session.

        Args:
            session_id: Session to end
            reason: Reason for ending (logout, timeout, forced, etc.)

        Returns:
            True if session ended successfully
        """
        pass

    @abstractmethod
    def cleanup_expired_sessions(self, max_age_hours: int = 24) -> int:
        """Clean up expired sessions.

        Args:
            max_age_hours: Maximum age of sessions to keep

        Returns:
            Number of sessions cleaned up
        """
        pass

    def get_sessions_by_ip(self, source_ip: str) -> List[UserSession]:
        """Get all sessions from a specific IP.

        Args:
            source_ip: IP address to search

        Returns:
            List of sessions from this IP
        """
        # Default implementation - subclasses can optimize
        raise NotImplementedError("Subclass should implement get_sessions_by_ip")

    def get_sessions_by_provider(
        self, provider: str, active_only: bool = True
    ) -> List[UserSession]:
        """Get all sessions for a specific provider.

        Args:
            provider: Identity provider name
            active_only: Only return active sessions

        Returns:
            List of sessions for this provider
        """
        # Default implementation - subclasses can optimize
        raise NotImplementedError("Subclass should implement get_sessions_by_provider")


class InMemorySessionStore(SessionStore):
    """In-memory implementation of session storage for development/testing."""

    def __init__(self):
        self._sessions: Dict[str, UserSession] = {}
        self._user_sessions: Dict[str, List[str]] = {}  # email -> [session_ids]

    def create_session(self, session: UserSession) -> str:
        """Create a new session."""
        if not session.session_id:
            session.session_id = str(uuid.uuid4())

        self._sessions[session.session_id] = session

        # Index by user email
        email = session.user_email.lower()
        if email not in self._user_sessions:
            self._user_sessions[email] = []
        self._user_sessions[email].append(session.session_id)

        logger.debug(f"Created session {session.session_id} for {email}")
        return session.session_id

    def update_session(self, session_id: str, updates: Dict[str, Any]) -> bool:
        """Update an existing session."""
        if session_id not in self._sessions:
            logger.warning(f"Session not found for update: {session_id}")
            return False

        session = self._sessions[session_id]

        for key, value in updates.items():
            if hasattr(session, key):
                if key == "last_activity" and isinstance(value, str):
                    value = datetime.fromisoformat(value.replace("Z", "+00:00"))
                elif key == "source_geo" and isinstance(value, dict):
                    value = GeoLocation.from_dict(value)
                setattr(session, key, value)

        logger.debug(f"Updated session {session_id}")
        return True

    def get_session(self, session_id: str) -> Optional[UserSession]:
        """Get a session by ID."""
        return self._sessions.get(session_id)

    def get_active_sessions_for_user(self, user_email: str) -> List[UserSession]:
        """Get all active sessions for a user."""
        email = user_email.lower()
        session_ids = self._user_sessions.get(email, [])

        return [
            self._sessions[sid]
            for sid in session_ids
            if sid in self._sessions and self._sessions[sid].is_active
        ]

    def get_recent_sessions_for_user(
        self, user_email: str, hours: int = 24
    ) -> List[UserSession]:
        """Get recent sessions for a user."""
        email = user_email.lower()
        session_ids = self._user_sessions.get(email, [])

        cutoff = datetime.now(timezone.utc)
        from datetime import timedelta
        cutoff = cutoff - timedelta(hours=hours)

        recent = []
        for sid in session_ids:
            if sid not in self._sessions:
                continue
            session = self._sessions[sid]
            started = session.started_at
            if started.tzinfo is None:
                started = started.replace(tzinfo=timezone.utc)
            if started >= cutoff:
                recent.append(session)

        return sorted(recent, key=lambda s: s.started_at, reverse=True)

    def get_concurrent_sessions(self, user_email: str) -> List[UserSession]:
        """Get concurrent active sessions (active within last 5 minutes)."""
        from datetime import timedelta

        email = user_email.lower()
        session_ids = self._user_sessions.get(email, [])

        cutoff = datetime.now(timezone.utc) - timedelta(minutes=5)

        concurrent = []
        for sid in session_ids:
            if sid not in self._sessions:
                continue
            session = self._sessions[sid]
            if not session.is_active:
                continue

            last = session.last_activity
            if last.tzinfo is None:
                last = last.replace(tzinfo=timezone.utc)

            if last >= cutoff:
                concurrent.append(session)

        return concurrent

    def end_session(self, session_id: str, reason: str) -> bool:
        """End/terminate a session."""
        if session_id not in self._sessions:
            logger.warning(f"Session not found for end: {session_id}")
            return False

        session = self._sessions[session_id]
        session.is_active = False
        session.ended_at = datetime.now(timezone.utc)
        session.end_reason = reason

        logger.debug(f"Ended session {session_id}: {reason}")
        return True

    def cleanup_expired_sessions(self, max_age_hours: int = 24) -> int:
        """Clean up expired sessions."""
        from datetime import timedelta

        cutoff = datetime.now(timezone.utc) - timedelta(hours=max_age_hours)
        cleaned = 0

        sessions_to_remove = []
        for session_id, session in self._sessions.items():
            started = session.started_at
            if started.tzinfo is None:
                started = started.replace(tzinfo=timezone.utc)

            if started < cutoff:
                sessions_to_remove.append(session_id)

        for session_id in sessions_to_remove:
            session = self._sessions.pop(session_id)
            email = session.user_email.lower()
            if email in self._user_sessions:
                self._user_sessions[email] = [
                    sid for sid in self._user_sessions[email] if sid != session_id
                ]
            cleaned += 1

        logger.info(f"Cleaned up {cleaned} expired sessions")
        return cleaned

    def get_sessions_by_ip(self, source_ip: str) -> List[UserSession]:
        """Get all sessions from a specific IP."""
        return [s for s in self._sessions.values() if s.source_ip == source_ip]

    def get_sessions_by_provider(
        self, provider: str, active_only: bool = True
    ) -> List[UserSession]:
        """Get all sessions for a specific provider."""
        provider_lower = provider.lower()
        return [
            s for s in self._sessions.values()
            if s.provider == provider_lower and (not active_only or s.is_active)
        ]
