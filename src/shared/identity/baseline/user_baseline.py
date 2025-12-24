"""User baseline data model - compatibility wrapper for tests.

Provides the UserBaseline interface expected by tests, with property names
like first_seen, typical_hours, known_locations, etc.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set


@dataclass
class UserBaseline:
    """User behavioral baseline for anomaly detection.

    This class provides the interface expected by tests, with property names
    like first_seen, typical_hours, known_locations, etc.

    Attributes:
        user_email: User's email address
        first_seen: When the user was first observed
        last_updated: Last update timestamp
        event_count: Total events analyzed
        typical_hours: Hours when user typically logs in (0-23)
        typical_days: Days when user typically logs in (0-6)
        known_locations: List of GeoLocation objects
        known_devices: List of device dictionaries
        known_ips: Set of known IP addresses
        typical_applications: Set of applications accessed
        auth_methods: Set of authentication methods used
        avg_events_per_day: Average number of events per day
        events_std_dev: Standard deviation of daily events
    """

    # Core identifier
    user_email: str = ""
    user_id: str = ""

    # Baseline metadata
    first_seen: Optional[datetime] = None
    last_updated: Optional[datetime] = None
    event_count: int = 0
    baseline_period_days: int = 14

    # Time patterns
    typical_hours: List[int] = field(default_factory=list)
    typical_days: List[int] = field(default_factory=list)

    # Location patterns
    known_locations: List[Any] = field(default_factory=list)
    known_ips: Set[str] = field(default_factory=set)
    known_countries: Set[str] = field(default_factory=set)
    known_cities: Set[str] = field(default_factory=set)

    # Device patterns
    known_devices: List[Dict[str, Any]] = field(default_factory=list)
    known_user_agents: Set[str] = field(default_factory=set)

    # Application patterns
    typical_applications: Set[str] = field(default_factory=set)

    # Authentication patterns
    auth_methods: Set[str] = field(default_factory=set)
    mfa_methods: Set[str] = field(default_factory=set)

    # Volume statistics
    avg_events_per_day: float = 0.0
    events_std_dev: float = 0.0

    # Session statistics
    avg_session_duration_minutes: float = 0.0
    session_duration_stddev: float = 0.0

    # Failure rates
    failed_auth_rate: float = 0.0
    mfa_challenge_rate: float = 0.0

    # Privilege info
    typical_privilege_level: str = "user"
    is_vpn_user: bool = False

    def __post_init__(self):
        """Normalize fields after initialization."""
        if self.user_email:
            self.user_email = self.user_email.lower()
        if not self.user_id and self.user_email:
            self.user_id = self.user_email

    @property
    def is_mature(self) -> bool:
        """Check if baseline has reached maturity (14+ days with sufficient events)."""
        if not self.first_seen:
            return False
        age = datetime.now(timezone.utc) - self.first_seen
        return age.days >= self.baseline_period_days and self.event_count >= 50

    @property
    def typical_login_hours(self) -> List[int]:
        """Alias for typical_hours for compatibility."""
        return self.typical_hours

    @property
    def typical_login_days(self) -> List[int]:
        """Alias for typical_days for compatibility."""
        return self.typical_days

    @property
    def known_source_ips(self) -> Set[str]:
        """Alias for known_ips for compatibility."""
        return self.known_ips

    @property
    def age_days(self) -> int:
        """Get the age of the baseline in days."""
        if not self.first_seen:
            return 0
        age = datetime.now(timezone.utc) - self.first_seen
        return age.days

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for storage/serialization."""
        return {
            "user_email": self.user_email,
            "user_id": self.user_id,
            "first_seen": self.first_seen.isoformat() if self.first_seen else None,
            "last_updated": self.last_updated.isoformat() if self.last_updated else None,
            "event_count": self.event_count,
            "baseline_period_days": self.baseline_period_days,
            "typical_hours": self.typical_hours,
            "typical_days": self.typical_days,
            "known_locations": [
                loc.to_dict() if hasattr(loc, "to_dict") else loc
                for loc in self.known_locations
            ],
            "known_ips": list(self.known_ips),
            "known_countries": list(self.known_countries),
            "known_cities": list(self.known_cities),
            "known_devices": self.known_devices,
            "known_user_agents": list(self.known_user_agents),
            "typical_applications": list(self.typical_applications),
            "auth_methods": list(self.auth_methods),
            "mfa_methods": list(self.mfa_methods),
            "avg_events_per_day": self.avg_events_per_day,
            "events_std_dev": self.events_std_dev,
            "avg_session_duration_minutes": self.avg_session_duration_minutes,
            "session_duration_stddev": self.session_duration_stddev,
            "failed_auth_rate": self.failed_auth_rate,
            "mfa_challenge_rate": self.mfa_challenge_rate,
            "typical_privilege_level": self.typical_privilege_level,
            "is_vpn_user": self.is_vpn_user,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "UserBaseline":
        """Create UserBaseline from dictionary."""
        first_seen = data.get("first_seen")
        if isinstance(first_seen, str):
            first_seen = datetime.fromisoformat(first_seen.replace("Z", "+00:00"))

        last_updated = data.get("last_updated")
        if isinstance(last_updated, str):
            last_updated = datetime.fromisoformat(last_updated.replace("Z", "+00:00"))

        return cls(
            user_email=data.get("user_email", ""),
            user_id=data.get("user_id", ""),
            first_seen=first_seen,
            last_updated=last_updated,
            event_count=data.get("event_count", 0),
            baseline_period_days=data.get("baseline_period_days", 14),
            typical_hours=data.get("typical_hours", []),
            typical_days=data.get("typical_days", []),
            known_locations=data.get("known_locations", []),
            known_ips=set(data.get("known_ips", [])),
            known_countries=set(data.get("known_countries", [])),
            known_cities=set(data.get("known_cities", [])),
            known_devices=data.get("known_devices", []),
            known_user_agents=set(data.get("known_user_agents", [])),
            typical_applications=set(data.get("typical_applications", [])),
            auth_methods=set(data.get("auth_methods", [])),
            mfa_methods=set(data.get("mfa_methods", [])),
            avg_events_per_day=data.get("avg_events_per_day", 0.0),
            events_std_dev=data.get("events_std_dev", 0.0),
            avg_session_duration_minutes=data.get("avg_session_duration_minutes", 0.0),
            session_duration_stddev=data.get("session_duration_stddev", 0.0),
            failed_auth_rate=data.get("failed_auth_rate", 0.0),
            mfa_challenge_rate=data.get("mfa_challenge_rate", 0.0),
            typical_privilege_level=data.get("typical_privilege_level", "user"),
            is_vpn_user=data.get("is_vpn_user", False),
        )


__all__ = ["UserBaseline"]
