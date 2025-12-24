"""Identity-specific user baseline model for ITDR.

Extends the existing behavioral baseline system with identity-specific
patterns for detecting anomalous authentication behavior.
"""

import json
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Set
import uuid


@dataclass
class IdentityBaseline:
    """Extended baseline for identity-specific behavioral patterns.

    Captures normal user authentication patterns across identity providers
    for the 14-day learning period.

    Attributes:
        user_id: Unique user identifier
        email: User's email address (normalized)

        # Time patterns (inherited from UserBaseline)
        typical_login_hours: Set of hours (0-23) when user typically logs in
        typical_login_days: Set of weekdays (0-6, Mon-Sun) when user logs in

        # Location patterns (inherited from UserBaseline)
        known_source_ips: Set of IP addresses user has logged in from
        known_countries: Set of countries user has logged in from
        known_cities: Set of cities user has logged in from

        # Device patterns (inherited from UserBaseline)
        known_devices: Set of device types/fingerprints
        known_user_agents: Set of browser/client hashes

        # Application patterns (inherited from UserBaseline)
        known_applications: Set of applications accessed

        # Identity-specific patterns
        typical_auth_methods: Set of MFA methods normally used
        typical_providers: Set of identity providers used
        typical_session_duration_minutes: Average session length
        session_duration_stddev: Standard deviation of session length
        failed_auth_rate: Normal ratio of failed to total auth attempts
        mfa_challenge_rate: How often MFA is triggered
        password_changes_per_period: Frequency of password changes
        api_token_usage: Whether user normally uses API tokens
        typical_privilege_level: Normal privilege level (admin, user, etc.)
        peer_group_id: For peer comparison (department/team)

        # Baseline metadata
        baseline_start_date: When baseline collection started
        baseline_end_date: When baseline reached maturity
        event_count: Total events analyzed for baseline
        confidence_score: 0-1, based on data volume and variety
        last_updated: Last update timestamp
    """

    # Core identifiers
    user_id: str
    email: str = ""

    # Time patterns
    typical_login_hours: Set[int] = field(default_factory=set)
    typical_login_days: Set[int] = field(default_factory=set)

    # Location patterns
    known_source_ips: Set[str] = field(default_factory=set)
    known_countries: Set[str] = field(default_factory=set)
    known_cities: Set[str] = field(default_factory=set)

    # Device patterns
    known_devices: Set[str] = field(default_factory=set)
    known_user_agents: Set[str] = field(default_factory=set)

    # Application patterns
    known_applications: Set[str] = field(default_factory=set)

    # Identity-specific patterns
    typical_auth_methods: Set[str] = field(default_factory=set)
    typical_providers: Set[str] = field(default_factory=set)
    typical_session_duration_minutes: float = 0.0
    session_duration_stddev: float = 0.0
    failed_auth_rate: float = 0.0
    mfa_challenge_rate: float = 0.0
    password_changes_per_period: float = 0.0
    api_token_usage: bool = False
    typical_privilege_level: str = "user"
    peer_group_id: Optional[str] = None

    # Event counters for rate calculations
    total_auth_attempts: int = 0
    failed_auth_attempts: int = 0
    mfa_challenges: int = 0
    password_change_count: int = 0
    session_durations: List[float] = field(default_factory=list)

    # Baseline metadata
    baseline_start_date: Optional[datetime] = None
    baseline_end_date: Optional[datetime] = None
    event_count: int = 0
    confidence_score: float = 0.0
    last_updated: Optional[datetime] = None
    baseline_period_days: int = 14

    def __post_init__(self):
        """Normalize fields after initialization."""
        if self.email:
            self.email = self.email.lower()

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for storage/serialization."""
        return {
            "user_id": self.user_id,
            "email": self.email,
            "typical_login_hours": list(self.typical_login_hours),
            "typical_login_days": list(self.typical_login_days),
            "known_source_ips": list(self.known_source_ips)[-100:],  # Limit to last 100
            "known_countries": list(self.known_countries),
            "known_cities": list(self.known_cities)[-50:],
            "known_devices": list(self.known_devices)[-20:],
            "known_user_agents": list(self.known_user_agents)[-20:],
            "known_applications": list(self.known_applications),
            "typical_auth_methods": list(self.typical_auth_methods),
            "typical_providers": list(self.typical_providers),
            "typical_session_duration_minutes": self.typical_session_duration_minutes,
            "session_duration_stddev": self.session_duration_stddev,
            "failed_auth_rate": self.failed_auth_rate,
            "mfa_challenge_rate": self.mfa_challenge_rate,
            "password_changes_per_period": self.password_changes_per_period,
            "api_token_usage": self.api_token_usage,
            "typical_privilege_level": self.typical_privilege_level,
            "peer_group_id": self.peer_group_id,
            "total_auth_attempts": self.total_auth_attempts,
            "failed_auth_attempts": self.failed_auth_attempts,
            "mfa_challenges": self.mfa_challenges,
            "password_change_count": self.password_change_count,
            "session_durations": self.session_durations[-100:],  # Keep last 100
            "baseline_start_date": self.baseline_start_date.isoformat() if self.baseline_start_date else None,
            "baseline_end_date": self.baseline_end_date.isoformat() if self.baseline_end_date else None,
            "event_count": self.event_count,
            "confidence_score": self.confidence_score,
            "last_updated": self.last_updated.isoformat() if self.last_updated else None,
            "baseline_period_days": self.baseline_period_days,
        }

    def to_json(self) -> str:
        """Convert to JSON string."""
        return json.dumps(self.to_dict())

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "IdentityBaseline":
        """Create IdentityBaseline from dictionary."""
        # Parse timestamps
        baseline_start = data.get("baseline_start_date")
        if isinstance(baseline_start, str):
            baseline_start = datetime.fromisoformat(baseline_start.replace("Z", "+00:00"))

        baseline_end = data.get("baseline_end_date")
        if isinstance(baseline_end, str):
            baseline_end = datetime.fromisoformat(baseline_end.replace("Z", "+00:00"))

        last_updated = data.get("last_updated")
        if isinstance(last_updated, str):
            last_updated = datetime.fromisoformat(last_updated.replace("Z", "+00:00"))

        return cls(
            user_id=data.get("user_id", ""),
            email=data.get("email", ""),
            typical_login_hours=set(data.get("typical_login_hours", [])),
            typical_login_days=set(data.get("typical_login_days", [])),
            known_source_ips=set(data.get("known_source_ips", [])),
            known_countries=set(data.get("known_countries", [])),
            known_cities=set(data.get("known_cities", [])),
            known_devices=set(data.get("known_devices", [])),
            known_user_agents=set(data.get("known_user_agents", [])),
            known_applications=set(data.get("known_applications", [])),
            typical_auth_methods=set(data.get("typical_auth_methods", [])),
            typical_providers=set(data.get("typical_providers", [])),
            typical_session_duration_minutes=float(data.get("typical_session_duration_minutes", 0)),
            session_duration_stddev=float(data.get("session_duration_stddev", 0)),
            failed_auth_rate=float(data.get("failed_auth_rate", 0)),
            mfa_challenge_rate=float(data.get("mfa_challenge_rate", 0)),
            password_changes_per_period=float(data.get("password_changes_per_period", 0)),
            api_token_usage=bool(data.get("api_token_usage", False)),
            typical_privilege_level=data.get("typical_privilege_level", "user"),
            peer_group_id=data.get("peer_group_id"),
            total_auth_attempts=int(data.get("total_auth_attempts", 0)),
            failed_auth_attempts=int(data.get("failed_auth_attempts", 0)),
            mfa_challenges=int(data.get("mfa_challenges", 0)),
            password_change_count=int(data.get("password_change_count", 0)),
            session_durations=data.get("session_durations", []),
            baseline_start_date=baseline_start,
            baseline_end_date=baseline_end,
            event_count=int(data.get("event_count", 0)),
            confidence_score=float(data.get("confidence_score", 0)),
            last_updated=last_updated,
            baseline_period_days=int(data.get("baseline_period_days", 14)),
        )

    def get_baseline_age_days(self) -> int:
        """Get the age of the baseline in days."""
        if not self.baseline_start_date:
            return 0

        start = self.baseline_start_date
        if start.tzinfo is None:
            start = start.replace(tzinfo=timezone.utc)

        now = datetime.now(timezone.utc)
        return (now - start).days

    def is_mature(self, min_days: int = 14, min_events: int = 50) -> bool:
        """Check if baseline has reached maturity.

        Args:
            min_days: Minimum days of data collection
            min_events: Minimum number of events

        Returns:
            True if baseline is mature enough for reliable detection
        """
        return self.get_baseline_age_days() >= min_days and self.event_count >= min_events

    def get_diversity_score(self) -> float:
        """Calculate diversity score based on variety of patterns.

        Higher diversity means more reliable baseline.

        Returns:
            Score from 0-1
        """
        scores = []

        # Time diversity
        if len(self.typical_login_hours) >= 3:
            scores.append(1.0)
        elif len(self.typical_login_hours) >= 1:
            scores.append(0.5)
        else:
            scores.append(0.0)

        # Location diversity
        if len(self.known_source_ips) >= 2:
            scores.append(1.0)
        elif len(self.known_source_ips) >= 1:
            scores.append(0.5)
        else:
            scores.append(0.0)

        # Device diversity
        if len(self.known_devices) >= 1 or len(self.known_user_agents) >= 1:
            scores.append(1.0)
        else:
            scores.append(0.0)

        # Provider diversity
        if len(self.typical_providers) >= 1:
            scores.append(1.0)
        else:
            scores.append(0.0)

        # Auth method diversity
        if len(self.typical_auth_methods) >= 1:
            scores.append(1.0)
        else:
            scores.append(0.5)  # No MFA is still valid

        return sum(scores) / len(scores) if scores else 0.0
