"""Unusual login time detection for identity events.

Provides detection of logins that occur outside a user's normal working hours
based on their behavioral baseline. Considers timezone differences and
special cases like on-call personnel.
"""

import logging
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Set, Tuple

from ..anomaly_types import AnomalySeverity, IdentityAnomaly, IdentityAnomalyType
from ..user_baseline import IdentityBaseline

logger = logging.getLogger(__name__)


# Common timezone mappings by country
COUNTRY_TIMEZONES = {
    "United States": "America/New_York",  # Default to Eastern
    "United Kingdom": "Europe/London",
    "Germany": "Europe/Berlin",
    "France": "Europe/Paris",
    "Japan": "Asia/Tokyo",
    "Australia": "Australia/Sydney",
    "India": "Asia/Kolkata",
    "Brazil": "America/Sao_Paulo",
    "Canada": "America/Toronto",
    "China": "Asia/Shanghai",
    "Singapore": "Asia/Singapore",
    "Netherlands": "Europe/Amsterdam",
    "Ireland": "Europe/Dublin",
    "Sweden": "Europe/Stockholm",
    "Switzerland": "Europe/Zurich",
}

# City to timezone overrides for major cities
CITY_TIMEZONES = {
    "Los Angeles": "America/Los_Angeles",
    "San Francisco": "America/Los_Angeles",
    "Seattle": "America/Los_Angeles",
    "Denver": "America/Denver",
    "Chicago": "America/Chicago",
    "New York": "America/New_York",
    "Boston": "America/New_York",
    "Atlanta": "America/New_York",
    "Miami": "America/New_York",
    "London": "Europe/London",
    "Paris": "Europe/Paris",
    "Berlin": "Europe/Berlin",
    "Tokyo": "Asia/Tokyo",
    "Sydney": "Australia/Sydney",
    "Melbourne": "Australia/Melbourne",
    "Singapore": "Asia/Singapore",
}

# On-call user patterns
ON_CALL_PATTERNS = [
    "oncall",
    "on-call",
    "ops",
    "sre",
    "devops",
    "noc",
    "support",
    "incident",
    "pagerduty",
    "opsgenie",
]


@dataclass
class TimeAnalysisDetails:
    """Details of unusual time analysis.

    Attributes:
        event_hour_utc: Hour of event in UTC
        event_hour_local: Hour of event in user's local timezone
        event_day_of_week: Day of week (0=Monday, 6=Sunday)
        user_timezone: User's inferred timezone
        is_night_hour: Whether this is a night hour (midnight to 6 AM)
        is_weekend: Whether this is a weekend day
        is_in_typical_hours: Whether hour is in user's typical login hours
        is_in_typical_days: Whether day is in user's typical login days
        typical_hours: User's typical login hours
        typical_days: User's typical login days
        deviation_score: How unusual this time is (0.0-1.0)
    """

    event_hour_utc: int
    event_hour_local: int
    event_day_of_week: int
    user_timezone: str
    is_night_hour: bool
    is_weekend: bool
    is_in_typical_hours: bool
    is_in_typical_days: bool
    typical_hours: Set[int] = field(default_factory=set)
    typical_days: Set[int] = field(default_factory=set)
    deviation_score: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "event_hour_utc": self.event_hour_utc,
            "event_hour_local": self.event_hour_local,
            "event_day_of_week": self.event_day_of_week,
            "user_timezone": self.user_timezone,
            "is_night_hour": self.is_night_hour,
            "is_weekend": self.is_weekend,
            "is_in_typical_hours": self.is_in_typical_hours,
            "is_in_typical_days": self.is_in_typical_days,
            "typical_hours": list(self.typical_hours),
            "typical_days": list(self.typical_days),
            "deviation_score": round(self.deviation_score, 3),
        }


@dataclass
class UnusualTimeAlert:
    """Alert for unusual login time detection.

    Attributes:
        alert_id: Unique identifier for this alert
        severity: Alert severity (critical, high, medium, low)
        title: Human-readable alert title
        description: Detailed description
        user_email: User who triggered the alert
        event_time: Time of the event
        time_analysis: Detailed time analysis
        is_on_call_user: Whether user is known on-call
        source_ip: Source IP of the event
        provider: Identity provider
        evidence: Additional evidence data
        mitre_techniques: Associated MITRE ATT&CK techniques
        recommended_actions: Suggested response actions
    """

    alert_id: str
    severity: str
    title: str
    description: str
    user_email: str
    event_time: Optional[datetime] = None
    time_analysis: Optional[TimeAnalysisDetails] = None
    is_on_call_user: bool = False
    source_ip: str = ""
    provider: str = ""
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
            "user_email": self.user_email,
            "event_time": self.event_time.isoformat() if self.event_time else None,
            "time_analysis": (
                self.time_analysis.to_dict() if self.time_analysis else None
            ),
            "is_on_call_user": self.is_on_call_user,
            "source_ip": self.source_ip,
            "provider": self.provider,
            "evidence": self.evidence,
            "mitre_techniques": self.mitre_techniques,
            "recommended_actions": self.recommended_actions,
            "detected_at": self.detected_at.isoformat(),
        }


class UnusualTimeDetector:
    """Detects logins outside user's normal working hours.

    Uses user's behavioral baseline to identify authentication events
    that occur at unusual times, considering timezone differences.

    Attributes:
        query_executor: Executor for querying identity events
        baseline_store: Store for retrieving user baselines
        NIGHT_HOURS: Hours considered night time (midnight to 6 AM)
        WEEKEND_DAYS: Days considered weekend (Saturday, Sunday)
    """

    # Night hours (local time)
    NIGHT_HOURS = {0, 1, 2, 3, 4, 5}  # Midnight to 6 AM

    # Weekend days (Monday = 0, Sunday = 6)
    WEEKEND_DAYS = {5, 6}  # Saturday, Sunday

    # Default time window
    DEFAULT_WINDOW_HOURS = 24

    # Deviation thresholds for severity
    HIGH_DEVIATION_THRESHOLD = 0.9
    MEDIUM_DEVIATION_THRESHOLD = 0.7

    def __init__(
        self,
        query_executor: Any,
        baseline_store: Any = None,
        identity_events_table: str = "identity_events",
    ):
        """Initialize the unusual time detector.

        Args:
            query_executor: Executor for querying the data lake
            baseline_store: Store for retrieving user baselines
            identity_events_table: Name of the identity events table
        """
        self.query_executor = query_executor
        self.baseline_store = baseline_store
        self.identity_events_table = identity_events_table

        # Cache for on-call users
        self._on_call_cache: Set[str] = set()

    def detect_unusual_login_times(
        self,
        window_hours: int = None,
    ) -> List[UnusualTimeAlert]:
        """Detect logins at unusual times across all users.

        Gets all successful auth events in window, retrieves baselines,
        and identifies logins outside typical hours.

        Args:
            window_hours: Detection window in hours

        Returns:
            List of UnusualTimeAlert for each unusual login
        """
        window = window_hours or self.DEFAULT_WINDOW_HOURS
        alerts = []

        cutoff = datetime.now(timezone.utc) - timedelta(hours=window)
        cutoff_str = cutoff.strftime("%Y-%m-%d %H:%M:%S")

        query = f"""
            SELECT
                event_id,
                user_email,
                source_ip,
                source_geo_country,
                source_geo_city,
                provider,
                event_timestamp
            FROM {self.identity_events_table}
            WHERE event_type = 'AUTH_SUCCESS'
              AND event_timestamp >= TIMESTAMP '{cutoff_str}'
            ORDER BY event_timestamp DESC
            LIMIT 1000
        """

        try:
            result = self.query_executor.execute_query(query, timeout_seconds=120)

            for row in result.rows:
                user_email = row.get("user_email")
                if not user_email:
                    continue

                # Get user's baseline
                baseline = self._get_user_baseline(user_email)
                if not baseline:
                    continue

                # Check if time is unusual
                event_time = self._parse_timestamp(row.get("event_timestamp"))
                if not event_time:
                    continue

                is_unusual, details = self.is_unusual_time(
                    event_time=event_time,
                    baseline=baseline,
                    country=row.get("source_geo_country"),
                    city=row.get("source_geo_city"),
                )

                if is_unusual:
                    alert = self.generate_time_alert(
                        user_email=user_email,
                        event_time=event_time,
                        time_analysis=details,
                        source_ip=row.get("source_ip", ""),
                        provider=row.get("provider", ""),
                        baseline=baseline,
                    )
                    alerts.append(alert)

        except Exception as e:
            logger.error(f"Error detecting unusual login times: {e}")

        return alerts

    def is_unusual_time(
        self,
        event_time: datetime,
        baseline: IdentityBaseline,
        country: str = None,
        city: str = None,
    ) -> Tuple[bool, TimeAnalysisDetails]:
        """Check if event time is unusual for user.

        Args:
            event_time: Timestamp of the event
            baseline: User's behavioral baseline
            country: Event source country (for timezone inference)
            city: Event source city (for timezone inference)

        Returns:
            Tuple of (is_unusual, TimeAnalysisDetails)
        """
        # Get user's timezone
        user_tz = self.get_user_timezone(baseline, country, city)

        # Convert to user's local time
        local_time = self._convert_to_timezone(event_time, user_tz)
        local_hour = local_time.hour
        day_of_week = local_time.weekday()  # Monday = 0, Sunday = 6

        # Check if night hour
        is_night = local_hour in self.NIGHT_HOURS

        # Check if weekend
        is_weekend = day_of_week in self.WEEKEND_DAYS

        # Check against baseline
        typical_hours = baseline.typical_login_hours or set()
        typical_days = baseline.typical_login_days or set()

        is_in_typical_hours = local_hour in typical_hours if typical_hours else True
        is_in_typical_days = day_of_week in typical_days if typical_days else True

        # Calculate deviation score
        deviation = self.calculate_time_deviation(
            local_hour=local_hour,
            day_of_week=day_of_week,
            typical_hours=typical_hours,
            typical_days=typical_days,
            is_night=is_night,
            is_weekend=is_weekend,
        )

        details = TimeAnalysisDetails(
            event_hour_utc=event_time.hour,
            event_hour_local=local_hour,
            event_day_of_week=day_of_week,
            user_timezone=user_tz,
            is_night_hour=is_night,
            is_weekend=is_weekend,
            is_in_typical_hours=is_in_typical_hours,
            is_in_typical_days=is_in_typical_days,
            typical_hours=typical_hours,
            typical_days=typical_days,
            deviation_score=deviation,
        )

        # Consider unusual if deviation is significant
        is_unusual = deviation >= 0.5 and (not is_in_typical_hours or not is_in_typical_days)

        return is_unusual, details

    def calculate_time_deviation(
        self,
        local_hour: int,
        day_of_week: int,
        typical_hours: Set[int],
        typical_days: Set[int],
        is_night: bool,
        is_weekend: bool,
    ) -> float:
        """Calculate how unusual this login time is.

        Args:
            local_hour: Hour in user's local timezone
            day_of_week: Day of week (0=Monday, 6=Sunday)
            typical_hours: User's typical login hours
            typical_days: User's typical login days
            is_night: Whether this is a night hour
            is_weekend: Whether this is a weekend

        Returns:
            Deviation score from 0.0 (normal) to 1.0 (very unusual)
        """
        deviation = 0.0

        # Check hour deviation
        if typical_hours:
            if local_hour not in typical_hours:
                # Find distance to nearest typical hour
                min_distance = min(
                    min(abs(local_hour - h), abs(24 - abs(local_hour - h)))
                    for h in typical_hours
                )
                # Normalize to 0-0.5 (hour deviation can contribute up to 50%)
                hour_deviation = min(min_distance / 12.0, 1.0) * 0.5
                deviation += hour_deviation

        # Check day deviation
        if typical_days:
            if day_of_week not in typical_days:
                # User doesn't typically log in on this day
                deviation += 0.25

        # Extra penalty for night hours
        if is_night:
            deviation += 0.15

        # Extra penalty for weekend if user doesn't typically work weekends
        if is_weekend and typical_days and not any(d in self.WEEKEND_DAYS for d in typical_days):
            deviation += 0.10

        # Cap at 1.0
        return min(deviation, 1.0)

    def get_user_timezone(
        self,
        baseline: IdentityBaseline,
        event_country: str = None,
        event_city: str = None,
    ) -> str:
        """Infer user's timezone from baseline or event location.

        Args:
            baseline: User's behavioral baseline
            event_country: Country from current event
            event_city: City from current event

        Returns:
            Timezone string (e.g., "America/New_York")
        """
        # Try to infer from baseline known locations
        if baseline.known_countries:
            # Use most common country in baseline
            for country in baseline.known_countries:
                if country in COUNTRY_TIMEZONES:
                    return COUNTRY_TIMEZONES[country]

        if baseline.known_cities:
            for city in baseline.known_cities:
                if city in CITY_TIMEZONES:
                    return CITY_TIMEZONES[city]

        # Fall back to event location
        if event_city and event_city in CITY_TIMEZONES:
            return CITY_TIMEZONES[event_city]

        if event_country and event_country in COUNTRY_TIMEZONES:
            return COUNTRY_TIMEZONES[event_country]

        # Default to UTC
        return "UTC"

    def is_on_call_user(self, user_email: str) -> bool:
        """Check if user is known on-call personnel.

        On-call users may legitimately log in at any time.

        Args:
            user_email: User email to check

        Returns:
            True if user appears to be on-call
        """
        if not user_email:
            return False

        # Check cache
        if user_email in self._on_call_cache:
            return True

        email_lower = user_email.lower()

        # Check against patterns
        for pattern in ON_CALL_PATTERNS:
            if pattern in email_lower:
                self._on_call_cache.add(user_email)
                return True

        return False

    def generate_time_alert(
        self,
        user_email: str,
        event_time: datetime,
        time_analysis: TimeAnalysisDetails,
        source_ip: str,
        provider: str,
        baseline: IdentityBaseline,
    ) -> UnusualTimeAlert:
        """Create alert for unusual login time.

        Args:
            user_email: User who triggered the alert
            event_time: Time of the event
            time_analysis: Detailed time analysis
            source_ip: Source IP of the event
            provider: Identity provider
            baseline: User's baseline for context

        Returns:
            UnusualTimeAlert
        """
        is_on_call = self.is_on_call_user(user_email)
        deviation = time_analysis.deviation_score

        # Determine severity based on deviation
        if deviation >= self.HIGH_DEVIATION_THRESHOLD:
            severity = "high"
        elif deviation >= self.MEDIUM_DEVIATION_THRESHOLD:
            severity = "medium"
        else:
            severity = "low"

        # Reduce severity for on-call users
        if is_on_call:
            if severity == "high":
                severity = "medium"
            elif severity == "medium":
                severity = "low"

        # Build description
        local_time_str = f"{time_analysis.event_hour_local:02d}:00"
        day_names = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"]
        day_name = day_names[time_analysis.event_day_of_week]

        description_parts = [
            f"Unusual login time for {user_email}.",
            f"Login at {local_time_str} ({time_analysis.user_timezone}) on {day_name}.",
        ]

        if time_analysis.is_night_hour:
            description_parts.append("This is during night hours (midnight to 6 AM).")
        if time_analysis.is_weekend and not time_analysis.is_in_typical_days:
            description_parts.append("User does not typically log in on weekends.")
        if not time_analysis.is_in_typical_hours:
            typical_hours_str = ", ".join(f"{h:02d}:00" for h in sorted(time_analysis.typical_hours)[:5])
            description_parts.append(f"Typical login hours: {typical_hours_str}.")

        if is_on_call:
            description_parts.append("User appears to be on-call personnel.")

        # Build recommended actions
        actions = [
            f"Verify login is from legitimate {user_email}",
        ]

        if time_analysis.is_night_hour and not is_on_call:
            actions.append("Check if user has emergency or on-call responsibilities")
        if time_analysis.is_weekend:
            actions.append("Verify if weekend work is expected")

        actions.extend(
            [
                "Review session activity for suspicious behavior",
                "Consider requiring step-up authentication for off-hours logins",
            ]
        )

        return UnusualTimeAlert(
            alert_id=str(uuid.uuid4()),
            severity=severity,
            title=f"Unusual Login Time: {user_email} at {local_time_str}",
            description=" ".join(description_parts),
            user_email=user_email,
            event_time=event_time,
            time_analysis=time_analysis,
            is_on_call_user=is_on_call,
            source_ip=source_ip,
            provider=provider,
            evidence={
                "deviation_score": deviation,
                "baseline_event_count": baseline.event_count,
                "baseline_confidence": baseline.confidence_score,
            },
            mitre_techniques=["T1078"],  # Valid Accounts
            recommended_actions=actions,
        )

    def _get_user_baseline(self, user_email: str) -> Optional[IdentityBaseline]:
        """Get user's baseline from store.

        Args:
            user_email: User email

        Returns:
            IdentityBaseline or None
        """
        if not self.baseline_store:
            return None

        try:
            return self.baseline_store.get_baseline(user_email)
        except Exception as e:
            logger.warning(f"Error retrieving baseline for {user_email}: {e}")
            return None

    def _convert_to_timezone(self, dt: datetime, tz_name: str) -> datetime:
        """Convert datetime to specified timezone.

        Args:
            dt: Datetime to convert
            tz_name: Target timezone name

        Returns:
            Datetime in target timezone
        """
        try:
            from zoneinfo import ZoneInfo

            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)

            target_tz = ZoneInfo(tz_name)
            return dt.astimezone(target_tz)
        except Exception:
            # Fall back to UTC if timezone conversion fails
            if dt.tzinfo is None:
                return dt.replace(tzinfo=timezone.utc)
            return dt

    def _parse_timestamp(self, ts: Any) -> Optional[datetime]:
        """Parse timestamp from query result.

        Args:
            ts: Timestamp value

        Returns:
            Parsed datetime or None
        """
        if ts is None:
            return None
        if isinstance(ts, datetime):
            if ts.tzinfo is None:
                return ts.replace(tzinfo=timezone.utc)
            return ts
        if isinstance(ts, str):
            try:
                dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
                return dt
            except ValueError:
                return None
        return None

    def run_detection(
        self,
        window_hours: int = None,
    ) -> List[UnusualTimeAlert]:
        """Run unusual time detection.

        Main entry point for detection.

        Args:
            window_hours: Detection window in hours

        Returns:
            List of UnusualTimeAlert
        """
        return self.detect_unusual_login_times(window_hours=window_hours)
