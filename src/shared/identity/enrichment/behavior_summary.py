"""Historical behavior summary generator.

Generates human-readable summaries of user behavior for inclusion
in alerts and investigation panels.
"""

import logging
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Protocol

logger = logging.getLogger(__name__)


# Day names for human-readable output
DAY_NAMES = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"]

# Hour formatting helpers
def format_hour(hour: int) -> str:
    """Format hour as 12-hour time."""
    if hour == 0:
        return "12am"
    elif hour < 12:
        return f"{hour}am"
    elif hour == 12:
        return "12pm"
    else:
        return f"{hour - 12}pm"


def format_hour_range(hours: set) -> str:
    """Format a set of hours as a readable range."""
    if not hours:
        return "no established pattern"

    sorted_hours = sorted(hours)

    if len(sorted_hours) <= 3:
        return ", ".join(format_hour(h) for h in sorted_hours)

    # Find contiguous ranges
    ranges = []
    start = sorted_hours[0]
    end = sorted_hours[0]

    for hour in sorted_hours[1:]:
        if hour == end + 1:
            end = hour
        else:
            if start == end:
                ranges.append(format_hour(start))
            else:
                ranges.append(f"{format_hour(start)}-{format_hour(end)}")
            start = hour
            end = hour

    # Add final range
    if start == end:
        ranges.append(format_hour(start))
    else:
        ranges.append(f"{format_hour(start)}-{format_hour(end)}")

    return ", ".join(ranges)


def format_days(days: set) -> str:
    """Format a set of weekday numbers as readable text."""
    if not days:
        return "no established pattern"

    sorted_days = sorted(days)

    # Check for weekdays vs weekend
    weekdays = {0, 1, 2, 3, 4}
    weekend = {5, 6}

    if set(sorted_days) == weekdays:
        return "weekdays"
    elif set(sorted_days) == weekend:
        return "weekends"
    elif set(sorted_days) == weekdays | weekend:
        return "all days"
    else:
        return ", ".join(DAY_NAMES[d] for d in sorted_days)


class BaselineStoreProtocol(Protocol):
    """Protocol for baseline store interface."""

    def get_baseline(self, user_email: str) -> Any:
        """Get baseline for a user."""
        ...


class QueryExecutorProtocol(Protocol):
    """Protocol for query executor interface."""

    def execute(self, query: str, **kwargs) -> List[Dict[str, Any]]:
        """Execute a query and return results."""
        ...


@dataclass
class UserBehaviorSummary:
    """
    Comprehensive user behavior summary.

    Contains human-readable summaries and structured data about
    a user's typical behavior patterns.
    """

    user_email: str
    summary_text: str
    typical_behavior: Dict[str, Any] = field(default_factory=dict)
    recent_activity: Dict[str, Any] = field(default_factory=dict)
    risk_indicators: List[str] = field(default_factory=list)
    generated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    # Additional context
    baseline_maturity: str = "unknown"
    baseline_confidence: float = 0.0
    event_count: int = 0

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "user_email": self.user_email,
            "summary_text": self.summary_text,
            "typical_behavior": self.typical_behavior,
            "recent_activity": self.recent_activity,
            "risk_indicators": self.risk_indicators,
            "generated_at": self.generated_at.isoformat(),
            "baseline_maturity": self.baseline_maturity,
            "baseline_confidence": self.baseline_confidence,
            "event_count": self.event_count,
        }


class BehaviorSummaryGenerator:
    """
    Generates human-readable behavior summaries for users.

    Provides comprehensive profiles and quick summaries suitable
    for alert enrichment and investigation panels.
    """

    def __init__(
        self,
        baseline_store: Optional[BaselineStoreProtocol] = None,
        query_executor: Optional[QueryExecutorProtocol] = None,
    ):
        """
        Initialize behavior summary generator.

        Args:
            baseline_store: Store for user baselines
            query_executor: Executor for historical queries
        """
        self.baseline_store = baseline_store
        self.query_executor = query_executor

    def generate_user_summary(
        self,
        user_email: str
    ) -> UserBehaviorSummary:
        """
        Generate comprehensive user behavior profile.

        Creates a detailed, human-readable summary of a user's
        typical behavior patterns based on their baseline.

        Args:
            user_email: User email address

        Returns:
            UserBehaviorSummary with comprehensive profile
        """
        baseline = None
        if self.baseline_store:
            baseline = self.baseline_store.get_baseline(user_email)

        if not baseline:
            return UserBehaviorSummary(
                user_email=user_email,
                summary_text=f"No behavioral baseline established for {user_email}.",
                typical_behavior={},
                recent_activity={},
                risk_indicators=["No baseline - unable to assess behavior"],
                baseline_maturity="none",
            )

        # Build typical behavior profile
        typical = self._build_typical_behavior(baseline)

        # Get recent activity if query executor available
        recent = self._get_recent_activity(user_email) if self.query_executor else {}

        # Identify risk indicators
        risk_indicators = self._identify_risk_indicators(baseline, recent)

        # Generate summary text
        summary_text = self._generate_summary_text(user_email, baseline, typical, recent)

        # Determine baseline maturity
        maturity = self._assess_baseline_maturity(baseline)

        return UserBehaviorSummary(
            user_email=user_email,
            summary_text=summary_text,
            typical_behavior=typical,
            recent_activity=recent,
            risk_indicators=risk_indicators,
            baseline_maturity=maturity,
            baseline_confidence=getattr(baseline, 'confidence_score', 0.0),
            event_count=getattr(baseline, 'event_count', 0),
        )

    def generate_quick_summary(
        self,
        user_email: str
    ) -> str:
        """
        Generate one-paragraph summary for alert bodies.

        Creates a concise summary suitable for inclusion in alerts
        or quick reference panels.

        Args:
            user_email: User email address

        Returns:
            One-paragraph summary string
        """
        baseline = None
        if self.baseline_store:
            baseline = self.baseline_store.get_baseline(user_email)

        if not baseline:
            return f"No behavioral baseline established for {user_email}."

        # Extract user's typical patterns
        name = user_email.split('@')[0].replace('.', ' ').title()

        # Time patterns
        hours = getattr(baseline, 'typical_login_hours', set())
        days = getattr(baseline, 'typical_login_days', set())
        time_desc = f"{format_days(days)} {format_hour_range(hours)}"

        # Location patterns
        countries = list(getattr(baseline, 'known_countries', set()))
        cities = list(getattr(baseline, 'known_cities', set()))

        if cities:
            location_desc = cities[0] if len(cities) == 1 else f"{cities[0]} and {len(cities)-1} other location(s)"
        elif countries:
            location_desc = countries[0] if len(countries) == 1 else f"{len(countries)} countries"
        else:
            location_desc = "unknown locations"

        # Device patterns
        devices = list(getattr(baseline, 'known_devices', set()))
        if devices:
            device_desc = f"{len(devices)} known device(s)"
        else:
            device_desc = "various devices"

        # Activity level
        event_count = getattr(baseline, 'event_count', 0)
        baseline_days = getattr(baseline, 'baseline_period_days', 14)
        daily_avg = round(event_count / max(baseline_days, 1), 1)

        summary = (
            f"{name} typically logs in {time_desc} from {location_desc}, "
            f"using {device_desc}. Normal activity: ~{daily_avg} auth events/day."
        )

        return summary

    def compare_to_baseline(
        self,
        event: Any,
        baseline: Any
    ) -> str:
        """
        Generate natural language comparison of event to baseline.

        Creates a human-readable explanation of why an event
        might be considered unusual.

        Args:
            event: Identity event to compare
            baseline: User's baseline

        Returns:
            Natural language comparison string
        """
        if not baseline:
            return "Unable to compare: no baseline established for this user."

        deviations = []

        # Check location
        source_ip = getattr(event, 'source_ip', None)
        known_ips = getattr(baseline, 'known_source_ips', set())
        if source_ip and known_ips and source_ip not in known_ips:
            deviations.append(f"New IP address: {source_ip}")

        # Check country
        geo = getattr(event, 'source_geo', None)
        if geo:
            country = getattr(geo, 'country', None) or (geo.get('country') if isinstance(geo, dict) else None)
            known_countries = getattr(baseline, 'known_countries', set())
            if country and known_countries and country not in known_countries:
                deviations.append(f"First time from {country}")

            city = getattr(geo, 'city', None) or (geo.get('city') if isinstance(geo, dict) else None)
            known_cities = getattr(baseline, 'known_cities', set())
            if city and known_cities and city not in known_cities:
                deviations.append(f"New city: {city}")

        # Check time
        timestamp = getattr(event, 'timestamp', None)
        if timestamp:
            if isinstance(timestamp, str):
                try:
                    timestamp = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
                except ValueError:
                    timestamp = None

            if timestamp:
                hour = timestamp.hour
                day = timestamp.weekday()

                typical_hours = getattr(baseline, 'typical_login_hours', set())
                typical_days = getattr(baseline, 'typical_login_days', set())

                if typical_hours and hour not in typical_hours:
                    usual_range = format_hour_range(typical_hours)
                    deviations.append(
                        f"Outside normal hours ({format_hour(hour)} vs usual {usual_range})"
                    )

                if typical_days and day not in typical_days:
                    usual_days = format_days(typical_days)
                    deviations.append(
                        f"Unusual day ({DAY_NAMES[day]} vs usual {usual_days})"
                    )

        # Check device
        device = getattr(event, 'device_fingerprint', None)
        known_devices = getattr(baseline, 'known_devices', set())
        if device and known_devices and device not in known_devices:
            deviations.append("New device")

        # Check user agent
        user_agent = getattr(event, 'user_agent', None)
        known_agents = getattr(baseline, 'known_user_agents', set())
        if user_agent and known_agents and user_agent not in known_agents:
            deviations.append("New browser/client")

        # Check application
        app = getattr(event, 'application_name', None)
        known_apps = getattr(baseline, 'known_applications', set())
        if app and known_apps and app not in known_apps:
            deviations.append(f"New application: {app}")

        if not deviations:
            return "This activity appears consistent with the user's normal behavior."

        deviation_list = "\n".join(f"  {i+1}) {d}" for i, d in enumerate(deviations))
        return f"This activity is unusual because:\n{deviation_list}"

    def generate_timeline_summary(
        self,
        user_email: str,
        hours: int = 24
    ) -> str:
        """
        Generate summary of recent activity.

        Creates a concise summary of the user's activity
        over the specified time period.

        Args:
            user_email: User email address
            hours: Number of hours to summarize

        Returns:
            Timeline summary string
        """
        if not self.query_executor:
            return f"Unable to generate timeline: no query executor configured."

        recent = self._get_recent_activity(user_email, hours)

        if not recent.get('events'):
            return f"Last {hours} hours: No activity recorded."

        # Count event types
        successful_logins = recent.get('successful_logins', 0)
        failed_logins = recent.get('failed_logins', 0)
        mfa_failures = recent.get('mfa_failures', 0)
        privilege_changes = recent.get('privilege_changes', 0)
        unique_locations = len(recent.get('locations', []))

        parts = [f"Last {hours} hours:"]

        if successful_logins > 0:
            parts.append(f"{successful_logins} successful login(s)")

        if failed_logins > 0:
            parts.append(f"{failed_logins} failed login(s)")

        if mfa_failures > 0:
            parts.append(f"{mfa_failures} failed MFA attempt(s)")

        if privilege_changes > 0:
            parts.append(f"{privilege_changes} privilege change(s)")

        if unique_locations > 1:
            parts.append(f"from {unique_locations} locations")

        return " ".join(parts) + "."

    def _build_typical_behavior(self, baseline: Any) -> Dict[str, Any]:
        """Build structured typical behavior from baseline."""
        return {
            "login_times": {
                "hours": list(getattr(baseline, 'typical_login_hours', set())),
                "hours_readable": format_hour_range(getattr(baseline, 'typical_login_hours', set())),
                "days": list(getattr(baseline, 'typical_login_days', set())),
                "days_readable": format_days(getattr(baseline, 'typical_login_days', set())),
            },
            "locations": {
                "countries": list(getattr(baseline, 'known_countries', set())),
                "cities": list(getattr(baseline, 'known_cities', set()))[:10],
                "ip_count": len(getattr(baseline, 'known_source_ips', set())),
            },
            "devices": {
                "known_device_count": len(getattr(baseline, 'known_devices', set())),
                "known_user_agent_count": len(getattr(baseline, 'known_user_agents', set())),
            },
            "applications": list(getattr(baseline, 'known_applications', set())),
            "providers": list(getattr(baseline, 'typical_providers', set())),
            "auth_methods": list(getattr(baseline, 'typical_auth_methods', set())),
            "session_duration": {
                "average_minutes": getattr(baseline, 'typical_session_duration_minutes', 0),
                "stddev_minutes": getattr(baseline, 'session_duration_stddev', 0),
            },
            "auth_metrics": {
                "failed_auth_rate": getattr(baseline, 'failed_auth_rate', 0),
                "mfa_challenge_rate": getattr(baseline, 'mfa_challenge_rate', 0),
            },
            "privilege_level": getattr(baseline, 'typical_privilege_level', 'user'),
            "uses_api_tokens": getattr(baseline, 'api_token_usage', False),
        }

    def _get_recent_activity(
        self,
        user_email: str,
        hours: int = 24
    ) -> Dict[str, Any]:
        """Get recent activity for user."""
        # This would query the event store for recent activity
        # For now, return empty structure
        return {
            "events": [],
            "successful_logins": 0,
            "failed_logins": 0,
            "mfa_failures": 0,
            "privilege_changes": 0,
            "locations": [],
            "hours_analyzed": hours,
        }

    def _identify_risk_indicators(
        self,
        baseline: Any,
        recent: Dict[str, Any]
    ) -> List[str]:
        """Identify risk indicators from baseline and recent activity."""
        indicators = []

        # Check baseline confidence
        confidence = getattr(baseline, 'confidence_score', 0.0)
        if confidence < 0.5:
            indicators.append("Low baseline confidence - behavior patterns not well established")

        # Check for high failed auth rate
        failed_rate = getattr(baseline, 'failed_auth_rate', 0.0)
        if failed_rate > 0.2:
            indicators.append(f"Higher than normal failed authentication rate ({failed_rate:.1%})")

        # Check for privilege level
        privilege = getattr(baseline, 'typical_privilege_level', 'user')
        if privilege in ['admin', 'administrator', 'global_admin']:
            indicators.append("User has elevated privileges")

        # Check for API token usage
        if getattr(baseline, 'api_token_usage', False):
            indicators.append("User utilizes API tokens")

        # Check for many known IPs (might indicate credential sharing)
        ip_count = len(getattr(baseline, 'known_source_ips', set()))
        if ip_count > 50:
            indicators.append(f"Unusual number of source IPs in baseline ({ip_count})")

        # Check for many countries
        country_count = len(getattr(baseline, 'known_countries', set()))
        if country_count > 5:
            indicators.append(f"Activity from many countries ({country_count})")

        return indicators

    def _generate_summary_text(
        self,
        user_email: str,
        baseline: Any,
        typical: Dict[str, Any],
        recent: Dict[str, Any]
    ) -> str:
        """Generate full summary text."""
        name = user_email.split('@')[0].replace('.', ' ').title()
        parts = []

        # Opening
        event_count = getattr(baseline, 'event_count', 0)
        confidence = getattr(baseline, 'confidence_score', 0.0)
        parts.append(
            f"Behavior profile for {name} ({user_email}) based on "
            f"{event_count} events (confidence: {confidence:.0%})."
        )

        # Time patterns
        hours_desc = typical['login_times']['hours_readable']
        days_desc = typical['login_times']['days_readable']
        parts.append(f"\nTypical login times: {days_desc}, {hours_desc}.")

        # Location patterns
        countries = typical['locations']['countries']
        cities = typical['locations']['cities']
        if countries:
            if len(countries) == 1:
                loc_desc = f"Usually logs in from {countries[0]}"
                if cities:
                    loc_desc += f" ({', '.join(cities[:3])})"
            else:
                loc_desc = f"Logs in from {len(countries)} countries: {', '.join(countries[:5])}"
            parts.append(loc_desc + ".")

        # Device patterns
        device_count = typical['devices']['known_device_count']
        if device_count > 0:
            parts.append(f"Uses {device_count} known device(s).")

        # Application access
        apps = typical['applications']
        if apps:
            parts.append(f"Accesses: {', '.join(list(apps)[:5])}")
            if len(apps) > 5:
                parts[-1] += f" and {len(apps) - 5} other applications."
            else:
                parts[-1] += "."

        # Privilege level
        privilege = typical['privilege_level']
        if privilege != 'user':
            parts.append(f"Privilege level: {privilege}.")

        return " ".join(parts)

    def _assess_baseline_maturity(self, baseline: Any) -> str:
        """Assess baseline maturity level."""
        event_count = getattr(baseline, 'event_count', 0)
        confidence = getattr(baseline, 'confidence_score', 0.0)

        baseline_start = getattr(baseline, 'baseline_start_date', None)
        if baseline_start:
            if isinstance(baseline_start, str):
                try:
                    baseline_start = datetime.fromisoformat(
                        baseline_start.replace('Z', '+00:00')
                    )
                except ValueError:
                    baseline_start = None

            if baseline_start:
                days_old = (datetime.now(timezone.utc) - baseline_start).days
                if days_old >= 14 and event_count >= 50:
                    return "mature"
                elif days_old >= 7:
                    return "developing"
                else:
                    return "immature"

        # Fallback to confidence
        if confidence >= 0.8:
            return "mature"
        elif confidence >= 0.5:
            return "developing"
        else:
            return "immature"


def generate_quick_summary(
    user_email: str,
    baseline_store: Optional[BaselineStoreProtocol] = None
) -> str:
    """Convenience function to generate a quick summary."""
    generator = BehaviorSummaryGenerator(baseline_store=baseline_store)
    return generator.generate_quick_summary(user_email)
