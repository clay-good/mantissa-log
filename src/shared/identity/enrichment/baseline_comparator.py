"""Baseline comparator for identity alert enrichment.

Compares current events against user behavioral baselines.
"""

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

# Maturity thresholds
BASELINE_MATURE_DAYS = 14
BASELINE_MINIMUM_EVENTS = 50


@dataclass
class BaselineDeviation:
    """A deviation from expected baseline behavior."""

    deviation_type: str
    description: str
    severity: str = "low"
    expected_value: Optional[Any] = None
    actual_value: Optional[Any] = None
    deviation_score: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "deviation_type": self.deviation_type,
            "description": self.description,
            "severity": self.severity,
            "expected_value": self.expected_value,
            "actual_value": self.actual_value,
            "deviation_score": self.deviation_score,
        }


@dataclass
class BaselineComparison:
    """Result of comparing an event to a user baseline."""

    user_email: str
    baseline_mature: bool = False
    baseline_age_days: int = 0
    baseline_event_count: int = 0
    deviations: List[BaselineDeviation] = field(default_factory=list)
    overall_deviation_score: float = 0.0
    matches_typical_behavior: bool = True

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "user_email": self.user_email,
            "baseline_mature": self.baseline_mature,
            "baseline_age_days": self.baseline_age_days,
            "baseline_event_count": self.baseline_event_count,
            "deviations": [d.to_dict() for d in self.deviations],
            "overall_deviation_score": self.overall_deviation_score,
            "matches_typical_behavior": self.matches_typical_behavior,
        }


class BaselineComparator:
    """Compares events against user behavioral baselines."""

    def __init__(
        self,
        baseline_store: Optional[Any] = None,
    ):
        """Initialize baseline comparator.

        Args:
            baseline_store: Store for user baselines
        """
        self.baseline_store = baseline_store

    def compare(
        self,
        event: Any,
        baseline: Optional[Any] = None,
    ) -> Dict[str, Any]:
        """Compare an event against the user's baseline.

        Args:
            event: The identity event to compare
            baseline: Optional baseline (if not provided, will be fetched)

        Returns:
            Dictionary with comparison results including:
                - is_unusual_hour, login_hour, typical_hours
                - is_new_location, is_new_country, login_location
                - is_new_device, device_id
                - baseline_maturity, comparison_confidence
                - location_unknown (if geo data missing)
        """
        user_email = getattr(event, "user_email", None) or ""
        result: Dict[str, Any] = {
            "user_email": user_email,
            "has_baseline": False,
            "baseline_maturity": "none",
            "comparison_confidence": 0.0,
        }

        # Get baseline if not provided
        if baseline is None and self.baseline_store:
            try:
                baseline = self.baseline_store.get_baseline(user_email)
            except Exception as e:
                logger.warning(f"Failed to get baseline for {user_email}: {e}")

        if baseline is None:
            return result

        result["has_baseline"] = True

        # Check baseline maturity
        first_seen = getattr(baseline, "first_seen", None)
        event_count = getattr(baseline, "event_count", 0)
        baseline_age_days = 0

        if first_seen:
            if isinstance(first_seen, str):
                try:
                    first_seen = datetime.fromisoformat(first_seen.replace("Z", "+00:00"))
                except ValueError:
                    first_seen = None

            if first_seen:
                age = datetime.now(timezone.utc) - first_seen
                baseline_age_days = age.days

        result["baseline_age_days"] = baseline_age_days
        result["baseline_event_count"] = event_count

        # Determine maturity and confidence
        if baseline_age_days >= BASELINE_MATURE_DAYS and event_count >= BASELINE_MINIMUM_EVENTS:
            result["baseline_maturity"] = "mature"
            result["comparison_confidence"] = min(0.95, 0.5 + (event_count / 200) * 0.45)
        elif baseline_age_days >= 7:
            result["baseline_maturity"] = "learning"
            result["comparison_confidence"] = 0.3 + (baseline_age_days / BASELINE_MATURE_DAYS) * 0.2
        else:
            result["baseline_maturity"] = "new"
            result["comparison_confidence"] = 0.1 + (baseline_age_days / 7) * 0.2

        # Time of day check
        timestamp = getattr(event, "timestamp", None)
        typical_hours = getattr(baseline, "typical_hours", None)

        if timestamp and typical_hours:
            hour = timestamp.hour
            result["login_hour"] = hour
            result["typical_hours"] = typical_hours
            result["is_unusual_hour"] = hour not in typical_hours
            if result["is_unusual_hour"]:
                result["hour_deviation_score"] = 0.6
        else:
            result["is_unusual_hour"] = False

        # Location check
        source_geo = getattr(event, "source_geo", None)
        known_locations = getattr(baseline, "known_locations", None)

        if source_geo is None:
            result["location_unknown"] = True
            result["is_new_location"] = None
            result["is_new_country"] = None
        else:
            current_country = getattr(source_geo, "country", None)
            current_city = getattr(source_geo, "city", None)

            result["login_location"] = {
                "country": current_country,
                "city": current_city,
            }

            if known_locations:
                is_known_location = False
                is_known_country = False

                for loc in known_locations:
                    loc_country = loc.get("country") if isinstance(loc, dict) else getattr(loc, "country", None)
                    loc_city = loc.get("city") if isinstance(loc, dict) else getattr(loc, "city", None)

                    if loc_country == current_country:
                        is_known_country = True
                        if loc_city == current_city:
                            is_known_location = True
                            break

                result["is_new_location"] = not is_known_location
                result["is_new_country"] = not is_known_country
            else:
                result["is_new_location"] = False
                result["is_new_country"] = False

        # Device check
        device_id = getattr(event, "device_id", None)
        known_devices = getattr(baseline, "known_devices", None)

        if device_id:
            result["device_id"] = device_id
            if known_devices:
                known_device_ids = {
                    d.get("device_id") if isinstance(d, dict) else getattr(d, "device_id", None)
                    for d in known_devices
                }
                result["is_new_device"] = device_id not in known_device_ids
            else:
                result["is_new_device"] = False
        else:
            result["is_new_device"] = False

        return result

    def compare_to_dataclass(
        self,
        event: Any,
        baseline: Optional[Any] = None,
    ) -> BaselineComparison:
        """Compare an event against the user's baseline, returning a dataclass.

        Args:
            event: The identity event to compare
            baseline: Optional baseline (if not provided, will be fetched)

        Returns:
            BaselineComparison with deviation analysis
        """
        user_email = getattr(event, "user_email", None) or ""
        comparison = BaselineComparison(user_email=user_email)

        # Get baseline if not provided
        if baseline is None and self.baseline_store:
            try:
                baseline = self.baseline_store.get_baseline(user_email)
            except Exception as e:
                logger.warning(f"Failed to get baseline for {user_email}: {e}")

        if baseline is None:
            # No baseline available
            return comparison

        # Check baseline maturity
        first_seen = getattr(baseline, "first_seen", None)
        event_count = getattr(baseline, "event_count", 0)

        if first_seen:
            age = datetime.now(timezone.utc) - first_seen
            comparison.baseline_age_days = age.days
            comparison.baseline_mature = (
                age.days >= BASELINE_MATURE_DAYS
                and event_count >= BASELINE_MINIMUM_EVENTS
            )
        comparison.baseline_event_count = event_count

        # Skip detailed comparison for immature baselines
        if not comparison.baseline_mature:
            return comparison

        # Check for deviations
        deviations = []

        # Time of day check
        time_deviation = self._check_time_deviation(event, baseline)
        if time_deviation:
            deviations.append(time_deviation)

        # Day of week check
        day_deviation = self._check_day_deviation(event, baseline)
        if day_deviation:
            deviations.append(day_deviation)

        # Location check
        location_deviation = self._check_location_deviation(event, baseline)
        if location_deviation:
            deviations.append(location_deviation)

        # Device check
        device_deviation = self._check_device_deviation(event, baseline)
        if device_deviation:
            deviations.append(device_deviation)

        # IP check
        ip_deviation = self._check_ip_deviation(event, baseline)
        if ip_deviation:
            deviations.append(ip_deviation)

        # Application check
        app_deviation = self._check_application_deviation(event, baseline)
        if app_deviation:
            deviations.append(app_deviation)

        comparison.deviations = deviations
        comparison.matches_typical_behavior = len(deviations) == 0

        # Calculate overall deviation score
        if deviations:
            comparison.overall_deviation_score = sum(
                d.deviation_score for d in deviations
            ) / len(deviations)

        return comparison

    def _check_time_deviation(
        self,
        event: Any,
        baseline: Any,
    ) -> Optional[BaselineDeviation]:
        """Check if event time is outside typical hours."""
        timestamp = getattr(event, "timestamp", None)
        typical_hours = getattr(baseline, "typical_hours", None)

        if timestamp is None or typical_hours is None:
            return None

        hour = timestamp.hour
        if hour not in typical_hours:
            return BaselineDeviation(
                deviation_type="unusual_time",
                description=f"Activity at hour {hour} outside typical hours {typical_hours}",
                severity="medium",
                expected_value=typical_hours,
                actual_value=hour,
                deviation_score=0.6,
            )
        return None

    def _check_day_deviation(
        self,
        event: Any,
        baseline: Any,
    ) -> Optional[BaselineDeviation]:
        """Check if event day is outside typical days."""
        timestamp = getattr(event, "timestamp", None)
        typical_days = getattr(baseline, "typical_days", None)

        if timestamp is None or typical_days is None:
            return None

        day = timestamp.weekday()
        if day not in typical_days:
            day_names = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"]
            return BaselineDeviation(
                deviation_type="unusual_day",
                description=f"Activity on {day_names[day]} outside typical days",
                severity="low",
                expected_value=[day_names[d] for d in typical_days],
                actual_value=day_names[day],
                deviation_score=0.4,
            )
        return None

    def _check_location_deviation(
        self,
        event: Any,
        baseline: Any,
    ) -> Optional[BaselineDeviation]:
        """Check if event location is outside known locations."""
        source_geo = getattr(event, "source_geo", None)
        known_locations = getattr(baseline, "known_locations", None)

        if source_geo is None or not known_locations:
            return None

        # Check if current location matches any known location (by country/city)
        current_country = getattr(source_geo, "country", None)
        current_city = getattr(source_geo, "city", None)

        for known in known_locations:
            known_country = getattr(known, "country", None)
            known_city = getattr(known, "city", None)
            if current_country == known_country and current_city == known_city:
                return None  # Match found

        return BaselineDeviation(
            deviation_type="new_location",
            description=f"Activity from new location: {current_city}, {current_country}",
            severity="high",
            expected_value=[f"{getattr(l, 'city', '')}, {getattr(l, 'country', '')}" for l in known_locations[:3]],
            actual_value=f"{current_city}, {current_country}",
            deviation_score=0.8,
        )

    def _check_device_deviation(
        self,
        event: Any,
        baseline: Any,
    ) -> Optional[BaselineDeviation]:
        """Check if event device is outside known devices."""
        device_id = getattr(event, "device_id", None)
        known_devices = getattr(baseline, "known_devices", None)

        if device_id is None or not known_devices:
            return None

        known_device_ids = {
            d.get("device_id") if isinstance(d, dict) else getattr(d, "device_id", None)
            for d in known_devices
        }

        if device_id not in known_device_ids:
            return BaselineDeviation(
                deviation_type="new_device",
                description=f"Activity from new device: {device_id}",
                severity="medium",
                expected_value=list(known_device_ids)[:3],
                actual_value=device_id,
                deviation_score=0.7,
            )
        return None

    def _check_ip_deviation(
        self,
        event: Any,
        baseline: Any,
    ) -> Optional[BaselineDeviation]:
        """Check if event IP is outside known IPs."""
        source_ip = getattr(event, "source_ip", None)
        known_ips = getattr(baseline, "known_ips", None)

        if source_ip is None or not known_ips:
            return None

        if source_ip not in known_ips:
            return BaselineDeviation(
                deviation_type="new_ip",
                description=f"Activity from new IP: {source_ip}",
                severity="low",
                expected_value=list(known_ips)[:3],
                actual_value=source_ip,
                deviation_score=0.3,
            )
        return None

    def _check_application_deviation(
        self,
        event: Any,
        baseline: Any,
    ) -> Optional[BaselineDeviation]:
        """Check if event application is outside typical applications."""
        application_name = getattr(event, "application_name", None)
        typical_applications = getattr(baseline, "typical_applications", None)

        if application_name is None or not typical_applications:
            return None

        if application_name not in typical_applications:
            return BaselineDeviation(
                deviation_type="new_application",
                description=f"Access to new application: {application_name}",
                severity="low",
                expected_value=list(typical_applications)[:5],
                actual_value=application_name,
                deviation_score=0.3,
            )
        return None


    def compare_daily_volume(
        self,
        user_email: str,
        event_count: int,
        baseline: Optional[Any] = None,
    ) -> Dict[str, Any]:
        """Compare daily event volume against baseline.

        Args:
            user_email: User email address
            event_count: Actual event count for the day
            baseline: Optional baseline (if not provided, will be fetched)

        Returns:
            Dictionary with volume comparison results
        """
        result = {
            "user_email": user_email,
            "actual_count": event_count,
            "is_volume_anomaly": False,
            "z_score": 0.0,
        }

        # Get baseline if not provided
        if baseline is None and self.baseline_store:
            try:
                baseline = self.baseline_store.get_baseline(user_email)
            except Exception as e:
                logger.warning(f"Failed to get baseline for {user_email}: {e}")

        if baseline is None:
            return result

        # Get baseline statistics
        avg_events = getattr(baseline, "avg_events_per_day", None)
        std_dev = getattr(baseline, "events_std_dev", None)

        if avg_events is None or std_dev is None or std_dev == 0:
            result["expected_count"] = avg_events or 0
            return result

        result["expected_count"] = avg_events

        # Calculate z-score
        z_score = (event_count - avg_events) / std_dev
        result["z_score"] = round(z_score, 2)

        # Check if anomaly (more than 2 standard deviations)
        result["is_volume_anomaly"] = abs(z_score) > 2

        return result


__all__ = [
    "BaselineDeviation",
    "BaselineComparison",
    "BaselineComparator",
]
