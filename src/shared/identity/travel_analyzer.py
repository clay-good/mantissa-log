"""Impossible travel analysis for identity threat detection.

Analyzes geographic distance and time between identity events to detect
physically impossible travel scenarios that may indicate credential theft
or session hijacking.
"""

import logging
import math
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Optional

from ..models.identity_event import GeoLocation, IdentityEvent
from .anomaly_types import (
    AnomalySeverity,
    IdentityAnomaly,
    IdentityAnomalyType,
    get_recommended_action,
)

logger = logging.getLogger(__name__)


class GeoUtils:
    """Utility methods for geographic calculations."""

    # Earth's radius in kilometers
    EARTH_RADIUS_KM = 6371.0

    @staticmethod
    def haversine_distance(
        lat1: float, lon1: float, lat2: float, lon2: float
    ) -> float:
        """Calculate the great-circle distance between two points on Earth.

        Uses the Haversine formula for accurate distance calculation.

        Args:
            lat1: Latitude of first point in degrees
            lon1: Longitude of first point in degrees
            lat2: Latitude of second point in degrees
            lon2: Longitude of second point in degrees

        Returns:
            Distance in kilometers
        """
        # Convert to radians
        lat1_rad = math.radians(lat1)
        lat2_rad = math.radians(lat2)
        delta_lat = math.radians(lat2 - lat1)
        delta_lon = math.radians(lon2 - lon1)

        # Haversine formula
        a = (
            math.sin(delta_lat / 2) ** 2
            + math.cos(lat1_rad) * math.cos(lat2_rad) * math.sin(delta_lon / 2) ** 2
        )
        c = 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))

        return GeoUtils.EARTH_RADIUS_KM * c

    @staticmethod
    def calculate_velocity(
        geo1: GeoLocation, geo2: GeoLocation, time_delta: timedelta
    ) -> float:
        """Calculate required travel velocity between two locations.

        Args:
            geo1: First location
            geo2: Second location
            time_delta: Time difference between locations

        Returns:
            Required velocity in km/h, or infinity if time_delta is zero
        """
        if time_delta.total_seconds() <= 0:
            return float("inf")

        if not geo1.latitude or not geo1.longitude or not geo2.latitude or not geo2.longitude:
            return 0.0

        distance_km = GeoUtils.haversine_distance(
            geo1.latitude, geo1.longitude, geo2.latitude, geo2.longitude
        )

        hours = time_delta.total_seconds() / 3600
        return distance_km / hours if hours > 0 else float("inf")

    @staticmethod
    def is_same_city(geo1: GeoLocation, geo2: GeoLocation) -> bool:
        """Check if two locations are in the same city.

        Args:
            geo1: First location
            geo2: Second location

        Returns:
            True if same city (or very close proximity)
        """
        # If both have city names, compare them
        if geo1.city and geo2.city:
            return geo1.city.lower() == geo2.city.lower()

        # Fall back to geographic proximity (within 50km)
        if geo1.latitude and geo1.longitude and geo2.latitude and geo2.longitude:
            distance = GeoUtils.haversine_distance(
                geo1.latitude, geo1.longitude, geo2.latitude, geo2.longitude
            )
            return distance < 50

        return False

    @staticmethod
    def is_same_country(geo1: GeoLocation, geo2: GeoLocation) -> bool:
        """Check if two locations are in the same country.

        Args:
            geo1: First location
            geo2: Second location

        Returns:
            True if same country
        """
        if geo1.country and geo2.country:
            return geo1.country.lower() == geo2.country.lower()
        return False

    @staticmethod
    def get_distance_km(geo1: GeoLocation, geo2: GeoLocation) -> Optional[float]:
        """Get distance between two locations in kilometers.

        Args:
            geo1: First location
            geo2: Second location

        Returns:
            Distance in km, or None if coordinates unavailable
        """
        if not geo1.latitude or not geo1.longitude or not geo2.latitude or not geo2.longitude:
            return None

        return GeoUtils.haversine_distance(
            geo1.latitude, geo1.longitude, geo2.latitude, geo2.longitude
        )


@dataclass
class TravelAnalysisResult:
    """Result of impossible travel analysis."""

    is_impossible: bool
    distance_km: float
    time_delta_minutes: float
    velocity_kmh: float
    severity: AnomalySeverity
    confidence: float
    details: str


class ImpossibleTravelAnalyzer:
    """Analyzes events for physically impossible travel scenarios.

    Detects when a user authenticates from two distant locations in a
    timeframe that would require superhuman travel speeds.

    Thresholds:
    - MAX_HUMAN_VELOCITY_KMH = 800 (commercial flight speed)
    - VPN_DETECTION_THRESHOLD_KMH = 5000 (instant travel = likely VPN/proxy)
    """

    # Maximum realistic human travel speed (commercial aircraft)
    MAX_HUMAN_VELOCITY_KMH = 800

    # Threshold above which travel is likely VPN/proxy rather than credential theft
    VPN_DETECTION_THRESHOLD_KMH = 5000

    # Minimum distance for analysis (ignore very short distances)
    MIN_DISTANCE_KM = 100

    # Minimum time gap to consider (ignore near-simultaneous events)
    MIN_TIME_GAP_SECONDS = 60

    def __init__(
        self,
        max_velocity_kmh: float = None,
        vpn_threshold_kmh: float = None,
        min_distance_km: float = None,
    ):
        """Initialize the analyzer with configurable thresholds.

        Args:
            max_velocity_kmh: Maximum realistic travel velocity
            vpn_threshold_kmh: Velocity above which VPN is suspected
            min_distance_km: Minimum distance to trigger analysis
        """
        self.max_velocity_kmh = max_velocity_kmh or self.MAX_HUMAN_VELOCITY_KMH
        self.vpn_threshold_kmh = vpn_threshold_kmh or self.VPN_DETECTION_THRESHOLD_KMH
        self.min_distance_km = min_distance_km or self.MIN_DISTANCE_KM

    def haversine_distance(
        self, lat1: float, lon1: float, lat2: float, lon2: float
    ) -> float:
        """Calculate the great-circle distance between two points.

        Wrapper around GeoUtils.haversine_distance for test compatibility.

        Args:
            lat1: Latitude of first point in degrees
            lon1: Longitude of first point in degrees
            lat2: Latitude of second point in degrees
            lon2: Longitude of second point in degrees

        Returns:
            Distance in kilometers
        """
        return GeoUtils.haversine_distance(lat1, lon1, lat2, lon2)

    def calculate_velocity(self, distance_km: float, time_seconds: float) -> float:
        """Calculate travel velocity.

        Args:
            distance_km: Distance in kilometers
            time_seconds: Time in seconds

        Returns:
            Velocity in km/h, or infinity if time_seconds is zero
        """
        if time_seconds <= 0:
            return float("inf")
        hours = time_seconds / 3600
        return distance_km / hours

    def is_impossible_travel(
        self,
        geo1: GeoLocation,
        geo2: GeoLocation,
        time_diff_seconds: float,
    ) -> bool:
        """Check if travel between two locations is impossible.

        Args:
            geo1: First location
            geo2: Second location
            time_diff_seconds: Time difference in seconds

        Returns:
            True if travel is impossible (velocity exceeds max threshold)
        """
        # Handle missing coordinates
        lat1 = geo1.latitude if geo1.latitude is not None else geo1.lat
        lon1 = geo1.longitude if geo1.longitude is not None else geo1.lon
        lat2 = geo2.latitude if geo2.latitude is not None else geo2.lat
        lon2 = geo2.longitude if geo2.longitude is not None else geo2.lon

        if lat1 is None or lon1 is None or lat2 is None or lon2 is None:
            return False

        # Calculate distance
        distance_km = self.haversine_distance(lat1, lon1, lat2, lon2)

        # Same location is never impossible
        if distance_km < 1:  # Less than 1 km
            return False

        # Calculate velocity
        velocity_kmh = self.calculate_velocity(distance_km, time_diff_seconds)

        # Travel is impossible if velocity exceeds threshold
        return velocity_kmh > self.max_velocity_kmh

    def analyze(
        self, current_event: IdentityEvent, previous_event: IdentityEvent
    ) -> Optional[IdentityAnomaly]:
        """Analyze two events for impossible travel.

        Args:
            current_event: The more recent identity event
            previous_event: The earlier identity event

        Returns:
            IdentityAnomaly if impossible travel detected, None otherwise
        """
        # Validate we have the required geo data
        if not current_event.source_geo or not previous_event.source_geo:
            logger.debug("Missing geo data for travel analysis")
            return None

        current_geo = current_event.source_geo
        previous_geo = previous_event.source_geo

        if not (current_geo.latitude and current_geo.longitude):
            return None
        if not (previous_geo.latitude and previous_geo.longitude):
            return None

        # Calculate time difference
        current_time = current_event.timestamp
        previous_time = previous_event.timestamp

        if current_time.tzinfo is None:
            current_time = current_time.replace(tzinfo=timezone.utc)
        if previous_time.tzinfo is None:
            previous_time = previous_time.replace(tzinfo=timezone.utc)

        time_delta = current_time - previous_time

        # Ensure we're comparing in the right order
        if time_delta.total_seconds() < 0:
            # Events are in wrong order, swap them
            current_event, previous_event = previous_event, current_event
            current_geo, previous_geo = previous_geo, current_geo
            time_delta = -time_delta

        # Skip if time gap is too small
        if time_delta.total_seconds() < self.MIN_TIME_GAP_SECONDS:
            return None

        # Calculate distance
        distance_km = GeoUtils.haversine_distance(
            previous_geo.latitude,
            previous_geo.longitude,
            current_geo.latitude,
            current_geo.longitude,
        )

        # Skip if distance is too small
        if distance_km < self.min_distance_km:
            return None

        # Calculate required velocity
        hours = time_delta.total_seconds() / 3600
        velocity_kmh = distance_km / hours if hours > 0 else float("inf")

        # Check if travel is impossible
        if velocity_kmh <= self.max_velocity_kmh:
            return None  # Travel is possible

        # Determine severity based on velocity
        result = self._analyze_result(distance_km, time_delta, velocity_kmh)

        if not result.is_impossible:
            return None

        # Build the anomaly
        return IdentityAnomaly.create(
            anomaly_type=IdentityAnomalyType.IMPOSSIBLE_TRAVEL,
            user_email=current_event.user_email,
            event_id=current_event.event_id,
            severity=result.severity,
            confidence=result.confidence,
            title=f"Impossible travel detected: {int(distance_km)}km in {int(result.time_delta_minutes)}min",
            description=result.details,
            evidence={
                "current_location": {
                    "country": current_geo.country,
                    "city": current_geo.city,
                    "latitude": current_geo.latitude,
                    "longitude": current_geo.longitude,
                    "ip": current_event.source_ip,
                },
                "previous_location": {
                    "country": previous_geo.country,
                    "city": previous_geo.city,
                    "latitude": previous_geo.latitude,
                    "longitude": previous_geo.longitude,
                    "ip": previous_event.source_ip,
                },
                "distance_km": round(distance_km, 1),
                "time_delta_minutes": round(result.time_delta_minutes, 1),
                "velocity_kmh": round(velocity_kmh, 1),
                "previous_event_id": previous_event.event_id,
                "previous_event_time": previous_event.timestamp.isoformat(),
            },
            baseline_comparison={
                "max_realistic_velocity_kmh": self.max_velocity_kmh,
                "observed_velocity_kmh": round(velocity_kmh, 1),
                "velocity_multiple": round(velocity_kmh / self.max_velocity_kmh, 1),
            },
            recommended_action=get_recommended_action(
                IdentityAnomalyType.IMPOSSIBLE_TRAVEL
            ),
        )

    def _analyze_result(
        self, distance_km: float, time_delta: timedelta, velocity_kmh: float
    ) -> TravelAnalysisResult:
        """Analyze travel metrics and determine severity.

        Args:
            distance_km: Distance between locations
            time_delta: Time between events
            velocity_kmh: Required travel velocity

        Returns:
            TravelAnalysisResult with analysis details
        """
        time_minutes = time_delta.total_seconds() / 60

        # Determine if this is impossible travel
        is_impossible = velocity_kmh > self.max_velocity_kmh

        if not is_impossible:
            return TravelAnalysisResult(
                is_impossible=False,
                distance_km=distance_km,
                time_delta_minutes=time_minutes,
                velocity_kmh=velocity_kmh,
                severity=AnomalySeverity.LOW,
                confidence=0.0,
                details="Travel is within realistic bounds",
            )

        # Determine severity based on velocity
        if velocity_kmh >= self.vpn_threshold_kmh:
            # Extremely high velocity - likely VPN/proxy
            severity = AnomalySeverity.HIGH
            confidence = 0.95
            details = (
                f"User authenticated from {distance_km:.0f}km away in "
                f"{time_minutes:.0f} minutes, requiring {velocity_kmh:.0f} km/h "
                f"(likely VPN/proxy usage or credential theft)"
            )
        elif velocity_kmh >= 1500:
            # Very fast - faster than any commercial transport
            severity = AnomalySeverity.HIGH
            confidence = 0.9
            details = (
                f"User authenticated from {distance_km:.0f}km away in "
                f"{time_minutes:.0f} minutes, requiring {velocity_kmh:.0f} km/h "
                f"(exceeds maximum commercial flight speed)"
            )
        elif velocity_kmh >= self.max_velocity_kmh:
            # Borderline impossible - faster than commercial flight
            severity = AnomalySeverity.MEDIUM
            confidence = 0.7
            details = (
                f"User authenticated from {distance_km:.0f}km away in "
                f"{time_minutes:.0f} minutes, requiring {velocity_kmh:.0f} km/h "
                f"(slightly exceeds commercial flight speed)"
            )
        else:
            # Should not reach here, but handle gracefully
            severity = AnomalySeverity.LOW
            confidence = 0.5
            details = f"Unusual travel pattern detected"

        return TravelAnalysisResult(
            is_impossible=is_impossible,
            distance_km=distance_km,
            time_delta_minutes=time_minutes,
            velocity_kmh=velocity_kmh,
            severity=severity,
            confidence=confidence,
            details=details,
        )

    def get_travel_anomaly_details(
        self, geo1: GeoLocation, geo2: GeoLocation, time_diff: timedelta
    ) -> dict:
        """Get detailed travel analysis without creating an anomaly.

        Useful for reporting and investigation.

        Args:
            geo1: First location
            geo2: Second location
            time_diff: Time difference between events

        Returns:
            Dictionary with travel analysis details
        """
        if not (geo1.latitude and geo1.longitude and geo2.latitude and geo2.longitude):
            return {
                "error": "Missing coordinate data",
                "geo1_has_coords": bool(geo1.latitude and geo1.longitude),
                "geo2_has_coords": bool(geo2.latitude and geo2.longitude),
            }

        distance_km = GeoUtils.haversine_distance(
            geo1.latitude, geo1.longitude, geo2.latitude, geo2.longitude
        )

        hours = time_diff.total_seconds() / 3600
        velocity_kmh = distance_km / hours if hours > 0 else float("inf")

        is_impossible = velocity_kmh > self.max_velocity_kmh
        is_vpn_likely = velocity_kmh > self.vpn_threshold_kmh

        return {
            "distance_km": round(distance_km, 2),
            "time_minutes": round(time_diff.total_seconds() / 60, 1),
            "velocity_kmh": round(velocity_kmh, 2) if velocity_kmh != float("inf") else "infinite",
            "is_impossible": is_impossible,
            "is_vpn_likely": is_vpn_likely,
            "max_velocity_threshold": self.max_velocity_kmh,
            "vpn_threshold": self.vpn_threshold_kmh,
            "location_1": {
                "country": geo1.country,
                "city": geo1.city,
                "coords": f"{geo1.latitude}, {geo1.longitude}",
            },
            "location_2": {
                "country": geo2.country,
                "city": geo2.city,
                "coords": f"{geo2.latitude}, {geo2.longitude}",
            },
        }
