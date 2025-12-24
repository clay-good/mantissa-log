"""Impossible travel detection for identity events.

Provides detection of impossible travel scenarios where a user authenticates
from geographically distant locations in impossibly short time frames.
Integrates with the ImpossibleTravelAnalyzer from travel_analyzer.py.
"""

import logging
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Set

from ..anomaly_types import AnomalySeverity, IdentityAnomaly, IdentityAnomalyType
from ..travel_analyzer import GeoUtils, ImpossibleTravelAnalyzer

logger = logging.getLogger(__name__)


# Known VPN provider IP ranges (sample - in production would use threat intel feeds)
KNOWN_VPN_ASN_NAMES = {
    "nordvpn",
    "expressvpn",
    "protonvpn",
    "surfshark",
    "cyberghost",
    "privatevpn",
    "mullvad",
    "windscribe",
    "hotspot shield",
    "tunnelbear",
}

# Known cloud/datacenter providers (often used for proxies)
KNOWN_DATACENTER_PROVIDERS = {
    "amazon",
    "aws",
    "microsoft azure",
    "google cloud",
    "digitalocean",
    "linode",
    "vultr",
    "hetzner",
    "ovh",
    "cloudflare",
}

# Shared/service account patterns
SHARED_ACCOUNT_PATTERNS = [
    "noreply@",
    "service@",
    "system@",
    "automation@",
    "bot@",
    "integration@",
    "sync@",
    "admin@",
    "shared@",
    "generic@",
]


@dataclass
class TravelDetails:
    """Human-readable travel analysis details.

    Attributes:
        distance_km: Distance between locations in kilometers
        distance_miles: Distance in miles
        required_velocity_kmh: Required travel velocity in km/h
        time_delta_minutes: Time between events in minutes
        time_by_plane_hours: Estimated flight time
        time_by_car_hours: Estimated driving time
        is_possible_by_plane: Whether travel is possible by commercial flight
        is_possible_by_car: Whether travel is possible by car
        vpn_likely: Whether VPN usage is likely based on velocity
    """

    distance_km: float
    distance_miles: float
    required_velocity_kmh: float
    time_delta_minutes: float
    time_by_plane_hours: float
    time_by_car_hours: float
    is_possible_by_plane: bool
    is_possible_by_car: bool
    vpn_likely: bool

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "distance_km": round(self.distance_km, 1),
            "distance_miles": round(self.distance_miles, 1),
            "required_velocity_kmh": round(self.required_velocity_kmh, 1),
            "time_delta_minutes": round(self.time_delta_minutes, 1),
            "time_by_plane_hours": round(self.time_by_plane_hours, 2),
            "time_by_car_hours": round(self.time_by_car_hours, 2),
            "is_possible_by_plane": self.is_possible_by_plane,
            "is_possible_by_car": self.is_possible_by_car,
            "vpn_likely": self.vpn_likely,
        }


@dataclass
class ImpossibleTravelAlert:
    """Alert for impossible travel detection.

    Attributes:
        alert_id: Unique identifier for this alert
        severity: Alert severity (critical, high, medium, low)
        title: Human-readable alert title
        description: Detailed description
        user_email: User who triggered the alert
        current_location: Current authentication location
        previous_location: Previous authentication location
        travel_details: Detailed travel analysis
        time_window_hours: Detection time window
        current_event_time: Time of current event
        previous_event_time: Time of previous event
        is_vpn_related: Whether VPN is likely involved
        is_shared_account: Whether account is shared/service account
        source_ips: Source IPs involved
        providers: Identity providers involved
        anomaly: The underlying IdentityAnomaly if detected
        evidence: Additional evidence data
        mitre_techniques: Associated MITRE ATT&CK techniques
        recommended_actions: Suggested response actions
    """

    alert_id: str
    severity: str
    title: str
    description: str
    user_email: str
    current_location: Dict[str, Any] = field(default_factory=dict)
    previous_location: Dict[str, Any] = field(default_factory=dict)
    travel_details: Optional[TravelDetails] = None
    time_window_hours: int = 24
    current_event_time: Optional[datetime] = None
    previous_event_time: Optional[datetime] = None
    is_vpn_related: bool = False
    is_shared_account: bool = False
    source_ips: List[str] = field(default_factory=list)
    providers: List[str] = field(default_factory=list)
    anomaly: Optional[IdentityAnomaly] = None
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
            "current_location": self.current_location,
            "previous_location": self.previous_location,
            "travel_details": (
                self.travel_details.to_dict() if self.travel_details else None
            ),
            "time_window_hours": self.time_window_hours,
            "current_event_time": (
                self.current_event_time.isoformat() if self.current_event_time else None
            ),
            "previous_event_time": (
                self.previous_event_time.isoformat()
                if self.previous_event_time
                else None
            ),
            "is_vpn_related": self.is_vpn_related,
            "is_shared_account": self.is_shared_account,
            "source_ips": self.source_ips,
            "providers": self.providers,
            "anomaly": self.anomaly.to_dict() if self.anomaly else None,
            "evidence": self.evidence,
            "mitre_techniques": self.mitre_techniques,
            "recommended_actions": self.recommended_actions,
            "detected_at": self.detected_at.isoformat(),
        }


class ImpossibleTravelDetector:
    """Detects impossible travel across identity events.

    Uses ImpossibleTravelAnalyzer to identify authentication events that
    occur from geographically distant locations in impossibly short time
    frames, indicating potential credential theft or session hijacking.

    Attributes:
        query_executor: Executor for querying identity events
        travel_analyzer: Analyzer for impossible travel calculations
        DEFAULT_WINDOW_HOURS: Default time window for detection
    """

    # Default time window
    DEFAULT_WINDOW_HOURS = 24

    # Average travel speeds for estimation
    AVG_PLANE_SPEED_KMH = 800
    AVG_CAR_SPEED_KMH = 100

    def __init__(
        self,
        query_executor: Any,
        identity_events_table: str = "identity_events",
        travel_analyzer: ImpossibleTravelAnalyzer = None,
        ip_reputation_service: Any = None,
    ):
        """Initialize the impossible travel detector.

        Args:
            query_executor: Executor for querying the data lake
            identity_events_table: Name of the identity events table
            travel_analyzer: Optional pre-configured analyzer
            ip_reputation_service: Optional IP reputation service for VPN detection
        """
        self.query_executor = query_executor
        self.identity_events_table = identity_events_table
        self.travel_analyzer = travel_analyzer or ImpossibleTravelAnalyzer()
        self.ip_reputation_service = ip_reputation_service

        # Cache for shared account detection
        self._shared_account_cache: Set[str] = set()

    def detect_impossible_travel(
        self,
        window_hours: int = None,
    ) -> List[ImpossibleTravelAlert]:
        """Detect impossible travel across all users.

        Gets all successful auth events in window, then compares
        consecutive events per user to find impossible travel.

        Args:
            window_hours: Detection window in hours

        Returns:
            List of ImpossibleTravelAlert for each detection
        """
        window = window_hours or self.DEFAULT_WINDOW_HOURS
        alerts = []

        cutoff = datetime.now(timezone.utc) - timedelta(hours=window)
        cutoff_str = cutoff.strftime("%Y-%m-%d %H:%M:%S")

        # Get all successful auth events with geolocation
        query = f"""
            SELECT
                event_id,
                user_email,
                source_ip,
                source_geo_latitude,
                source_geo_longitude,
                source_geo_country,
                source_geo_city,
                provider,
                event_timestamp,
                user_agent,
                asn_name
            FROM {self.identity_events_table}
            WHERE event_type = 'AUTH_SUCCESS'
              AND event_timestamp >= TIMESTAMP '{cutoff_str}'
              AND source_geo_latitude IS NOT NULL
              AND source_geo_longitude IS NOT NULL
            ORDER BY user_email, event_timestamp ASC
        """

        try:
            result = self.query_executor.execute_query(query, timeout_seconds=180)

            # Group events by user
            user_events: Dict[str, List[Dict]] = {}
            for row in result.rows:
                user = row.get("user_email")
                if user not in user_events:
                    user_events[user] = []
                user_events[user].append(row)

            # Analyze consecutive events per user
            for user_email, events in user_events.items():
                if len(events) < 2:
                    continue

                user_alerts = self._analyze_user_events(
                    user_email=user_email,
                    events=events,
                    window_hours=window,
                )
                alerts.extend(user_alerts)

        except Exception as e:
            logger.error(f"Error detecting impossible travel: {e}")

        return alerts

    def analyze_user_travel(
        self,
        user_email: str,
        window_hours: int = None,
    ) -> List[IdentityAnomaly]:
        """Focused analysis for a single user.

        Args:
            user_email: User to analyze
            window_hours: Detection window in hours

        Returns:
            List of IdentityAnomaly for impossible travel detections
        """
        window = window_hours or self.DEFAULT_WINDOW_HOURS
        anomalies = []

        cutoff = datetime.now(timezone.utc) - timedelta(hours=window)
        cutoff_str = cutoff.strftime("%Y-%m-%d %H:%M:%S")

        query = f"""
            SELECT
                event_id,
                user_email,
                source_ip,
                source_geo_latitude,
                source_geo_longitude,
                source_geo_country,
                source_geo_city,
                provider,
                event_timestamp,
                user_agent,
                asn_name
            FROM {self.identity_events_table}
            WHERE user_email = '{user_email}'
              AND event_type = 'AUTH_SUCCESS'
              AND event_timestamp >= TIMESTAMP '{cutoff_str}'
              AND source_geo_latitude IS NOT NULL
              AND source_geo_longitude IS NOT NULL
            ORDER BY event_timestamp ASC
        """

        try:
            result = self.query_executor.execute_query(query, timeout_seconds=60)

            if len(result.rows) < 2:
                return anomalies

            # Compare consecutive events
            for i in range(1, len(result.rows)):
                current = result.rows[i]
                previous = result.rows[i - 1]

                anomaly = self._check_travel_pair(current, previous)
                if anomaly:
                    anomalies.append(anomaly)

        except Exception as e:
            logger.error(f"Error analyzing user travel: {e}")

        return anomalies

    def is_vpn_related(
        self,
        event1_ip: str,
        event1_asn: str,
        event2_ip: str,
        event2_asn: str,
    ) -> bool:
        """Check if either IP is a known VPN/proxy.

        Args:
            event1_ip: First event's source IP
            event1_asn: First event's ASN name
            event2_ip: Second event's source IP
            event2_asn: Second event's ASN name

        Returns:
            True if VPN/proxy is likely
        """
        # Check ASN names for known VPN providers
        for asn in [event1_asn, event2_asn]:
            if asn:
                asn_lower = asn.lower()
                for vpn_pattern in KNOWN_VPN_ASN_NAMES:
                    if vpn_pattern in asn_lower:
                        return True

        # Check for datacenter IPs (often used for proxies)
        for asn in [event1_asn, event2_asn]:
            if asn:
                asn_lower = asn.lower()
                for dc_pattern in KNOWN_DATACENTER_PROVIDERS:
                    if dc_pattern in asn_lower:
                        return True

        # Use IP reputation service if available
        if self.ip_reputation_service:
            try:
                for ip in [event1_ip, event2_ip]:
                    rep = self.ip_reputation_service.check_ip(ip)
                    if rep and rep.get("is_vpn") or rep.get("is_proxy"):
                        return True
            except Exception as e:
                logger.warning(f"IP reputation check failed: {e}")

        return False

    def is_shared_account(self, user_email: str) -> bool:
        """Check if account is a known shared/service account.

        Args:
            user_email: User email to check

        Returns:
            True if account is shared/service account
        """
        if not user_email:
            return False

        # Check cache first
        if user_email in self._shared_account_cache:
            return True

        email_lower = user_email.lower()

        # Check against patterns
        for pattern in SHARED_ACCOUNT_PATTERNS:
            if pattern in email_lower:
                self._shared_account_cache.add(user_email)
                return True

        return False

    def calculate_travel_details(
        self,
        lat1: float,
        lon1: float,
        lat2: float,
        lon2: float,
        time_delta: timedelta,
    ) -> TravelDetails:
        """Calculate human-readable travel analysis.

        Args:
            lat1: Latitude of first location
            lon1: Longitude of first location
            lat2: Latitude of second location
            lon2: Longitude of second location
            time_delta: Time between events

        Returns:
            TravelDetails with human-readable analysis
        """
        distance_km = GeoUtils.haversine_distance(lat1, lon1, lat2, lon2)
        distance_miles = distance_km * 0.621371

        time_hours = time_delta.total_seconds() / 3600
        time_minutes = time_delta.total_seconds() / 60

        velocity_kmh = distance_km / time_hours if time_hours > 0 else float("inf")

        # Estimate travel times
        time_by_plane = distance_km / self.AVG_PLANE_SPEED_KMH if distance_km > 0 else 0
        time_by_car = distance_km / self.AVG_CAR_SPEED_KMH if distance_km > 0 else 0

        # Add typical airport overhead for flights (2 hours total)
        time_by_plane += 2.0

        return TravelDetails(
            distance_km=distance_km,
            distance_miles=distance_miles,
            required_velocity_kmh=velocity_kmh,
            time_delta_minutes=time_minutes,
            time_by_plane_hours=time_by_plane,
            time_by_car_hours=time_by_car,
            is_possible_by_plane=time_hours >= time_by_plane,
            is_possible_by_car=time_hours >= time_by_car,
            vpn_likely=velocity_kmh > self.travel_analyzer.vpn_threshold_kmh,
        )

    def _analyze_user_events(
        self,
        user_email: str,
        events: List[Dict],
        window_hours: int,
    ) -> List[ImpossibleTravelAlert]:
        """Analyze consecutive events for a user.

        Args:
            user_email: User being analyzed
            events: List of auth events sorted by time
            window_hours: Detection window used

        Returns:
            List of alerts for impossible travel
        """
        alerts = []

        for i in range(1, len(events)):
            current = events[i]
            previous = events[i - 1]

            # Check for impossible travel
            anomaly = self._check_travel_pair(current, previous)
            if not anomaly:
                continue

            # Get travel details
            travel_details = self.calculate_travel_details(
                lat1=previous.get("source_geo_latitude"),
                lon1=previous.get("source_geo_longitude"),
                lat2=current.get("source_geo_latitude"),
                lon2=current.get("source_geo_longitude"),
                time_delta=self._get_time_delta(
                    current.get("event_timestamp"),
                    previous.get("event_timestamp"),
                ),
            )

            # Check for VPN
            is_vpn = self.is_vpn_related(
                event1_ip=current.get("source_ip", ""),
                event1_asn=current.get("asn_name", ""),
                event2_ip=previous.get("source_ip", ""),
                event2_asn=previous.get("asn_name", ""),
            )

            # Check for shared account
            is_shared = self.is_shared_account(user_email)

            # Create alert
            alert = self._create_travel_alert(
                user_email=user_email,
                current_event=current,
                previous_event=previous,
                anomaly=anomaly,
                travel_details=travel_details,
                is_vpn_related=is_vpn,
                is_shared_account=is_shared,
                window_hours=window_hours,
            )
            alerts.append(alert)

        return alerts

    def _check_travel_pair(
        self,
        current: Dict,
        previous: Dict,
    ) -> Optional[IdentityAnomaly]:
        """Check a pair of events for impossible travel.

        Args:
            current: Current event data
            previous: Previous event data

        Returns:
            IdentityAnomaly if impossible travel detected
        """
        from ..models.identity_event import GeoLocation, IdentityEvent

        # Build minimal IdentityEvent objects for the analyzer
        current_geo = GeoLocation(
            latitude=current.get("source_geo_latitude"),
            longitude=current.get("source_geo_longitude"),
            country=current.get("source_geo_country"),
            city=current.get("source_geo_city"),
        )

        previous_geo = GeoLocation(
            latitude=previous.get("source_geo_latitude"),
            longitude=previous.get("source_geo_longitude"),
            country=previous.get("source_geo_country"),
            city=previous.get("source_geo_city"),
        )

        current_event = IdentityEvent(
            event_id=current.get("event_id", str(uuid.uuid4())),
            user_email=current.get("user_email", ""),
            event_type="AUTH_SUCCESS",
            timestamp=self._parse_timestamp(current.get("event_timestamp")),
            provider=current.get("provider", ""),
            source_ip=current.get("source_ip"),
            source_geo=current_geo,
        )

        previous_event = IdentityEvent(
            event_id=previous.get("event_id", str(uuid.uuid4())),
            user_email=previous.get("user_email", ""),
            event_type="AUTH_SUCCESS",
            timestamp=self._parse_timestamp(previous.get("event_timestamp")),
            provider=previous.get("provider", ""),
            source_ip=previous.get("source_ip"),
            source_geo=previous_geo,
        )

        return self.travel_analyzer.analyze(current_event, previous_event)

    def _create_travel_alert(
        self,
        user_email: str,
        current_event: Dict,
        previous_event: Dict,
        anomaly: IdentityAnomaly,
        travel_details: TravelDetails,
        is_vpn_related: bool,
        is_shared_account: bool,
        window_hours: int,
    ) -> ImpossibleTravelAlert:
        """Create alert for impossible travel.

        Args:
            user_email: User who triggered the alert
            current_event: Current event data
            previous_event: Previous event data
            anomaly: Detected anomaly
            travel_details: Travel analysis details
            is_vpn_related: Whether VPN is likely
            is_shared_account: Whether account is shared
            window_hours: Detection window

        Returns:
            ImpossibleTravelAlert
        """
        # Adjust severity based on context
        severity = anomaly.severity.value
        if is_vpn_related:
            # VPN may explain the travel, reduce severity
            if severity == "critical":
                severity = "high"
            elif severity == "high":
                severity = "medium"
        if is_shared_account:
            # Shared accounts may have legitimate distributed usage
            if severity == "high":
                severity = "medium"
            elif severity == "medium":
                severity = "low"

        # Build description
        description_parts = [
            f"Impossible travel detected for {user_email}.",
            f"Distance: {travel_details.distance_km:.0f} km in {travel_details.time_delta_minutes:.0f} minutes.",
            f"Required velocity: {travel_details.required_velocity_kmh:.0f} km/h (max realistic: 800 km/h).",
        ]

        if is_vpn_related:
            description_parts.append("VPN/proxy usage suspected - may be benign.")
        if is_shared_account:
            description_parts.append("Account appears to be shared - verify usage pattern.")

        # Build recommended actions
        actions = [
            f"Verify identity of {user_email} through out-of-band communication",
        ]

        if is_vpn_related:
            actions.append("Confirm if VPN usage is expected per policy")
        else:
            actions.extend(
                [
                    "Review session for suspicious activity",
                    "Consider requiring step-up authentication",
                ]
            )

        if not is_shared_account:
            actions.append("Check if user has legitimate travel plans")

        return ImpossibleTravelAlert(
            alert_id=str(uuid.uuid4()),
            severity=severity,
            title=f"Impossible Travel: {travel_details.distance_km:.0f}km in {travel_details.time_delta_minutes:.0f}min",
            description=" ".join(description_parts),
            user_email=user_email,
            current_location={
                "country": current_event.get("source_geo_country"),
                "city": current_event.get("source_geo_city"),
                "ip": current_event.get("source_ip"),
                "latitude": current_event.get("source_geo_latitude"),
                "longitude": current_event.get("source_geo_longitude"),
            },
            previous_location={
                "country": previous_event.get("source_geo_country"),
                "city": previous_event.get("source_geo_city"),
                "ip": previous_event.get("source_ip"),
                "latitude": previous_event.get("source_geo_latitude"),
                "longitude": previous_event.get("source_geo_longitude"),
            },
            travel_details=travel_details,
            time_window_hours=window_hours,
            current_event_time=self._parse_timestamp(current_event.get("event_timestamp")),
            previous_event_time=self._parse_timestamp(previous_event.get("event_timestamp")),
            is_vpn_related=is_vpn_related,
            is_shared_account=is_shared_account,
            source_ips=[
                current_event.get("source_ip", ""),
                previous_event.get("source_ip", ""),
            ],
            providers=list(
                {
                    current_event.get("provider", ""),
                    previous_event.get("provider", ""),
                }
            ),
            anomaly=anomaly,
            evidence={
                "velocity_kmh": travel_details.required_velocity_kmh,
                "velocity_multiple": round(
                    travel_details.required_velocity_kmh / 800, 1
                ),
                "current_event_id": current_event.get("event_id"),
                "previous_event_id": previous_event.get("event_id"),
            },
            mitre_techniques=["T1078", "T1078.004"],
            recommended_actions=actions,
        )

    def _get_time_delta(self, ts1: Any, ts2: Any) -> timedelta:
        """Get time delta between two timestamps.

        Args:
            ts1: First timestamp
            ts2: Second timestamp

        Returns:
            timedelta between timestamps
        """
        dt1 = self._parse_timestamp(ts1)
        dt2 = self._parse_timestamp(ts2)

        if dt1 and dt2:
            delta = dt1 - dt2
            if delta.total_seconds() < 0:
                delta = -delta
            return delta

        return timedelta(0)

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
    ) -> List[ImpossibleTravelAlert]:
        """Run impossible travel detection.

        Main entry point for detection.

        Args:
            window_hours: Detection window in hours

        Returns:
            List of ImpossibleTravelAlert
        """
        return self.detect_impossible_travel(window_hours=window_hours)
