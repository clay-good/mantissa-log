"""New device and location detection for identity events.

Provides detection of authentication from new devices or locations not in
the user's behavioral baseline. Includes logic for combining multiple
anomalies to escalate severity.
"""

import hashlib
import logging
import re
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple

from ..anomaly_types import AnomalySeverity, IdentityAnomaly, IdentityAnomalyType
from ..user_baseline import IdentityBaseline

logger = logging.getLogger(__name__)


class NewAccessType(Enum):
    """Types of new access detected."""

    NEW_COUNTRY = "new_country"
    NEW_CITY = "new_city"
    NEW_IP = "new_ip"
    NEW_DEVICE = "new_device"
    NEW_USER_AGENT = "new_user_agent"
    NEW_APPLICATION = "new_application"


@dataclass
class LocationNovelty:
    """Results of location novelty analysis.

    Attributes:
        is_new_country: Whether country is new
        is_new_city: Whether city is new (but country is known)
        is_new_ip: Whether IP is new (but city is known)
        country: Event's source country
        city: Event's source city
        ip: Event's source IP
        known_countries: Countries in baseline
        known_cities: Cities in baseline
        novelty_score: Overall novelty score (0.0-1.0)
    """

    is_new_country: bool = False
    is_new_city: bool = False
    is_new_ip: bool = False
    country: str = ""
    city: str = ""
    ip: str = ""
    known_countries: Set[str] = field(default_factory=set)
    known_cities: Set[str] = field(default_factory=set)
    novelty_score: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "is_new_country": self.is_new_country,
            "is_new_city": self.is_new_city,
            "is_new_ip": self.is_new_ip,
            "country": self.country,
            "city": self.city,
            "ip": self.ip,
            "known_countries": list(self.known_countries),
            "known_cities": list(self.known_cities)[:10],
            "novelty_score": round(self.novelty_score, 3),
        }


@dataclass
class DeviceNovelty:
    """Results of device novelty analysis.

    Attributes:
        is_new_device: Whether device is new
        is_new_user_agent: Whether user agent is new
        device_fingerprint: Event's device fingerprint
        user_agent: Event's user agent
        browser_family: Extracted browser family
        os_family: Extracted OS family
        known_devices: Devices in baseline
        known_user_agents: User agents in baseline
        is_similar_user_agent: Whether UA is similar to known ones
    """

    is_new_device: bool = False
    is_new_user_agent: bool = False
    device_fingerprint: str = ""
    user_agent: str = ""
    browser_family: str = ""
    os_family: str = ""
    known_devices: Set[str] = field(default_factory=set)
    known_user_agents: Set[str] = field(default_factory=set)
    is_similar_user_agent: bool = False

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "is_new_device": self.is_new_device,
            "is_new_user_agent": self.is_new_user_agent,
            "device_fingerprint": self.device_fingerprint,
            "user_agent": self.user_agent[:100] if self.user_agent else "",
            "browser_family": self.browser_family,
            "os_family": self.os_family,
            "known_device_count": len(self.known_devices),
            "known_user_agent_count": len(self.known_user_agents),
            "is_similar_user_agent": self.is_similar_user_agent,
        }


@dataclass
class NewAccessAlert:
    """Alert for new access detection.

    Attributes:
        alert_id: Unique identifier for this alert
        alert_type: Type of new access detected
        severity: Alert severity (critical, high, medium, low)
        title: Human-readable alert title
        description: Detailed description
        user_email: User who triggered the alert
        location_novelty: Location analysis results
        device_novelty: Device analysis results
        combined_anomalies: List of all detected anomalies
        combined_severity: Severity after combining anomalies
        event_time: Time of the event
        source_ip: Source IP of the event
        provider: Identity provider
        evidence: Additional evidence data
        mitre_techniques: Associated MITRE ATT&CK techniques
        recommended_actions: Suggested response actions
    """

    alert_id: str
    alert_type: NewAccessType
    severity: str
    title: str
    description: str
    user_email: str
    location_novelty: Optional[LocationNovelty] = None
    device_novelty: Optional[DeviceNovelty] = None
    combined_anomalies: List[str] = field(default_factory=list)
    combined_severity: str = ""
    event_time: Optional[datetime] = None
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
            "alert_type": self.alert_type.value,
            "severity": self.severity,
            "title": self.title,
            "description": self.description,
            "user_email": self.user_email,
            "location_novelty": (
                self.location_novelty.to_dict() if self.location_novelty else None
            ),
            "device_novelty": (
                self.device_novelty.to_dict() if self.device_novelty else None
            ),
            "combined_anomalies": self.combined_anomalies,
            "combined_severity": self.combined_severity,
            "event_time": self.event_time.isoformat() if self.event_time else None,
            "source_ip": self.source_ip,
            "provider": self.provider,
            "evidence": self.evidence,
            "mitre_techniques": self.mitre_techniques,
            "recommended_actions": self.recommended_actions,
            "detected_at": self.detected_at.isoformat(),
        }


class NewAccessDetector:
    """Detects new devices and locations for identity events.

    Compares authentication events against user baselines to identify
    access from new countries, cities, IPs, devices, and applications.

    Attributes:
        query_executor: Executor for querying identity events
        baseline_store: Store for retrieving user baselines
        DEFAULT_WINDOW_HOURS: Default time window for detection
    """

    # Default time window
    DEFAULT_WINDOW_HOURS = 24

    # Browser family patterns for user agent parsing
    BROWSER_PATTERNS = [
        (r"Chrome/(\d+)", "Chrome"),
        (r"Firefox/(\d+)", "Firefox"),
        (r"Safari/(\d+)", "Safari"),
        (r"Edge/(\d+)", "Edge"),
        (r"MSIE (\d+)", "Internet Explorer"),
        (r"Trident/.*rv:(\d+)", "Internet Explorer"),
        (r"Opera/(\d+)", "Opera"),
        (r"OPR/(\d+)", "Opera"),
    ]

    # OS family patterns
    OS_PATTERNS = [
        (r"Windows NT (\d+\.\d+)", "Windows"),
        (r"Mac OS X (\d+[._]\d+)", "macOS"),
        (r"Linux", "Linux"),
        (r"Android (\d+)", "Android"),
        (r"iPhone OS (\d+)", "iOS"),
        (r"iPad.*OS (\d+)", "iPadOS"),
    ]

    def __init__(
        self,
        query_executor: Any,
        baseline_store: Any = None,
        identity_events_table: str = "identity_events",
    ):
        """Initialize the new access detector.

        Args:
            query_executor: Executor for querying the data lake
            baseline_store: Store for retrieving user baselines
            identity_events_table: Name of the identity events table
        """
        self.query_executor = query_executor
        self.baseline_store = baseline_store
        self.identity_events_table = identity_events_table

    def detect_new_locations(
        self,
        window_hours: int = None,
    ) -> List[NewAccessAlert]:
        """Detect logins from new locations.

        Args:
            window_hours: Detection window in hours

        Returns:
            List of NewAccessAlert for new location access
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
                device_fingerprint,
                user_agent,
                provider,
                event_timestamp
            FROM {self.identity_events_table}
            WHERE event_type = 'AUTH_SUCCESS'
              AND event_timestamp >= TIMESTAMP '{cutoff_str}'
              AND source_geo_country IS NOT NULL
            ORDER BY event_timestamp DESC
            LIMIT 1000
        """

        try:
            result = self.query_executor.execute_query(query, timeout_seconds=120)

            for row in result.rows:
                user_email = row.get("user_email")
                if not user_email:
                    continue

                baseline = self._get_user_baseline(user_email)
                if not baseline:
                    continue

                # Check location novelty
                location_novelty = self._analyze_location_novelty(row, baseline)

                if location_novelty.is_new_country or location_novelty.is_new_city:
                    # Also check device for combined severity
                    device_novelty = self._analyze_device_novelty(row, baseline)

                    alert = self._create_location_alert(
                        user_email=user_email,
                        event=row,
                        location_novelty=location_novelty,
                        device_novelty=device_novelty,
                        window_hours=window,
                    )
                    alerts.append(alert)

        except Exception as e:
            logger.error(f"Error detecting new locations: {e}")

        return alerts

    def detect_new_devices(
        self,
        window_hours: int = None,
    ) -> List[NewAccessAlert]:
        """Detect logins from new devices.

        Args:
            window_hours: Detection window in hours

        Returns:
            List of NewAccessAlert for new device access
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
                device_fingerprint,
                user_agent,
                provider,
                event_timestamp
            FROM {self.identity_events_table}
            WHERE event_type = 'AUTH_SUCCESS'
              AND event_timestamp >= TIMESTAMP '{cutoff_str}'
              AND (device_fingerprint IS NOT NULL OR user_agent IS NOT NULL)
            ORDER BY event_timestamp DESC
            LIMIT 1000
        """

        try:
            result = self.query_executor.execute_query(query, timeout_seconds=120)

            for row in result.rows:
                user_email = row.get("user_email")
                if not user_email:
                    continue

                baseline = self._get_user_baseline(user_email)
                if not baseline:
                    continue

                # Check device novelty
                device_novelty = self._analyze_device_novelty(row, baseline)

                if device_novelty.is_new_device or device_novelty.is_new_user_agent:
                    # Skip if user agent is just a version update
                    if device_novelty.is_similar_user_agent and not device_novelty.is_new_device:
                        continue

                    # Also check location for combined severity
                    location_novelty = self._analyze_location_novelty(row, baseline)

                    alert = self._create_device_alert(
                        user_email=user_email,
                        event=row,
                        device_novelty=device_novelty,
                        location_novelty=location_novelty,
                        window_hours=window,
                    )
                    alerts.append(alert)

        except Exception as e:
            logger.error(f"Error detecting new devices: {e}")

        return alerts

    def detect_first_access_to_resource(
        self,
        window_hours: int = None,
    ) -> List[NewAccessAlert]:
        """Detect first-time access to applications.

        Args:
            window_hours: Detection window in hours

        Returns:
            List of NewAccessAlert for first-time application access
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
                application_name,
                provider,
                event_timestamp
            FROM {self.identity_events_table}
            WHERE event_type = 'AUTH_SUCCESS'
              AND event_timestamp >= TIMESTAMP '{cutoff_str}'
              AND application_name IS NOT NULL
            ORDER BY event_timestamp DESC
            LIMIT 1000
        """

        try:
            result = self.query_executor.execute_query(query, timeout_seconds=120)

            for row in result.rows:
                user_email = row.get("user_email")
                application = row.get("application_name")
                if not user_email or not application:
                    continue

                baseline = self._get_user_baseline(user_email)
                if not baseline:
                    continue

                # Check if application is new
                if application not in baseline.known_applications:
                    alert = self._create_application_alert(
                        user_email=user_email,
                        event=row,
                        application=application,
                        baseline=baseline,
                        window_hours=window,
                    )
                    alerts.append(alert)

        except Exception as e:
            logger.error(f"Error detecting first resource access: {e}")

        return alerts

    def is_new_country(
        self,
        country: str,
        baseline: IdentityBaseline,
    ) -> bool:
        """Check if country is new for user.

        Args:
            country: Country from event
            baseline: User's baseline

        Returns:
            True if country is not in baseline
        """
        if not country:
            return False

        known = baseline.known_countries or set()
        return country.lower() not in {c.lower() for c in known}

    def is_new_device(
        self,
        device_fingerprint: str,
        user_agent: str,
        baseline: IdentityBaseline,
    ) -> bool:
        """Check if device is new for user.

        Args:
            device_fingerprint: Device fingerprint from event
            user_agent: User agent from event
            baseline: User's baseline

        Returns:
            True if device is not in baseline
        """
        # Check fingerprint first (most reliable)
        if device_fingerprint:
            known_devices = baseline.known_devices or set()
            if device_fingerprint in known_devices:
                return False

        # Fall back to user agent
        if user_agent:
            known_uas = baseline.known_user_agents or set()
            ua_hash = self._hash_user_agent(user_agent)
            if ua_hash in known_uas or user_agent in known_uas:
                return False

            # Check for similar user agents (same browser, different version)
            if self._has_similar_user_agent(user_agent, known_uas):
                return False

        return True

    def calculate_location_novelty_score(
        self,
        country: str,
        city: str,
        ip: str,
        baseline: IdentityBaseline,
    ) -> float:
        """Calculate location novelty score.

        Args:
            country: Event's source country
            city: Event's source city
            ip: Event's source IP
            baseline: User's baseline

        Returns:
            Novelty score from 0.0 (known) to 1.0 (completely new)
        """
        known_countries = {c.lower() for c in (baseline.known_countries or set())}
        known_cities = {c.lower() for c in (baseline.known_cities or set())}
        known_ips = baseline.known_source_ips or set()

        country_lower = country.lower() if country else ""
        city_lower = city.lower() if city else ""

        # Completely new country
        if country_lower and country_lower not in known_countries:
            return 1.0

        # Known country, new city
        if city_lower and city_lower not in known_cities:
            return 0.5

        # Known city, new IP
        if ip and ip not in known_ips:
            return 0.2

        # Everything is known
        return 0.0

    def combine_with_other_anomalies(
        self,
        new_location: bool,
        new_country: bool,
        new_device: bool,
        unusual_time: bool = False,
    ) -> str:
        """Determine combined severity when multiple anomalies present.

        Args:
            new_location: Whether location is new
            new_country: Whether country is new (subset of new_location)
            new_device: Whether device is new
            unusual_time: Whether login time is unusual

        Returns:
            Combined severity level
        """
        anomaly_count = sum([new_country, new_device, unusual_time])

        # New country + new device + unusual time = critical
        if new_country and new_device and unusual_time:
            return "critical"

        # New country + new device = critical
        if new_country and new_device:
            return "critical"

        # New country + unusual time = critical
        if new_country and unusual_time:
            return "critical"

        # New device + unusual time = high
        if new_device and unusual_time:
            return "high"

        # New country alone = high
        if new_country:
            return "high"

        # New device alone = medium
        if new_device:
            return "medium"

        # New city/location alone = medium
        if new_location:
            return "medium"

        return "low"

    def _analyze_location_novelty(
        self,
        event: Dict,
        baseline: IdentityBaseline,
    ) -> LocationNovelty:
        """Analyze location novelty for an event.

        Args:
            event: Event data
            baseline: User's baseline

        Returns:
            LocationNovelty analysis
        """
        country = event.get("source_geo_country", "")
        city = event.get("source_geo_city", "")
        ip = event.get("source_ip", "")

        known_countries = {c.lower() for c in (baseline.known_countries or set())}
        known_cities = {c.lower() for c in (baseline.known_cities or set())}
        known_ips = baseline.known_source_ips or set()

        country_lower = country.lower() if country else ""
        city_lower = city.lower() if city else ""

        is_new_country = bool(country_lower and country_lower not in known_countries)
        is_new_city = bool(
            city_lower
            and city_lower not in known_cities
            and not is_new_country  # Only flag city if country is known
        )
        is_new_ip = bool(ip and ip not in known_ips and not is_new_city)

        novelty_score = self.calculate_location_novelty_score(
            country, city, ip, baseline
        )

        return LocationNovelty(
            is_new_country=is_new_country,
            is_new_city=is_new_city,
            is_new_ip=is_new_ip,
            country=country,
            city=city,
            ip=ip,
            known_countries=baseline.known_countries or set(),
            known_cities=baseline.known_cities or set(),
            novelty_score=novelty_score,
        )

    def _analyze_device_novelty(
        self,
        event: Dict,
        baseline: IdentityBaseline,
    ) -> DeviceNovelty:
        """Analyze device novelty for an event.

        Args:
            event: Event data
            baseline: User's baseline

        Returns:
            DeviceNovelty analysis
        """
        device_fp = event.get("device_fingerprint", "")
        user_agent = event.get("user_agent", "")

        known_devices = baseline.known_devices or set()
        known_uas = baseline.known_user_agents or set()

        # Check fingerprint
        is_new_device = bool(device_fp and device_fp not in known_devices)

        # Check user agent
        ua_hash = self._hash_user_agent(user_agent) if user_agent else ""
        is_new_ua = bool(
            user_agent and ua_hash not in known_uas and user_agent not in known_uas
        )

        # Check if user agent is similar to known ones
        is_similar = self._has_similar_user_agent(user_agent, known_uas) if user_agent else False

        # Parse browser and OS
        browser_family = self._extract_browser_family(user_agent)
        os_family = self._extract_os_family(user_agent)

        return DeviceNovelty(
            is_new_device=is_new_device,
            is_new_user_agent=is_new_ua,
            device_fingerprint=device_fp,
            user_agent=user_agent,
            browser_family=browser_family,
            os_family=os_family,
            known_devices=known_devices,
            known_user_agents=known_uas,
            is_similar_user_agent=is_similar,
        )

    def _create_location_alert(
        self,
        user_email: str,
        event: Dict,
        location_novelty: LocationNovelty,
        device_novelty: DeviceNovelty,
        window_hours: int,
    ) -> NewAccessAlert:
        """Create alert for new location access.

        Args:
            user_email: User email
            event: Event data
            location_novelty: Location analysis
            device_novelty: Device analysis
            window_hours: Detection window

        Returns:
            NewAccessAlert
        """
        # Determine alert type
        if location_novelty.is_new_country:
            alert_type = NewAccessType.NEW_COUNTRY
            base_severity = "high"
        else:
            alert_type = NewAccessType.NEW_CITY
            base_severity = "medium"

        # Collect anomalies
        anomalies = []
        if location_novelty.is_new_country:
            anomalies.append("new_country")
        if location_novelty.is_new_city:
            anomalies.append("new_city")
        if device_novelty.is_new_device:
            anomalies.append("new_device")

        # Get combined severity
        combined_severity = self.combine_with_other_anomalies(
            new_location=True,
            new_country=location_novelty.is_new_country,
            new_device=device_novelty.is_new_device,
        )

        # Build description
        if location_novelty.is_new_country:
            description = (
                f"Login from new country for {user_email}. "
                f"Country: {location_novelty.country}. "
                f"This country has not been seen in user's baseline."
            )
        else:
            description = (
                f"Login from new city for {user_email}. "
                f"City: {location_novelty.city}, {location_novelty.country}. "
                f"This city has not been seen in user's baseline."
            )

        if device_novelty.is_new_device:
            description += " Also detected login from new device."

        # Build actions
        actions = [
            f"Verify login with {user_email} through out-of-band channel",
            "Check if user has legitimate travel plans",
        ]
        if location_novelty.is_new_country:
            actions.append("Review for VPN usage that might explain location")
        if combined_severity in ["critical", "high"]:
            actions.append("Consider requiring step-up authentication")
            actions.append("Review session activity for suspicious behavior")

        return NewAccessAlert(
            alert_id=str(uuid.uuid4()),
            alert_type=alert_type,
            severity=combined_severity,
            title=f"New Location: {user_email} from {location_novelty.country}",
            description=description,
            user_email=user_email,
            location_novelty=location_novelty,
            device_novelty=device_novelty,
            combined_anomalies=anomalies,
            combined_severity=combined_severity,
            event_time=self._parse_timestamp(event.get("event_timestamp")),
            source_ip=event.get("source_ip", ""),
            provider=event.get("provider", ""),
            evidence={
                "location_novelty_score": location_novelty.novelty_score,
                "event_id": event.get("event_id"),
            },
            mitre_techniques=["T1078", "T1078.004"],
            recommended_actions=actions,
        )

    def _create_device_alert(
        self,
        user_email: str,
        event: Dict,
        device_novelty: DeviceNovelty,
        location_novelty: LocationNovelty,
        window_hours: int,
    ) -> NewAccessAlert:
        """Create alert for new device access.

        Args:
            user_email: User email
            event: Event data
            device_novelty: Device analysis
            location_novelty: Location analysis
            window_hours: Detection window

        Returns:
            NewAccessAlert
        """
        alert_type = NewAccessType.NEW_DEVICE

        # Collect anomalies
        anomalies = ["new_device"]
        if location_novelty.is_new_country:
            anomalies.append("new_country")
        elif location_novelty.is_new_city:
            anomalies.append("new_city")

        # Get combined severity
        combined_severity = self.combine_with_other_anomalies(
            new_location=location_novelty.is_new_country or location_novelty.is_new_city,
            new_country=location_novelty.is_new_country,
            new_device=True,
        )

        # Build description
        description = f"Login from new device for {user_email}. "
        if device_novelty.browser_family:
            description += f"Browser: {device_novelty.browser_family}. "
        if device_novelty.os_family:
            description += f"OS: {device_novelty.os_family}. "

        if location_novelty.is_new_country:
            description += f"Also from new country: {location_novelty.country}."
        elif location_novelty.is_new_city:
            description += f"Also from new city: {location_novelty.city}."

        # Build actions
        actions = [
            f"Verify new device with {user_email}",
            "Check if IT recently issued new equipment",
        ]
        if combined_severity in ["critical", "high"]:
            actions.append("Review session activity for suspicious behavior")
            actions.append("Consider requiring step-up authentication")

        return NewAccessAlert(
            alert_id=str(uuid.uuid4()),
            alert_type=alert_type,
            severity=combined_severity,
            title=f"New Device: {user_email} using {device_novelty.browser_family or 'unknown browser'}",
            description=description,
            user_email=user_email,
            location_novelty=location_novelty,
            device_novelty=device_novelty,
            combined_anomalies=anomalies,
            combined_severity=combined_severity,
            event_time=self._parse_timestamp(event.get("event_timestamp")),
            source_ip=event.get("source_ip", ""),
            provider=event.get("provider", ""),
            evidence={
                "browser_family": device_novelty.browser_family,
                "os_family": device_novelty.os_family,
                "event_id": event.get("event_id"),
            },
            mitre_techniques=["T1078"],
            recommended_actions=actions,
        )

    def _create_application_alert(
        self,
        user_email: str,
        event: Dict,
        application: str,
        baseline: IdentityBaseline,
        window_hours: int,
    ) -> NewAccessAlert:
        """Create alert for first-time application access.

        Args:
            user_email: User email
            event: Event data
            application: Application name
            baseline: User's baseline
            window_hours: Detection window

        Returns:
            NewAccessAlert
        """
        known_apps = list(baseline.known_applications or set())[:10]

        return NewAccessAlert(
            alert_id=str(uuid.uuid4()),
            alert_type=NewAccessType.NEW_APPLICATION,
            severity="low",
            title=f"First Access: {user_email} to {application}",
            description=(
                f"First-time access to {application} by {user_email}. "
                f"User typically accesses: {', '.join(known_apps) if known_apps else 'no recorded applications'}."
            ),
            user_email=user_email,
            event_time=self._parse_timestamp(event.get("event_timestamp")),
            source_ip=event.get("source_ip", ""),
            provider=event.get("provider", ""),
            evidence={
                "application": application,
                "known_applications": known_apps,
                "event_id": event.get("event_id"),
            },
            mitre_techniques=["T1078"],
            recommended_actions=[
                f"Verify {user_email} should have access to {application}",
                "Check if this is a new application rollout",
                "Review if access was granted recently",
            ],
        )

    def _extract_browser_family(self, user_agent: str) -> str:
        """Extract browser family from user agent.

        Args:
            user_agent: User agent string

        Returns:
            Browser family name
        """
        if not user_agent:
            return ""

        for pattern, name in self.BROWSER_PATTERNS:
            if re.search(pattern, user_agent):
                return name

        return "Unknown"

    def _extract_os_family(self, user_agent: str) -> str:
        """Extract OS family from user agent.

        Args:
            user_agent: User agent string

        Returns:
            OS family name
        """
        if not user_agent:
            return ""

        for pattern, name in self.OS_PATTERNS:
            if re.search(pattern, user_agent):
                return name

        return "Unknown"

    def _hash_user_agent(self, user_agent: str) -> str:
        """Create hash of user agent for comparison.

        Args:
            user_agent: User agent string

        Returns:
            SHA256 hash of user agent
        """
        return hashlib.sha256(user_agent.encode()).hexdigest()[:16]

    def _has_similar_user_agent(self, user_agent: str, known_uas: Set[str]) -> bool:
        """Check if user agent is similar to known ones.

        Same browser, different version is considered similar.

        Args:
            user_agent: User agent to check
            known_uas: Known user agents

        Returns:
            True if similar to a known user agent
        """
        if not user_agent or not known_uas:
            return False

        current_browser = self._extract_browser_family(user_agent)
        current_os = self._extract_os_family(user_agent)

        if not current_browser:
            return False

        for known_ua in known_uas:
            known_browser = self._extract_browser_family(known_ua)
            known_os = self._extract_os_family(known_ua)

            # Same browser and OS = similar (just version update)
            if current_browser == known_browser and current_os == known_os:
                return True

        return False

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

    def run_all_detections(
        self,
        window_hours: int = None,
        include_applications: bool = False,
    ) -> List[NewAccessAlert]:
        """Run all new access detection methods.

        Args:
            window_hours: Detection window in hours
            include_applications: Whether to include first-time app access

        Returns:
            Combined list of alerts
        """
        all_alerts = []

        # Detect new locations
        location_alerts = self.detect_new_locations(window_hours=window_hours)
        all_alerts.extend(location_alerts)

        # Detect new devices (filter out duplicates with location alerts)
        location_event_ids = {
            a.evidence.get("event_id") for a in location_alerts if a.evidence
        }
        device_alerts = self.detect_new_devices(window_hours=window_hours)
        device_alerts = [
            a for a in device_alerts
            if a.evidence.get("event_id") not in location_event_ids
        ]
        all_alerts.extend(device_alerts)

        # Optionally detect first-time application access
        if include_applications:
            app_alerts = self.detect_first_access_to_resource(window_hours=window_hours)
            all_alerts.extend(app_alerts)

        # Sort by severity
        severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        all_alerts.sort(key=lambda a: severity_order.get(a.severity, 4))

        return all_alerts
