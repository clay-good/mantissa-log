"""Identity anomaly detection for ITDR.

Main anomaly detection engine that analyzes identity events against user
baselines to detect behavioral anomalies. Implements detection algorithms
for various types of identity-related threats.
"""

import hashlib
import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Set

from ..models.identity_event import GeoLocation, IdentityEvent, IdentityEventType
from .anomaly_types import (
    ANOMALY_CONFIG,
    AnomalySeverity,
    AnomalyResult,
    IdentityAnomaly,
    IdentityAnomalyType,
    get_default_severity,
    get_recommended_action,
)
from .baseline_store import BaselineStore
from .session_store import SessionStore
from .travel_analyzer import GeoUtils, ImpossibleTravelAnalyzer
from .user_baseline import IdentityBaseline

logger = logging.getLogger(__name__)


# Known VPN provider ASNs (sample - would be maintained as a separate data file)
KNOWN_VPN_ASNS = {
    "AS20473",  # Vultr
    "AS14061",  # DigitalOcean
    "AS16276",  # OVH
    "AS24940",  # Hetzner
    "AS9009",   # M247
    "AS60068",  # Datacamp
    "AS202425", # IP Volume
    "AS44066",  # Firstcolo
    "AS21100",  # Leaseweb
}

# Known datacenter/cloud provider ASNs
DATACENTER_ASNS = {
    "AS16509",  # Amazon
    "AS14618",  # Amazon AWS
    "AS15169",  # Google
    "AS8075",   # Microsoft Azure
    "AS396982", # Google Cloud
    "AS13335",  # Cloudflare
    "AS54113",  # Fastly
}


class IdentityAnomalyDetector:
    """Detects identity anomalies by comparing events against baselines.

    Implements multiple detection algorithms:
    - Impossible travel detection
    - Unusual login time detection
    - New device/location detection
    - Volume anomaly detection
    - Authentication pattern change detection
    - VPN/Proxy detection

    Attributes:
        baseline_store: Store for user baselines
        session_store: Store for user sessions
        query_executor: Executor for querying event data
        travel_analyzer: Analyzer for impossible travel
        min_confidence: Minimum confidence threshold for reporting anomalies
    """

    # Default thresholds
    DEFAULT_MIN_CONFIDENCE = 0.5
    VOLUME_Z_SCORE_THRESHOLD = 2.0
    VOLUME_Z_SCORE_HIGH = 3.0
    VOLUME_Z_SCORE_CRITICAL = 4.0

    def __init__(
        self,
        baseline_store: Optional[BaselineStore] = None,
        session_store: Optional[SessionStore] = None,
        query_executor: Any = None,
        min_confidence: float = None,
    ):
        """Initialize the anomaly detector.

        Args:
            baseline_store: Store for user baselines (optional)
            session_store: Store for user sessions (optional)
            query_executor: Executor for querying events (optional)
            min_confidence: Minimum confidence threshold for reporting
        """
        self.baseline_store = baseline_store
        self.session_store = session_store
        self.query_executor = query_executor
        self.min_confidence = min_confidence or self.DEFAULT_MIN_CONFIDENCE
        self.travel_analyzer = ImpossibleTravelAnalyzer()

        # Cache for recent events per user (for travel analysis)
        self._recent_events_cache: Dict[str, List[IdentityEvent]] = {}

    def detect_all_anomalies(
        self,
        event: IdentityEvent,
        baseline: Optional[IdentityBaseline] = None,
        previous_event: Optional[IdentityEvent] = None,
    ) -> List[IdentityAnomaly]:
        """Run all anomaly detection algorithms on an event.

        Args:
            event: The identity event to analyze
            baseline: User's baseline (fetched if not provided)
            previous_event: Previous event for travel analysis (optional)

        Returns:
            List of detected anomalies, sorted by severity
        """
        anomalies: List[IdentityAnomaly] = []

        # Get baseline if not provided
        if baseline is None:
            baseline = self.baseline_store.get_baseline(event.user_email)

        # Check impossible travel (doesn't require baseline)
        if previous_event:
            travel_anomaly = self.detect_impossible_travel(event, previous_event)
            if travel_anomaly:
                anomalies.append(travel_anomaly)

        # If no baseline exists, we can't do baseline comparisons
        if baseline is None:
            logger.debug(f"No baseline found for {event.user_email}, skipping baseline checks")
            # Still check for VPN/proxy
            vpn_anomaly = self.detect_vpn_or_proxy(event)
            if vpn_anomaly:
                anomalies.append(vpn_anomaly)
            return self._filter_and_sort_anomalies(anomalies, None)

        # Run all baseline-dependent checks
        time_anomaly = self.detect_unusual_time(event, baseline)
        if time_anomaly:
            anomalies.append(time_anomaly)

        device_anomaly = self.detect_new_device(event, baseline)
        if device_anomaly:
            anomalies.append(device_anomaly)

        location_anomaly = self.detect_new_location(event, baseline)
        if location_anomaly:
            anomalies.append(location_anomaly)

        ip_anomaly = self.detect_new_ip(event, baseline)
        if ip_anomaly:
            anomalies.append(ip_anomaly)

        auth_anomaly = self.detect_auth_pattern_change(event, baseline)
        if auth_anomaly:
            anomalies.append(auth_anomaly)

        vpn_anomaly = self.detect_vpn_or_proxy(event)
        if vpn_anomaly:
            anomalies.append(vpn_anomaly)

        # Filter by confidence and sort by severity
        return self._filter_and_sort_anomalies(anomalies, baseline)

    def detect_impossible_travel(
        self,
        event: IdentityEvent,
        previous_event: Optional[IdentityEvent] = None,
        baseline: Optional[Any] = None,
    ) -> AnomalyResult:
        """Detect impossible travel between two events.

        Args:
            event: Current identity event
            previous_event: Previous event for same user
            baseline: User baseline (optional, used for VPN user check)

        Returns:
            AnomalyResult indicating whether impossible travel was detected
        """
        # Check if user is known VPN user - skip travel analysis
        if baseline is not None and hasattr(baseline, 'is_vpn_user') and baseline.is_vpn_user:
            return AnomalyResult.no_anomaly()

        if previous_event is None:
            # Try to get previous event from cache or query
            previous_event = self._get_previous_event(
                event.user_email, event.timestamp
            )

        if previous_event is None:
            return AnomalyResult.no_anomaly()

        anomaly = self.travel_analyzer.analyze(event, previous_event)
        if anomaly is None:
            return AnomalyResult.no_anomaly()
        return AnomalyResult.from_anomaly(anomaly)

    def detect_unusual_time(
        self, event: IdentityEvent, baseline: Any
    ) -> AnomalyResult:
        """Detect login at unusual time compared to baseline.

        Args:
            event: Identity event to check
            baseline: User's behavioral baseline

        Returns:
            AnomalyResult indicating whether unusual time was detected
        """
        # Handle both typical_login_hours and typical_hours (compatibility)
        typical_hours = getattr(baseline, 'typical_login_hours', None) or getattr(baseline, 'typical_hours', [])

        if not typical_hours:
            return AnomalyResult.no_anomaly()  # Not enough data

        # Check baseline maturity if available
        if hasattr(baseline, 'is_mature') and not baseline.is_mature:
            return AnomalyResult.no_anomaly()

        event_hour = event.timestamp.hour

        # Check if this hour is outside typical hours
        if event_hour in typical_hours:
            return AnomalyResult.no_anomaly()  # Normal hour

        # Calculate how unusual this is
        if len(typical_hours) < 3:
            # Not enough variety in baseline
            confidence = 0.3
        else:
            confidence = 0.7

        # Adjust severity based on how far outside normal hours
        # Find closest normal hour
        min_distance = min(
            min(abs(event_hour - h), 24 - abs(event_hour - h))
            for h in typical_hours
        )

        if min_distance >= 6:
            severity = AnomalySeverity.MEDIUM
            confidence = min(confidence + 0.2, 1.0)
        elif min_distance >= 3:
            severity = AnomalySeverity.LOW
        else:
            severity = AnomalySeverity.LOW
            confidence = max(confidence - 0.2, 0.3)

        anomaly = IdentityAnomaly.create(
            anomaly_type=IdentityAnomalyType.UNUSUAL_LOGIN_TIME,
            user_email=event.user_email,
            event_id=event.event_id,
            severity=severity,
            confidence=confidence,
            title=f"Login at unusual hour: {event_hour}:00",
            description=(
                f"User {event.user_email} logged in at {event_hour}:00, "
                f"which is outside their typical login hours"
            ),
            evidence={
                "event_hour": event_hour,
                "event_day": event.timestamp.strftime("%A"),
                "event_timestamp": event.timestamp.isoformat(),
            },
            baseline_comparison={
                "typical_hours": sorted(list(typical_hours)),
                "hours_from_typical": min_distance,
            },
            recommended_action=get_recommended_action(
                IdentityAnomalyType.UNUSUAL_LOGIN_TIME
            ),
        )
        return AnomalyResult.from_anomaly(anomaly)

    def detect_new_device(
        self, event: IdentityEvent, baseline: Any
    ) -> AnomalyResult:
        """Detect login from new device.

        Args:
            event: Identity event to check
            baseline: User's behavioral baseline

        Returns:
            AnomalyResult indicating whether new device was detected
        """
        is_new_device = False
        device_type = event.device_type or "unknown"
        user_agent = event.user_agent or ""

        # Get known devices - handle both list of dicts and set of device_ids
        known_devices = getattr(baseline, 'known_devices', [])
        known_user_agents = getattr(baseline, 'known_user_agents', set())

        # Extract device IDs if known_devices is a list of dicts
        known_device_ids = set()
        if known_devices:
            for device in known_devices:
                if isinstance(device, dict) and 'device_id' in device:
                    known_device_ids.add(device['device_id'])
                elif isinstance(device, str):
                    known_device_ids.add(device)

        # Check device fingerprint first
        if event.device_id:
            if known_device_ids and event.device_id not in known_device_ids:
                is_new_device = True

        # Check user agent hash if no device ID
        if not is_new_device and user_agent:
            ua_hash = hashlib.md5(user_agent.encode()).hexdigest()[:16]
            if known_user_agents and ua_hash not in known_user_agents:
                is_new_device = True

        if not is_new_device:
            return AnomalyResult.no_anomaly()

        # Determine severity
        if not known_devices and not known_user_agents:
            # First device - establishing baseline
            severity = AnomalySeverity.LOW
            confidence = 0.4
        else:
            severity = AnomalySeverity.MEDIUM
            confidence = 0.7

        anomaly = IdentityAnomaly.create(
            anomaly_type=IdentityAnomalyType.NEW_DEVICE,
            user_email=event.user_email,
            event_id=event.event_id,
            severity=severity,
            confidence=confidence,
            title=f"Login from new device: {device_type}",
            description=(
                f"User {event.user_email} logged in from a device not seen before"
            ),
            evidence={
                "device_type": device_type,
                "device_id": event.device_id,
                "user_agent": user_agent[:100] if user_agent else None,
            },
            baseline_comparison={
                "known_devices_count": len(known_devices),
                "known_user_agents_count": len(known_user_agents),
            },
            recommended_action=get_recommended_action(IdentityAnomalyType.NEW_DEVICE),
        )
        return AnomalyResult.from_anomaly(anomaly)

    def detect_new_location(
        self, event: IdentityEvent, baseline: Any
    ) -> AnomalyResult:
        """Detect login from new location (country or city).

        Args:
            event: Identity event to check
            baseline: User's behavioral baseline

        Returns:
            AnomalyResult indicating whether new location was detected
        """
        if not event.source_geo:
            return AnomalyResult.no_anomaly()

        geo = event.source_geo
        country = geo.country
        city = geo.city

        known_countries = getattr(baseline, 'known_countries', set())
        known_cities = getattr(baseline, 'known_cities', set())

        # Also check known_locations for countries/cities
        known_locations = getattr(baseline, 'known_locations', [])
        for loc in known_locations:
            if hasattr(loc, 'country') and loc.country:
                known_countries = set(known_countries) | {loc.country}
            if hasattr(loc, 'city') and loc.city:
                known_cities = set(known_cities) | {loc.city}

        # Check for new country (higher severity)
        if country and known_countries:
            if country.lower() not in {c.lower() for c in known_countries}:
                anomaly = IdentityAnomaly.create(
                    anomaly_type=IdentityAnomalyType.FIRST_TIME_COUNTRY,
                    user_email=event.user_email,
                    event_id=event.event_id,
                    severity=AnomalySeverity.HIGH,
                    confidence=0.85,
                    title=f"First login from country: {country}",
                    description=(
                        f"User {event.user_email} logged in from {country}, "
                        f"a country not previously seen in their login history"
                    ),
                    evidence={
                        "country": country,
                        "city": city,
                        "ip": event.source_ip,
                        "latitude": geo.latitude,
                        "longitude": geo.longitude,
                    },
                    baseline_comparison={
                        "known_countries": list(known_countries),
                    },
                    recommended_action=get_recommended_action(
                        IdentityAnomalyType.FIRST_TIME_COUNTRY
                    ),
                )
                return AnomalyResult.from_anomaly(anomaly)

        # Check for new city (lower severity)
        if city and known_cities:
            if city.lower() not in {c.lower() for c in known_cities}:
                anomaly = IdentityAnomaly.create(
                    anomaly_type=IdentityAnomalyType.NEW_LOCATION,
                    user_email=event.user_email,
                    event_id=event.event_id,
                    severity=AnomalySeverity.MEDIUM,
                    confidence=0.6,
                    title=f"Login from new city: {city}",
                    description=(
                        f"User {event.user_email} logged in from {city}, "
                        f"a city not previously seen in their login history"
                    ),
                    evidence={
                        "country": country,
                        "city": city,
                        "ip": event.source_ip,
                    },
                    baseline_comparison={
                        "known_cities_count": len(known_cities),
                        "country_is_known": country.lower() in {c.lower() for c in known_countries} if country and known_countries else False,
                    },
                    recommended_action=get_recommended_action(
                        IdentityAnomalyType.NEW_LOCATION
                    ),
                )
                return AnomalyResult.from_anomaly(anomaly)

        return AnomalyResult.no_anomaly()

    def detect_new_ip(
        self, event: IdentityEvent, baseline: IdentityBaseline
    ) -> Optional[IdentityAnomaly]:
        """Detect login from new IP address.

        Args:
            event: Identity event to check
            baseline: User's behavioral baseline

        Returns:
            IdentityAnomaly if new IP detected
        """
        if not event.source_ip:
            return None

        if not baseline.known_source_ips:
            return None  # No baseline IPs to compare against

        if event.source_ip in baseline.known_source_ips:
            return None  # Known IP

        # Determine severity based on IP diversity in baseline
        if len(baseline.known_source_ips) > 10:
            # User has many IPs, new ones are less concerning
            severity = AnomalySeverity.LOW
            confidence = 0.4
        else:
            severity = AnomalySeverity.LOW
            confidence = 0.5

        return IdentityAnomaly.create(
            anomaly_type=IdentityAnomalyType.NEW_IP_ADDRESS,
            user_email=event.user_email,
            event_id=event.event_id,
            severity=severity,
            confidence=confidence,
            title=f"Login from new IP: {event.source_ip}",
            description=(
                f"User {event.user_email} logged in from IP {event.source_ip}, "
                f"which is not in their known IP history"
            ),
            evidence={
                "source_ip": event.source_ip,
                "geo_country": event.source_geo.country if event.source_geo else None,
                "geo_city": event.source_geo.city if event.source_geo else None,
            },
            baseline_comparison={
                "known_ips_count": len(baseline.known_source_ips),
            },
            recommended_action=get_recommended_action(
                IdentityAnomalyType.NEW_IP_ADDRESS
            ),
        )

    def detect_volume_anomaly(
        self,
        user_email: str,
        window_hours: int = 24,
        baseline: Any = None,
    ) -> AnomalyResult:
        """Detect unusual volume of authentication events.

        Args:
            user_email: User to check
            window_hours: Time window to analyze
            baseline: User baseline (optional, fetched if not provided)

        Returns:
            AnomalyResult indicating whether volume anomaly was detected
        """
        if not self.query_executor:
            return AnomalyResult.no_anomaly()

        # Get baseline if not provided
        if baseline is None:
            if self.baseline_store:
                baseline = self.baseline_store.get_baseline(user_email)
            if not baseline:
                return AnomalyResult.no_anomaly()

        # Get baseline statistics
        avg_events = getattr(baseline, 'avg_events_per_day', 0)
        std_dev = getattr(baseline, 'events_std_dev', 0)

        if avg_events == 0:
            return AnomalyResult.no_anomaly()

        # Query recent event count
        try:
            results = self.query_executor.execute_query(
                user_email=user_email,
                window_hours=window_hours
            )
            if results and isinstance(results, list) and len(results) > 0:
                count = results[0].get("event_count", 0)
            else:
                count = 0
        except Exception as e:
            logger.warning(f"Failed to count recent events: {e}")
            return AnomalyResult.no_anomaly()

        # Scale avg to window (if window_hours < 24)
        expected = avg_events * (window_hours / 24) if window_hours < 24 else avg_events

        # Calculate z-score
        if std_dev > 0:
            z_score = (count - expected) / std_dev
        elif expected > 0:
            z_score = (count - expected) / max(expected * 0.5, 1)
        else:
            z_score = 0

        if z_score < self.VOLUME_Z_SCORE_THRESHOLD:
            return AnomalyResult.no_anomaly()

        # Determine severity based on z-score
        if z_score >= self.VOLUME_Z_SCORE_CRITICAL:
            severity = AnomalySeverity.HIGH
            confidence = 0.9
        elif z_score >= self.VOLUME_Z_SCORE_HIGH:
            severity = AnomalySeverity.MEDIUM
            confidence = 0.8
        else:
            severity = AnomalySeverity.LOW
            confidence = 0.6

        anomaly = IdentityAnomaly.create(
            anomaly_type=IdentityAnomalyType.VOLUME_SPIKE,
            user_email=user_email,
            event_id="volume_check",
            severity=severity,
            confidence=confidence,
            title=f"Unusual authentication volume: {count} events in {window_hours}h",
            description=(
                f"User {user_email} had {count} authentication events in the last "
                f"{window_hours} hour(s), which is {z_score:.1f}x higher than normal"
            ),
            evidence={
                "event_count": count,
                "window_hours": window_hours,
                "z_score": round(z_score, 2),
            },
            baseline_comparison={
                "expected_count": round(expected, 1),
                "baseline_avg_daily": round(avg_events, 2),
            },
            recommended_action=get_recommended_action(IdentityAnomalyType.VOLUME_SPIKE),
        )
        return AnomalyResult.from_anomaly(anomaly)

    def detect_auth_pattern_change(
        self, event: IdentityEvent, baseline: IdentityBaseline
    ) -> Optional[IdentityAnomaly]:
        """Detect changes in authentication patterns (MFA, app, provider).

        Args:
            event: Identity event to check
            baseline: User's behavioral baseline

        Returns:
            IdentityAnomaly if pattern change detected
        """
        changes = []

        # Check MFA method change
        if event.mfa_method and baseline.typical_auth_methods:
            if event.mfa_method.lower() not in {
                m.lower() for m in baseline.typical_auth_methods
            }:
                changes.append(f"MFA method: {event.mfa_method}")

        # Check application change
        if event.application_name and baseline.known_applications:
            if event.application_name not in baseline.known_applications:
                changes.append(f"Application: {event.application_name}")

        # Check provider change
        if event.provider and baseline.typical_providers:
            if event.provider.lower() not in {
                p.lower() for p in baseline.typical_providers
            }:
                changes.append(f"Provider: {event.provider}")

        if not changes:
            return None

        # Multiple changes are more concerning
        if len(changes) >= 2:
            severity = AnomalySeverity.HIGH
            confidence = 0.8
        else:
            severity = AnomalySeverity.MEDIUM
            confidence = 0.6

        return IdentityAnomaly.create(
            anomaly_type=IdentityAnomalyType.AUTH_METHOD_CHANGE,
            user_email=event.user_email,
            event_id=event.event_id,
            severity=severity,
            confidence=confidence,
            title=f"Authentication pattern change: {', '.join(changes)}",
            description=(
                f"User {event.user_email} used authentication patterns not seen before: "
                f"{', '.join(changes)}"
            ),
            evidence={
                "changes": changes,
                "mfa_method": event.mfa_method,
                "application": event.application_name,
                "provider": event.provider,
            },
            baseline_comparison={
                "typical_auth_methods": list(baseline.typical_auth_methods),
                "typical_providers": list(baseline.typical_providers),
                "known_applications": list(baseline.known_applications)[:10],
            },
            recommended_action=get_recommended_action(
                IdentityAnomalyType.AUTH_METHOD_CHANGE
            ),
        )

    def detect_vpn_or_proxy(self, event: IdentityEvent) -> Optional[IdentityAnomaly]:
        """Detect if the source IP is from a known VPN or proxy service.

        Args:
            event: Identity event to check

        Returns:
            IdentityAnomaly if VPN/proxy detected
        """
        if not event.source_geo:
            return None

        asn = event.source_geo.asn
        if not asn:
            return None

        # Check for known VPN ASNs
        if asn in KNOWN_VPN_ASNS:
            return IdentityAnomaly.create(
                anomaly_type=IdentityAnomalyType.VPN_OR_PROXY_DETECTED,
                user_email=event.user_email,
                event_id=event.event_id,
                severity=AnomalySeverity.LOW,
                confidence=0.7,
                title=f"VPN/Proxy detected: {asn}",
                description=(
                    f"User {event.user_email} authenticated from a known VPN provider "
                    f"(ASN: {asn})"
                ),
                evidence={
                    "asn": asn,
                    "source_ip": event.source_ip,
                    "provider_type": "vpn",
                },
                baseline_comparison={},
                recommended_action=get_recommended_action(
                    IdentityAnomalyType.VPN_OR_PROXY_DETECTED
                ),
            )

        # Check for datacenter IPs
        if asn in DATACENTER_ASNS:
            return IdentityAnomaly.create(
                anomaly_type=IdentityAnomalyType.DATACENTER_IP,
                user_email=event.user_email,
                event_id=event.event_id,
                severity=AnomalySeverity.MEDIUM,
                confidence=0.8,
                title=f"Datacenter IP detected: {asn}",
                description=(
                    f"User {event.user_email} authenticated from a datacenter IP "
                    f"(ASN: {asn}), which may indicate automated access or proxy usage"
                ),
                evidence={
                    "asn": asn,
                    "source_ip": event.source_ip,
                    "provider_type": "datacenter",
                },
                baseline_comparison={},
                recommended_action="Verify if this is expected automated access or investigate",
            )

        return None

    def _get_previous_event(
        self, user_email: str, before_timestamp: datetime
    ) -> Optional[IdentityEvent]:
        """Get the most recent event for a user before the given timestamp.

        Args:
            user_email: User's email address
            before_timestamp: Get events before this time

        Returns:
            Most recent previous event, or None
        """
        # Check cache first
        if user_email in self._recent_events_cache:
            events = self._recent_events_cache[user_email]
            for event in reversed(events):
                if event.timestamp < before_timestamp:
                    return event

        # Query if executor available
        if self.query_executor:
            try:
                results = self.query_executor.execute_query(
                    user_email=user_email,
                    before=before_timestamp.isoformat(),
                    limit=1
                )
                if results:
                    result = results[0]
                    # Parse result into IdentityEvent-like object
                    from datetime import datetime
                    timestamp_str = result.get("timestamp")
                    if isinstance(timestamp_str, str):
                        timestamp = datetime.fromisoformat(timestamp_str.replace("Z", "+00:00"))
                    else:
                        timestamp = timestamp_str

                    # Create a minimal event for travel analysis
                    geo_data = result.get("source_geo", {})
                    geo = None
                    if geo_data:
                        geo = GeoLocation(
                            latitude=geo_data.get("lat") or geo_data.get("latitude"),
                            longitude=geo_data.get("lon") or geo_data.get("longitude"),
                            country=geo_data.get("country"),
                            city=geo_data.get("city"),
                        )

                    return IdentityEvent(
                        event_id=result.get("event_id", "previous"),
                        event_type=IdentityEventType.AUTH_SUCCESS,
                        timestamp=timestamp,
                        provider=result.get("provider", "unknown"),
                        user_id=result.get("user_id", ""),
                        user_email=user_email,
                        source_ip=result.get("source_ip"),
                        source_geo=geo,
                    )
            except Exception as e:
                logger.debug(f"Failed to query previous event: {e}")

        return None

    def _count_recent_events(self, user_email: str, since: datetime) -> int:
        """Count events for a user since a given time.

        Args:
            user_email: User's email address
            since: Count events since this time

        Returns:
            Event count
        """
        # This would query the actual event store
        # For now, return 0 as placeholder
        return 0

    def _filter_and_sort_anomalies(
        self, anomalies: List[IdentityAnomaly], baseline: Optional[IdentityBaseline]
    ) -> List[IdentityAnomaly]:
        """Filter anomalies by confidence and sort by severity.

        Args:
            anomalies: List of detected anomalies
            baseline: User's baseline for confidence adjustment

        Returns:
            Filtered and sorted list of anomalies
        """
        # Adjust confidence based on baseline maturity
        if baseline:
            for anomaly in anomalies:
                anomaly.confidence = self._adjust_confidence_for_baseline_maturity(
                    anomaly.confidence, baseline
                )

        # Filter by minimum confidence
        filtered = [a for a in anomalies if a.confidence >= self.min_confidence]

        # Sort by severity (critical first) then by confidence
        severity_order = {
            AnomalySeverity.CRITICAL: 0,
            AnomalySeverity.HIGH: 1,
            AnomalySeverity.MEDIUM: 2,
            AnomalySeverity.LOW: 3,
        }

        filtered.sort(key=lambda a: (severity_order.get(a.severity, 4), -a.confidence))

        return filtered

    def _adjust_confidence_for_baseline_maturity(
        self, confidence: float, baseline: IdentityBaseline
    ) -> float:
        """Adjust confidence based on baseline maturity.

        Immature baselines result in lower confidence scores.

        Args:
            confidence: Original confidence score
            baseline: User's baseline

        Returns:
            Adjusted confidence score
        """
        if baseline.is_mature():
            return confidence

        # Reduce confidence for immature baselines
        maturity_factor = baseline.confidence_score

        # Minimum 50% of original confidence
        return confidence * (0.5 + 0.5 * maturity_factor)

    def cache_event(self, event: IdentityEvent, max_cache_size: int = 10) -> None:
        """Cache an event for travel analysis.

        Args:
            event: Event to cache
            max_cache_size: Maximum events to cache per user
        """
        user_email = event.user_email

        if user_email not in self._recent_events_cache:
            self._recent_events_cache[user_email] = []

        self._recent_events_cache[user_email].append(event)

        # Limit cache size
        if len(self._recent_events_cache[user_email]) > max_cache_size:
            self._recent_events_cache[user_email] = self._recent_events_cache[
                user_email
            ][-max_cache_size:]

    def clear_cache(self, user_email: Optional[str] = None) -> None:
        """Clear the event cache.

        Args:
            user_email: Specific user to clear, or None to clear all
        """
        if user_email:
            self._recent_events_cache.pop(user_email, None)
        else:
            self._recent_events_cache.clear()
