"""Cross-provider attack correlation for identity threats.

Correlates attacks that span multiple identity providers to detect
coordinated attacks using leaked credentials across systems.

Key detection patterns:
- Credential reuse attacks (same creds tried across Okta, Azure, Google)
- Synchronized attacks (different creds, same attacker IP, multiple providers)
- Provider hopping (user authenticated to multiple providers from different locations)
- Common attack infrastructure (shared IPs, user agents across attacks)
"""

import logging
import hashlib
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Set, Tuple

from ...alerting.correlation import IncidentSeverity, TimelineEntry
from .identity_incident import (
    IdentityAttackType,
    IdentityCorrelationType,
    IdentityIncident,
    create_identity_incident,
)

logger = logging.getLogger(__name__)


# Supported identity providers
SUPPORTED_PROVIDERS = ["okta", "azure", "google_workspace", "duo", "microsoft365"]

# Provider display names
PROVIDER_DISPLAY_NAMES = {
    "okta": "Okta",
    "azure": "Azure AD / Entra ID",
    "google_workspace": "Google Workspace",
    "duo": "Cisco Duo",
    "microsoft365": "Microsoft 365",
}


@dataclass
class CrossProviderIncident:
    """
    Incident representing a cross-provider attack correlation.

    Tracks attacks that span multiple identity providers and
    identifies common attack infrastructure.
    """

    incident_id: str
    title: str
    severity: str
    status: str = "open"

    # Cross-provider specific
    providers_involved: List[str] = field(default_factory=list)
    attack_type: str = ""
    correlation_confidence: float = 0.0

    # Common indicators across providers
    common_indicators: Dict[str, Any] = field(default_factory=lambda: {
        "shared_ips": [],
        "shared_user_agents": [],
        "shared_users": [],
        "time_correlation": None,
    })

    # Unified timeline across providers
    unified_timeline: List[Dict[str, Any]] = field(default_factory=list)

    # Entities
    target_users: List[str] = field(default_factory=list)
    attacker_ips: List[str] = field(default_factory=list)

    # Metrics
    total_events: int = 0
    events_per_provider: Dict[str, int] = field(default_factory=dict)
    failure_count: int = 0
    success_count: int = 0

    # Alert IDs from each provider
    alert_ids: List[str] = field(default_factory=list)
    provider_alerts: Dict[str, List[str]] = field(default_factory=dict)

    # Timing
    first_seen: str = ""
    last_seen: str = ""
    created_at: str = ""
    attack_duration_minutes: float = 0.0

    # Response
    recommended_actions: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "incident_id": self.incident_id,
            "title": self.title,
            "severity": self.severity,
            "status": self.status,
            "providers_involved": self.providers_involved,
            "providers_display": [
                PROVIDER_DISPLAY_NAMES.get(p, p) for p in self.providers_involved
            ],
            "attack_type": self.attack_type,
            "correlation_confidence": self.correlation_confidence,
            "common_indicators": self.common_indicators,
            "unified_timeline": self.unified_timeline,
            "target_users": self.target_users,
            "attacker_ips": self.attacker_ips,
            "total_events": self.total_events,
            "events_per_provider": self.events_per_provider,
            "failure_count": self.failure_count,
            "success_count": self.success_count,
            "alert_ids": self.alert_ids,
            "provider_alerts": self.provider_alerts,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "created_at": self.created_at,
            "attack_duration_minutes": self.attack_duration_minutes,
            "recommended_actions": self.recommended_actions,
        }


class CrossProviderCorrelator:
    """
    Correlates identity attacks across multiple providers.

    Detects coordinated attacks that span Okta, Azure AD, Google Workspace,
    Duo, and Microsoft 365 by analyzing common attack patterns and infrastructure.
    """

    def __init__(
        self,
        query_executor: Any = None,
        identity_events_table: str = "identity_events",
    ):
        """
        Initialize cross-provider correlator.

        Args:
            query_executor: Executor for querying identity events
            identity_events_table: Name of the identity events table
        """
        self.query_executor = query_executor
        self.identity_events_table = identity_events_table
        self._incidents: Dict[str, CrossProviderIncident] = {}

    def correlate_cross_provider_attacks(
        self,
        alerts: List[Dict[str, Any]],
        window_hours: int = 4
    ) -> List[CrossProviderIncident]:
        """
        Find attacks spanning multiple providers.

        Groups alerts by:
        - Same user_email
        - Same source_ip
        - Same time window

        Args:
            alerts: List of alerts from all providers
            window_hours: Time window for correlation

        Returns:
            List of CrossProviderIncident objects
        """
        if not alerts:
            return []

        incidents: List[CrossProviderIncident] = []

        # Filter to window
        cutoff = datetime.utcnow() - timedelta(hours=window_hours)
        windowed_alerts = [
            a for a in alerts
            if self._parse_timestamp(a.get("timestamp", "")) >= cutoff
        ]

        if not windowed_alerts:
            return []

        # Group by user and check for multi-provider activity
        user_incidents = self._correlate_by_user(windowed_alerts)
        incidents.extend(user_incidents)

        # Group by IP and check for multi-provider activity
        ip_incidents = self._correlate_by_ip(windowed_alerts)
        incidents.extend(ip_incidents)

        # Deduplicate incidents (some may overlap)
        unique_incidents = self._deduplicate_incidents(incidents)

        # Store incidents
        for incident in unique_incidents:
            self._incidents[incident.incident_id] = incident

        return unique_incidents

    def _correlate_by_user(
        self,
        alerts: List[Dict[str, Any]]
    ) -> List[CrossProviderIncident]:
        """Correlate alerts by target user across providers."""
        incidents = []

        # Group by user
        user_alerts: Dict[str, List[Dict]] = defaultdict(list)
        for alert in alerts:
            user = self._extract_user(alert)
            if user:
                user_alerts[user.lower()].append(alert)

        # Check each user for multi-provider activity
        for user_email, user_alert_list in user_alerts.items():
            providers = self._get_unique_providers(user_alert_list)

            if len(providers) >= 2:
                incident = self._create_user_based_incident(
                    user_email, user_alert_list, providers
                )
                if incident:
                    incidents.append(incident)

        return incidents

    def _correlate_by_ip(
        self,
        alerts: List[Dict[str, Any]]
    ) -> List[CrossProviderIncident]:
        """Correlate alerts by source IP across providers."""
        incidents = []

        # Group by IP
        ip_alerts: Dict[str, List[Dict]] = defaultdict(list)
        for alert in alerts:
            ip = alert.get("source_ip", "")
            if ip:
                ip_alerts[ip].append(alert)

        # Check each IP for multi-provider activity
        for source_ip, ip_alert_list in ip_alerts.items():
            providers = self._get_unique_providers(ip_alert_list)

            if len(providers) >= 2:
                incident = self._create_ip_based_incident(
                    source_ip, ip_alert_list, providers
                )
                if incident:
                    incidents.append(incident)

        return incidents

    def detect_credential_reuse_attack(
        self,
        alerts: List[Dict[str, Any]],
        window_hours: int = 1
    ) -> List[CrossProviderIncident]:
        """
        Detect same credentials tried across providers.

        Pattern: Failures in Okta, Azure, Google from same IP targeting same user.

        Args:
            alerts: List of alerts to analyze
            window_hours: Time window for correlation

        Returns:
            List of credential reuse incidents
        """
        incidents = []

        # Filter to window and failures
        cutoff = datetime.utcnow() - timedelta(hours=window_hours)
        failure_alerts = [
            a for a in alerts
            if self._parse_timestamp(a.get("timestamp", "")) >= cutoff
            and self._is_auth_failure(a)
        ]

        if not failure_alerts:
            return []

        # Group by (user, IP) pairs
        user_ip_alerts: Dict[Tuple[str, str], List[Dict]] = defaultdict(list)
        for alert in failure_alerts:
            user = self._extract_user(alert)
            ip = alert.get("source_ip", "")
            if user and ip:
                user_ip_alerts[(user.lower(), ip)].append(alert)

        # Check for multi-provider failures
        for (user_email, source_ip), pair_alerts in user_ip_alerts.items():
            providers = self._get_unique_providers(pair_alerts)

            if len(providers) >= 2:
                now = datetime.utcnow().isoformat() + "Z"

                # Build timeline
                timeline = self._build_timeline(pair_alerts)

                # Calculate duration
                if len(timeline) >= 2:
                    first_time = self._parse_timestamp(timeline[0]["timestamp"])
                    last_time = self._parse_timestamp(timeline[-1]["timestamp"])
                    duration = (last_time - first_time).total_seconds() / 60
                else:
                    duration = 0

                incident = CrossProviderIncident(
                    incident_id=self._generate_incident_id(),
                    title=f"Credential Reuse Attack: {user_email}",
                    severity="critical",
                    status="open",
                    providers_involved=providers,
                    attack_type="credential_reuse",
                    correlation_confidence=0.9,
                    common_indicators={
                        "shared_ips": [source_ip],
                        "shared_user_agents": self._get_unique_user_agents(pair_alerts),
                        "shared_users": [user_email],
                        "time_correlation": f"Within {window_hours} hour(s)",
                    },
                    unified_timeline=timeline,
                    target_users=[user_email],
                    attacker_ips=[source_ip],
                    total_events=len(pair_alerts),
                    events_per_provider=self._count_per_provider(pair_alerts),
                    failure_count=len(pair_alerts),
                    success_count=0,
                    alert_ids=[
                        a.get("id", a.get("alert_id", "")) for a in pair_alerts
                    ],
                    first_seen=timeline[0]["timestamp"] if timeline else now,
                    last_seen=timeline[-1]["timestamp"] if timeline else now,
                    created_at=now,
                    attack_duration_minutes=round(duration, 1),
                    recommended_actions=[
                        f"CRITICAL: Block source IP {source_ip} immediately",
                        f"Reset credentials for {user_email} across ALL providers",
                        "Check if credentials were exposed in known breaches",
                        "Enable/verify MFA on all identity providers",
                        "Review for any successful authentications from this IP",
                        "Add IP to threat intelligence watchlist",
                    ],
                )

                incidents.append(incident)

        return incidents

    def detect_synchronized_attack(
        self,
        alerts: List[Dict[str, Any]],
        window_hours: int = 1
    ) -> List[CrossProviderIncident]:
        """
        Detect multiple providers targeted simultaneously.

        Pattern: Different credentials but same attacker IP targeting
        multiple providers. Indicates broader campaign.

        Args:
            alerts: List of alerts to analyze
            window_hours: Time window for correlation

        Returns:
            List of synchronized attack incidents
        """
        incidents = []

        # Filter to window
        cutoff = datetime.utcnow() - timedelta(hours=window_hours)
        windowed_alerts = [
            a for a in alerts
            if self._parse_timestamp(a.get("timestamp", "")) >= cutoff
        ]

        if not windowed_alerts:
            return []

        # Group by source IP
        ip_alerts: Dict[str, List[Dict]] = defaultdict(list)
        for alert in windowed_alerts:
            ip = alert.get("source_ip", "")
            if ip:
                ip_alerts[ip].append(alert)

        # Check for multi-provider, multi-user attacks from same IP
        for source_ip, ip_alert_list in ip_alerts.items():
            providers = self._get_unique_providers(ip_alert_list)
            users = self._get_unique_users(ip_alert_list)

            # Need multiple providers AND multiple users (not just one user)
            if len(providers) >= 2 and len(users) >= 3:
                now = datetime.utcnow().isoformat() + "Z"
                timeline = self._build_timeline(ip_alert_list)

                if len(timeline) >= 2:
                    first_time = self._parse_timestamp(timeline[0]["timestamp"])
                    last_time = self._parse_timestamp(timeline[-1]["timestamp"])
                    duration = (last_time - first_time).total_seconds() / 60
                else:
                    duration = 0

                failures = sum(1 for a in ip_alert_list if self._is_auth_failure(a))
                successes = len(ip_alert_list) - failures

                incident = CrossProviderIncident(
                    incident_id=self._generate_incident_id(),
                    title=f"Synchronized Multi-Provider Attack from {source_ip}",
                    severity="critical",
                    status="open",
                    providers_involved=providers,
                    attack_type="synchronized_attack",
                    correlation_confidence=0.85,
                    common_indicators={
                        "shared_ips": [source_ip],
                        "shared_user_agents": self._get_unique_user_agents(ip_alert_list),
                        "shared_users": users,
                        "time_correlation": f"Within {window_hours} hour(s)",
                        "attack_pattern": "password_spray_or_credential_stuffing",
                    },
                    unified_timeline=timeline,
                    target_users=users,
                    attacker_ips=[source_ip],
                    total_events=len(ip_alert_list),
                    events_per_provider=self._count_per_provider(ip_alert_list),
                    failure_count=failures,
                    success_count=successes,
                    alert_ids=[
                        a.get("id", a.get("alert_id", "")) for a in ip_alert_list
                    ],
                    first_seen=timeline[0]["timestamp"] if timeline else now,
                    last_seen=timeline[-1]["timestamp"] if timeline else now,
                    created_at=now,
                    attack_duration_minutes=round(duration, 1),
                    recommended_actions=[
                        f"CRITICAL: Block source IP {source_ip} at perimeter",
                        f"This IP targeted {len(users)} users across {len(providers)} providers",
                        "Investigate all successful authentications from this IP",
                        "Reset passwords for any accounts that succeeded",
                        "Report IP to threat intelligence feeds",
                        "Review firewall/WAF rules for similar attack patterns",
                        "Consider geo-blocking if IP is from unexpected region",
                    ],
                )

                if successes > 0:
                    incident.recommended_actions.insert(
                        0,
                        f"URGENT: {successes} successful auth(s) - verify compromised accounts!"
                    )

                incidents.append(incident)

        return incidents

    def detect_provider_hopping(
        self,
        alerts: List[Dict[str, Any]],
        user_email: str,
        window_hours: int = 24
    ) -> Optional[CrossProviderIncident]:
        """
        Detect user authenticating to multiple providers from different locations.

        Could be legitimate or token theft across systems.

        Args:
            alerts: List of alerts to analyze
            user_email: User to check for provider hopping
            window_hours: Time window for analysis

        Returns:
            CrossProviderIncident if hopping detected, None otherwise
        """
        # Filter to user and window
        cutoff = datetime.utcnow() - timedelta(hours=window_hours)
        user_alerts = [
            a for a in alerts
            if self._extract_user(a) and
            self._extract_user(a).lower() == user_email.lower() and
            self._parse_timestamp(a.get("timestamp", "")) >= cutoff and
            self._is_auth_success(a)
        ]

        if not user_alerts:
            return None

        providers = self._get_unique_providers(user_alerts)
        locations = self._get_unique_locations(user_alerts)
        ips = list(set(a.get("source_ip", "") for a in user_alerts if a.get("source_ip")))

        # Need multiple providers AND multiple locations
        if len(providers) < 2 or len(locations) < 2:
            return None

        now = datetime.utcnow().isoformat() + "Z"
        timeline = self._build_timeline(user_alerts)

        if len(timeline) >= 2:
            first_time = self._parse_timestamp(timeline[0]["timestamp"])
            last_time = self._parse_timestamp(timeline[-1]["timestamp"])
            duration = (last_time - first_time).total_seconds() / 60
        else:
            duration = 0

        # Calculate confidence based on location diversity
        confidence = 0.5
        if len(locations) >= 3:
            confidence += 0.2
        if len(ips) >= 3:
            confidence += 0.1
        if duration < 60:  # Very fast hopping
            confidence += 0.2

        incident = CrossProviderIncident(
            incident_id=self._generate_incident_id(),
            title=f"Provider Hopping Detected: {user_email}",
            severity="high",
            status="open",
            providers_involved=providers,
            attack_type="provider_hopping",
            correlation_confidence=min(confidence, 1.0),
            common_indicators={
                "shared_ips": ips,
                "shared_user_agents": self._get_unique_user_agents(user_alerts),
                "shared_users": [user_email],
                "locations": locations,
                "time_correlation": f"Within {window_hours} hour(s)",
            },
            unified_timeline=timeline,
            target_users=[user_email],
            attacker_ips=ips,
            total_events=len(user_alerts),
            events_per_provider=self._count_per_provider(user_alerts),
            failure_count=0,
            success_count=len(user_alerts),
            alert_ids=[
                a.get("id", a.get("alert_id", "")) for a in user_alerts
            ],
            first_seen=timeline[0]["timestamp"] if timeline else now,
            last_seen=timeline[-1]["timestamp"] if timeline else now,
            created_at=now,
            attack_duration_minutes=round(duration, 1),
            recommended_actions=[
                f"Verify with {user_email} that all activity is legitimate",
                f"User accessed {len(providers)} providers from {len(locations)} locations",
                "Check for VPN or proxy usage that could explain location diversity",
                "If unverified, terminate all sessions and reset credentials",
                "Review for any unauthorized data access during sessions",
            ],
        )

        return incident

    def build_cross_provider_timeline(
        self,
        alerts: List[Dict[str, Any]],
        user_email: str,
        window_hours: int = 24
    ) -> List[Dict[str, Any]]:
        """
        Build unified timeline across all providers for a user.

        Args:
            alerts: List of alerts to analyze
            user_email: User to build timeline for
            window_hours: Time window for timeline

        Returns:
            Unified timeline with events from all providers
        """
        cutoff = datetime.utcnow() - timedelta(hours=window_hours)

        user_alerts = [
            a for a in alerts
            if self._extract_user(a) and
            self._extract_user(a).lower() == user_email.lower() and
            self._parse_timestamp(a.get("timestamp", "")) >= cutoff
        ]

        return self._build_timeline(user_alerts)

    def identify_common_attack_infrastructure(
        self,
        alerts: List[Dict[str, Any]],
        window_hours: int = 24
    ) -> Dict[str, Any]:
        """
        Find IPs, user agents, patterns common across provider attacks.

        Identifies attack infrastructure for threat intel sharing.

        Args:
            alerts: List of alerts to analyze
            window_hours: Time window for analysis

        Returns:
            Dictionary with common attack infrastructure
        """
        cutoff = datetime.utcnow() - timedelta(hours=window_hours)

        # Filter to attack-related alerts
        attack_alerts = [
            a for a in alerts
            if self._parse_timestamp(a.get("timestamp", "")) >= cutoff
            and self._is_attack_indicator(a)
        ]

        if not attack_alerts:
            return {
                "common_ips": [],
                "common_user_agents": [],
                "common_patterns": [],
                "attack_sources": [],
                "threat_indicators": [],
            }

        # Find IPs used across multiple providers
        ip_providers: Dict[str, Set[str]] = defaultdict(set)
        for alert in attack_alerts:
            ip = alert.get("source_ip", "")
            provider = alert.get("provider", "")
            if ip and provider:
                ip_providers[ip].add(provider)

        multi_provider_ips = [
            ip for ip, providers in ip_providers.items()
            if len(providers) >= 2
        ]

        # Find user agents used across multiple providers
        ua_providers: Dict[str, Set[str]] = defaultdict(set)
        for alert in attack_alerts:
            ua = alert.get("user_agent", "")
            provider = alert.get("provider", "")
            if ua and provider:
                ua_providers[ua].add(provider)

        multi_provider_uas = [
            ua for ua, providers in ua_providers.items()
            if len(providers) >= 2
        ]

        # Identify attack patterns
        patterns = []
        ip_counts = defaultdict(int)
        for alert in attack_alerts:
            ip = alert.get("source_ip", "")
            if ip:
                ip_counts[ip] += 1

        # High-volume IPs
        high_volume_ips = [
            ip for ip, count in ip_counts.items()
            if count >= 10
        ]
        if high_volume_ips:
            patterns.append({
                "type": "high_volume_source",
                "ips": high_volume_ips,
                "description": "IPs with 10+ attack events",
            })

        # Rapid succession attacks
        rapid_ips = self._find_rapid_succession_ips(attack_alerts)
        if rapid_ips:
            patterns.append({
                "type": "rapid_succession",
                "ips": rapid_ips,
                "description": "IPs with rapid-fire authentication attempts",
            })

        # Build threat indicators for sharing
        threat_indicators = []
        for ip in multi_provider_ips:
            threat_indicators.append({
                "type": "ip",
                "value": ip,
                "confidence": "high",
                "context": f"Used in attacks against {len(ip_providers[ip])} providers",
                "providers": list(ip_providers[ip]),
            })

        for ua in multi_provider_uas[:10]:  # Limit to top 10
            threat_indicators.append({
                "type": "user_agent",
                "value": ua,
                "confidence": "medium",
                "context": f"Used in attacks against {len(ua_providers[ua])} providers",
            })

        return {
            "common_ips": multi_provider_ips,
            "common_user_agents": multi_provider_uas[:20],  # Limit output
            "common_patterns": patterns,
            "attack_sources": [
                {
                    "ip": ip,
                    "providers_targeted": list(providers),
                    "event_count": ip_counts[ip],
                }
                for ip, providers in ip_providers.items()
                if len(providers) >= 2
            ],
            "threat_indicators": threat_indicators,
            "analysis_window_hours": window_hours,
            "total_attack_events": len(attack_alerts),
        }

    def _create_user_based_incident(
        self,
        user_email: str,
        alerts: List[Dict[str, Any]],
        providers: List[str]
    ) -> Optional[CrossProviderIncident]:
        """Create incident for user-based cross-provider correlation."""
        now = datetime.utcnow().isoformat() + "Z"
        timeline = self._build_timeline(alerts)

        ips = list(set(a.get("source_ip", "") for a in alerts if a.get("source_ip")))
        user_agents = self._get_unique_user_agents(alerts)

        failures = sum(1 for a in alerts if self._is_auth_failure(a))
        successes = len(alerts) - failures

        if len(timeline) >= 2:
            first_time = self._parse_timestamp(timeline[0]["timestamp"])
            last_time = self._parse_timestamp(timeline[-1]["timestamp"])
            duration = (last_time - first_time).total_seconds() / 60
        else:
            duration = 0

        # Determine attack type
        if failures > successes * 2:
            attack_type = "credential_attack"
            severity = "high"
        elif successes > 0 and len(providers) >= 2:
            attack_type = "account_activity"
            severity = "medium"
        else:
            attack_type = "suspicious_activity"
            severity = "medium"

        # Calculate confidence
        confidence = 0.5
        if len(providers) >= 3:
            confidence += 0.2
        if len(ips) == 1:  # Same IP across providers
            confidence += 0.2
        if failures >= 5:
            confidence += 0.1

        return CrossProviderIncident(
            incident_id=self._generate_incident_id(),
            title=f"Cross-Provider Activity: {user_email}",
            severity=severity,
            status="open",
            providers_involved=providers,
            attack_type=attack_type,
            correlation_confidence=min(confidence, 1.0),
            common_indicators={
                "shared_ips": ips,
                "shared_user_agents": user_agents,
                "shared_users": [user_email],
                "time_correlation": "correlated",
            },
            unified_timeline=timeline,
            target_users=[user_email],
            attacker_ips=ips,
            total_events=len(alerts),
            events_per_provider=self._count_per_provider(alerts),
            failure_count=failures,
            success_count=successes,
            alert_ids=[a.get("id", a.get("alert_id", "")) for a in alerts],
            first_seen=timeline[0]["timestamp"] if timeline else now,
            last_seen=timeline[-1]["timestamp"] if timeline else now,
            created_at=now,
            attack_duration_minutes=round(duration, 1),
            recommended_actions=self._get_recommendations(attack_type, user_email, providers),
        )

    def _create_ip_based_incident(
        self,
        source_ip: str,
        alerts: List[Dict[str, Any]],
        providers: List[str]
    ) -> Optional[CrossProviderIncident]:
        """Create incident for IP-based cross-provider correlation."""
        now = datetime.utcnow().isoformat() + "Z"
        timeline = self._build_timeline(alerts)

        users = self._get_unique_users(alerts)
        user_agents = self._get_unique_user_agents(alerts)

        failures = sum(1 for a in alerts if self._is_auth_failure(a))
        successes = len(alerts) - failures

        if len(timeline) >= 2:
            first_time = self._parse_timestamp(timeline[0]["timestamp"])
            last_time = self._parse_timestamp(timeline[-1]["timestamp"])
            duration = (last_time - first_time).total_seconds() / 60
        else:
            duration = 0

        # Determine attack type based on patterns
        if len(users) >= 5 and failures > successes:
            attack_type = "password_spray"
            severity = "critical"
        elif failures >= 10:
            attack_type = "brute_force"
            severity = "high"
        else:
            attack_type = "suspicious_activity"
            severity = "medium"

        confidence = 0.6
        if len(providers) >= 3:
            confidence += 0.2
        if len(users) >= 5:
            confidence += 0.1

        return CrossProviderIncident(
            incident_id=self._generate_incident_id(),
            title=f"Cross-Provider Attack from {source_ip}",
            severity=severity,
            status="open",
            providers_involved=providers,
            attack_type=attack_type,
            correlation_confidence=min(confidence, 1.0),
            common_indicators={
                "shared_ips": [source_ip],
                "shared_user_agents": user_agents,
                "shared_users": users,
                "time_correlation": "correlated",
            },
            unified_timeline=timeline,
            target_users=users,
            attacker_ips=[source_ip],
            total_events=len(alerts),
            events_per_provider=self._count_per_provider(alerts),
            failure_count=failures,
            success_count=successes,
            alert_ids=[a.get("id", a.get("alert_id", "")) for a in alerts],
            first_seen=timeline[0]["timestamp"] if timeline else now,
            last_seen=timeline[-1]["timestamp"] if timeline else now,
            created_at=now,
            attack_duration_minutes=round(duration, 1),
            recommended_actions=[
                f"Block source IP {source_ip} at firewall/WAF",
                f"IP targeted {len(users)} users across {len(providers)} providers",
                "Review all activity from this IP for successful access",
                "Add to threat intelligence blocklist",
            ],
        )

    def _build_timeline(
        self,
        alerts: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """Build unified timeline from alerts."""
        timeline = []

        for alert in alerts:
            entry = {
                "timestamp": alert.get("timestamp", ""),
                "provider": alert.get("provider", "unknown"),
                "event_type": alert.get("event_type", ""),
                "user_email": self._extract_user(alert),
                "source_ip": alert.get("source_ip", ""),
                "location": alert.get("source_geo", {}).get("country", ""),
                "status": "success" if self._is_auth_success(alert) else "failure",
                "alert_id": alert.get("id", alert.get("alert_id", "")),
                "title": alert.get("title", ""),
            }
            timeline.append(entry)

        # Sort by timestamp
        timeline.sort(key=lambda x: x["timestamp"])

        return timeline

    def _get_unique_providers(self, alerts: List[Dict[str, Any]]) -> List[str]:
        """Get unique providers from alerts."""
        providers = set()
        for alert in alerts:
            provider = alert.get("provider", "")
            if provider:
                providers.add(provider.lower())
        return list(providers)

    def _get_unique_users(self, alerts: List[Dict[str, Any]]) -> List[str]:
        """Get unique users from alerts."""
        users = set()
        for alert in alerts:
            user = self._extract_user(alert)
            if user:
                users.add(user.lower())
        return list(users)

    def _get_unique_user_agents(self, alerts: List[Dict[str, Any]]) -> List[str]:
        """Get unique user agents from alerts."""
        uas = set()
        for alert in alerts:
            ua = alert.get("user_agent", "")
            if ua:
                uas.add(ua)
        return list(uas)[:10]  # Limit to top 10

    def _get_unique_locations(self, alerts: List[Dict[str, Any]]) -> List[str]:
        """Get unique locations from alerts."""
        locations = set()
        for alert in alerts:
            geo = alert.get("source_geo", {})
            if isinstance(geo, dict):
                country = geo.get("country", "")
                city = geo.get("city", "")
                if country:
                    loc = f"{city}, {country}" if city else country
                    locations.add(loc)
        return list(locations)

    def _count_per_provider(self, alerts: List[Dict[str, Any]]) -> Dict[str, int]:
        """Count alerts per provider."""
        counts: Dict[str, int] = defaultdict(int)
        for alert in alerts:
            provider = alert.get("provider", "unknown")
            counts[provider] += 1
        return dict(counts)

    def _extract_user(self, alert: Dict[str, Any]) -> Optional[str]:
        """Extract user email from alert."""
        user_fields = [
            "user_email", "userPrincipalName", "actor.email",
            "principal.email", "target.email"
        ]

        for field in user_fields:
            if "." in field:
                parts = field.split(".")
                value = alert
                for part in parts:
                    if isinstance(value, dict):
                        value = value.get(part)
                    else:
                        value = None
                        break
                if value and isinstance(value, str):
                    return value
            else:
                value = alert.get(field)
                if value and isinstance(value, str):
                    return value

        return None

    def _is_auth_failure(self, alert: Dict[str, Any]) -> bool:
        """Check if alert represents auth failure."""
        event_type = alert.get("event_type", "").upper()
        outcome = alert.get("outcome", "").lower()
        status = alert.get("status", "").lower()

        if "FAILURE" in event_type or "FAILED" in event_type:
            return True
        if outcome in ["failure", "failed", "denied"]:
            return True
        if status in ["failure", "failed", "denied"]:
            return True

        return False

    def _is_auth_success(self, alert: Dict[str, Any]) -> bool:
        """Check if alert represents auth success."""
        event_type = alert.get("event_type", "").upper()
        outcome = alert.get("outcome", "").lower()

        if "SUCCESS" in event_type:
            return True
        if outcome in ["success", "allowed"]:
            return True

        return False

    def _is_attack_indicator(self, alert: Dict[str, Any]) -> bool:
        """Check if alert indicates an attack."""
        # Auth failures are attack indicators
        if self._is_auth_failure(alert):
            return True

        # Check rule patterns
        rule_name = alert.get("rule_name", "").lower()
        attack_patterns = [
            "brute", "spray", "stuffing", "attack",
            "suspicious", "anomaly", "unusual"
        ]
        return any(p in rule_name for p in attack_patterns)

    def _find_rapid_succession_ips(
        self,
        alerts: List[Dict[str, Any]]
    ) -> List[str]:
        """Find IPs with rapid succession attempts."""
        rapid_ips = []

        # Group by IP
        ip_alerts: Dict[str, List[Dict]] = defaultdict(list)
        for alert in alerts:
            ip = alert.get("source_ip", "")
            if ip:
                ip_alerts[ip].append(alert)

        for ip, ip_alert_list in ip_alerts.items():
            if len(ip_alert_list) < 5:
                continue

            # Sort by timestamp
            sorted_alerts = sorted(
                ip_alert_list,
                key=lambda a: a.get("timestamp", "")
            )

            # Check for 5+ events in 1 minute
            for i in range(len(sorted_alerts) - 4):
                t1 = self._parse_timestamp(sorted_alerts[i].get("timestamp", ""))
                t2 = self._parse_timestamp(sorted_alerts[i + 4].get("timestamp", ""))
                if (t2 - t1).total_seconds() <= 60:
                    rapid_ips.append(ip)
                    break

        return rapid_ips

    def _deduplicate_incidents(
        self,
        incidents: List[CrossProviderIncident]
    ) -> List[CrossProviderIncident]:
        """Deduplicate incidents that share significant overlap."""
        if len(incidents) <= 1:
            return incidents

        unique = []
        seen_alert_sets: List[Set[str]] = []

        for incident in incidents:
            alert_set = set(incident.alert_ids)

            # Check overlap with existing
            is_duplicate = False
            for seen_set in seen_alert_sets:
                overlap = len(alert_set & seen_set)
                if overlap > len(alert_set) * 0.7:  # 70% overlap
                    is_duplicate = True
                    break

            if not is_duplicate:
                unique.append(incident)
                seen_alert_sets.append(alert_set)

        return unique

    def _get_recommendations(
        self,
        attack_type: str,
        user_email: str,
        providers: List[str]
    ) -> List[str]:
        """Get recommendations based on attack type."""
        provider_names = [PROVIDER_DISPLAY_NAMES.get(p, p) for p in providers]

        if attack_type == "credential_attack":
            return [
                f"Reset credentials for {user_email} across: {', '.join(provider_names)}",
                "Verify MFA is enabled on all providers",
                "Check for credential exposure in breach databases",
                "Review all recent authentications for the user",
            ]
        elif attack_type == "account_activity":
            return [
                f"Verify activity with {user_email}",
                f"User active across: {', '.join(provider_names)}",
                "Check for unauthorized access or data exfiltration",
            ]
        else:
            return [
                f"Monitor {user_email} for suspicious activity",
                f"Activity detected across: {', '.join(provider_names)}",
                "Review logs for additional context",
            ]

    def _parse_timestamp(self, timestamp: str) -> datetime:
        """Parse ISO timestamp string."""
        try:
            return datetime.fromisoformat(timestamp.replace("Z", ""))
        except (ValueError, TypeError):
            return datetime.utcnow()

    def _generate_incident_id(self) -> str:
        """Generate unique incident ID."""
        now = datetime.utcnow().isoformat()
        return f"XP-{hashlib.md5(now.encode()).hexdigest()[:12].upper()}"

    def get_incident(self, incident_id: str) -> Optional[CrossProviderIncident]:
        """Get incident by ID."""
        return self._incidents.get(incident_id)

    def get_active_incidents(self) -> List[CrossProviderIncident]:
        """Get all active cross-provider incidents."""
        return [i for i in self._incidents.values() if i.status == "open"]


def correlate_cross_provider(
    alerts: List[Dict[str, Any]],
    window_hours: int = 4
) -> List[CrossProviderIncident]:
    """Convenience function to correlate cross-provider attacks."""
    correlator = CrossProviderCorrelator()
    return correlator.correlate_cross_provider_attacks(alerts, window_hours)
