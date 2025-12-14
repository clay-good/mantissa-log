"""
Alert Correlation Engine.

Groups related alerts by common entities (IP, user, asset) and timeframe
to create incidents and reduce alert fatigue.

Features:
- Correlate by IP address, user, asset, and rule family
- Configurable time windows for correlation
- Automatic incident timeline generation
- Kill chain progression detection
- Alert deduplication within incidents
"""

import logging
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Set, Tuple
from collections import defaultdict
from enum import Enum
import hashlib

logger = logging.getLogger(__name__)


class CorrelationType(Enum):
    """Types of correlation."""
    IP_BASED = "ip_based"
    USER_BASED = "user_based"
    ASSET_BASED = "asset_based"
    RULE_FAMILY = "rule_family"
    KILL_CHAIN = "kill_chain"
    TIME_WINDOW = "time_window"


class IncidentSeverity(Enum):
    """Incident severity levels."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class TimelineEntry:
    """A single entry in an incident timeline."""

    timestamp: str
    alert_id: str
    rule_name: str
    severity: str
    title: str
    entities: Dict[str, Any]  # IPs, users, assets involved
    mitre_attack: Optional[Dict[str, str]] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "timestamp": self.timestamp,
            "alert_id": self.alert_id,
            "rule_name": self.rule_name,
            "severity": self.severity,
            "title": self.title,
            "entities": self.entities,
            "mitre_attack": self.mitre_attack,
        }


@dataclass
class Incident:
    """A correlated incident containing multiple alerts."""

    incident_id: str
    title: str
    severity: IncidentSeverity
    status: str = "open"

    # Timing
    first_seen: str = ""
    last_seen: str = ""
    created_at: str = ""

    # Correlation info
    correlation_types: List[str] = field(default_factory=list)
    correlation_keys: Dict[str, List[str]] = field(default_factory=dict)

    # Alerts
    alert_ids: List[str] = field(default_factory=list)
    alert_count: int = 0
    unique_rules: int = 0

    # Timeline
    timeline: List[TimelineEntry] = field(default_factory=list)

    # Entities
    source_ips: List[str] = field(default_factory=list)
    users: List[str] = field(default_factory=list)
    assets: List[str] = field(default_factory=list)

    # MITRE ATT&CK progression
    mitre_tactics: List[str] = field(default_factory=list)
    mitre_techniques: List[str] = field(default_factory=list)
    kill_chain_stage: Optional[str] = None

    # Metadata
    summary: str = ""
    recommendations: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "incident_id": self.incident_id,
            "title": self.title,
            "severity": self.severity.value,
            "status": self.status,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "created_at": self.created_at,
            "correlation_types": self.correlation_types,
            "correlation_keys": self.correlation_keys,
            "alert_ids": self.alert_ids,
            "alert_count": self.alert_count,
            "unique_rules": self.unique_rules,
            "timeline": [t.to_dict() for t in self.timeline],
            "source_ips": self.source_ips,
            "users": self.users,
            "assets": self.assets,
            "mitre_tactics": self.mitre_tactics,
            "mitre_techniques": self.mitre_techniques,
            "kill_chain_stage": self.kill_chain_stage,
            "summary": self.summary,
            "recommendations": self.recommendations,
        }


@dataclass
class CorrelationConfig:
    """Configuration for alert correlation."""

    # Time windows
    ip_correlation_window_minutes: int = 60
    user_correlation_window_minutes: int = 120
    asset_correlation_window_minutes: int = 60
    kill_chain_window_hours: int = 24

    # Thresholds
    min_alerts_for_incident: int = 2
    max_alerts_per_incident: int = 100

    # Entity extraction field mappings
    ip_fields: List[str] = field(default_factory=lambda: [
        "source_ip", "sourceIPAddress", "srcaddr", "src_ip",
        "destination_ip", "destinationIPAddress", "dstaddr", "dst_ip"
    ])
    user_fields: List[str] = field(default_factory=lambda: [
        "user", "userName", "principal", "userPrincipalName",
        "actor", "subject"
    ])
    asset_fields: List[str] = field(default_factory=lambda: [
        "asset_id", "resource_id", "instance_id", "hostname",
        "computer_name", "device_id"
    ])

    # Rule families for correlation
    rule_families: Dict[str, List[str]] = field(default_factory=dict)

    # Kill chain / MITRE tactic order
    kill_chain_order: List[str] = field(default_factory=lambda: [
        "reconnaissance",
        "resource-development",
        "initial-access",
        "execution",
        "persistence",
        "privilege-escalation",
        "defense-evasion",
        "credential-access",
        "discovery",
        "lateral-movement",
        "collection",
        "command-and-control",
        "exfiltration",
        "impact"
    ])


class AlertCorrelator:
    """
    Correlates alerts into incidents based on common entities and time windows.
    """

    def __init__(self, config: Optional[CorrelationConfig] = None):
        """
        Initialize correlator.

        Args:
            config: Correlation configuration
        """
        self.config = config or CorrelationConfig()

        # In-memory correlation state
        self._ip_index: Dict[str, List[Dict]] = defaultdict(list)
        self._user_index: Dict[str, List[Dict]] = defaultdict(list)
        self._asset_index: Dict[str, List[Dict]] = defaultdict(list)
        self._incidents: Dict[str, Incident] = {}
        self._alert_to_incident: Dict[str, str] = {}

    def process_alert(self, alert: Dict[str, Any]) -> Optional[Incident]:
        """
        Process a new alert and correlate with existing alerts.

        Args:
            alert: Alert data

        Returns:
            Incident if alert was correlated, None if standalone
        """
        alert_id = alert.get("id", alert.get("alert_id", ""))
        timestamp = alert.get("timestamp", datetime.utcnow().isoformat())

        # Extract entities
        entities = self._extract_entities(alert)

        # Find correlation candidates
        candidates = self._find_correlation_candidates(alert, entities, timestamp)

        if candidates:
            # Add to existing incident or merge incidents
            incident = self._correlate_to_incident(alert, entities, candidates)
        else:
            # Check if we should create a new incident based on alert characteristics
            incident = None

        # Index the alert for future correlation
        self._index_alert(alert, entities, timestamp)

        return incident

    def correlate_batch(self, alerts: List[Dict[str, Any]]) -> List[Incident]:
        """
        Correlate a batch of alerts.

        Args:
            alerts: List of alerts to correlate

        Returns:
            List of incidents created
        """
        # Sort by timestamp
        sorted_alerts = sorted(
            alerts,
            key=lambda a: a.get("timestamp", "")
        )

        incidents_created = set()

        for alert in sorted_alerts:
            incident = self.process_alert(alert)
            if incident:
                incidents_created.add(incident.incident_id)

        # Also create incidents from clusters that haven't been processed
        additional_incidents = self._create_pending_incidents()
        incidents_created.update(i.incident_id for i in additional_incidents)

        return [self._incidents[iid] for iid in incidents_created if iid in self._incidents]

    def get_incident(self, incident_id: str) -> Optional[Incident]:
        """Get incident by ID."""
        return self._incidents.get(incident_id)

    def get_incident_for_alert(self, alert_id: str) -> Optional[Incident]:
        """Get incident containing an alert."""
        incident_id = self._alert_to_incident.get(alert_id)
        if incident_id:
            return self._incidents.get(incident_id)
        return None

    def get_active_incidents(self, max_age_hours: int = 24) -> List[Incident]:
        """Get active incidents within time window."""
        cutoff = (datetime.utcnow() - timedelta(hours=max_age_hours)).isoformat()

        active = []
        for incident in self._incidents.values():
            if incident.status == "open" and incident.last_seen >= cutoff:
                active.append(incident)

        return sorted(active, key=lambda i: i.last_seen, reverse=True)

    def _extract_entities(self, alert: Dict[str, Any]) -> Dict[str, Set[str]]:
        """Extract entities (IPs, users, assets) from alert."""
        entities = {
            "ips": set(),
            "users": set(),
            "assets": set()
        }

        # Also check nested results
        results = alert.get("results", [])
        sources = [alert] + (results if isinstance(results, list) else [])

        for source in sources:
            if not isinstance(source, dict):
                continue

            # Extract IPs
            for field in self.config.ip_fields:
                value = self._get_nested_field(source, field)
                if value and isinstance(value, str):
                    entities["ips"].add(value)

            # Extract users
            for field in self.config.user_fields:
                value = self._get_nested_field(source, field)
                if value:
                    if isinstance(value, str):
                        entities["users"].add(value)
                    elif isinstance(value, dict):
                        # Handle nested user objects
                        for subfield in ["userName", "name", "email", "id"]:
                            if subfield in value:
                                entities["users"].add(str(value[subfield]))
                                break

            # Extract assets
            for field in self.config.asset_fields:
                value = self._get_nested_field(source, field)
                if value and isinstance(value, str):
                    entities["assets"].add(value)

        return entities

    def _get_nested_field(self, data: Dict, field: str) -> Any:
        """Get a potentially nested field from data."""
        if "." in field:
            parts = field.split(".")
            current = data
            for part in parts:
                if isinstance(current, dict) and part in current:
                    current = current[part]
                else:
                    return None
            return current
        return data.get(field)

    def _find_correlation_candidates(
        self,
        alert: Dict[str, Any],
        entities: Dict[str, Set[str]],
        timestamp: str
    ) -> List[Tuple[str, Dict[str, Any], str]]:
        """
        Find alerts that could be correlated with this one.

        Returns list of (correlation_type, candidate_alert, correlation_key) tuples.
        """
        candidates = []
        alert_time = self._parse_timestamp(timestamp)

        # IP-based correlation
        ip_window = timedelta(minutes=self.config.ip_correlation_window_minutes)
        for ip in entities["ips"]:
            for indexed in self._ip_index.get(ip, []):
                indexed_time = self._parse_timestamp(indexed["timestamp"])
                if abs((alert_time - indexed_time).total_seconds()) <= ip_window.total_seconds():
                    candidates.append((CorrelationType.IP_BASED.value, indexed, ip))

        # User-based correlation
        user_window = timedelta(minutes=self.config.user_correlation_window_minutes)
        for user in entities["users"]:
            for indexed in self._user_index.get(user, []):
                indexed_time = self._parse_timestamp(indexed["timestamp"])
                if abs((alert_time - indexed_time).total_seconds()) <= user_window.total_seconds():
                    candidates.append((CorrelationType.USER_BASED.value, indexed, user))

        # Asset-based correlation
        asset_window = timedelta(minutes=self.config.asset_correlation_window_minutes)
        for asset in entities["assets"]:
            for indexed in self._asset_index.get(asset, []):
                indexed_time = self._parse_timestamp(indexed["timestamp"])
                if abs((alert_time - indexed_time).total_seconds()) <= asset_window.total_seconds():
                    candidates.append((CorrelationType.ASSET_BASED.value, indexed, asset))

        return candidates

    def _correlate_to_incident(
        self,
        alert: Dict[str, Any],
        entities: Dict[str, Set[str]],
        candidates: List[Tuple[str, Dict[str, Any], str]]
    ) -> Incident:
        """Add alert to an existing incident or create new one from candidates."""
        alert_id = alert.get("id", alert.get("alert_id", ""))

        # Find existing incidents for candidates
        candidate_incidents = set()
        for _, candidate, _ in candidates:
            candidate_id = candidate.get("id", candidate.get("alert_id", ""))
            if candidate_id in self._alert_to_incident:
                candidate_incidents.add(self._alert_to_incident[candidate_id])

        if candidate_incidents:
            # Add to existing incident (use first one, merge if multiple)
            incident_id = next(iter(candidate_incidents))
            incident = self._incidents[incident_id]

            # Merge other incidents if any
            for other_id in candidate_incidents:
                if other_id != incident_id:
                    self._merge_incidents(incident_id, other_id)

        else:
            # Create new incident
            incident = self._create_incident(alert, entities, candidates)
            self._incidents[incident.incident_id] = incident

        # Add alert to incident
        self._add_alert_to_incident(incident, alert, entities)

        return incident

    def _create_incident(
        self,
        alert: Dict[str, Any],
        entities: Dict[str, Set[str]],
        candidates: List[Tuple[str, Dict[str, Any], str]]
    ) -> Incident:
        """Create a new incident."""
        now = datetime.utcnow().isoformat() + "Z"
        timestamp = alert.get("timestamp", now)

        # Generate incident ID
        incident_id = f"INC-{hashlib.md5(now.encode()).hexdigest()[:12].upper()}"

        # Determine correlation types and keys
        correlation_types = list(set(c[0] for c in candidates))
        correlation_keys = defaultdict(list)
        for corr_type, _, key in candidates:
            if key not in correlation_keys[corr_type]:
                correlation_keys[corr_type].append(key)

        # Generate title
        title = self._generate_incident_title(alert, entities, correlation_types)

        # Initial severity from alert
        severity = self._map_severity(alert.get("severity", "medium"))

        incident = Incident(
            incident_id=incident_id,
            title=title,
            severity=severity,
            status="open",
            first_seen=timestamp,
            last_seen=timestamp,
            created_at=now,
            correlation_types=correlation_types,
            correlation_keys=dict(correlation_keys),
            source_ips=list(entities["ips"]),
            users=list(entities["users"]),
            assets=list(entities["assets"]),
        )

        return incident

    def _add_alert_to_incident(
        self,
        incident: Incident,
        alert: Dict[str, Any],
        entities: Dict[str, Set[str]]
    ) -> None:
        """Add an alert to an incident."""
        alert_id = alert.get("id", alert.get("alert_id", ""))
        timestamp = alert.get("timestamp", datetime.utcnow().isoformat())

        # Skip if already in incident
        if alert_id in incident.alert_ids:
            return

        # Add to incident
        incident.alert_ids.append(alert_id)
        incident.alert_count = len(incident.alert_ids)
        self._alert_to_incident[alert_id] = incident.incident_id

        # Update timing
        if timestamp < incident.first_seen:
            incident.first_seen = timestamp
        if timestamp > incident.last_seen:
            incident.last_seen = timestamp

        # Update entities
        for ip in entities["ips"]:
            if ip not in incident.source_ips:
                incident.source_ips.append(ip)
        for user in entities["users"]:
            if user not in incident.users:
                incident.users.append(user)
        for asset in entities["assets"]:
            if asset not in incident.assets:
                incident.assets.append(asset)

        # Update MITRE ATT&CK
        mitre = alert.get("mitre_attack", {})
        if mitre:
            tactic = mitre.get("tactic", "")
            technique = mitre.get("technique", "")
            if tactic and tactic not in incident.mitre_tactics:
                incident.mitre_tactics.append(tactic)
            if technique and technique not in incident.mitre_techniques:
                incident.mitre_techniques.append(technique)

        # Update kill chain stage
        incident.kill_chain_stage = self._determine_kill_chain_stage(incident.mitre_tactics)

        # Add to timeline
        timeline_entry = TimelineEntry(
            timestamp=timestamp,
            alert_id=alert_id,
            rule_name=alert.get("rule_name", "Unknown"),
            severity=alert.get("severity", "medium"),
            title=alert.get("title", "Alert"),
            entities={
                "ips": list(entities["ips"]),
                "users": list(entities["users"]),
                "assets": list(entities["assets"])
            },
            mitre_attack=mitre if mitre else None
        )
        incident.timeline.append(timeline_entry)

        # Sort timeline by timestamp
        incident.timeline.sort(key=lambda t: t.timestamp)

        # Update unique rules count
        rule_names = set(t.rule_name for t in incident.timeline)
        incident.unique_rules = len(rule_names)

        # Update severity based on escalation
        incident.severity = self._calculate_incident_severity(incident)

        # Update summary and recommendations
        incident.summary = self._generate_summary(incident)
        incident.recommendations = self._generate_recommendations(incident)

    def _merge_incidents(self, target_id: str, source_id: str) -> None:
        """Merge source incident into target incident."""
        if source_id not in self._incidents:
            return

        target = self._incidents[target_id]
        source = self._incidents[source_id]

        # Merge alert IDs
        for alert_id in source.alert_ids:
            if alert_id not in target.alert_ids:
                target.alert_ids.append(alert_id)
                self._alert_to_incident[alert_id] = target_id

        # Merge timeline
        target.timeline.extend(source.timeline)
        target.timeline.sort(key=lambda t: t.timestamp)

        # Merge entities
        for ip in source.source_ips:
            if ip not in target.source_ips:
                target.source_ips.append(ip)
        for user in source.users:
            if user not in target.users:
                target.users.append(user)
        for asset in source.assets:
            if asset not in target.assets:
                target.assets.append(asset)

        # Merge MITRE
        for tactic in source.mitre_tactics:
            if tactic not in target.mitre_tactics:
                target.mitre_tactics.append(tactic)
        for technique in source.mitre_techniques:
            if technique not in target.mitre_techniques:
                target.mitre_techniques.append(technique)

        # Update timing
        if source.first_seen < target.first_seen:
            target.first_seen = source.first_seen
        if source.last_seen > target.last_seen:
            target.last_seen = source.last_seen

        # Update counts
        target.alert_count = len(target.alert_ids)
        rule_names = set(t.rule_name for t in target.timeline)
        target.unique_rules = len(rule_names)

        # Remove source incident
        del self._incidents[source_id]

    def _index_alert(
        self,
        alert: Dict[str, Any],
        entities: Dict[str, Set[str]],
        timestamp: str
    ) -> None:
        """Index alert for future correlation lookups."""
        alert_data = {
            "id": alert.get("id", alert.get("alert_id", "")),
            "timestamp": timestamp,
            "alert": alert
        }

        for ip in entities["ips"]:
            self._ip_index[ip].append(alert_data)

        for user in entities["users"]:
            self._user_index[user].append(alert_data)

        for asset in entities["assets"]:
            self._asset_index[asset].append(alert_data)

    def _create_pending_incidents(self) -> List[Incident]:
        """Create incidents from clusters of alerts that meet threshold."""
        # This would analyze the indices for clusters that haven't been
        # processed into incidents yet
        return []

    def _parse_timestamp(self, timestamp: str) -> datetime:
        """Parse ISO timestamp string."""
        try:
            return datetime.fromisoformat(timestamp.replace("Z", ""))
        except (ValueError, TypeError):
            return datetime.utcnow()

    def _map_severity(self, severity: str) -> IncidentSeverity:
        """Map string severity to IncidentSeverity."""
        mapping = {
            "critical": IncidentSeverity.CRITICAL,
            "high": IncidentSeverity.HIGH,
            "medium": IncidentSeverity.MEDIUM,
            "low": IncidentSeverity.LOW,
            "info": IncidentSeverity.INFO,
        }
        return mapping.get(severity.lower(), IncidentSeverity.MEDIUM)

    def _calculate_incident_severity(self, incident: Incident) -> IncidentSeverity:
        """Calculate incident severity based on alerts and progression."""
        # Base severity from highest alert severity
        severity_order = [
            IncidentSeverity.INFO,
            IncidentSeverity.LOW,
            IncidentSeverity.MEDIUM,
            IncidentSeverity.HIGH,
            IncidentSeverity.CRITICAL
        ]

        max_severity = IncidentSeverity.INFO
        for entry in incident.timeline:
            entry_severity = self._map_severity(entry.severity)
            if severity_order.index(entry_severity) > severity_order.index(max_severity):
                max_severity = entry_severity

        # Escalate based on factors
        severity_index = severity_order.index(max_severity)

        # Multiple alerts escalate severity
        if incident.alert_count >= 5:
            severity_index = min(severity_index + 1, len(severity_order) - 1)

        # Kill chain progression escalates severity
        if len(incident.mitre_tactics) >= 3:
            severity_index = min(severity_index + 1, len(severity_order) - 1)

        # Late-stage kill chain is always high+
        late_stage_tactics = ["exfiltration", "impact", "command-and-control"]
        if any(t in incident.mitre_tactics for t in late_stage_tactics):
            severity_index = max(severity_index, severity_order.index(IncidentSeverity.HIGH))

        return severity_order[severity_index]

    def _determine_kill_chain_stage(self, tactics: List[str]) -> Optional[str]:
        """Determine the furthest kill chain stage reached."""
        if not tactics:
            return None

        tactics_lower = [t.lower().replace(" ", "-") for t in tactics]

        furthest_index = -1
        furthest_stage = None

        for tactic in tactics_lower:
            if tactic in self.config.kill_chain_order:
                index = self.config.kill_chain_order.index(tactic)
                if index > furthest_index:
                    furthest_index = index
                    furthest_stage = tactic

        return furthest_stage

    def _generate_incident_title(
        self,
        alert: Dict[str, Any],
        entities: Dict[str, Set[str]],
        correlation_types: List[str]
    ) -> str:
        """Generate a descriptive incident title."""
        parts = []

        # Entity-based title
        if entities["users"]:
            user = next(iter(entities["users"]))
            parts.append(f"Activity by {user}")
        elif entities["ips"]:
            ip = next(iter(entities["ips"]))
            parts.append(f"Activity from {ip}")
        elif entities["assets"]:
            asset = next(iter(entities["assets"]))
            parts.append(f"Activity on {asset}")
        else:
            parts.append("Correlated Security Activity")

        # Add correlation context
        if CorrelationType.KILL_CHAIN.value in correlation_types:
            parts.append("(potential attack progression)")

        return " ".join(parts)

    def _generate_summary(self, incident: Incident) -> str:
        """Generate a summary of the incident."""
        parts = []

        parts.append(f"Incident involving {incident.alert_count} related alerts")

        if incident.users:
            parts.append(f"affecting user(s): {', '.join(incident.users[:3])}")
        if incident.source_ips:
            parts.append(f"from IP(s): {', '.join(incident.source_ips[:3])}")
        if incident.assets:
            parts.append(f"on asset(s): {', '.join(incident.assets[:3])}")

        if incident.mitre_tactics:
            parts.append(f"MITRE tactics observed: {', '.join(incident.mitre_tactics)}")

        if incident.kill_chain_stage:
            parts.append(f"Furthest kill chain stage: {incident.kill_chain_stage}")

        return ". ".join(parts) + "."

    def _generate_recommendations(self, incident: Incident) -> List[str]:
        """Generate response recommendations based on incident characteristics."""
        recommendations = []

        # Based on severity
        if incident.severity == IncidentSeverity.CRITICAL:
            recommendations.append("Immediately escalate to incident response team")
            recommendations.append("Consider isolating affected systems")

        # Based on kill chain stage
        if incident.kill_chain_stage in ["exfiltration", "impact"]:
            recommendations.append("Check for data loss or system damage")
            recommendations.append("Preserve forensic evidence")
        elif incident.kill_chain_stage in ["credential-access", "privilege-escalation"]:
            recommendations.append("Review and rotate potentially compromised credentials")
            recommendations.append("Check for unauthorized access")
        elif incident.kill_chain_stage == "lateral-movement":
            recommendations.append("Map extent of lateral movement")
            recommendations.append("Identify all affected systems")

        # Based on entities
        if incident.users:
            recommendations.append(f"Review activity history for: {', '.join(incident.users[:2])}")
        if incident.source_ips:
            recommendations.append(f"Block or investigate IPs: {', '.join(incident.source_ips[:2])}")

        # Generic
        if not recommendations:
            recommendations.append("Review alert details and assess risk")
            recommendations.append("Determine if activity is authorized")

        return recommendations

    def cleanup_old_indices(self, max_age_hours: int = 24) -> int:
        """Remove old entries from correlation indices."""
        cutoff = datetime.utcnow() - timedelta(hours=max_age_hours)
        removed = 0

        for index in [self._ip_index, self._user_index, self._asset_index]:
            for key in list(index.keys()):
                index[key] = [
                    entry for entry in index[key]
                    if self._parse_timestamp(entry["timestamp"]) > cutoff
                ]
                if not index[key]:
                    del index[key]
                    removed += 1

        return removed


def correlate_alerts(
    alerts: List[Dict[str, Any]],
    config: Optional[CorrelationConfig] = None
) -> List[Incident]:
    """Convenience function to correlate a batch of alerts."""
    correlator = AlertCorrelator(config)
    return correlator.correlate_batch(alerts)
