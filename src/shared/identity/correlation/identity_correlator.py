"""Identity-specific alert correlation engine.

Extends the base AlertCorrelator with identity-focused correlation rules
for detecting attack chains, account takeovers, and lateral movement.
"""

import logging
import hashlib
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Set, Tuple

from ...alerting.correlation import (
    AlertCorrelator,
    CorrelationConfig,
    CorrelationType,
    Incident,
    IncidentSeverity,
    TimelineEntry,
)
from .identity_incident import (
    IdentityAttackType,
    IdentityCorrelationType,
    IdentityIncident,
    IDENTITY_ATTACK_STAGES,
    ATTACK_TYPE_STAGES,
    create_identity_incident,
)

logger = logging.getLogger(__name__)


# MITRE ATT&CK technique to attack type mapping
MITRE_TO_ATTACK_TYPE: Dict[str, IdentityAttackType] = {
    # Credential attacks
    "T1110": IdentityAttackType.BRUTE_FORCE,
    "T1110.001": IdentityAttackType.BRUTE_FORCE,  # Guessing
    "T1110.002": IdentityAttackType.BRUTE_FORCE,  # Cracking
    "T1110.003": IdentityAttackType.PASSWORD_SPRAY,
    "T1110.004": IdentityAttackType.CREDENTIAL_STUFFING,
    # Valid accounts
    "T1078": IdentityAttackType.ACCOUNT_TAKEOVER,
    "T1078.001": IdentityAttackType.ACCOUNT_TAKEOVER,  # Default accounts
    "T1078.002": IdentityAttackType.ACCOUNT_TAKEOVER,  # Domain accounts
    "T1078.004": IdentityAttackType.ACCOUNT_TAKEOVER,  # Cloud accounts
    # Privilege escalation
    "T1098": IdentityAttackType.PRIVILEGE_ESCALATION,  # Account manipulation
    "T1098.001": IdentityAttackType.PRIVILEGE_ESCALATION,  # Additional cloud credentials
    "T1098.003": IdentityAttackType.PRIVILEGE_ESCALATION,  # Additional cloud roles
    # Session/token attacks
    "T1539": IdentityAttackType.SESSION_HIJACK,  # Steal web session cookie
    "T1550": IdentityAttackType.SESSION_HIJACK,  # Use alternate auth material
    "T1550.001": IdentityAttackType.TOKEN_THEFT,  # Application access token
    "T1528": IdentityAttackType.TOKEN_THEFT,  # Steal application access token
    # MFA attacks
    "T1111": IdentityAttackType.MFA_BYPASS,  # MFA interception
    "T1621": IdentityAttackType.MFA_FATIGUE,  # MFA request generation
    # Lateral movement
    "T1021": IdentityAttackType.LATERAL_MOVEMENT,  # Remote services
}

# Alert rule patterns to attack type mapping
RULE_PATTERN_TO_ATTACK_TYPE: Dict[str, IdentityAttackType] = {
    "brute_force": IdentityAttackType.BRUTE_FORCE,
    "brute-force": IdentityAttackType.BRUTE_FORCE,
    "credential_stuffing": IdentityAttackType.CREDENTIAL_STUFFING,
    "credential-stuffing": IdentityAttackType.CREDENTIAL_STUFFING,
    "password_spray": IdentityAttackType.PASSWORD_SPRAY,
    "password-spray": IdentityAttackType.PASSWORD_SPRAY,
    "mfa_bypass": IdentityAttackType.MFA_BYPASS,
    "mfa-bypass": IdentityAttackType.MFA_BYPASS,
    "mfa_fatigue": IdentityAttackType.MFA_FATIGUE,
    "mfa-fatigue": IdentityAttackType.MFA_FATIGUE,
    "impossible_travel": IdentityAttackType.IMPOSSIBLE_TRAVEL,
    "impossible-travel": IdentityAttackType.IMPOSSIBLE_TRAVEL,
    "privilege": IdentityAttackType.PRIVILEGE_ESCALATION,
    "admin_grant": IdentityAttackType.PRIVILEGE_ESCALATION,
    "session_hijack": IdentityAttackType.SESSION_HIJACK,
    "session-hijack": IdentityAttackType.SESSION_HIJACK,
    "token_theft": IdentityAttackType.TOKEN_THEFT,
    "token-theft": IdentityAttackType.TOKEN_THEFT,
    "oauth": IdentityAttackType.TOKEN_THEFT,
    "illicit_consent": IdentityAttackType.TOKEN_THEFT,
    "dormant": IdentityAttackType.DORMANT_ACTIVATION,
    "lateral": IdentityAttackType.LATERAL_MOVEMENT,
}


@dataclass
class IdentityCorrelationConfig(CorrelationConfig):
    """Extended configuration for identity correlation."""

    # Identity-specific time windows
    identity_correlation_window_hours: int = 4
    attack_chain_window_hours: int = 24
    takeover_window_hours: int = 8

    # Thresholds
    min_alerts_for_takeover: int = 3
    takeover_confidence_threshold: float = 0.7

    # Identity-specific field mappings
    identity_user_fields: List[str] = field(default_factory=lambda: [
        "user_email", "userPrincipalName", "actor.email", "actor.user",
        "principal.email", "target.email", "subject.email"
    ])
    provider_fields: List[str] = field(default_factory=lambda: [
        "provider", "identity_provider", "source_provider"
    ])

    # Correlation scoring weights
    same_user_weight: float = 0.5
    same_ip_weight: float = 0.4
    time_proximity_weight: float = 0.3
    related_mitre_weight: float = 0.2
    same_provider_weight: float = 0.1


class IdentityCorrelator(AlertCorrelator):
    """
    Identity-specific alert correlator.

    Extends AlertCorrelator with identity attack chain detection,
    account takeover identification, and cross-provider correlation.
    """

    def __init__(
        self,
        config: Optional[IdentityCorrelationConfig] = None
    ):
        """
        Initialize identity correlator.

        Args:
            config: Identity correlation configuration
        """
        self.identity_config = config or IdentityCorrelationConfig()
        super().__init__(self.identity_config)

        # Identity-specific indices
        self._user_attack_index: Dict[str, List[Dict]] = defaultdict(list)
        self._identity_incidents: Dict[str, IdentityIncident] = {}

    def correlate_identity_alerts(
        self,
        alerts: List[Dict[str, Any]],
        window_hours: int = 4
    ) -> List[IdentityIncident]:
        """
        Correlate alerts using identity-specific rules.

        Args:
            alerts: List of alerts to correlate
            window_hours: Time window for correlation

        Returns:
            List of IdentityIncident objects
        """
        if not alerts:
            return []

        # Sort alerts by timestamp
        sorted_alerts = sorted(
            alerts,
            key=lambda a: a.get("timestamp", "")
        )

        incidents: List[IdentityIncident] = []
        processed_alert_ids: Set[str] = set()

        # Group alerts by user
        user_alerts: Dict[str, List[Dict]] = defaultdict(list)
        for alert in sorted_alerts:
            user = self._extract_user(alert)
            if user:
                user_alerts[user].append(alert)

        # Process each user's alerts
        for user_email, user_alert_list in user_alerts.items():
            # Skip already processed alerts
            unprocessed = [
                a for a in user_alert_list
                if a.get("id", a.get("alert_id", "")) not in processed_alert_ids
            ]

            if not unprocessed:
                continue

            # Detect attack chains
            chain_incident = self.detect_attack_chain(unprocessed)
            if chain_incident:
                incidents.append(chain_incident)
                for a in unprocessed:
                    processed_alert_ids.add(a.get("id", a.get("alert_id", "")))
                continue

            # Detect account takeover
            takeover_incident = self.detect_account_takeover(user_email, unprocessed)
            if takeover_incident:
                incidents.append(takeover_incident)
                for a in unprocessed:
                    processed_alert_ids.add(a.get("id", a.get("alert_id", "")))
                continue

            # Group remaining by correlation score
            incident = self._correlate_by_score(unprocessed, window_hours)
            if incident:
                incidents.append(incident)
                for a in unprocessed:
                    processed_alert_ids.add(a.get("id", a.get("alert_id", "")))

        # Store incidents
        for incident in incidents:
            self._identity_incidents[incident.incident_id] = incident

        return incidents

    def detect_attack_chain(
        self,
        alerts: List[Dict[str, Any]]
    ) -> Optional[IdentityIncident]:
        """
        Look for progression through attack stages.

        Detects patterns like:
        - Credential attacks -> successful auth
        - Successful auth from anomaly -> privilege grant
        - Privilege grant -> data access

        Args:
            alerts: List of alerts to analyze

        Returns:
            IdentityIncident if chain detected, None otherwise
        """
        if len(alerts) < 2:
            return None

        # Sort by timestamp
        sorted_alerts = sorted(
            alerts,
            key=lambda a: a.get("timestamp", "")
        )

        # Classify alerts by attack type
        classified: List[Tuple[Dict, IdentityAttackType, str]] = []
        for alert in sorted_alerts:
            attack_type = self._classify_attack_type(alert)
            stage = ATTACK_TYPE_STAGES.get(attack_type, "unknown")
            classified.append((alert, attack_type, stage))

        # Look for progression through stages
        chain_stages = []
        for alert, attack_type, stage in classified:
            if stage in IDENTITY_ATTACK_STAGES:
                stage_index = IDENTITY_ATTACK_STAGES.index(stage)
                chain_stages.append((stage_index, stage, alert, attack_type))

        if not chain_stages:
            return None

        # Sort by stage index
        chain_stages.sort(key=lambda x: (x[0], x[2].get("timestamp", "")))

        # Check for meaningful progression (at least 2 different stages)
        unique_stages = set(s[1] for s in chain_stages)
        if len(unique_stages) < 2:
            return None

        # Detect specific patterns

        # Pattern 1: Credential attack -> Initial access
        credential_to_access = self._detect_credential_to_access(chain_stages)
        if credential_to_access:
            return credential_to_access

        # Pattern 2: Initial access -> Privilege escalation
        access_to_privilege = self._detect_access_to_privilege(chain_stages)
        if access_to_privilege:
            return access_to_privilege

        # Pattern 3: Full chain (credential -> access -> privilege)
        full_chain = self._detect_full_chain(chain_stages)
        if full_chain:
            return full_chain

        return None

    def _detect_credential_to_access(
        self,
        chain_stages: List[Tuple[int, str, Dict, IdentityAttackType]]
    ) -> Optional[IdentityIncident]:
        """Detect credential attack followed by successful access."""
        credential_stage = None
        access_stage = None

        for stage_idx, stage, alert, attack_type in chain_stages:
            if stage == "credential_attack":
                credential_stage = (stage, alert, attack_type)
            elif stage == "initial_access" and credential_stage:
                access_stage = (stage, alert, attack_type)
                break

        if credential_stage and access_stage:
            # Create incident
            user = self._extract_user(access_stage[1])
            ips = self._extract_ips([credential_stage[1], access_stage[1]])

            incident = create_identity_incident(
                incident_id=self._generate_incident_id(),
                title=f"Credential Attack Followed by Access: {user or 'Unknown'}",
                severity=IncidentSeverity.CRITICAL,
                attack_type=IdentityAttackType.ACCOUNT_TAKEOVER,
                target_users=[user] if user else [],
                attacker_ips=ips,
            )

            # Add chain entries
            incident.add_to_attack_chain(
                "credential_attack",
                credential_stage[1].get("id", ""),
                f"{credential_stage[2].value} attack detected",
                credential_stage[1].get("timestamp", ""),
            )
            incident.add_to_attack_chain(
                "initial_access",
                access_stage[1].get("id", ""),
                "Successful authentication after credential attack",
                access_stage[1].get("timestamp", ""),
            )

            # Add alerts to timeline
            self._add_alert_to_identity_incident(incident, credential_stage[1])
            self._add_alert_to_identity_incident(incident, access_stage[1])

            incident.correlation_types.append(
                IdentityCorrelationType.CREDENTIAL_ATTACK_CHAIN.value
            )
            incident.takeover_confidence = 0.8
            incident.compromise_confirmed = True

            return incident

        return None

    def _detect_access_to_privilege(
        self,
        chain_stages: List[Tuple[int, str, Dict, IdentityAttackType]]
    ) -> Optional[IdentityIncident]:
        """Detect initial access followed by privilege escalation."""
        access_stage = None
        privilege_stage = None

        for stage_idx, stage, alert, attack_type in chain_stages:
            if stage == "initial_access":
                access_stage = (stage, alert, attack_type)
            elif stage == "privilege_escalation" and access_stage:
                privilege_stage = (stage, alert, attack_type)
                break

        if access_stage and privilege_stage:
            user = self._extract_user(privilege_stage[1])
            ips = self._extract_ips([access_stage[1], privilege_stage[1]])

            incident = create_identity_incident(
                incident_id=self._generate_incident_id(),
                title=f"Suspicious Access with Privilege Escalation: {user or 'Unknown'}",
                severity=IncidentSeverity.CRITICAL,
                attack_type=IdentityAttackType.PRIVILEGE_ESCALATION,
                target_users=[user] if user else [],
                attacker_ips=ips,
            )

            incident.add_to_attack_chain(
                "initial_access",
                access_stage[1].get("id", ""),
                f"Suspicious access: {access_stage[2].value}",
                access_stage[1].get("timestamp", ""),
            )
            incident.add_to_attack_chain(
                "privilege_escalation",
                privilege_stage[1].get("id", ""),
                "Privilege escalation after suspicious access",
                privilege_stage[1].get("timestamp", ""),
            )

            self._add_alert_to_identity_incident(incident, access_stage[1])
            self._add_alert_to_identity_incident(incident, privilege_stage[1])

            incident.correlation_types.append(
                IdentityCorrelationType.PRIVILEGE_CHAIN.value
            )
            incident.takeover_confidence = 0.9

            return incident

        return None

    def _detect_full_chain(
        self,
        chain_stages: List[Tuple[int, str, Dict, IdentityAttackType]]
    ) -> Optional[IdentityIncident]:
        """Detect full attack chain: credential -> access -> privilege/lateral."""
        credential = None
        access = None
        escalation = None

        for stage_idx, stage, alert, attack_type in chain_stages:
            if stage == "credential_attack" and not credential:
                credential = (stage, alert, attack_type)
            elif stage == "initial_access" and not access:
                access = (stage, alert, attack_type)
            elif stage in ["privilege_escalation", "lateral_movement"] and not escalation:
                escalation = (stage, alert, attack_type)

        if credential and access and escalation:
            user = self._extract_user(access[1])
            ips = self._extract_ips([credential[1], access[1], escalation[1]])

            incident = create_identity_incident(
                incident_id=self._generate_incident_id(),
                title=f"Complete Attack Chain Detected: {user or 'Unknown'}",
                severity=IncidentSeverity.CRITICAL,
                attack_type=IdentityAttackType.ACCOUNT_TAKEOVER,
                target_users=[user] if user else [],
                attacker_ips=ips,
            )

            incident.add_to_attack_chain(
                "credential_attack",
                credential[1].get("id", ""),
                f"{credential[2].value} attack",
                credential[1].get("timestamp", ""),
            )
            incident.add_to_attack_chain(
                "initial_access",
                access[1].get("id", ""),
                "Successful authentication",
                access[1].get("timestamp", ""),
            )
            incident.add_to_attack_chain(
                escalation[0],
                escalation[1].get("id", ""),
                f"{escalation[2].value}",
                escalation[1].get("timestamp", ""),
            )

            self._add_alert_to_identity_incident(incident, credential[1])
            self._add_alert_to_identity_incident(incident, access[1])
            self._add_alert_to_identity_incident(incident, escalation[1])

            incident.correlation_types.append(
                IdentityCorrelationType.ACCOUNT_TAKEOVER_CHAIN.value
            )
            incident.chain_complete = True
            incident.takeover_confidence = 0.95
            incident.mark_compromised(0.95)

            return incident

        return None

    def detect_account_takeover(
        self,
        user_email: str,
        alerts: List[Dict[str, Any]]
    ) -> Optional[IdentityIncident]:
        """
        Detect potential account takeover for a user.

        Multiple anomalies + privilege changes = takeover.

        Args:
            user_email: Target user email
            alerts: Alerts related to this user

        Returns:
            IdentityIncident if takeover detected, None otherwise
        """
        if len(alerts) < self.identity_config.min_alerts_for_takeover:
            return None

        # Classify alerts
        anomaly_count = 0
        privilege_change = False
        session_compromise = False
        credential_attack = False

        classified_alerts = []
        for alert in alerts:
            attack_type = self._classify_attack_type(alert)
            classified_alerts.append((alert, attack_type))

            if attack_type in [
                IdentityAttackType.IMPOSSIBLE_TRAVEL,
                IdentityAttackType.DORMANT_ACTIVATION,
            ]:
                anomaly_count += 1

            if attack_type == IdentityAttackType.PRIVILEGE_ESCALATION:
                privilege_change = True

            if attack_type in [
                IdentityAttackType.SESSION_HIJACK,
                IdentityAttackType.TOKEN_THEFT,
            ]:
                session_compromise = True

            if attack_type in [
                IdentityAttackType.BRUTE_FORCE,
                IdentityAttackType.CREDENTIAL_STUFFING,
                IdentityAttackType.PASSWORD_SPRAY,
            ]:
                credential_attack = True

        # Calculate takeover indicators
        indicators = 0
        if anomaly_count >= 2:
            indicators += 1
        if privilege_change:
            indicators += 2  # Strong indicator
        if session_compromise:
            indicators += 2  # Strong indicator
        if credential_attack:
            indicators += 1

        # Need sufficient indicators
        if indicators < 2:
            return None

        # Create incident
        ips = self._extract_ips(alerts)

        incident = create_identity_incident(
            incident_id=self._generate_incident_id(),
            title=f"Potential Account Takeover: {user_email}",
            severity=IncidentSeverity.CRITICAL,
            attack_type=IdentityAttackType.ACCOUNT_TAKEOVER,
            target_users=[user_email],
            attacker_ips=ips,
        )

        # Add all alerts
        for alert, attack_type in classified_alerts:
            self._add_alert_to_identity_incident(incident, alert)
            stage = ATTACK_TYPE_STAGES.get(attack_type, "unknown")
            incident.add_to_attack_chain(
                stage,
                alert.get("id", alert.get("alert_id", "")),
                f"{attack_type.value}: {alert.get('title', 'Alert')}",
                alert.get("timestamp", ""),
            )

        incident.correlation_types.append(
            IdentityCorrelationType.ACCOUNT_TAKEOVER_CHAIN.value
        )

        # Calculate confidence
        confidence = incident.calculate_takeover_confidence()

        # Additional confidence factors
        if privilege_change:
            confidence += 0.15
        if session_compromise:
            confidence += 0.15

        confidence = min(confidence, 1.0)
        incident.takeover_confidence = confidence

        if confidence >= self.identity_config.takeover_confidence_threshold:
            incident.mark_compromised(confidence)

        return incident

    def calculate_correlation_score(
        self,
        alert1: Dict[str, Any],
        alert2: Dict[str, Any]
    ) -> float:
        """
        Calculate how related two alerts are.

        Scoring:
        - Same user: +0.5
        - Same IP: +0.4
        - Same time window: +0.3
        - Related MITRE technique: +0.2
        - Same provider: +0.1

        Args:
            alert1: First alert
            alert2: Second alert

        Returns:
            Correlation score between 0.0 and 1.0+
        """
        score = 0.0

        # Same user
        user1 = self._extract_user(alert1)
        user2 = self._extract_user(alert2)
        if user1 and user2 and user1.lower() == user2.lower():
            score += self.identity_config.same_user_weight

        # Same IP
        ips1 = set(self._extract_ips([alert1]))
        ips2 = set(self._extract_ips([alert2]))
        if ips1 & ips2:  # Intersection
            score += self.identity_config.same_ip_weight

        # Time proximity (within 1 hour = full points)
        time1 = self._parse_timestamp(alert1.get("timestamp", ""))
        time2 = self._parse_timestamp(alert2.get("timestamp", ""))
        time_diff = abs((time1 - time2).total_seconds())

        if time_diff <= 3600:  # 1 hour
            score += self.identity_config.time_proximity_weight
        elif time_diff <= 14400:  # 4 hours
            score += self.identity_config.time_proximity_weight * 0.5
        elif time_diff <= 86400:  # 24 hours
            score += self.identity_config.time_proximity_weight * 0.2

        # Related MITRE techniques
        mitre1 = alert1.get("mitre_attack", {})
        mitre2 = alert2.get("mitre_attack", {})
        if mitre1 and mitre2:
            tactic1 = mitre1.get("tactic", "")
            tactic2 = mitre2.get("tactic", "")
            tech1 = mitre1.get("technique", "")
            tech2 = mitre2.get("technique", "")

            if tactic1 == tactic2:
                score += self.identity_config.related_mitre_weight
            elif tech1[:5] == tech2[:5]:  # Same technique family
                score += self.identity_config.related_mitre_weight * 0.5

        # Same provider
        provider1 = self._extract_provider(alert1)
        provider2 = self._extract_provider(alert2)
        if provider1 and provider2 and provider1 == provider2:
            score += self.identity_config.same_provider_weight

        return score

    def _correlate_by_score(
        self,
        alerts: List[Dict[str, Any]],
        window_hours: int
    ) -> Optional[IdentityIncident]:
        """Correlate alerts by score when no specific chain detected."""
        if len(alerts) < 2:
            return None

        # Calculate pairwise scores
        high_correlation = False
        total_score = 0.0

        for i, alert1 in enumerate(alerts):
            for alert2 in alerts[i + 1:]:
                score = self.calculate_correlation_score(alert1, alert2)
                total_score += score
                if score >= 0.6:
                    high_correlation = True

        # Average score
        num_pairs = len(alerts) * (len(alerts) - 1) / 2
        avg_score = total_score / num_pairs if num_pairs > 0 else 0

        if not high_correlation and avg_score < 0.4:
            return None

        # Determine primary attack type
        attack_types = [self._classify_attack_type(a) for a in alerts]
        primary_type = max(set(attack_types), key=attack_types.count)

        user = self._extract_user(alerts[0])
        ips = self._extract_ips(alerts)

        incident = create_identity_incident(
            incident_id=self._generate_incident_id(),
            title=f"Correlated Identity Activity: {user or 'Unknown'}",
            severity=self._determine_severity(alerts),
            attack_type=primary_type,
            target_users=[user] if user else [],
            attacker_ips=ips,
        )

        for alert in alerts:
            self._add_alert_to_identity_incident(incident, alert)

        incident.correlation_types.append(
            IdentityCorrelationType.SAME_TARGET_USER.value
        )
        incident.correlation_score = avg_score

        return incident

    def _extract_user(self, alert: Dict[str, Any]) -> Optional[str]:
        """Extract user email from alert."""
        for field in self.identity_config.identity_user_fields:
            value = self._get_nested_field(alert, field)
            if value:
                if isinstance(value, str):
                    return value
                elif isinstance(value, dict):
                    for subfield in ["email", "userName", "id"]:
                        if subfield in value:
                            return str(value[subfield])
        return None

    def _extract_ips(self, alerts: List[Dict[str, Any]]) -> List[str]:
        """Extract unique IPs from alerts."""
        ips = set()
        for alert in alerts:
            for field in self.config.ip_fields:
                value = self._get_nested_field(alert, field)
                if value and isinstance(value, str):
                    ips.add(value)
        return list(ips)

    def _extract_provider(self, alert: Dict[str, Any]) -> Optional[str]:
        """Extract identity provider from alert."""
        for field in self.identity_config.provider_fields:
            value = self._get_nested_field(alert, field)
            if value and isinstance(value, str):
                return value
        return None

    def _classify_attack_type(self, alert: Dict[str, Any]) -> IdentityAttackType:
        """Classify alert into attack type."""
        # Check MITRE technique first
        mitre = alert.get("mitre_attack", {})
        technique = mitre.get("technique", "")
        if technique and technique in MITRE_TO_ATTACK_TYPE:
            return MITRE_TO_ATTACK_TYPE[technique]

        # Check rule name patterns
        rule_name = alert.get("rule_name", "").lower()
        rule_id = alert.get("rule_id", "").lower()
        title = alert.get("title", "").lower()

        for pattern, attack_type in RULE_PATTERN_TO_ATTACK_TYPE.items():
            if pattern in rule_name or pattern in rule_id or pattern in title:
                return attack_type

        # Check custom fields
        custom = alert.get("custom", {})
        if isinstance(custom, dict):
            subcategory = custom.get("itdr_subcategory", "")
            for pattern, attack_type in RULE_PATTERN_TO_ATTACK_TYPE.items():
                if pattern in subcategory:
                    return attack_type

        return IdentityAttackType.UNKNOWN

    def _add_alert_to_identity_incident(
        self,
        incident: IdentityIncident,
        alert: Dict[str, Any]
    ) -> None:
        """Add an alert to an identity incident."""
        alert_id = alert.get("id", alert.get("alert_id", ""))
        timestamp = alert.get("timestamp", datetime.utcnow().isoformat())

        if alert_id in incident.alert_ids:
            return

        # Extract entities
        entities = self._extract_entities(alert)

        # Add to base incident
        incident.alert_ids.append(alert_id)
        incident.alert_count = len(incident.alert_ids)

        # Update timing
        if not incident.first_seen or timestamp < incident.first_seen:
            incident.first_seen = timestamp
        if not incident.last_seen or timestamp > incident.last_seen:
            incident.last_seen = timestamp

        # Update entities
        for ip in entities["ips"]:
            if ip not in incident.source_ips:
                incident.source_ips.append(ip)
            if ip not in incident.attacker_ips:
                incident.attacker_ips.append(ip)

        for user in entities["users"]:
            if user not in incident.users:
                incident.users.append(user)
            if user not in incident.target_users:
                incident.target_users.append(user)

        # Add provider
        provider = self._extract_provider(alert)
        if provider and provider not in incident.affected_providers:
            incident.affected_providers.append(provider)

        # Update MITRE
        mitre = alert.get("mitre_attack", {})
        if mitre:
            tactic = mitre.get("tactic", "")
            technique = mitre.get("technique", "")
            if tactic and tactic not in incident.mitre_tactics:
                incident.mitre_tactics.append(tactic)
            if technique and technique not in incident.mitre_techniques:
                incident.mitre_techniques.append(technique)

        # Add timeline entry
        entry = TimelineEntry(
            timestamp=timestamp,
            alert_id=alert_id,
            rule_name=alert.get("rule_name", "Unknown"),
            severity=alert.get("severity", "medium"),
            title=alert.get("title", "Alert"),
            entities={
                "ips": list(entities["ips"]),
                "users": list(entities["users"]),
            },
            mitre_attack=mitre if mitre else None,
        )
        incident.timeline.append(entry)
        incident.timeline.sort(key=lambda t: t.timestamp)

        # Update unique rules
        rule_names = set(t.rule_name for t in incident.timeline)
        incident.unique_rules = len(rule_names)

    def _determine_severity(
        self,
        alerts: List[Dict[str, Any]]
    ) -> IncidentSeverity:
        """Determine severity from alerts."""
        severity_order = [
            IncidentSeverity.INFO,
            IncidentSeverity.LOW,
            IncidentSeverity.MEDIUM,
            IncidentSeverity.HIGH,
            IncidentSeverity.CRITICAL,
        ]

        max_severity = IncidentSeverity.INFO

        for alert in alerts:
            severity_str = alert.get("severity", "medium").lower()
            severity = self._map_severity(severity_str)
            if severity_order.index(severity) > severity_order.index(max_severity):
                max_severity = severity

        # Escalate for multiple alerts
        if len(alerts) >= 5:
            idx = min(
                severity_order.index(max_severity) + 1,
                len(severity_order) - 1
            )
            max_severity = severity_order[idx]

        return max_severity

    def _generate_incident_id(self) -> str:
        """Generate unique incident ID."""
        now = datetime.utcnow().isoformat()
        return f"IDNT-{hashlib.md5(now.encode()).hexdigest()[:12].upper()}"

    def get_identity_incident(
        self,
        incident_id: str
    ) -> Optional[IdentityIncident]:
        """Get identity incident by ID."""
        return self._identity_incidents.get(incident_id)

    def get_incidents_for_user(
        self,
        user_email: str,
        max_age_hours: int = 168  # 7 days
    ) -> List[IdentityIncident]:
        """Get all incidents involving a user."""
        cutoff = (datetime.utcnow() - timedelta(hours=max_age_hours)).isoformat()
        incidents = []

        for incident in self._identity_incidents.values():
            if user_email.lower() in [u.lower() for u in incident.target_users]:
                if incident.last_seen >= cutoff:
                    incidents.append(incident)

        return sorted(incidents, key=lambda i: i.last_seen, reverse=True)

    def get_active_takeovers(self) -> List[IdentityIncident]:
        """Get all active account takeover incidents."""
        return [
            i for i in self._identity_incidents.values()
            if i.status == "open"
            and i.attack_type == IdentityAttackType.ACCOUNT_TAKEOVER
            and i.compromise_confirmed
        ]


def correlate_identity_alerts(
    alerts: List[Dict[str, Any]],
    config: Optional[IdentityCorrelationConfig] = None
) -> List[IdentityIncident]:
    """Convenience function to correlate identity alerts."""
    correlator = IdentityCorrelator(config)
    return correlator.correlate_identity_alerts(alerts)
