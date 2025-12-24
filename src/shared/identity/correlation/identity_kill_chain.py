"""Identity attack kill chain detection.

Detects progression through identity-specific attack kill chain stages,
which differs from the generic MITRE ATT&CK framework by focusing on
identity-centric attack patterns.

Identity Kill Chain Stages:
1. Reconnaissance - Low-volume probing, password enumeration
2. Credential Attack - Brute force, stuffing, spray
3. Initial Access - Successful auth after attack
4. Defense Evasion - MFA bypass, token theft
5. Privilege Escalation - Admin grants, role manipulation
6. Persistence - New tokens, new MFA devices
7. Lateral Movement - Accessing other accounts/systems
8. Objectives - Data access, exfiltration indicators
"""

import logging
import hashlib
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple

from ...alerting.correlation import IncidentSeverity, TimelineEntry
from .identity_incident import (
    IdentityAttackType,
    IdentityIncident,
    create_identity_incident,
)

logger = logging.getLogger(__name__)


class IdentityKillChainStage(Enum):
    """Identity-specific kill chain stages."""

    RECONNAISSANCE = "reconnaissance"
    CREDENTIAL_ATTACK = "credential_attack"
    INITIAL_ACCESS = "initial_access"
    DEFENSE_EVASION = "defense_evasion"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    PERSISTENCE = "persistence"
    LATERAL_MOVEMENT = "lateral_movement"
    OBJECTIVES = "objectives"


# Ordered sequence of kill chain stages
KILL_CHAIN_SEQUENCE: List[IdentityKillChainStage] = [
    IdentityKillChainStage.RECONNAISSANCE,
    IdentityKillChainStage.CREDENTIAL_ATTACK,
    IdentityKillChainStage.INITIAL_ACCESS,
    IdentityKillChainStage.DEFENSE_EVASION,
    IdentityKillChainStage.PRIVILEGE_ESCALATION,
    IdentityKillChainStage.PERSISTENCE,
    IdentityKillChainStage.LATERAL_MOVEMENT,
    IdentityKillChainStage.OBJECTIVES,
]

# Map attack types to kill chain stages
ATTACK_TYPE_TO_STAGE: Dict[IdentityAttackType, IdentityKillChainStage] = {
    IdentityAttackType.PASSWORD_SPRAY: IdentityKillChainStage.CREDENTIAL_ATTACK,
    IdentityAttackType.BRUTE_FORCE: IdentityKillChainStage.CREDENTIAL_ATTACK,
    IdentityAttackType.CREDENTIAL_STUFFING: IdentityKillChainStage.CREDENTIAL_ATTACK,
    IdentityAttackType.ACCOUNT_TAKEOVER: IdentityKillChainStage.INITIAL_ACCESS,
    IdentityAttackType.SESSION_HIJACK: IdentityKillChainStage.INITIAL_ACCESS,
    IdentityAttackType.DORMANT_ACTIVATION: IdentityKillChainStage.INITIAL_ACCESS,
    IdentityAttackType.IMPOSSIBLE_TRAVEL: IdentityKillChainStage.INITIAL_ACCESS,
    IdentityAttackType.MFA_BYPASS: IdentityKillChainStage.DEFENSE_EVASION,
    IdentityAttackType.MFA_FATIGUE: IdentityKillChainStage.DEFENSE_EVASION,
    IdentityAttackType.TOKEN_THEFT: IdentityKillChainStage.DEFENSE_EVASION,
    IdentityAttackType.PRIVILEGE_ESCALATION: IdentityKillChainStage.PRIVILEGE_ESCALATION,
    IdentityAttackType.LATERAL_MOVEMENT: IdentityKillChainStage.LATERAL_MOVEMENT,
}

# Map MITRE ATT&CK techniques to kill chain stages
MITRE_TO_KILL_CHAIN: Dict[str, IdentityKillChainStage] = {
    # Reconnaissance
    "T1589": IdentityKillChainStage.RECONNAISSANCE,  # Gather victim identity info
    "T1589.001": IdentityKillChainStage.RECONNAISSANCE,  # Credentials
    "T1589.002": IdentityKillChainStage.RECONNAISSANCE,  # Email addresses
    "T1589.003": IdentityKillChainStage.RECONNAISSANCE,  # Employee names
    "T1591": IdentityKillChainStage.RECONNAISSANCE,  # Gather org info
    "T1598": IdentityKillChainStage.RECONNAISSANCE,  # Phishing for information
    # Credential attacks
    "T1110": IdentityKillChainStage.CREDENTIAL_ATTACK,
    "T1110.001": IdentityKillChainStage.CREDENTIAL_ATTACK,  # Password guessing
    "T1110.002": IdentityKillChainStage.CREDENTIAL_ATTACK,  # Password cracking
    "T1110.003": IdentityKillChainStage.CREDENTIAL_ATTACK,  # Password spraying
    "T1110.004": IdentityKillChainStage.CREDENTIAL_ATTACK,  # Credential stuffing
    # Initial access
    "T1078": IdentityKillChainStage.INITIAL_ACCESS,
    "T1078.001": IdentityKillChainStage.INITIAL_ACCESS,  # Default accounts
    "T1078.002": IdentityKillChainStage.INITIAL_ACCESS,  # Domain accounts
    "T1078.004": IdentityKillChainStage.INITIAL_ACCESS,  # Cloud accounts
    "T1199": IdentityKillChainStage.INITIAL_ACCESS,  # Trusted relationship
    # Defense evasion
    "T1111": IdentityKillChainStage.DEFENSE_EVASION,  # MFA interception
    "T1621": IdentityKillChainStage.DEFENSE_EVASION,  # MFA request generation
    "T1550": IdentityKillChainStage.DEFENSE_EVASION,  # Use alternate auth
    "T1550.001": IdentityKillChainStage.DEFENSE_EVASION,  # Application access token
    "T1539": IdentityKillChainStage.DEFENSE_EVASION,  # Steal web session cookie
    "T1528": IdentityKillChainStage.DEFENSE_EVASION,  # Steal app access token
    # Privilege escalation
    "T1098": IdentityKillChainStage.PRIVILEGE_ESCALATION,  # Account manipulation
    "T1098.001": IdentityKillChainStage.PRIVILEGE_ESCALATION,  # Additional cloud creds
    "T1098.003": IdentityKillChainStage.PRIVILEGE_ESCALATION,  # Additional cloud roles
    "T1098.005": IdentityKillChainStage.PRIVILEGE_ESCALATION,  # Device registration
    "T1134": IdentityKillChainStage.PRIVILEGE_ESCALATION,  # Access token manipulation
    # Persistence
    "T1136": IdentityKillChainStage.PERSISTENCE,  # Create account
    "T1136.003": IdentityKillChainStage.PERSISTENCE,  # Cloud account
    "T1098.002": IdentityKillChainStage.PERSISTENCE,  # Additional email delegate
    "T1556": IdentityKillChainStage.PERSISTENCE,  # Modify auth process
    # Lateral movement
    "T1021": IdentityKillChainStage.LATERAL_MOVEMENT,  # Remote services
    "T1021.001": IdentityKillChainStage.LATERAL_MOVEMENT,  # Remote desktop
    "T1021.004": IdentityKillChainStage.LATERAL_MOVEMENT,  # SSH
    "T1534": IdentityKillChainStage.LATERAL_MOVEMENT,  # Internal spearphishing
    # Objectives
    "T1530": IdentityKillChainStage.OBJECTIVES,  # Data from cloud storage
    "T1213": IdentityKillChainStage.OBJECTIVES,  # Data from information repos
    "T1567": IdentityKillChainStage.OBJECTIVES,  # Exfiltration over web service
}

# Rule patterns to kill chain stages
RULE_PATTERN_TO_STAGE: Dict[str, IdentityKillChainStage] = {
    # Reconnaissance
    "enumeration": IdentityKillChainStage.RECONNAISSANCE,
    "recon": IdentityKillChainStage.RECONNAISSANCE,
    "probe": IdentityKillChainStage.RECONNAISSANCE,
    "discovery": IdentityKillChainStage.RECONNAISSANCE,
    # Credential attacks
    "brute_force": IdentityKillChainStage.CREDENTIAL_ATTACK,
    "brute-force": IdentityKillChainStage.CREDENTIAL_ATTACK,
    "credential_stuffing": IdentityKillChainStage.CREDENTIAL_ATTACK,
    "password_spray": IdentityKillChainStage.CREDENTIAL_ATTACK,
    # Initial access
    "login_success": IdentityKillChainStage.INITIAL_ACCESS,
    "auth_success": IdentityKillChainStage.INITIAL_ACCESS,
    "account_takeover": IdentityKillChainStage.INITIAL_ACCESS,
    "impossible_travel": IdentityKillChainStage.INITIAL_ACCESS,
    "dormant": IdentityKillChainStage.INITIAL_ACCESS,
    # Defense evasion
    "mfa_bypass": IdentityKillChainStage.DEFENSE_EVASION,
    "mfa_fatigue": IdentityKillChainStage.DEFENSE_EVASION,
    "token_theft": IdentityKillChainStage.DEFENSE_EVASION,
    "session_hijack": IdentityKillChainStage.DEFENSE_EVASION,
    "oauth": IdentityKillChainStage.DEFENSE_EVASION,
    # Privilege escalation
    "privilege": IdentityKillChainStage.PRIVILEGE_ESCALATION,
    "admin_grant": IdentityKillChainStage.PRIVILEGE_ESCALATION,
    "role_assignment": IdentityKillChainStage.PRIVILEGE_ESCALATION,
    "escalation": IdentityKillChainStage.PRIVILEGE_ESCALATION,
    # Persistence
    "new_mfa": IdentityKillChainStage.PERSISTENCE,
    "mfa_enroll": IdentityKillChainStage.PERSISTENCE,
    "new_app": IdentityKillChainStage.PERSISTENCE,
    "api_key": IdentityKillChainStage.PERSISTENCE,
    "service_account": IdentityKillChainStage.PERSISTENCE,
    # Lateral movement
    "lateral": IdentityKillChainStage.LATERAL_MOVEMENT,
    "cross_account": IdentityKillChainStage.LATERAL_MOVEMENT,
    # Objectives
    "data_access": IdentityKillChainStage.OBJECTIVES,
    "exfiltration": IdentityKillChainStage.OBJECTIVES,
    "download": IdentityKillChainStage.OBJECTIVES,
    "export": IdentityKillChainStage.OBJECTIVES,
}

# Stage severity mapping
STAGE_SEVERITY: Dict[IdentityKillChainStage, str] = {
    IdentityKillChainStage.RECONNAISSANCE: "low",
    IdentityKillChainStage.CREDENTIAL_ATTACK: "medium",
    IdentityKillChainStage.INITIAL_ACCESS: "high",
    IdentityKillChainStage.DEFENSE_EVASION: "high",
    IdentityKillChainStage.PRIVILEGE_ESCALATION: "critical",
    IdentityKillChainStage.PERSISTENCE: "critical",
    IdentityKillChainStage.LATERAL_MOVEMENT: "critical",
    IdentityKillChainStage.OBJECTIVES: "critical",
}

# Recommended responses per stage
STAGE_RESPONSES: Dict[IdentityKillChainStage, str] = {
    IdentityKillChainStage.RECONNAISSANCE: (
        "Monitor: Increase logging for targeted accounts. "
        "Block known malicious IPs. Review authentication policies."
    ),
    IdentityKillChainStage.CREDENTIAL_ATTACK: (
        "Defend: Block attacking IPs. Enable account lockout. "
        "Enforce MFA. Alert security team for monitoring."
    ),
    IdentityKillChainStage.INITIAL_ACCESS: (
        "Respond: Verify user identity via alternate channel. "
        "If unverified, terminate sessions and reset credentials. "
        "Enable enhanced monitoring."
    ),
    IdentityKillChainStage.DEFENSE_EVASION: (
        "Contain: Investigate bypass method. Revoke tokens. "
        "Force MFA re-enrollment. Review OAuth consents. "
        "Escalate to incident response."
    ),
    IdentityKillChainStage.PRIVILEGE_ESCALATION: (
        "Contain: IMMEDIATELY revoke escalated privileges. "
        "Suspend account. Audit all administrative actions. "
        "Full incident response."
    ),
    IdentityKillChainStage.PERSISTENCE: (
        "Eradicate: Remove all persistence mechanisms. "
        "Revoke all tokens and API keys. Remove unauthorized MFA devices. "
        "Delete malicious accounts. Full audit required."
    ),
    IdentityKillChainStage.LATERAL_MOVEMENT: (
        "Isolate: Identify all compromised accounts. "
        "Suspend all affected identities. Reset all credentials. "
        "Network segmentation review. Full IR engagement."
    ),
    IdentityKillChainStage.OBJECTIVES: (
        "Critical: Data breach likely. Preserve evidence. "
        "Legal/compliance notification. Full forensic investigation. "
        "Business impact assessment. Disclosure requirements."
    ),
}


@dataclass
class KillChainIncident:
    """
    Represents a kill chain progression incident.

    Tracks observed stages, timeline, and predicted next steps.
    """

    incident_id: str
    title: str
    severity: str
    status: str = "open"

    # Kill chain specific
    stages_observed: List[IdentityKillChainStage] = field(default_factory=list)
    stage_timeline: List[Tuple[str, IdentityKillChainStage, str]] = field(
        default_factory=list
    )  # (timestamp, stage, alert_id)
    current_stage: IdentityKillChainStage = IdentityKillChainStage.RECONNAISSANCE
    predicted_next_stage: Optional[IdentityKillChainStage] = None

    # Progression analysis
    progression_velocity: float = 0.0  # stages per hour
    time_in_current_stage: float = 0.0  # hours
    stage_skip_detected: bool = False
    skipped_stages: List[IdentityKillChainStage] = field(default_factory=list)

    # Entities
    target_users: List[str] = field(default_factory=list)
    attacker_ips: List[str] = field(default_factory=list)
    affected_providers: List[str] = field(default_factory=list)

    # Related alerts
    alert_ids: List[str] = field(default_factory=list)
    alert_count: int = 0

    # Timing
    first_seen: str = ""
    last_seen: str = ""
    created_at: str = ""

    # Response
    recommended_response: str = ""
    response_urgency: str = "normal"  # normal, elevated, immediate

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "incident_id": self.incident_id,
            "title": self.title,
            "severity": self.severity,
            "status": self.status,
            "stages_observed": [s.value for s in self.stages_observed],
            "stage_timeline": [
                {"timestamp": t, "stage": s.value, "alert_id": a}
                for t, s, a in self.stage_timeline
            ],
            "current_stage": self.current_stage.value,
            "predicted_next_stage": (
                self.predicted_next_stage.value
                if self.predicted_next_stage
                else None
            ),
            "progression_velocity": self.progression_velocity,
            "time_in_current_stage": self.time_in_current_stage,
            "stage_skip_detected": self.stage_skip_detected,
            "skipped_stages": [s.value for s in self.skipped_stages],
            "target_users": self.target_users,
            "attacker_ips": self.attacker_ips,
            "affected_providers": self.affected_providers,
            "alert_ids": self.alert_ids,
            "alert_count": self.alert_count,
            "first_seen": self.first_seen,
            "last_seen": self.last_seen,
            "created_at": self.created_at,
            "recommended_response": self.recommended_response,
            "response_urgency": self.response_urgency,
        }


class KillChainDetector:
    """
    Detects progression through identity attack kill chain stages.

    Analyzes alerts to identify attack patterns that show progression
    through the kill chain, indicating an active intrusion attempt.
    """

    stage_sequence = KILL_CHAIN_SEQUENCE

    def __init__(self):
        """Initialize kill chain detector."""
        self._incidents: Dict[str, KillChainIncident] = {}

    def detect_kill_chain_progression(
        self,
        alerts: List[Dict[str, Any]],
        window_hours: int = 24
    ) -> List[KillChainIncident]:
        """
        Detect kill chain progression in alerts.

        Args:
            alerts: List of alerts to analyze
            window_hours: Time window for grouping alerts

        Returns:
            List of KillChainIncident objects for detected progressions
        """
        if not alerts:
            return []

        # Sort by timestamp
        sorted_alerts = sorted(
            alerts,
            key=lambda a: a.get("timestamp", "")
        )

        # Filter to window
        cutoff = datetime.utcnow() - timedelta(hours=window_hours)
        windowed_alerts = [
            a for a in sorted_alerts
            if self._parse_timestamp(a.get("timestamp", "")) >= cutoff
        ]

        if not windowed_alerts:
            return []

        # Group by user
        user_alerts: Dict[str, List[Dict]] = defaultdict(list)
        for alert in windowed_alerts:
            user = self._extract_user(alert)
            if user:
                user_alerts[user].append(alert)

        incidents: List[KillChainIncident] = []

        # Analyze each user's alerts for kill chain progression
        for user_email, user_alert_list in user_alerts.items():
            # Map alerts to stages
            staged_alerts: List[Tuple[Dict, IdentityKillChainStage]] = []
            for alert in user_alert_list:
                stage = self.map_alert_to_stage(alert)
                if stage:
                    staged_alerts.append((alert, stage))

            if len(staged_alerts) < 2:
                continue

            # Check for progression
            incident = self._analyze_progression(user_email, staged_alerts)
            if incident:
                incidents.append(incident)
                self._incidents[incident.incident_id] = incident

        return incidents

    def map_alert_to_stage(
        self,
        alert: Dict[str, Any]
    ) -> Optional[IdentityKillChainStage]:
        """
        Map an alert to a kill chain stage.

        Args:
            alert: Alert to classify

        Returns:
            Kill chain stage or None if not mappable
        """
        # Check MITRE technique first
        mitre = alert.get("mitre_attack", {})
        technique = mitre.get("technique", "")
        if technique in MITRE_TO_KILL_CHAIN:
            return MITRE_TO_KILL_CHAIN[technique]

        # Check attack type
        attack_type_str = alert.get("attack_type", "")
        if attack_type_str:
            try:
                attack_type = IdentityAttackType(attack_type_str)
                if attack_type in ATTACK_TYPE_TO_STAGE:
                    return ATTACK_TYPE_TO_STAGE[attack_type]
            except ValueError:
                pass

        # Check rule patterns
        rule_name = alert.get("rule_name", "").lower()
        rule_id = alert.get("rule_id", "").lower()
        title = alert.get("title", "").lower()

        for pattern, stage in RULE_PATTERN_TO_STAGE.items():
            if pattern in rule_name or pattern in rule_id or pattern in title:
                return stage

        # Check custom fields
        custom = alert.get("custom", {})
        if isinstance(custom, dict):
            subcategory = custom.get("itdr_subcategory", "").lower()
            for pattern, stage in RULE_PATTERN_TO_STAGE.items():
                if pattern in subcategory:
                    return stage

        return None

    def calculate_progression_severity(
        self,
        stages: List[IdentityKillChainStage]
    ) -> str:
        """
        Calculate severity based on stages observed.

        Args:
            stages: List of observed stages

        Returns:
            Severity string (low, medium, high, critical)
        """
        if not stages:
            return "low"

        # Get the furthest stage
        furthest_index = -1
        furthest_stage = None

        for stage in stages:
            if stage in KILL_CHAIN_SEQUENCE:
                idx = KILL_CHAIN_SEQUENCE.index(stage)
                if idx > furthest_index:
                    furthest_index = idx
                    furthest_stage = stage

        if furthest_stage:
            base_severity = STAGE_SEVERITY.get(furthest_stage, "medium")
        else:
            base_severity = "medium"

        # Escalate if multiple stages observed (indicates active progression)
        unique_stages = set(stages)
        if len(unique_stages) >= 3:
            severity_order = ["low", "medium", "high", "critical"]
            current_idx = severity_order.index(base_severity)
            return severity_order[min(current_idx + 1, 3)]

        return base_severity

    def detect_stage_skipping(
        self,
        alerts: List[Dict[str, Any]]
    ) -> Optional[Tuple[Dict[str, Any], List[IdentityKillChainStage]]]:
        """
        Detect if attacker skipped stages (insider threat indicator).

        For example, going straight to privilege escalation without
        credential attack or initial access stages.

        Args:
            alerts: List of alerts to analyze

        Returns:
            Tuple of (suspicious alert, skipped stages) or None
        """
        # Map alerts to stages
        staged_alerts: List[Tuple[Dict, IdentityKillChainStage, int]] = []
        for alert in alerts:
            stage = self.map_alert_to_stage(alert)
            if stage and stage in KILL_CHAIN_SEQUENCE:
                idx = KILL_CHAIN_SEQUENCE.index(stage)
                staged_alerts.append((alert, stage, idx))

        if len(staged_alerts) < 2:
            return None

        # Sort by timestamp
        staged_alerts.sort(key=lambda x: x[0].get("timestamp", ""))

        # Check for jumps (skipping 2+ stages)
        observed_indices = set()
        for alert, stage, idx in staged_alerts:
            # Check if this is a significant jump
            if observed_indices:
                min_observed = min(observed_indices)
                if idx > min_observed + 2:
                    # Significant skip detected
                    skipped = []
                    for skip_idx in range(min_observed + 1, idx):
                        skipped.append(KILL_CHAIN_SEQUENCE[skip_idx])
                    return (alert, skipped)

            observed_indices.add(idx)

        return None

    def get_expected_next_stages(
        self,
        current_stage: IdentityKillChainStage
    ) -> List[IdentityKillChainStage]:
        """
        Get expected next stages for predictive alerting.

        Args:
            current_stage: Current observed stage

        Returns:
            List of likely next stages to watch for
        """
        if current_stage not in KILL_CHAIN_SEQUENCE:
            return []

        current_idx = KILL_CHAIN_SEQUENCE.index(current_stage)

        # Return next 2 stages if available
        next_stages = []
        for i in range(current_idx + 1, min(current_idx + 3, len(KILL_CHAIN_SEQUENCE))):
            next_stages.append(KILL_CHAIN_SEQUENCE[i])

        return next_stages

    def _analyze_progression(
        self,
        user_email: str,
        staged_alerts: List[Tuple[Dict, IdentityKillChainStage]]
    ) -> Optional[KillChainIncident]:
        """Analyze staged alerts for kill chain progression."""
        if len(staged_alerts) < 2:
            return None

        # Sort by timestamp
        staged_alerts.sort(key=lambda x: x[0].get("timestamp", ""))

        # Get unique stages in order observed
        seen_stages: List[IdentityKillChainStage] = []
        stage_timeline: List[Tuple[str, IdentityKillChainStage, str]] = []

        for alert, stage in staged_alerts:
            timestamp = alert.get("timestamp", "")
            alert_id = alert.get("id", alert.get("alert_id", ""))

            stage_timeline.append((timestamp, stage, alert_id))

            if stage not in seen_stages:
                seen_stages.append(stage)

        # Check for meaningful progression (at least 2 different stages)
        if len(seen_stages) < 2:
            return None

        # Verify stages are in progression order (not random)
        stage_indices = [
            KILL_CHAIN_SEQUENCE.index(s)
            for s in seen_stages
            if s in KILL_CHAIN_SEQUENCE
        ]

        if not stage_indices:
            return None

        # Check if generally progressing forward
        is_progression = False
        if len(stage_indices) >= 2:
            # Allow some backtracking but overall should progress
            first_half = stage_indices[: len(stage_indices) // 2 + 1]
            second_half = stage_indices[len(stage_indices) // 2:]
            if max(second_half) > min(first_half):
                is_progression = True

        if not is_progression:
            return None

        # Calculate severity
        severity = self.calculate_progression_severity(seen_stages)

        # Get current (furthest) stage
        current_stage = max(
            seen_stages,
            key=lambda s: KILL_CHAIN_SEQUENCE.index(s) if s in KILL_CHAIN_SEQUENCE else -1
        )

        # Get predicted next stages
        predicted = self.get_expected_next_stages(current_stage)
        predicted_next = predicted[0] if predicted else None

        # Calculate progression velocity
        if len(stage_timeline) >= 2:
            first_time = self._parse_timestamp(stage_timeline[0][0])
            last_time = self._parse_timestamp(stage_timeline[-1][0])
            time_span = (last_time - first_time).total_seconds() / 3600  # hours

            if time_span > 0:
                velocity = len(seen_stages) / time_span
            else:
                velocity = float(len(seen_stages))  # All in same moment
        else:
            velocity = 0.0

        # Check for stage skipping
        skip_result = self.detect_stage_skipping([a for a, _ in staged_alerts])
        stage_skip_detected = skip_result is not None
        skipped_stages = skip_result[1] if skip_result else []

        # Extract entities
        all_alerts = [a for a, _ in staged_alerts]
        attacker_ips = list(set(
            a.get("source_ip", "")
            for a in all_alerts
            if a.get("source_ip")
        ))
        providers = list(set(
            a.get("provider", "")
            for a in all_alerts
            if a.get("provider")
        ))
        alert_ids = [
            a.get("id", a.get("alert_id", ""))
            for a in all_alerts
        ]

        # Determine response urgency
        if current_stage in [
            IdentityKillChainStage.LATERAL_MOVEMENT,
            IdentityKillChainStage.OBJECTIVES
        ]:
            response_urgency = "immediate"
        elif current_stage in [
            IdentityKillChainStage.PRIVILEGE_ESCALATION,
            IdentityKillChainStage.PERSISTENCE
        ]:
            response_urgency = "elevated"
        else:
            response_urgency = "normal"

        # Create incident
        now = datetime.utcnow().isoformat() + "Z"
        incident = KillChainIncident(
            incident_id=self._generate_incident_id(),
            title=f"Kill Chain Progression Detected: {user_email}",
            severity=severity,
            status="open",
            stages_observed=seen_stages,
            stage_timeline=stage_timeline,
            current_stage=current_stage,
            predicted_next_stage=predicted_next,
            progression_velocity=round(velocity, 2),
            stage_skip_detected=stage_skip_detected,
            skipped_stages=skipped_stages,
            target_users=[user_email],
            attacker_ips=attacker_ips,
            affected_providers=providers,
            alert_ids=alert_ids,
            alert_count=len(alert_ids),
            first_seen=stage_timeline[0][0] if stage_timeline else now,
            last_seen=stage_timeline[-1][0] if stage_timeline else now,
            created_at=now,
            recommended_response=STAGE_RESPONSES.get(current_stage, ""),
            response_urgency=response_urgency,
        )

        return incident

    def get_incident(self, incident_id: str) -> Optional[KillChainIncident]:
        """Get incident by ID."""
        return self._incidents.get(incident_id)

    def get_active_progressions(
        self,
        min_stages: int = 2
    ) -> List[KillChainIncident]:
        """Get active kill chain progressions with minimum stages."""
        return [
            i for i in self._incidents.values()
            if i.status == "open" and len(i.stages_observed) >= min_stages
        ]

    def get_critical_progressions(self) -> List[KillChainIncident]:
        """Get progressions that have reached critical stages."""
        critical_stages = {
            IdentityKillChainStage.PRIVILEGE_ESCALATION,
            IdentityKillChainStage.PERSISTENCE,
            IdentityKillChainStage.LATERAL_MOVEMENT,
            IdentityKillChainStage.OBJECTIVES,
        }

        return [
            i for i in self._incidents.values()
            if i.status == "open" and i.current_stage in critical_stages
        ]

    def _extract_user(self, alert: Dict[str, Any]) -> Optional[str]:
        """Extract user email from alert."""
        user_fields = [
            "user_email", "userPrincipalName", "actor.email",
            "principal.email", "target.email", "subject.email"
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

    def _parse_timestamp(self, timestamp: str) -> datetime:
        """Parse ISO timestamp string."""
        try:
            return datetime.fromisoformat(timestamp.replace("Z", ""))
        except (ValueError, TypeError):
            return datetime.utcnow()

    def _generate_incident_id(self) -> str:
        """Generate unique incident ID."""
        now = datetime.utcnow().isoformat()
        return f"KC-{hashlib.md5(now.encode()).hexdigest()[:12].upper()}"


def detect_kill_chain(
    alerts: List[Dict[str, Any]],
    window_hours: int = 24
) -> List[KillChainIncident]:
    """Convenience function to detect kill chain progressions."""
    detector = KillChainDetector()
    return detector.detect_kill_chain_progression(alerts, window_hours)
