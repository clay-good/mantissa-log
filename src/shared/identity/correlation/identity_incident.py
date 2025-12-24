"""Identity-specific incident data models.

Extends the base Incident dataclass with identity-specific fields
for tracking identity attacks and account takeovers.
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional

from ...alerting.correlation import Incident, IncidentSeverity


class IdentityAttackType(Enum):
    """Types of identity attacks."""

    BRUTE_FORCE = "brute_force"
    CREDENTIAL_STUFFING = "credential_stuffing"
    PASSWORD_SPRAY = "password_spray"
    ACCOUNT_TAKEOVER = "account_takeover"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    SESSION_HIJACK = "session_hijack"
    MFA_BYPASS = "mfa_bypass"
    MFA_FATIGUE = "mfa_fatigue"
    TOKEN_THEFT = "token_theft"
    LATERAL_MOVEMENT = "lateral_movement"
    DORMANT_ACTIVATION = "dormant_activation"
    IMPOSSIBLE_TRAVEL = "impossible_travel"
    UNKNOWN = "unknown"


class IdentityCorrelationType(Enum):
    """Identity-specific correlation types."""

    # Extends base CorrelationType
    SAME_TARGET_USER = "same_target_user"
    SAME_ATTACKER_IP = "same_attacker_ip"
    CREDENTIAL_ATTACK_CHAIN = "credential_attack_chain"
    ACCOUNT_TAKEOVER_CHAIN = "account_takeover_chain"
    LATERAL_MOVEMENT = "lateral_movement"
    PRIVILEGE_CHAIN = "privilege_chain"
    SESSION_COMPROMISE = "session_compromise"
    CROSS_PROVIDER = "cross_provider"


# Attack stage progression for kill chain tracking
IDENTITY_ATTACK_STAGES = [
    "reconnaissance",
    "credential_attack",
    "initial_access",
    "persistence",
    "privilege_escalation",
    "defense_evasion",
    "credential_access",
    "lateral_movement",
    "data_access",
    "exfiltration",
]

# Map attack types to their typical stages
ATTACK_TYPE_STAGES: Dict[IdentityAttackType, str] = {
    IdentityAttackType.BRUTE_FORCE: "credential_attack",
    IdentityAttackType.CREDENTIAL_STUFFING: "credential_attack",
    IdentityAttackType.PASSWORD_SPRAY: "credential_attack",
    IdentityAttackType.ACCOUNT_TAKEOVER: "initial_access",
    IdentityAttackType.PRIVILEGE_ESCALATION: "privilege_escalation",
    IdentityAttackType.SESSION_HIJACK: "initial_access",
    IdentityAttackType.MFA_BYPASS: "initial_access",
    IdentityAttackType.MFA_FATIGUE: "initial_access",
    IdentityAttackType.TOKEN_THEFT: "credential_access",
    IdentityAttackType.LATERAL_MOVEMENT: "lateral_movement",
    IdentityAttackType.DORMANT_ACTIVATION: "initial_access",
    IdentityAttackType.IMPOSSIBLE_TRAVEL: "initial_access",
}

# Recommended actions per attack type
ATTACK_TYPE_ACTIONS: Dict[IdentityAttackType, List[str]] = {
    IdentityAttackType.BRUTE_FORCE: [
        "Block source IP at firewall/WAF",
        "Enable account lockout policies",
        "Force password reset for targeted accounts",
        "Review authentication logs for success indicators",
    ],
    IdentityAttackType.CREDENTIAL_STUFFING: [
        "Block source IPs involved in attack",
        "Force password reset for affected accounts",
        "Enable MFA for all targeted accounts",
        "Check for credential reuse from breach databases",
        "Monitor for successful logins from attack IPs",
    ],
    IdentityAttackType.PASSWORD_SPRAY: [
        "Implement account lockout with progressive delays",
        "Block attacking IP ranges",
        "Force password changes for accounts with common passwords",
        "Enable MFA organization-wide",
        "Review for any successful authentications",
    ],
    IdentityAttackType.ACCOUNT_TAKEOVER: [
        "IMMEDIATELY suspend compromised account",
        "Terminate all active sessions",
        "Reset account password and MFA",
        "Audit all actions taken by compromised account",
        "Check for data exfiltration",
        "Review privilege changes and role assignments",
        "Notify account owner via alternate channel",
    ],
    IdentityAttackType.PRIVILEGE_ESCALATION: [
        "Revoke granted privileges immediately",
        "Suspend account pending investigation",
        "Audit all administrative actions",
        "Review role assignment history",
        "Check for persistence mechanisms",
        "Verify legitimate business need for privileges",
    ],
    IdentityAttackType.SESSION_HIJACK: [
        "Terminate all sessions for affected user",
        "Invalidate all session tokens",
        "Force re-authentication with MFA",
        "Investigate session token exposure",
        "Check for malware on user devices",
        "Review network logs for token interception",
    ],
    IdentityAttackType.MFA_BYPASS: [
        "Investigate MFA bypass method",
        "Review MFA configuration and policies",
        "Check for SIM swap or MFA device compromise",
        "Audit recent MFA enrollment changes",
        "Force MFA re-enrollment",
    ],
    IdentityAttackType.MFA_FATIGUE: [
        "Suspend account to stop push notifications",
        "Educate user about MFA fatigue attacks",
        "Switch to phishing-resistant MFA (FIDO2)",
        "Implement number matching for push MFA",
        "Block attacking source IPs",
    ],
    IdentityAttackType.TOKEN_THEFT: [
        "Revoke all OAuth tokens for affected user",
        "Review OAuth app consent history",
        "Investigate illicit consent grants",
        "Block suspicious OAuth applications",
        "Audit data accessed via stolen tokens",
    ],
    IdentityAttackType.LATERAL_MOVEMENT: [
        "Map full extent of lateral movement",
        "Isolate all compromised accounts and systems",
        "Reset credentials for all affected accounts",
        "Review access patterns across providers",
        "Check for persistence in accessed systems",
        "Initiate full incident response procedures",
    ],
    IdentityAttackType.DORMANT_ACTIVATION: [
        "Verify user identity through alternate channels",
        "Review access from dormant account",
        "Check if user returned from leave",
        "If unverified, suspend account immediately",
        "Force password reset before re-enabling",
        "Audit dormant account policies",
    ],
    IdentityAttackType.IMPOSSIBLE_TRAVEL: [
        "Verify user location through alternate means",
        "Check for VPN or proxy usage",
        "Review all actions from suspicious location",
        "If unverified, terminate session and lock account",
        "Investigate potential credential compromise",
    ],
}


@dataclass
class IdentityIncident(Incident):
    """
    An identity-specific incident extending the base Incident class.

    Adds identity-specific context such as target users, attacker IPs,
    attack type classification, and attack chain progression.
    """

    # Identity-specific fields
    target_users: List[str] = field(default_factory=list)
    attacker_ips: List[str] = field(default_factory=list)
    attack_type: IdentityAttackType = IdentityAttackType.UNKNOWN
    attack_stage: str = ""
    compromise_confirmed: bool = False
    affected_resources: List[str] = field(default_factory=list)
    recommended_actions: List[str] = field(default_factory=list)

    # Additional identity context
    affected_providers: List[str] = field(default_factory=list)
    compromised_credentials: List[str] = field(default_factory=list)
    escalated_privileges: List[str] = field(default_factory=list)
    hijacked_sessions: List[str] = field(default_factory=list)
    stolen_tokens: List[str] = field(default_factory=list)

    # Attack chain tracking
    attack_chain: List[Dict[str, Any]] = field(default_factory=list)
    chain_complete: bool = False
    takeover_confidence: float = 0.0

    # Cross-provider correlation
    correlation_score: float = 0.0
    related_incidents: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary including identity-specific fields."""
        # Get base incident dict
        result = super().to_dict()

        # Add identity-specific fields
        result.update({
            "target_users": self.target_users,
            "attacker_ips": self.attacker_ips,
            "attack_type": self.attack_type.value,
            "attack_stage": self.attack_stage,
            "compromise_confirmed": self.compromise_confirmed,
            "affected_resources": self.affected_resources,
            "recommended_actions": self.recommended_actions,
            "affected_providers": self.affected_providers,
            "compromised_credentials": self.compromised_credentials,
            "escalated_privileges": self.escalated_privileges,
            "hijacked_sessions": self.hijacked_sessions,
            "stolen_tokens": self.stolen_tokens,
            "attack_chain": self.attack_chain,
            "chain_complete": self.chain_complete,
            "takeover_confidence": self.takeover_confidence,
            "correlation_score": self.correlation_score,
            "related_incidents": self.related_incidents,
        })

        return result

    def add_to_attack_chain(
        self,
        stage: str,
        alert_id: str,
        description: str,
        timestamp: str
    ) -> None:
        """Add a step to the attack chain."""
        self.attack_chain.append({
            "stage": stage,
            "alert_id": alert_id,
            "description": description,
            "timestamp": timestamp,
        })
        # Update attack stage to furthest in chain
        if stage in IDENTITY_ATTACK_STAGES:
            stage_index = IDENTITY_ATTACK_STAGES.index(stage)
            current_index = (
                IDENTITY_ATTACK_STAGES.index(self.attack_stage)
                if self.attack_stage in IDENTITY_ATTACK_STAGES
                else -1
            )
            if stage_index > current_index:
                self.attack_stage = stage

    def mark_compromised(self, confidence: float = 1.0) -> None:
        """Mark this incident as a confirmed compromise."""
        self.compromise_confirmed = True
        self.takeover_confidence = min(confidence, 1.0)
        # Escalate severity for confirmed compromise
        self.severity = IncidentSeverity.CRITICAL

    def get_recommended_actions(self) -> List[str]:
        """Get recommended actions based on attack type."""
        if self.recommended_actions:
            return self.recommended_actions

        actions = ATTACK_TYPE_ACTIONS.get(self.attack_type, [])

        # Add escalated actions for confirmed compromise
        if self.compromise_confirmed:
            actions = [
                "CRITICAL: Confirmed compromise - initiate incident response",
                "Document timeline and preserve evidence",
            ] + actions

        return actions

    def calculate_takeover_confidence(self) -> float:
        """
        Calculate confidence that this represents an account takeover.

        Returns:
            Confidence score between 0.0 and 1.0
        """
        confidence = 0.0

        # Multiple anomalies increase confidence
        if len(self.timeline) >= 3:
            confidence += 0.2
        if len(self.timeline) >= 5:
            confidence += 0.1

        # Multiple attack types in chain
        if len(self.attack_chain) >= 2:
            confidence += 0.2
        if len(self.attack_chain) >= 4:
            confidence += 0.1

        # Late stage attacks
        late_stages = ["privilege_escalation", "lateral_movement", "data_access", "exfiltration"]
        if self.attack_stage in late_stages:
            confidence += 0.3

        # Multiple providers affected
        if len(self.affected_providers) >= 2:
            confidence += 0.1

        # Credential or session compromise confirmed
        if self.compromised_credentials or self.hijacked_sessions or self.stolen_tokens:
            confidence += 0.2

        # Cap at 1.0
        return min(confidence, 1.0)


def create_identity_incident(
    incident_id: str,
    title: str,
    severity: IncidentSeverity,
    attack_type: IdentityAttackType,
    target_users: Optional[List[str]] = None,
    attacker_ips: Optional[List[str]] = None,
) -> IdentityIncident:
    """
    Factory function to create an IdentityIncident.

    Args:
        incident_id: Unique incident identifier
        title: Incident title
        severity: Incident severity level
        attack_type: Type of identity attack
        target_users: List of targeted user emails
        attacker_ips: List of attacker source IPs

    Returns:
        Configured IdentityIncident
    """
    from datetime import datetime

    now = datetime.utcnow().isoformat() + "Z"

    incident = IdentityIncident(
        incident_id=incident_id,
        title=title,
        severity=severity,
        status="open",
        first_seen=now,
        last_seen=now,
        created_at=now,
        attack_type=attack_type,
        attack_stage=ATTACK_TYPE_STAGES.get(attack_type, ""),
        target_users=target_users or [],
        attacker_ips=attacker_ips or [],
    )

    # Set recommended actions
    incident.recommended_actions = incident.get_recommended_actions()

    return incident
