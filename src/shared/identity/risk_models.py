"""Risk scoring models for identity threat detection.

Defines the data models used by the risk scoring engine to calculate
and represent user, session, and event risk scores.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional


class RiskFactorType(Enum):
    """Types of factors that contribute to identity risk scores."""

    # Anomaly-based factors
    ANOMALY_DETECTED = "anomaly_detected"
    IMPOSSIBLE_TRAVEL = "impossible_travel"
    NEW_LOCATION_ACCESS = "new_location_access"
    UNUSUAL_VOLUME = "unusual_volume"
    CONCURRENT_SESSIONS = "concurrent_sessions"

    # Authentication factors
    MULTIPLE_FAILED_AUTHS = "multiple_failed_auths"
    MFA_BYPASS_ATTEMPT = "mfa_bypass_attempt"
    CREDENTIAL_STUFFING_PATTERN = "credential_stuffing_pattern"
    AUTH_METHOD_CHANGE = "auth_method_change"

    # Privilege factors
    HIGH_PRIVILEGE_USER = "high_privilege_user"
    RECENT_PRIVILEGE_CHANGE = "recent_privilege_change"
    DORMANT_ACCOUNT_ACTIVITY = "dormant_account_activity"

    # External factors
    THREAT_INTEL_MATCH = "threat_intel_match"
    VPN_PROXY_USAGE = "vpn_proxy_usage"
    TOR_EXIT_NODE = "tor_exit_node"

    # Behavioral factors
    PEER_GROUP_DEVIATION = "peer_group_deviation"
    UNUSUAL_LOGIN_TIME = "unusual_login_time"
    NEW_DEVICE_ACCESS = "new_device_access"

    # Session factors
    UNUSUAL_SESSION_DURATION = "unusual_session_duration"
    SESSION_FROM_BLOCKED_REGION = "session_from_blocked_region"


class RiskLevel(Enum):
    """Risk level classifications."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    MINIMAL = "minimal"


class RiskTrend(Enum):
    """Direction of risk score change."""

    RISING = "rising"
    STABLE = "stable"
    FALLING = "falling"


class SessionAction(Enum):
    """Recommended actions for sessions based on risk."""

    NONE = "none"
    MONITOR = "monitor"
    CHALLENGE = "challenge"  # Require MFA
    TERMINATE = "terminate"


# MITRE ATT&CK technique mappings for risk factors
RISK_FACTOR_MITRE_MAPPING = {
    RiskFactorType.IMPOSSIBLE_TRAVEL: "T1078.004",
    RiskFactorType.MULTIPLE_FAILED_AUTHS: "T1110",
    RiskFactorType.MFA_BYPASS_ATTEMPT: "T1556.006",
    RiskFactorType.CREDENTIAL_STUFFING_PATTERN: "T1110.004",
    RiskFactorType.CONCURRENT_SESSIONS: "T1550",
    RiskFactorType.RECENT_PRIVILEGE_CHANGE: "T1078",
    RiskFactorType.DORMANT_ACCOUNT_ACTIVITY: "T1078.001",
    RiskFactorType.TOR_EXIT_NODE: "T1090.003",
    RiskFactorType.VPN_PROXY_USAGE: "T1090",
}


@dataclass
class RiskFactor:
    """A single factor contributing to a risk score.

    Attributes:
        factor_type: Type of risk factor
        weight: Weight of this factor (0.0 to 1.0)
        raw_score: Raw severity score (0.0 to 1.0)
        weighted_score: Final weighted score (weight * raw_score)
        description: Human-readable description
        evidence: Supporting evidence data
        mitre_mapping: MITRE ATT&CK technique ID if applicable
    """

    factor_type: RiskFactorType
    weight: float
    raw_score: float
    description: str
    evidence: Dict[str, Any] = field(default_factory=dict)
    mitre_mapping: Optional[str] = None

    @property
    def weighted_score(self) -> float:
        """Calculate weighted score from weight and raw score."""
        return self.weight * self.raw_score

    def __post_init__(self):
        """Set MITRE mapping if not provided."""
        if self.mitre_mapping is None:
            self.mitre_mapping = RISK_FACTOR_MITRE_MAPPING.get(self.factor_type)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "factor_type": self.factor_type.value,
            "weight": round(self.weight, 3),
            "raw_score": round(self.raw_score, 3),
            "weighted_score": round(self.weighted_score, 3),
            "description": self.description,
            "evidence": self.evidence,
            "mitre_mapping": self.mitre_mapping,
        }


@dataclass
class UserRiskScore:
    """Risk score for a user identity.

    Provides an overall risk assessment for a user based on their
    recent activity, behavioral patterns, and external factors.

    Attributes:
        user_email: User's email address
        overall_score: Risk score from 0-100
        risk_level: Categorical risk level
        factors: Contributing risk factors
        trend: Direction of risk change
        trend_change_percent: Percentage change from previous score
        previous_score: Previous risk score for trend calculation
        calculated_at: When score was calculated
        confidence: Confidence in the score (0-1)
        recommendations: Suggested actions
    """

    user_email: str
    overall_score: float
    risk_level: RiskLevel
    factors: List[RiskFactor] = field(default_factory=list)
    trend: RiskTrend = RiskTrend.STABLE
    trend_change_percent: float = 0.0
    previous_score: float = 0.0
    calculated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    confidence: float = 1.0
    recommendations: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "user_email": self.user_email,
            "overall_score": round(self.overall_score, 1),
            "risk_level": self.risk_level.value,
            "factors": [f.to_dict() for f in self.factors],
            "trend": self.trend.value,
            "trend_change_percent": round(self.trend_change_percent, 1),
            "previous_score": round(self.previous_score, 1),
            "calculated_at": self.calculated_at.isoformat(),
            "confidence": round(self.confidence, 2),
            "recommendations": self.recommendations,
        }

    @property
    def top_factors(self) -> List[RiskFactor]:
        """Get top contributing factors sorted by weighted score."""
        return sorted(self.factors, key=lambda f: f.weighted_score, reverse=True)[:5]


@dataclass
class SessionRiskScore:
    """Risk score for an active session.

    Provides risk assessment for a specific session that can be used
    to determine if the session should be challenged or terminated.

    Attributes:
        session_id: Session identifier
        user_email: User's email address
        overall_score: Risk score from 0-100
        risk_level: Categorical risk level
        factors: Contributing risk factors
        recommended_action: Suggested action (monitor, challenge, terminate)
        calculated_at: When score was calculated
    """

    session_id: str
    user_email: str
    overall_score: float
    risk_level: RiskLevel
    factors: List[RiskFactor] = field(default_factory=list)
    recommended_action: SessionAction = SessionAction.NONE
    calculated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "session_id": self.session_id,
            "user_email": self.user_email,
            "overall_score": round(self.overall_score, 1),
            "risk_level": self.risk_level.value,
            "factors": [f.to_dict() for f in self.factors],
            "recommended_action": self.recommended_action.value,
            "calculated_at": self.calculated_at.isoformat(),
        }


@dataclass
class EventRiskScore:
    """Risk score for a single identity event.

    Provides immediate risk assessment for an event as it occurs,
    useful for real-time alerting and response decisions.

    Attributes:
        event_id: Event identifier
        user_email: User's email address
        overall_score: Risk score from 0-100
        risk_level: Categorical risk level
        factors: Contributing risk factors
        requires_immediate_action: Whether immediate response is needed
        calculated_at: When score was calculated
    """

    event_id: str
    user_email: str
    overall_score: float
    risk_level: RiskLevel
    factors: List[RiskFactor] = field(default_factory=list)
    requires_immediate_action: bool = False
    calculated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "event_id": self.event_id,
            "user_email": self.user_email,
            "overall_score": round(self.overall_score, 1),
            "risk_level": self.risk_level.value,
            "factors": [f.to_dict() for f in self.factors],
            "requires_immediate_action": self.requires_immediate_action,
            "calculated_at": self.calculated_at.isoformat(),
        }


@dataclass
class RiskScoringConfig:
    """Configuration for risk scoring thresholds and weights.

    Attributes:
        Threshold values for risk level classification.
        Weight values for each factor category.
    """

    # Risk level thresholds
    threshold_critical: float = 85
    threshold_high: float = 65
    threshold_medium: float = 40
    threshold_low: float = 20

    # Factor category weights (should sum to ~1.0)
    weight_anomaly: float = 0.25
    weight_threat_intel: float = 0.20
    weight_privilege: float = 0.15
    weight_auth_failures: float = 0.15
    weight_behavioral: float = 0.15
    weight_peer_deviation: float = 0.10

    # Session action thresholds
    session_action_terminate: float = 85
    session_action_challenge: float = 65
    session_action_monitor: float = 40

    # Trend calculation thresholds
    trend_rising_threshold: float = 10.0  # % increase to be "rising"
    trend_falling_threshold: float = -10.0  # % decrease to be "falling"

    # Baseline maturity confidence adjustment
    immature_baseline_penalty: float = 0.5  # 50% confidence reduction

    def get_risk_level(self, score: float) -> RiskLevel:
        """Get risk level for a given score."""
        if score >= self.threshold_critical:
            return RiskLevel.CRITICAL
        elif score >= self.threshold_high:
            return RiskLevel.HIGH
        elif score >= self.threshold_medium:
            return RiskLevel.MEDIUM
        elif score >= self.threshold_low:
            return RiskLevel.LOW
        else:
            return RiskLevel.MINIMAL

    def get_session_action(self, score: float) -> SessionAction:
        """Get recommended session action for a given score."""
        if score >= self.session_action_terminate:
            return SessionAction.TERMINATE
        elif score >= self.session_action_challenge:
            return SessionAction.CHALLENGE
        elif score >= self.session_action_monitor:
            return SessionAction.MONITOR
        else:
            return SessionAction.NONE


# Default recommendations based on risk level
DEFAULT_RECOMMENDATIONS = {
    RiskLevel.CRITICAL: [
        "Immediately investigate user activity",
        "Consider disabling account temporarily",
        "Review all active sessions",
        "Check for data exfiltration",
        "Notify security team",
    ],
    RiskLevel.HIGH: [
        "Investigate recent user activity",
        "Require MFA re-authentication",
        "Review recent privilege changes",
        "Monitor session activity closely",
    ],
    RiskLevel.MEDIUM: [
        "Monitor user activity for next 24 hours",
        "Consider additional authentication challenge",
        "Review if behavior is expected",
    ],
    RiskLevel.LOW: [
        "Log for awareness",
        "No immediate action required",
    ],
    RiskLevel.MINIMAL: [
        "Normal activity, no action needed",
    ],
}


def get_recommendations(risk_level: RiskLevel) -> List[str]:
    """Get default recommendations for a risk level.

    Args:
        risk_level: The risk level

    Returns:
        List of recommended actions
    """
    return DEFAULT_RECOMMENDATIONS.get(risk_level, [])
