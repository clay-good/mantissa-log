"""Identity anomaly types and data models for ITDR.

Defines the types of anomalies that can be detected when analyzing
identity events against user baselines.
"""

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional


class IdentityAnomalyType(Enum):
    """Types of identity-related anomalies that can be detected."""

    # Travel-based anomalies
    IMPOSSIBLE_TRAVEL = "impossible_travel"

    # Time-based anomalies
    UNUSUAL_LOGIN_TIME = "unusual_login_time"

    # Device/client anomalies
    NEW_DEVICE = "new_device"
    NEW_USER_AGENT = "new_user_agent"

    # Location anomalies
    NEW_LOCATION = "new_location"
    NEW_IP_ADDRESS = "new_ip_address"
    FIRST_TIME_COUNTRY = "first_time_country"

    # Volume anomalies
    VOLUME_SPIKE = "volume_spike"
    RAPID_FIRE_AUTH = "rapid_fire_auth"

    # Authentication pattern anomalies
    AUTH_METHOD_CHANGE = "auth_method_change"
    NEW_APPLICATION = "new_application"
    NEW_PROVIDER = "new_provider"

    # Session anomalies
    UNUSUAL_SESSION_DURATION = "unusual_session_duration"
    CONCURRENT_SESSIONS = "concurrent_sessions"

    # Network-based anomalies
    VPN_OR_PROXY_DETECTED = "vpn_or_proxy_detected"
    TOR_EXIT_NODE = "tor_exit_node"
    DATACENTER_IP = "datacenter_ip"

    # Credential-related anomalies
    UNUSUAL_FAILURE_RATE = "unusual_failure_rate"
    MFA_BYPASS_ATTEMPT = "mfa_bypass_attempt"


class AnomalySeverity(Enum):
    """Severity levels for detected anomalies."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


# MITRE ATT&CK technique mappings for identity anomalies
MITRE_TECHNIQUES = {
    IdentityAnomalyType.IMPOSSIBLE_TRAVEL: "T1078.004",  # Valid Accounts: Cloud
    IdentityAnomalyType.UNUSUAL_LOGIN_TIME: "T1078",  # Valid Accounts
    IdentityAnomalyType.NEW_DEVICE: "T1078",  # Valid Accounts
    IdentityAnomalyType.NEW_LOCATION: "T1078.004",  # Valid Accounts: Cloud
    IdentityAnomalyType.FIRST_TIME_COUNTRY: "T1078.004",  # Valid Accounts: Cloud
    IdentityAnomalyType.VPN_OR_PROXY_DETECTED: "T1090",  # Proxy
    IdentityAnomalyType.TOR_EXIT_NODE: "T1090.003",  # Multi-hop Proxy
    IdentityAnomalyType.AUTH_METHOD_CHANGE: "T1556",  # Modify Auth Process
    IdentityAnomalyType.MFA_BYPASS_ATTEMPT: "T1556.006",  # MFA Interception
    IdentityAnomalyType.CONCURRENT_SESSIONS: "T1550",  # Use Alternate Auth Material
    IdentityAnomalyType.VOLUME_SPIKE: "T1110",  # Brute Force
    IdentityAnomalyType.RAPID_FIRE_AUTH: "T1110.001",  # Password Guessing
}


@dataclass
class IdentityAnomaly:
    """Represents a detected identity anomaly.

    Captures all details about an anomaly detected during behavioral
    analysis of identity events.

    Attributes:
        anomaly_id: Unique identifier for this anomaly instance
        anomaly_type: Type of anomaly detected
        user_email: Email of the user involved
        event_id: ID of the triggering event
        severity: Severity level (low, medium, high, critical)
        confidence: Confidence score (0.0 to 1.0)
        title: Short human-readable title
        description: Detailed description of the anomaly
        evidence: Specific data supporting the anomaly detection
        baseline_comparison: What's normal vs what was observed
        recommended_action: Suggested response action
        detected_at: When the anomaly was detected
        mitre_technique: MITRE ATT&CK technique ID if applicable
    """

    anomaly_id: str
    anomaly_type: IdentityAnomalyType
    user_email: str
    event_id: str
    severity: AnomalySeverity
    confidence: float
    title: str
    description: str
    evidence: Dict[str, Any] = field(default_factory=dict)
    baseline_comparison: Dict[str, Any] = field(default_factory=dict)
    recommended_action: str = ""
    detected_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    mitre_technique: Optional[str] = None

    def __post_init__(self):
        """Set MITRE technique if not provided."""
        if self.mitre_technique is None:
            self.mitre_technique = MITRE_TECHNIQUES.get(self.anomaly_type)

    @property
    def is_anomaly(self) -> bool:
        """Returns True if this is an anomaly (always True for IdentityAnomaly instances)."""
        return True

    @classmethod
    def create(
        cls,
        anomaly_type: IdentityAnomalyType,
        user_email: str,
        event_id: str,
        severity: AnomalySeverity,
        confidence: float,
        title: str,
        description: str,
        evidence: Dict[str, Any] = None,
        baseline_comparison: Dict[str, Any] = None,
        recommended_action: str = "",
    ) -> "IdentityAnomaly":
        """Factory method to create an anomaly with auto-generated ID.

        Args:
            anomaly_type: Type of anomaly
            user_email: User's email address
            event_id: Triggering event ID
            severity: Anomaly severity
            confidence: Detection confidence (0-1)
            title: Short title
            description: Detailed description
            evidence: Supporting evidence data
            baseline_comparison: Normal vs observed comparison
            recommended_action: Suggested action

        Returns:
            New IdentityAnomaly instance
        """
        return cls(
            anomaly_id=str(uuid.uuid4()),
            anomaly_type=anomaly_type,
            user_email=user_email,
            event_id=event_id,
            severity=severity,
            confidence=confidence,
            title=title,
            description=description,
            evidence=evidence or {},
            baseline_comparison=baseline_comparison or {},
            recommended_action=recommended_action,
            detected_at=datetime.now(timezone.utc),
        )

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "anomaly_id": self.anomaly_id,
            "anomaly_type": self.anomaly_type.value,
            "user_email": self.user_email,
            "event_id": self.event_id,
            "severity": self.severity.value,
            "confidence": self.confidence,
            "title": self.title,
            "description": self.description,
            "evidence": self.evidence,
            "baseline_comparison": self.baseline_comparison,
            "recommended_action": self.recommended_action,
            "detected_at": self.detected_at.isoformat(),
            "mitre_technique": self.mitre_technique,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "IdentityAnomaly":
        """Create from dictionary."""
        detected_at = data.get("detected_at")
        if isinstance(detected_at, str):
            detected_at = datetime.fromisoformat(detected_at.replace("Z", "+00:00"))
        elif detected_at is None:
            detected_at = datetime.now(timezone.utc)

        return cls(
            anomaly_id=data.get("anomaly_id", str(uuid.uuid4())),
            anomaly_type=IdentityAnomalyType(data["anomaly_type"]),
            user_email=data["user_email"],
            event_id=data["event_id"],
            severity=AnomalySeverity(data["severity"]),
            confidence=float(data.get("confidence", 0.5)),
            title=data.get("title", ""),
            description=data.get("description", ""),
            evidence=data.get("evidence", {}),
            baseline_comparison=data.get("baseline_comparison", {}),
            recommended_action=data.get("recommended_action", ""),
            detected_at=detected_at,
            mitre_technique=data.get("mitre_technique"),
        )


# Severity thresholds and recommended actions per anomaly type
ANOMALY_CONFIG = {
    IdentityAnomalyType.IMPOSSIBLE_TRAVEL: {
        "default_severity": AnomalySeverity.HIGH,
        "recommended_action": "Verify user identity and review session for compromise indicators",
        "thresholds": {
            "velocity_kmh_medium": 800,
            "velocity_kmh_high": 1500,
            "velocity_kmh_critical": 5000,
        },
    },
    IdentityAnomalyType.UNUSUAL_LOGIN_TIME: {
        "default_severity": AnomalySeverity.LOW,
        "recommended_action": "Monitor for additional suspicious activity",
        "thresholds": {
            "hours_outside_normal_medium": 2,
            "hours_outside_normal_high": 4,
        },
    },
    IdentityAnomalyType.NEW_DEVICE: {
        "default_severity": AnomalySeverity.MEDIUM,
        "recommended_action": "Verify new device with user via out-of-band communication",
    },
    IdentityAnomalyType.FIRST_TIME_COUNTRY: {
        "default_severity": AnomalySeverity.HIGH,
        "recommended_action": "Require additional verification or contact user to confirm travel",
    },
    IdentityAnomalyType.NEW_LOCATION: {
        "default_severity": AnomalySeverity.MEDIUM,
        "recommended_action": "Monitor session for suspicious activity",
    },
    IdentityAnomalyType.NEW_IP_ADDRESS: {
        "default_severity": AnomalySeverity.LOW,
        "recommended_action": "Log for baseline update, no immediate action required",
    },
    IdentityAnomalyType.VOLUME_SPIKE: {
        "default_severity": AnomalySeverity.MEDIUM,
        "recommended_action": "Review activity logs for automated or malicious behavior",
        "thresholds": {
            "z_score_medium": 2.0,
            "z_score_high": 3.0,
            "z_score_critical": 4.0,
        },
    },
    IdentityAnomalyType.AUTH_METHOD_CHANGE: {
        "default_severity": AnomalySeverity.MEDIUM,
        "recommended_action": "Verify MFA change was user-initiated",
    },
    IdentityAnomalyType.VPN_OR_PROXY_DETECTED: {
        "default_severity": AnomalySeverity.LOW,
        "recommended_action": "Check if VPN usage is expected per company policy",
    },
    IdentityAnomalyType.TOR_EXIT_NODE: {
        "default_severity": AnomalySeverity.HIGH,
        "recommended_action": "Immediately verify user identity, consider blocking session",
    },
    IdentityAnomalyType.CONCURRENT_SESSIONS: {
        "default_severity": AnomalySeverity.MEDIUM,
        "recommended_action": "Verify sessions are legitimate, check for token theft",
    },
    IdentityAnomalyType.MFA_BYPASS_ATTEMPT: {
        "default_severity": AnomalySeverity.CRITICAL,
        "recommended_action": "Block access and require re-authentication with MFA",
    },
}


@dataclass
class AnomalyResult:
    """Result of an anomaly detection check.

    Can represent either a detected anomaly or a negative result (no anomaly).

    Attributes:
        is_anomaly: Whether an anomaly was detected
        anomaly_type: Type of anomaly detected (if any) - string value
        anomaly: Full anomaly details (if detected)
        severity: Severity level (if detected) - string value
        confidence: Detection confidence (0-1)
    """

    is_anomaly: bool = False
    anomaly_type: Optional[str] = None
    anomaly: Optional[IdentityAnomaly] = None
    _severity: Optional[AnomalySeverity] = field(default=None, repr=False)
    confidence: float = 0.0
    evidence: Dict[str, Any] = field(default_factory=dict)

    @property
    def severity(self) -> Optional[str]:
        """Get severity as string value for test compatibility."""
        if self._severity is None:
            return None
        return self._severity.value if isinstance(self._severity, AnomalySeverity) else self._severity

    @classmethod
    def no_anomaly(cls) -> "AnomalyResult":
        """Create a result indicating no anomaly was detected."""
        return cls(is_anomaly=False)

    @classmethod
    def from_anomaly(cls, anomaly: IdentityAnomaly) -> "AnomalyResult":
        """Create a result from a detected anomaly."""
        return cls(
            is_anomaly=True,
            anomaly_type=anomaly.anomaly_type.value,
            anomaly=anomaly,
            _severity=anomaly.severity,
            confidence=anomaly.confidence,
            evidence=anomaly.evidence,
        )


def get_recommended_action(anomaly_type: IdentityAnomalyType) -> str:
    """Get recommended action for an anomaly type.

    Args:
        anomaly_type: Type of anomaly

    Returns:
        Recommended action string
    """
    config = ANOMALY_CONFIG.get(anomaly_type, {})
    return config.get("recommended_action", "Investigate and monitor")


def get_default_severity(anomaly_type: IdentityAnomalyType) -> AnomalySeverity:
    """Get default severity for an anomaly type.

    Args:
        anomaly_type: Type of anomaly

    Returns:
        Default severity level
    """
    config = ANOMALY_CONFIG.get(anomaly_type, {})
    return config.get("default_severity", AnomalySeverity.MEDIUM)
