"""Risk scorer - re-export for package compatibility."""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Optional

from ..risk_scorer import IdentityRiskScorer
from ..risk_models import RiskFactor as _RiskFactor, RiskLevel, RiskFactorType


@dataclass
class RiskFactor:
    """Test-compatible RiskFactor with simplified interface.

    This class provides a simplified interface for unit testing,
    accepting string factor_type and numeric weight directly.
    """

    factor_type: str
    weight: float = 0.0
    evidence: Any = None
    detected_at: Optional[datetime] = None
    attack_succeeded: bool = False

    # These map to internal RiskFactor fields
    raw_score: float = field(default=1.0)
    description: str = field(default="")

    def __post_init__(self):
        """Set defaults."""
        if not self.description and self.evidence:
            self.description = str(self.evidence)
        if self.detected_at is None:
            self.detected_at = datetime.now(timezone.utc)

    def to_internal(self) -> _RiskFactor:
        """Convert to internal RiskFactor format."""
        # Try to map string factor_type to enum
        factor_type_map = {
            "new_device": RiskFactorType.NEW_DEVICE_ACCESS,
            "new_location": RiskFactorType.NEW_LOCATION_ACCESS,
            "impossible_travel": RiskFactorType.IMPOSSIBLE_TRAVEL,
            "unusual_time": RiskFactorType.UNUSUAL_LOGIN_TIME,
            "mfa_bypass": RiskFactorType.MFA_BYPASS_ATTEMPT,
            "brute_force": RiskFactorType.MULTIPLE_FAILED_AUTHS,
            "privilege_escalation": RiskFactorType.RECENT_PRIVILEGE_CHANGE,
            "concurrent_sessions": RiskFactorType.CONCURRENT_SESSIONS,
            "mfa_verified": RiskFactorType.ANOMALY_DETECTED,  # Risk reduction
            "info_only": RiskFactorType.ANOMALY_DETECTED,
            "critical_compromise": RiskFactorType.THREAT_INTEL_MATCH,
        }

        internal_type = factor_type_map.get(
            self.factor_type, RiskFactorType.ANOMALY_DETECTED
        )

        return _RiskFactor(
            factor_type=internal_type,
            weight=self.weight / 100.0,  # Normalize to 0-1 range
            raw_score=self.raw_score,
            description=self.description,
            evidence={"original_evidence": self.evidence} if self.evidence else {},
        )


__all__ = ["IdentityRiskScorer", "RiskFactor", "RiskLevel"]
