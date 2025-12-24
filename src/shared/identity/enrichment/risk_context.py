"""Risk context provider for identity alert enrichment.

Provides risk scoring context for identity events.
"""

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from ..risk_scorer import IdentityRiskScorer
from ..risk_models import UserRiskScore, RiskLevel, RiskFactor, RiskFactorType

logger = logging.getLogger(__name__)


@dataclass
class RiskContext:
    """Risk context for an identity alert."""

    risk_score: int = 0
    risk_level: str = "low"
    risk_factors: List[Dict[str, Any]] = field(default_factory=list)
    historical_alerts: int = 0
    historical_alert_types: List[str] = field(default_factory=list)
    risk_trend: str = "stable"
    recommended_actions: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "risk_score": self.risk_score,
            "risk_level": self.risk_level,
            "risk_factors": self.risk_factors,
            "historical_alerts": self.historical_alerts,
            "historical_alert_types": self.historical_alert_types,
            "risk_trend": self.risk_trend,
            "recommended_actions": self.recommended_actions,
        }


class RiskContextProvider:
    """Provides risk context for identity alerts."""

    def __init__(
        self,
        risk_scorer: Optional[IdentityRiskScorer] = None,
        alert_history_store: Optional[Any] = None,
    ):
        """Initialize risk context provider.

        Args:
            risk_scorer: Risk scoring engine
            alert_history_store: Store for historical alert data
        """
        self.risk_scorer = risk_scorer
        self.alert_history_store = alert_history_store

    def get_risk_context(
        self,
        user_email: str,
        event: Optional[Any] = None,
        include_history: bool = True,
    ) -> RiskContext:
        """Get risk context for a user.

        Args:
            user_email: User email address
            event: Optional current event triggering the alert
            include_history: Whether to include historical alert context

        Returns:
            RiskContext with risk scoring information
        """
        context = RiskContext()

        # Get risk score if scorer is available
        if self.risk_scorer:
            try:
                user_risk = self.risk_scorer.calculate_user_risk(
                    user_email, include_history=include_history
                )
                if user_risk:
                    context.risk_score = user_risk.overall_score
                    context.risk_level = user_risk.risk_level.value if hasattr(user_risk.risk_level, 'value') else str(user_risk.risk_level)
                    context.risk_trend = user_risk.trend.value if hasattr(user_risk.trend, 'value') else str(user_risk.trend)
                    context.risk_factors = [
                        {
                            "type": f.factor_type.value if hasattr(f.factor_type, 'value') else str(f.factor_type),
                            "description": f.description,
                            "severity": f.severity,
                        }
                        for f in (user_risk.factors or [])
                    ]
            except Exception as e:
                logger.warning(f"Failed to get risk score for {user_email}: {e}")

        # Get historical alerts if store is available
        if include_history and self.alert_history_store:
            try:
                history = self.alert_history_store.get_recent_alerts(user_email)
                if history:
                    context.historical_alerts = len(history)
                    context.historical_alert_types = list(set(
                        h.get("alert_type", "unknown") for h in history
                    ))
            except Exception as e:
                logger.warning(f"Failed to get alert history for {user_email}: {e}")

        # Generate recommended actions based on risk level
        context.recommended_actions = self._get_recommended_actions(
            context.risk_level, context.risk_factors
        )

        return context

    def _get_recommended_actions(
        self,
        risk_level: str,
        risk_factors: List[Dict[str, Any]],
    ) -> List[str]:
        """Get recommended actions based on risk level and factors.

        Args:
            risk_level: Current risk level
            risk_factors: List of risk factors

        Returns:
            List of recommended action strings
        """
        actions = []

        # Base actions by risk level
        if risk_level in ("critical", "high"):
            actions.extend([
                "Investigate immediately",
                "Consider session termination",
                "Verify user identity",
            ])
        elif risk_level == "medium":
            actions.extend([
                "Monitor user activity",
                "Review recent actions",
            ])
        else:
            actions.append("Continue monitoring")

        # Factor-specific actions
        factor_types = [f.get("type", "") for f in risk_factors]

        if "impossible_travel" in factor_types or "geographic_anomaly" in factor_types:
            actions.append("Verify travel or VPN usage")

        if "credential_attack" in factor_types or "brute_force" in factor_types:
            actions.append("Consider password reset")
            actions.append("Enable additional MFA")

        if "session_anomaly" in factor_types:
            actions.append("Review active sessions")

        if "privilege_escalation" in factor_types:
            actions.append("Audit privilege changes")

        return list(set(actions))  # Deduplicate


    def calculate_trend(
        self,
        historical_scores: List[int],
    ) -> Dict[str, Any]:
        """Calculate risk score trend from historical data.

        Args:
            historical_scores: List of historical risk scores (oldest to newest)

        Returns:
            Dictionary with trend information
        """
        if not historical_scores:
            return {
                "direction": "stable",
                "change_rate": 0.0,
                "current": 0,
                "previous_avg": 0.0,
            }

        current = historical_scores[-1]
        previous = historical_scores[:-1] if len(historical_scores) > 1 else [current]
        previous_avg = sum(previous) / len(previous) if previous else current

        # Calculate change rate
        if previous_avg > 0:
            change_rate = (current - previous_avg) / previous_avg
        else:
            change_rate = 1.0 if current > 0 else 0.0

        # Determine direction
        if change_rate > 0.1:
            direction = "rising"
        elif change_rate < -0.1:
            direction = "falling"
        else:
            direction = "stable"

        return {
            "direction": direction,
            "change_rate": round(change_rate, 3),
            "current": current,
            "previous_avg": round(previous_avg, 2),
        }

    def compare_to_peers(
        self,
        user_score: int,
        peer_scores: List[int],
    ) -> Dict[str, Any]:
        """Compare user's risk score to peer group.

        Args:
            user_score: User's current risk score
            peer_scores: List of peer group risk scores

        Returns:
            Dictionary with peer comparison data
        """
        if not peer_scores:
            return {
                "user_score": user_score,
                "peer_avg": 0.0,
                "percentile": 100.0,
                "is_outlier": False,
            }

        peer_avg = sum(peer_scores) / len(peer_scores)

        # Calculate percentile (percentage of peers with lower scores)
        below_count = sum(1 for score in peer_scores if score < user_score)
        percentile = (below_count / len(peer_scores)) * 100

        # Calculate standard deviation for outlier detection
        if len(peer_scores) >= 2:
            variance = sum((s - peer_avg) ** 2 for s in peer_scores) / len(peer_scores)
            std_dev = variance ** 0.5
            z_score = (user_score - peer_avg) / std_dev if std_dev > 0 else 0
            is_outlier = abs(z_score) > 2
        else:
            is_outlier = abs(user_score - peer_avg) > 30

        return {
            "user_score": user_score,
            "peer_avg": round(peer_avg, 2),
            "percentile": round(percentile, 1),
            "is_outlier": is_outlier,
        }

    def get_alert_history(
        self,
        alerts: List[Dict[str, Any]],
        days: int = 7,
    ) -> Dict[str, Any]:
        """Process alert history for a user.

        Args:
            alerts: List of alert dictionaries
            days: Number of days to consider

        Returns:
            Dictionary with alert history summary
        """
        if not alerts:
            return {
                "alert_count": 0,
                "unique_types": 0,
                "alert_types": [],
            }

        # Extract alert types
        alert_types = []
        for alert in alerts:
            alert_type = alert.get("type") or alert.get("alert_type") or "unknown"
            alert_types.append(alert_type)

        unique_types = list(set(alert_types))

        return {
            "alert_count": len(alerts),
            "unique_types": len(unique_types),
            "alert_types": unique_types,
        }


__all__ = [
    "RiskContext",
    "RiskContextProvider",
]
