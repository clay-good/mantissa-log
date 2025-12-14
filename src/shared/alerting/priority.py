"""
Alert Priority Scoring System.

Dynamically calculates alert priority based on multiple factors:
- Asset criticality (from cloud asset inventory)
- User risk score (from identity provider)
- Threat intelligence matches
- Historical false positive rate
- MITRE ATT&CK stage
- Time-based factors (business hours, etc.)
"""

import logging
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional
from enum import Enum

logger = logging.getLogger(__name__)


class PriorityLevel(Enum):
    """Priority levels for alerts."""
    CRITICAL = 1
    HIGH = 2
    MEDIUM = 3
    LOW = 4
    INFO = 5


@dataclass
class PriorityScore:
    """Detailed priority score for an alert."""

    alert_id: str
    final_priority: PriorityLevel
    final_score: float  # 0-100, higher = more urgent

    # Component scores (0-1 scale)
    base_severity_score: float = 0.0
    asset_criticality_score: float = 0.0
    user_risk_score: float = 0.0
    threat_intel_score: float = 0.0
    historical_accuracy_score: float = 0.0
    kill_chain_score: float = 0.0
    time_factor_score: float = 0.0

    # Factors applied
    factors_applied: List[str] = field(default_factory=list)
    boosters: List[str] = field(default_factory=list)
    reducers: List[str] = field(default_factory=list)

    # Metadata
    calculated_at: str = ""
    explanation: str = ""

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "alert_id": self.alert_id,
            "final_priority": self.final_priority.name,
            "final_score": round(self.final_score, 2),
            "component_scores": {
                "base_severity": round(self.base_severity_score, 2),
                "asset_criticality": round(self.asset_criticality_score, 2),
                "user_risk": round(self.user_risk_score, 2),
                "threat_intel": round(self.threat_intel_score, 2),
                "historical_accuracy": round(self.historical_accuracy_score, 2),
                "kill_chain": round(self.kill_chain_score, 2),
                "time_factor": round(self.time_factor_score, 2),
            },
            "factors_applied": self.factors_applied,
            "boosters": self.boosters,
            "reducers": self.reducers,
            "calculated_at": self.calculated_at,
            "explanation": self.explanation,
        }


@dataclass
class AssetInfo:
    """Information about an asset for priority calculation."""

    asset_id: str
    criticality: str = "medium"  # critical, high, medium, low
    environment: str = "production"  # production, staging, development
    data_classification: str = "internal"  # public, internal, confidential, restricted
    owner: Optional[str] = None
    tags: Dict[str, str] = field(default_factory=dict)


@dataclass
class UserInfo:
    """Information about a user for priority calculation."""

    user_id: str
    risk_level: str = "normal"  # elevated, normal, low
    is_privileged: bool = False
    is_service_account: bool = False
    department: Optional[str] = None
    recent_alert_count: int = 0
    recent_fp_count: int = 0


@dataclass
class ThreatIntelMatch:
    """Threat intelligence match for priority calculation."""

    indicator: str
    indicator_type: str  # ip, domain, hash
    source: str
    confidence: str = "medium"  # high, medium, low
    severity: str = "medium"  # critical, high, medium, low
    tags: List[str] = field(default_factory=list)


@dataclass
class PriorityConfig:
    """Configuration for priority scoring."""

    # Weight for each factor (should sum to ~1.0)
    weight_base_severity: float = 0.25
    weight_asset_criticality: float = 0.20
    weight_user_risk: float = 0.15
    weight_threat_intel: float = 0.20
    weight_historical_accuracy: float = 0.10
    weight_kill_chain: float = 0.05
    weight_time_factor: float = 0.05

    # Score thresholds for priority levels
    threshold_critical: float = 85
    threshold_high: float = 65
    threshold_medium: float = 40
    threshold_low: float = 20

    # Time-based factors
    business_hours_boost: float = 0.1  # 10% boost during business hours
    weekend_reduction: float = 0.05  # 5% reduction on weekends
    business_hours_start: int = 9
    business_hours_end: int = 17

    # High-value asset boost
    critical_asset_boost: float = 0.3  # 30% boost for critical assets
    production_boost: float = 0.1  # 10% boost for production

    # High-value user boost
    privileged_user_boost: float = 0.2  # 20% boost for privileged users
    elevated_risk_boost: float = 0.15  # 15% boost for elevated risk users

    # Threat intel boost
    high_confidence_ti_boost: float = 0.25  # 25% boost for high confidence TI match

    # Kill chain stage multipliers
    kill_chain_multipliers: Dict[str, float] = field(default_factory=lambda: {
        "reconnaissance": 0.6,
        "resource-development": 0.6,
        "initial-access": 0.8,
        "execution": 0.9,
        "persistence": 0.9,
        "privilege-escalation": 1.0,
        "defense-evasion": 0.8,
        "credential-access": 1.0,
        "discovery": 0.7,
        "lateral-movement": 1.0,
        "collection": 0.9,
        "command-and-control": 1.0,
        "exfiltration": 1.0,
        "impact": 1.0,
    })

    # Historical accuracy adjustments
    high_fp_rate_reduction: float = 0.3  # 30% reduction if >50% FP rate
    zero_fp_boost: float = 0.1  # 10% boost if 0% FP rate


class AlertPriorityScorer:
    """Calculates dynamic priority scores for alerts."""

    def __init__(
        self,
        config: Optional[PriorityConfig] = None,
        asset_lookup: Optional["AssetLookup"] = None,
        user_lookup: Optional["UserLookup"] = None,
        threat_intel_lookup: Optional["ThreatIntelLookup"] = None,
        fp_rate_lookup: Optional["FPRateLookup"] = None
    ):
        """
        Initialize priority scorer.

        Args:
            config: Priority scoring configuration
            asset_lookup: Service to look up asset information
            user_lookup: Service to look up user information
            threat_intel_lookup: Service to check threat intel
            fp_rate_lookup: Service to get historical FP rates
        """
        self.config = config or PriorityConfig()
        self.asset_lookup = asset_lookup
        self.user_lookup = user_lookup
        self.threat_intel_lookup = threat_intel_lookup
        self.fp_rate_lookup = fp_rate_lookup

    def calculate_priority(
        self,
        alert: Dict[str, Any],
        asset_info: Optional[AssetInfo] = None,
        user_info: Optional[UserInfo] = None,
        threat_intel_matches: Optional[List[ThreatIntelMatch]] = None,
        rule_fp_rate: Optional[float] = None
    ) -> PriorityScore:
        """
        Calculate priority score for an alert.

        Args:
            alert: Alert data
            asset_info: Optional asset information (looked up if not provided)
            user_info: Optional user information (looked up if not provided)
            threat_intel_matches: Optional TI matches (looked up if not provided)
            rule_fp_rate: Optional rule FP rate (looked up if not provided)

        Returns:
            PriorityScore with detailed breakdown
        """
        alert_id = alert.get("id", alert.get("alert_id", "unknown"))
        now = datetime.utcnow()

        score = PriorityScore(
            alert_id=alert_id,
            final_priority=PriorityLevel.MEDIUM,
            final_score=0.0,
            calculated_at=now.isoformat() + "Z"
        )

        # Look up context if not provided
        if asset_info is None:
            asset_info = self._lookup_asset(alert)
        if user_info is None:
            user_info = self._lookup_user(alert)
        if threat_intel_matches is None:
            threat_intel_matches = self._lookup_threat_intel(alert)
        if rule_fp_rate is None:
            rule_fp_rate = self._lookup_fp_rate(alert)

        # Calculate component scores
        score.base_severity_score = self._score_base_severity(alert)
        score.asset_criticality_score = self._score_asset_criticality(asset_info)
        score.user_risk_score = self._score_user_risk(user_info)
        score.threat_intel_score = self._score_threat_intel(threat_intel_matches)
        score.historical_accuracy_score = self._score_historical_accuracy(rule_fp_rate)
        score.kill_chain_score = self._score_kill_chain(alert)
        score.time_factor_score = self._score_time_factor(now)

        # Calculate weighted score
        weighted_score = (
            score.base_severity_score * self.config.weight_base_severity +
            score.asset_criticality_score * self.config.weight_asset_criticality +
            score.user_risk_score * self.config.weight_user_risk +
            score.threat_intel_score * self.config.weight_threat_intel +
            score.historical_accuracy_score * self.config.weight_historical_accuracy +
            score.kill_chain_score * self.config.weight_kill_chain +
            score.time_factor_score * self.config.weight_time_factor
        )

        # Apply boosters and reducers
        boost = 0.0
        reduction = 0.0

        # Asset boosters
        if asset_info and asset_info.criticality == "critical":
            boost += self.config.critical_asset_boost
            score.boosters.append(f"Critical asset (+{self.config.critical_asset_boost*100:.0f}%)")

        if asset_info and asset_info.environment == "production":
            boost += self.config.production_boost
            score.boosters.append(f"Production environment (+{self.config.production_boost*100:.0f}%)")

        # User boosters
        if user_info and user_info.is_privileged:
            boost += self.config.privileged_user_boost
            score.boosters.append(f"Privileged user (+{self.config.privileged_user_boost*100:.0f}%)")

        if user_info and user_info.risk_level == "elevated":
            boost += self.config.elevated_risk_boost
            score.boosters.append(f"Elevated risk user (+{self.config.elevated_risk_boost*100:.0f}%)")

        # Threat intel boosters
        if threat_intel_matches:
            high_conf_matches = [m for m in threat_intel_matches if m.confidence == "high"]
            if high_conf_matches:
                boost += self.config.high_confidence_ti_boost
                score.boosters.append(f"High confidence TI match (+{self.config.high_confidence_ti_boost*100:.0f}%)")

        # Historical accuracy adjustments
        if rule_fp_rate is not None:
            if rule_fp_rate > 0.5:
                reduction += self.config.high_fp_rate_reduction
                score.reducers.append(f"High FP rate ({rule_fp_rate*100:.0f}%) (-{self.config.high_fp_rate_reduction*100:.0f}%)")
            elif rule_fp_rate == 0:
                boost += self.config.zero_fp_boost
                score.boosters.append(f"Zero FP rate (+{self.config.zero_fp_boost*100:.0f}%)")

        # Time-based adjustments
        is_business_hours = self.config.business_hours_start <= now.hour < self.config.business_hours_end
        is_weekend = now.weekday() >= 5

        if is_business_hours and not is_weekend:
            boost += self.config.business_hours_boost
            score.boosters.append(f"Business hours (+{self.config.business_hours_boost*100:.0f}%)")

        if is_weekend:
            reduction += self.config.weekend_reduction
            score.reducers.append(f"Weekend (-{self.config.weekend_reduction*100:.0f}%)")

        # Apply boosters and reducers
        final_score = weighted_score * 100 * (1 + boost - reduction)
        final_score = max(0, min(100, final_score))  # Clamp to 0-100

        score.final_score = final_score
        score.final_priority = self._score_to_priority(final_score)

        # Track factors applied
        score.factors_applied = [
            f"Base severity: {score.base_severity_score:.2f}",
            f"Asset criticality: {score.asset_criticality_score:.2f}",
            f"User risk: {score.user_risk_score:.2f}",
            f"Threat intel: {score.threat_intel_score:.2f}",
            f"Historical accuracy: {score.historical_accuracy_score:.2f}",
            f"Kill chain: {score.kill_chain_score:.2f}",
            f"Time factor: {score.time_factor_score:.2f}",
        ]

        # Generate explanation
        score.explanation = self._generate_explanation(score, asset_info, user_info, threat_intel_matches)

        return score

    def calculate_batch(
        self,
        alerts: List[Dict[str, Any]]
    ) -> List[PriorityScore]:
        """Calculate priority for a batch of alerts."""
        scores = []
        for alert in alerts:
            score = self.calculate_priority(alert)
            scores.append(score)

        # Sort by priority (highest first)
        scores.sort(key=lambda s: s.final_score, reverse=True)

        return scores

    def _score_base_severity(self, alert: Dict[str, Any]) -> float:
        """Score based on alert's base severity."""
        severity = alert.get("severity", "medium").lower()

        severity_scores = {
            "critical": 1.0,
            "high": 0.8,
            "medium": 0.5,
            "low": 0.3,
            "info": 0.1,
        }

        return severity_scores.get(severity, 0.5)

    def _score_asset_criticality(self, asset_info: Optional[AssetInfo]) -> float:
        """Score based on asset criticality."""
        if not asset_info:
            return 0.5  # Default to medium

        criticality_scores = {
            "critical": 1.0,
            "high": 0.8,
            "medium": 0.5,
            "low": 0.3,
        }

        base_score = criticality_scores.get(asset_info.criticality, 0.5)

        # Adjust for data classification
        classification_boost = {
            "restricted": 0.2,
            "confidential": 0.1,
            "internal": 0.0,
            "public": -0.1,
        }

        boost = classification_boost.get(asset_info.data_classification, 0.0)

        return min(1.0, max(0.0, base_score + boost))

    def _score_user_risk(self, user_info: Optional[UserInfo]) -> float:
        """Score based on user risk level."""
        if not user_info:
            return 0.5  # Default to medium

        risk_scores = {
            "elevated": 0.9,
            "normal": 0.5,
            "low": 0.3,
        }

        base_score = risk_scores.get(user_info.risk_level, 0.5)

        # Boost for privileged users
        if user_info.is_privileged:
            base_score += 0.2

        # Slight reduction for service accounts (often noisy)
        if user_info.is_service_account:
            base_score -= 0.1

        return min(1.0, max(0.0, base_score))

    def _score_threat_intel(self, matches: Optional[List[ThreatIntelMatch]]) -> float:
        """Score based on threat intelligence matches."""
        if not matches:
            return 0.0  # No TI matches

        # Take highest confidence/severity match
        max_score = 0.0

        for match in matches:
            confidence_scores = {"high": 1.0, "medium": 0.6, "low": 0.3}
            severity_scores = {"critical": 1.0, "high": 0.8, "medium": 0.5, "low": 0.3}

            conf_score = confidence_scores.get(match.confidence, 0.5)
            sev_score = severity_scores.get(match.severity, 0.5)

            match_score = (conf_score + sev_score) / 2
            max_score = max(max_score, match_score)

        return max_score

    def _score_historical_accuracy(self, fp_rate: Optional[float]) -> float:
        """Score based on rule's historical accuracy (inverse of FP rate)."""
        if fp_rate is None:
            return 0.5  # Unknown, use default

        # Higher score for lower FP rate
        accuracy = 1.0 - fp_rate
        return max(0.0, min(1.0, accuracy))

    def _score_kill_chain(self, alert: Dict[str, Any]) -> float:
        """Score based on MITRE ATT&CK kill chain stage."""
        mitre = alert.get("mitre_attack", {})
        if not mitre:
            return 0.5  # Default

        tactic = mitre.get("tactic", "").lower().replace(" ", "-")

        return self.config.kill_chain_multipliers.get(tactic, 0.5)

    def _score_time_factor(self, now: datetime) -> float:
        """Score based on time factors."""
        # Base score
        score = 0.5

        # Business hours boost
        is_business_hours = self.config.business_hours_start <= now.hour < self.config.business_hours_end
        is_weekend = now.weekday() >= 5

        if is_business_hours and not is_weekend:
            score += 0.3

        # Off-hours might indicate suspicious activity
        if not is_business_hours:
            score += 0.1  # Slight boost for off-hours activity

        return min(1.0, score)

    def _score_to_priority(self, score: float) -> PriorityLevel:
        """Convert numeric score to priority level."""
        if score >= self.config.threshold_critical:
            return PriorityLevel.CRITICAL
        elif score >= self.config.threshold_high:
            return PriorityLevel.HIGH
        elif score >= self.config.threshold_medium:
            return PriorityLevel.MEDIUM
        elif score >= self.config.threshold_low:
            return PriorityLevel.LOW
        else:
            return PriorityLevel.INFO

    def _lookup_asset(self, alert: Dict[str, Any]) -> Optional[AssetInfo]:
        """Look up asset information from alert."""
        if not self.asset_lookup:
            return None

        # Try to extract asset identifier
        asset_fields = ["asset_id", "resource_id", "instance_id", "hostname"]
        results = alert.get("results", [{}])
        source = results[0] if results else alert

        for field in asset_fields:
            if field in source:
                return self.asset_lookup.get_asset(source[field])

        return None

    def _lookup_user(self, alert: Dict[str, Any]) -> Optional[UserInfo]:
        """Look up user information from alert."""
        if not self.user_lookup:
            return None

        # Try to extract user identifier
        user_fields = ["user", "userName", "principal", "userPrincipalName"]
        results = alert.get("results", [{}])
        source = results[0] if results else alert

        for field in user_fields:
            if field in source:
                user_value = source[field]
                if isinstance(user_value, dict):
                    user_value = user_value.get("userName", user_value.get("name", ""))
                return self.user_lookup.get_user(str(user_value))

        return None

    def _lookup_threat_intel(self, alert: Dict[str, Any]) -> List[ThreatIntelMatch]:
        """Look up threat intelligence for alert entities."""
        if not self.threat_intel_lookup:
            return []

        matches = []
        results = alert.get("results", [{}])
        source = results[0] if results else alert

        # Check IPs
        ip_fields = ["source_ip", "sourceIPAddress", "destination_ip"]
        for field in ip_fields:
            if field in source:
                match = self.threat_intel_lookup.check_ip(source[field])
                if match:
                    matches.append(match)

        # Check domains
        domain_fields = ["domain", "hostname", "url"]
        for field in domain_fields:
            if field in source:
                match = self.threat_intel_lookup.check_domain(source[field])
                if match:
                    matches.append(match)

        # Check hashes
        hash_fields = ["file_hash", "md5", "sha256", "sha1"]
        for field in hash_fields:
            if field in source:
                match = self.threat_intel_lookup.check_hash(source[field])
                if match:
                    matches.append(match)

        return matches

    def _lookup_fp_rate(self, alert: Dict[str, Any]) -> Optional[float]:
        """Look up historical FP rate for the rule."""
        if not self.fp_rate_lookup:
            return None

        rule_id = alert.get("rule_id", "")
        if rule_id:
            return self.fp_rate_lookup.get_fp_rate(rule_id)

        return None

    def _generate_explanation(
        self,
        score: PriorityScore,
        asset_info: Optional[AssetInfo],
        user_info: Optional[UserInfo],
        threat_intel_matches: Optional[List[ThreatIntelMatch]]
    ) -> str:
        """Generate human-readable explanation of priority."""
        parts = []

        parts.append(f"Priority {score.final_priority.name} (score: {score.final_score:.1f}/100)")

        if score.boosters:
            parts.append(f"Boosted by: {', '.join(score.boosters)}")

        if score.reducers:
            parts.append(f"Reduced by: {', '.join(score.reducers)}")

        if asset_info and asset_info.criticality in ["critical", "high"]:
            parts.append(f"Affects {asset_info.criticality} criticality asset")

        if user_info and user_info.is_privileged:
            parts.append("Involves privileged user account")

        if threat_intel_matches:
            parts.append(f"{len(threat_intel_matches)} threat intelligence match(es)")

        return ". ".join(parts) + "."


# Lookup interfaces
class AssetLookup:
    """Interface for asset information lookup."""

    def get_asset(self, asset_id: str) -> Optional[AssetInfo]:
        """Get asset information."""
        raise NotImplementedError


class UserLookup:
    """Interface for user information lookup."""

    def get_user(self, user_id: str) -> Optional[UserInfo]:
        """Get user information."""
        raise NotImplementedError


class ThreatIntelLookup:
    """Interface for threat intelligence lookup."""

    def check_ip(self, ip: str) -> Optional[ThreatIntelMatch]:
        """Check IP against threat intel."""
        raise NotImplementedError

    def check_domain(self, domain: str) -> Optional[ThreatIntelMatch]:
        """Check domain against threat intel."""
        raise NotImplementedError

    def check_hash(self, file_hash: str) -> Optional[ThreatIntelMatch]:
        """Check hash against threat intel."""
        raise NotImplementedError


class FPRateLookup:
    """Interface for FP rate lookup."""

    def get_fp_rate(self, rule_id: str) -> Optional[float]:
        """Get historical FP rate for a rule."""
        raise NotImplementedError


def calculate_priority(
    alert: Dict[str, Any],
    config: Optional[PriorityConfig] = None
) -> PriorityScore:
    """Convenience function to calculate alert priority."""
    scorer = AlertPriorityScorer(config)
    return scorer.calculate_priority(alert)
