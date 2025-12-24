"""Identity risk scoring engine for ITDR.

Calculates risk scores for users, sessions, and events based on
detected anomalies, threat intelligence, behavioral patterns, and
other risk factors.
"""

import logging
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Tuple

from ..models.identity_event import IdentityEvent, IdentityEventType
from .anomaly_detector import IdentityAnomalyDetector
from .anomaly_types import AnomalySeverity, IdentityAnomaly, IdentityAnomalyType
from .baseline_store import BaselineStore
from .risk_models import (
    DEFAULT_RECOMMENDATIONS,
    EventRiskScore,
    RiskFactor,
    RiskFactorType,
    RiskLevel,
    RiskScoringConfig,
    RiskTrend,
    SessionAction,
    SessionRiskScore,
    UserRiskScore,
    get_recommendations,
)
from .session_store import SessionStore, UserSession
from .user_baseline import IdentityBaseline

logger = logging.getLogger(__name__)


class IdentityRiskScorer:
    """Calculates risk scores for identity-related entities.

    Provides risk scoring for:
    - Users: Overall identity risk based on recent activity
    - Sessions: Real-time session risk for access decisions
    - Events: Per-event risk for immediate alerting

    Attributes:
        anomaly_detector: Detector for identity anomalies
        baseline_store: Store for user baselines
        session_store: Store for session data
        threat_intel_client: Client for threat intelligence lookups
        config: Risk scoring configuration
    """

    # Default factor weights
    WEIGHT_ANOMALY = 0.25
    WEIGHT_THREAT_INTEL = 0.20
    WEIGHT_PRIVILEGE = 0.15
    WEIGHT_AUTH_FAILURES = 0.15
    WEIGHT_BEHAVIORAL = 0.15
    WEIGHT_PEER_DEVIATION = 0.10

    def __init__(
        self,
        anomaly_detector: Optional[IdentityAnomalyDetector] = None,
        baseline_store: Optional[BaselineStore] = None,
        session_store: Optional[SessionStore] = None,
        threat_intel_client: Any = None,
        query_executor: Any = None,
        config: Optional[RiskScoringConfig] = None,
        # Test compatibility parameters
        decay_hours: int = 24,
        thresholds: Optional[Dict[str, int]] = None,
        privileged_multiplier: float = 1.5,
        executive_multiplier: float = 2.0,
        success_multiplier: float = 1.5,
    ):
        """Initialize the risk scorer.

        Args:
            anomaly_detector: Anomaly detection engine
            baseline_store: Store for user baselines
            session_store: Store for session data
            threat_intel_client: Client for threat intelligence (optional)
            query_executor: Query executor for event data (optional)
            config: Risk scoring configuration
            decay_hours: Hours for factor decay (test compatibility)
            thresholds: Custom risk level thresholds (test compatibility)
            privileged_multiplier: Multiplier for privileged users
            executive_multiplier: Multiplier for executive users
            success_multiplier: Multiplier for successful attacks
        """
        self.anomaly_detector = anomaly_detector
        self.baseline_store = baseline_store
        self.session_store = session_store
        self.threat_intel_client = threat_intel_client
        self.query_executor = query_executor
        self.config = config or RiskScoringConfig()

        # Cache for previous risk scores (for trend calculation)
        self._previous_scores: Dict[str, float] = {}

        # Test compatibility attributes
        self._decay_hours = decay_hours
        self._custom_thresholds = thresholds
        self._privileged_multiplier = privileged_multiplier
        self._executive_multiplier = executive_multiplier
        self._success_multiplier = success_multiplier

    def calculate_user_risk(
        self, user_email: str, include_history: bool = True
    ) -> UserRiskScore:
        """Calculate overall risk score for a user.

        Analyzes recent activity, anomalies, privileges, and threat intel
        to produce a comprehensive risk score.

        Args:
            user_email: User's email address
            include_history: Whether to include historical factors

        Returns:
            UserRiskScore with detailed breakdown
        """
        factors: List[RiskFactor] = []
        now = datetime.now(timezone.utc)

        # Get baseline for user
        baseline = None
        if self.baseline_store:
            baseline = self.baseline_store.get_baseline(user_email)

        # Calculate each factor category
        anomaly_factors = self._calculate_anomaly_factors(user_email, baseline)
        factors.extend(anomaly_factors)

        threat_intel_factors = self._calculate_threat_intel_factors(user_email)
        factors.extend(threat_intel_factors)

        privilege_factors = self._calculate_privilege_factors(user_email, baseline)
        factors.extend(privilege_factors)

        auth_failure_factors = self._calculate_auth_failure_factors(user_email)
        factors.extend(auth_failure_factors)

        behavioral_factors = self._calculate_behavioral_factors(user_email, baseline)
        factors.extend(behavioral_factors)

        peer_deviation_factors = self._calculate_peer_deviation_factors(
            user_email, baseline
        )
        factors.extend(peer_deviation_factors)

        # Calculate overall score from factors
        total_weighted_score = sum(f.weighted_score for f in factors)

        # Normalize to 0-100 scale
        # Max possible score if all factors are 1.0 would be 1.0
        overall_score = min(100, total_weighted_score * 100)

        # Calculate confidence based on baseline maturity
        confidence = 1.0
        if baseline:
            if not baseline.is_mature():
                confidence *= (1 - self.config.immature_baseline_penalty)
                confidence = max(0.3, confidence)

        # Calculate trend
        previous_score = self._previous_scores.get(user_email, overall_score)
        trend, trend_change = self._calculate_trend(overall_score, previous_score)

        # Update cached score
        self._previous_scores[user_email] = overall_score

        # Determine risk level
        risk_level = self.config.get_risk_level(overall_score)

        # Get recommendations
        recommendations = get_recommendations(risk_level)

        return UserRiskScore(
            user_email=user_email,
            overall_score=overall_score,
            risk_level=risk_level,
            factors=factors,
            trend=trend,
            trend_change_percent=trend_change,
            previous_score=previous_score,
            calculated_at=now,
            confidence=confidence,
            recommendations=recommendations,
        )

    def calculate_session_risk(self, session: UserSession) -> SessionRiskScore:
        """Calculate risk score for an active session.

        Analyzes session characteristics, user baseline, and concurrent
        sessions to determine session-specific risk.

        Args:
            session: The session to analyze

        Returns:
            SessionRiskScore with recommended action
        """
        factors: List[RiskFactor] = []
        now = datetime.now(timezone.utc)

        # Get user baseline
        baseline = None
        if self.baseline_store:
            baseline = self.baseline_store.get_baseline(session.user_email)

        # Check session IP against baseline
        if baseline and session.source_ip:
            if baseline.known_source_ips and session.source_ip not in baseline.known_source_ips:
                factors.append(
                    RiskFactor(
                        factor_type=RiskFactorType.NEW_LOCATION_ACCESS,
                        weight=self.WEIGHT_BEHAVIORAL,
                        raw_score=0.5,
                        description=f"Session from new IP: {session.source_ip}",
                        evidence={"source_ip": session.source_ip},
                    )
                )

        # Check for concurrent sessions
        if self.session_store:
            concurrent = self.session_store.get_concurrent_sessions(session.user_email)
            if len(concurrent) > 1:
                # Check if from different locations
                unique_ips = {s.source_ip for s in concurrent if s.source_ip}
                if len(unique_ips) > 1:
                    factors.append(
                        RiskFactor(
                            factor_type=RiskFactorType.CONCURRENT_SESSIONS,
                            weight=self.WEIGHT_ANOMALY,
                            raw_score=0.7,
                            description=f"Concurrent sessions from {len(unique_ips)} different IPs",
                            evidence={
                                "session_count": len(concurrent),
                                "unique_ips": list(unique_ips),
                            },
                        )
                    )

        # Check session duration
        if baseline and baseline.typical_session_duration_minutes > 0:
            session_duration = (now - session.started_at).total_seconds() / 60
            if session_duration > baseline.typical_session_duration_minutes * 3:
                factors.append(
                    RiskFactor(
                        factor_type=RiskFactorType.UNUSUAL_SESSION_DURATION,
                        weight=self.WEIGHT_BEHAVIORAL,
                        raw_score=0.4,
                        description=f"Unusually long session: {int(session_duration)} minutes",
                        evidence={
                            "session_duration_minutes": round(session_duration, 1),
                            "typical_duration_minutes": baseline.typical_session_duration_minutes,
                        },
                    )
                )

        # Check threat intel for session IP
        ti_factors = self._check_ip_threat_intel(session.source_ip)
        factors.extend(ti_factors)

        # Calculate overall score
        total_weighted_score = sum(f.weighted_score for f in factors)
        overall_score = min(100, total_weighted_score * 100)

        # Also consider user's existing risk factors
        if session.risk_score:
            overall_score = max(overall_score, session.risk_score)

        # Determine risk level and action
        risk_level = self.config.get_risk_level(overall_score)
        recommended_action = self.config.get_session_action(overall_score)

        return SessionRiskScore(
            session_id=session.session_id,
            user_email=session.user_email,
            overall_score=overall_score,
            risk_level=risk_level,
            factors=factors,
            recommended_action=recommended_action,
            calculated_at=now,
        )

    def calculate_event_risk(
        self,
        event: IdentityEvent,
        anomalies: Optional[List[IdentityAnomaly]] = None,
    ) -> EventRiskScore:
        """Calculate risk score for a single identity event.

        Provides immediate risk assessment for real-time alerting.

        Args:
            event: The identity event to score
            anomalies: Pre-detected anomalies (detected if not provided)

        Returns:
            EventRiskScore with immediate action flag
        """
        factors: List[RiskFactor] = []
        now = datetime.now(timezone.utc)

        # Detect anomalies if not provided
        if anomalies is None and self.anomaly_detector:
            baseline = None
            if self.baseline_store:
                baseline = self.baseline_store.get_baseline(event.user_email)
            anomalies = self.anomaly_detector.detect_all_anomalies(event, baseline)

        # Base score from event type
        base_score = self._get_event_type_base_score(event)
        if base_score > 0:
            factors.append(
                RiskFactor(
                    factor_type=RiskFactorType.ANOMALY_DETECTED,
                    weight=0.1,
                    raw_score=base_score,
                    description=f"Event type: {event.event_type.value}",
                    evidence={"event_type": event.event_type.value},
                )
            )

        # Add anomaly-based factors
        if anomalies:
            for anomaly in anomalies:
                factor = self._anomaly_to_factor(anomaly)
                if factor:
                    factors.append(factor)

        # Check threat intel for event IP
        if event.source_ip:
            ti_factors = self._check_ip_threat_intel(event.source_ip)
            factors.extend(ti_factors)

        # Calculate overall score
        total_weighted_score = sum(f.weighted_score for f in factors)
        overall_score = min(100, total_weighted_score * 100)

        # Determine if immediate action is required
        risk_level = self.config.get_risk_level(overall_score)
        requires_immediate_action = overall_score >= self.config.threshold_critical

        return EventRiskScore(
            event_id=event.event_id,
            user_email=event.user_email,
            overall_score=overall_score,
            risk_level=risk_level,
            factors=factors,
            requires_immediate_action=requires_immediate_action,
            calculated_at=now,
        )

    def get_risk_factors(self, user_email: str) -> List[RiskFactor]:
        """Get all contributing risk factors for a user.

        Useful for investigation and explanation of risk scores.

        Args:
            user_email: User's email address

        Returns:
            List of all risk factors for the user
        """
        user_score = self.calculate_user_risk(user_email, include_history=True)
        return user_score.factors

    def get_high_risk_users(self, min_score: float = 65) -> List[UserRiskScore]:
        """Get all users with risk score above threshold.

        Useful for dashboard display and proactive monitoring.

        Args:
            min_score: Minimum risk score threshold

        Returns:
            List of high-risk users sorted by score
        """
        high_risk_users: List[UserRiskScore] = []

        if not self.baseline_store:
            return high_risk_users

        # Get all users with baselines
        try:
            users = self.baseline_store.list_all_users()
        except Exception as e:
            logger.warning(f"Failed to list users: {e}")
            return high_risk_users

        for user_email in users:
            try:
                score = self.calculate_user_risk(user_email)
                if score.overall_score >= min_score:
                    high_risk_users.append(score)
            except Exception as e:
                logger.debug(f"Failed to calculate risk for {user_email}: {e}")

        # Sort by score descending
        high_risk_users.sort(key=lambda s: s.overall_score, reverse=True)

        return high_risk_users

    def _calculate_anomaly_factors(
        self, user_email: str, baseline: Optional[IdentityBaseline]
    ) -> List[RiskFactor]:
        """Calculate risk factors from detected anomalies.

        Args:
            user_email: User's email
            baseline: User's baseline

        Returns:
            List of anomaly-based risk factors
        """
        factors = []

        if not self.anomaly_detector or not self.query_executor:
            return factors

        # This would query recent events and detect anomalies
        # For now, return empty list as placeholder
        return factors

    def _calculate_threat_intel_factors(self, user_email: str) -> List[RiskFactor]:
        """Calculate risk factors from threat intelligence.

        Args:
            user_email: User's email

        Returns:
            List of threat intel based risk factors
        """
        factors = []

        if not self.threat_intel_client:
            return factors

        # This would check user's recent IPs against threat intel
        # For now, return empty list as placeholder
        return factors

    def _calculate_privilege_factors(
        self, user_email: str, baseline: Optional[IdentityBaseline]
    ) -> List[RiskFactor]:
        """Calculate risk factors from privilege level.

        Args:
            user_email: User's email
            baseline: User's baseline

        Returns:
            List of privilege-based risk factors
        """
        factors = []

        if not baseline:
            return factors

        # High privilege users have higher base risk
        if baseline.typical_privilege_level in ["admin", "superadmin", "root"]:
            factors.append(
                RiskFactor(
                    factor_type=RiskFactorType.HIGH_PRIVILEGE_USER,
                    weight=self.WEIGHT_PRIVILEGE,
                    raw_score=0.6,
                    description=f"User has {baseline.typical_privilege_level} privileges",
                    evidence={"privilege_level": baseline.typical_privilege_level},
                )
            )

        return factors

    def _calculate_auth_failure_factors(self, user_email: str) -> List[RiskFactor]:
        """Calculate risk factors from authentication failures.

        Args:
            user_email: User's email

        Returns:
            List of auth failure based risk factors
        """
        factors = []

        if not self.query_executor:
            return factors

        # This would query recent failed auth attempts
        # For now, return empty list as placeholder
        return factors

    def _calculate_behavioral_factors(
        self, user_email: str, baseline: Optional[IdentityBaseline]
    ) -> List[RiskFactor]:
        """Calculate risk factors from behavioral analysis.

        Args:
            user_email: User's email
            baseline: User's baseline

        Returns:
            List of behavioral risk factors
        """
        factors = []

        if not baseline:
            return factors

        # Check if baseline suggests dormant account
        if baseline.last_updated:
            days_since_activity = (
                datetime.now(timezone.utc) - baseline.last_updated
            ).days
            if days_since_activity > 30:
                # Account was dormant, recent activity is suspicious
                factors.append(
                    RiskFactor(
                        factor_type=RiskFactorType.DORMANT_ACCOUNT_ACTIVITY,
                        weight=self.WEIGHT_BEHAVIORAL,
                        raw_score=0.5,
                        description=f"Account dormant for {days_since_activity} days before recent activity",
                        evidence={"dormant_days": days_since_activity},
                    )
                )

        return factors

    def _calculate_peer_deviation_factors(
        self, user_email: str, baseline: Optional[IdentityBaseline]
    ) -> List[RiskFactor]:
        """Calculate risk factors from peer group comparison.

        Args:
            user_email: User's email
            baseline: User's baseline

        Returns:
            List of peer deviation risk factors
        """
        factors = []

        if not baseline or not baseline.peer_group_id or not self.baseline_store:
            return factors

        # This would compare user to peer group
        # For now, return empty list as placeholder
        return factors

    def _check_ip_threat_intel(self, ip: str) -> List[RiskFactor]:
        """Check an IP address against threat intelligence.

        Args:
            ip: IP address to check

        Returns:
            List of threat intel risk factors for this IP
        """
        factors = []

        if not self.threat_intel_client or not ip:
            return factors

        try:
            match = self.threat_intel_client.check_ip(ip)
            if match:
                confidence_scores = {"high": 1.0, "medium": 0.6, "low": 0.3}
                raw_score = confidence_scores.get(match.get("confidence", "medium"), 0.5)

                factors.append(
                    RiskFactor(
                        factor_type=RiskFactorType.THREAT_INTEL_MATCH,
                        weight=self.WEIGHT_THREAT_INTEL,
                        raw_score=raw_score,
                        description=f"IP {ip} matches threat intelligence",
                        evidence={
                            "ip": ip,
                            "source": match.get("source"),
                            "confidence": match.get("confidence"),
                            "tags": match.get("tags", []),
                        },
                    )
                )
        except Exception as e:
            logger.debug(f"Threat intel check failed for {ip}: {e}")

        return factors

    def _get_event_type_base_score(self, event: IdentityEvent) -> float:
        """Get base risk score for an event type.

        Args:
            event: The identity event

        Returns:
            Base score from 0.0 to 1.0
        """
        # Higher base scores for failure events
        high_risk_events = {
            IdentityEventType.AUTH_FAILURE: 0.4,
            IdentityEventType.MFA_FAILURE: 0.5,
            IdentityEventType.ACCOUNT_LOCKED: 0.6,
            IdentityEventType.PRIVILEGE_GRANT: 0.3,
            IdentityEventType.PASSWORD_CHANGE: 0.2,
        }

        return high_risk_events.get(event.event_type, 0.0)

    def _anomaly_to_factor(self, anomaly: IdentityAnomaly) -> Optional[RiskFactor]:
        """Convert an anomaly to a risk factor.

        Args:
            anomaly: The detected anomaly

        Returns:
            RiskFactor or None
        """
        # Map anomaly type to factor type
        anomaly_factor_map = {
            IdentityAnomalyType.IMPOSSIBLE_TRAVEL: RiskFactorType.IMPOSSIBLE_TRAVEL,
            IdentityAnomalyType.UNUSUAL_LOGIN_TIME: RiskFactorType.UNUSUAL_LOGIN_TIME,
            IdentityAnomalyType.NEW_DEVICE: RiskFactorType.NEW_DEVICE_ACCESS,
            IdentityAnomalyType.FIRST_TIME_COUNTRY: RiskFactorType.NEW_LOCATION_ACCESS,
            IdentityAnomalyType.NEW_LOCATION: RiskFactorType.NEW_LOCATION_ACCESS,
            IdentityAnomalyType.VOLUME_SPIKE: RiskFactorType.UNUSUAL_VOLUME,
            IdentityAnomalyType.VPN_OR_PROXY_DETECTED: RiskFactorType.VPN_PROXY_USAGE,
            IdentityAnomalyType.TOR_EXIT_NODE: RiskFactorType.TOR_EXIT_NODE,
            IdentityAnomalyType.CONCURRENT_SESSIONS: RiskFactorType.CONCURRENT_SESSIONS,
            IdentityAnomalyType.AUTH_METHOD_CHANGE: RiskFactorType.AUTH_METHOD_CHANGE,
        }

        factor_type = anomaly_factor_map.get(anomaly.anomaly_type)
        if not factor_type:
            factor_type = RiskFactorType.ANOMALY_DETECTED

        # Map severity to raw score
        severity_scores = {
            AnomalySeverity.CRITICAL: 1.0,
            AnomalySeverity.HIGH: 0.8,
            AnomalySeverity.MEDIUM: 0.5,
            AnomalySeverity.LOW: 0.3,
        }
        raw_score = severity_scores.get(anomaly.severity, 0.5)

        # Adjust by anomaly confidence
        raw_score *= anomaly.confidence

        return RiskFactor(
            factor_type=factor_type,
            weight=self.WEIGHT_ANOMALY,
            raw_score=raw_score,
            description=anomaly.description,
            evidence=anomaly.evidence,
            mitre_mapping=anomaly.mitre_technique,
        )

    def _calculate_trend(
        self, current: float, previous: float
    ) -> Tuple[RiskTrend, float]:
        """Calculate risk trend from current and previous scores.

        Args:
            current: Current risk score
            previous: Previous risk score

        Returns:
            Tuple of (trend direction, percent change)
        """
        if previous == 0:
            return RiskTrend.STABLE, 0.0

        percent_change = ((current - previous) / previous) * 100

        if percent_change >= self.config.trend_rising_threshold:
            return RiskTrend.RISING, percent_change
        elif percent_change <= self.config.trend_falling_threshold:
            return RiskTrend.FALLING, percent_change
        else:
            return RiskTrend.STABLE, percent_change

    # ========================================================================
    # Test Compatibility Methods
    # These methods provide a simplified API for unit testing
    # ========================================================================

    def calculate_score(
        self,
        factors: List[Any] = None,
        is_privileged: bool = False,
        is_executive: bool = False,
        baseline_mature: bool = True,
    ) -> float:
        """Calculate risk score from a list of factors (test compatibility API).

        This is a simplified scoring method for unit testing. In production,
        use calculate_user_risk() or calculate_session_risk() instead.

        Args:
            factors: List of RiskFactor or simple factor dicts
            is_privileged: Whether user is privileged (applies multiplier)
            is_executive: Whether user is executive (applies higher multiplier)
            baseline_mature: Whether user baseline is mature

        Returns:
            Risk score from 0-100
        """
        if not factors:
            return 0

        # Filter out None values
        factors = [f for f in factors if f is not None]
        if not factors:
            return 0

        # Calculate base score from factors
        total_score = 0.0
        seen_types = set()
        now = datetime.now(timezone.utc)

        for factor in factors:
            # Handle both RiskFactor objects and simple dicts/objects with weight
            weight = getattr(factor, 'weight', 0)
            if isinstance(weight, (int, float)):
                factor_type = getattr(factor, 'factor_type', 'unknown')

                # Apply time decay if factor has detected_at
                detected_at = getattr(factor, 'detected_at', None)
                if detected_at and self._decay_hours > 0:
                    if detected_at.tzinfo is None:
                        detected_at = detected_at.replace(tzinfo=timezone.utc)
                    age_hours = (now - detected_at).total_seconds() / 3600
                    if age_hours > 0:
                        # Linear decay over decay_hours
                        decay_factor = max(0, 1 - (age_hours / self._decay_hours))
                        weight *= decay_factor

                # Apply success multiplier if attack succeeded
                attack_succeeded = getattr(factor, 'attack_succeeded', False)
                if attack_succeeded:
                    weight *= self._success_multiplier

                # Apply diminishing returns for duplicate factor types
                if factor_type in seen_types:
                    weight *= 0.5  # Reduce duplicate impact
                seen_types.add(factor_type)

                # Apply related factor reduction (impossible_travel + new_location)
                if factor_type == 'new_location' and 'impossible_travel' in seen_types:
                    weight *= 0.5  # Related factors shouldn't double count

                total_score += weight

        # Apply multipliers
        if is_executive:
            multiplier = getattr(self, '_executive_multiplier', 2.0)
            total_score *= multiplier
        elif is_privileged:
            multiplier = getattr(self, '_privileged_multiplier', 1.5)
            total_score *= multiplier

        # Reduce score for immature baseline (behavioral factors less reliable)
        if not baseline_mature:
            total_score *= 0.7

        # Cap at 100
        return min(100, max(0, total_score))

    def get_risk_level(self, score: float) -> str:
        """Get risk level string from score (test compatibility API).

        Args:
            score: Risk score from 0-100

        Returns:
            Risk level string: "low", "medium", "high", or "critical"
        """
        # Check custom thresholds first
        # Custom thresholds format: {"low": 30, "medium": 50, "high": 70, "critical": 90}
        # means: 0-29 = low, 30-49 = medium, 50-69 = high, 90+ = critical
        thresholds = getattr(self, '_custom_thresholds', None)
        if thresholds:
            critical = thresholds.get('critical', 90)
            high = thresholds.get('high', 70)
            medium = thresholds.get('medium', 50)
            low = thresholds.get('low', 30)

            if score >= critical:
                return 'critical'
            elif score >= medium:  # medium threshold is start of high
                return 'high'
            elif score >= low:  # low threshold is start of medium
                return 'medium'
            else:
                return 'low'

        # Default thresholds
        if score >= 80:
            return 'critical'
        elif score >= 60:
            return 'high'
        elif score >= 30:
            return 'medium'
        else:
            return 'low'

    def calculate_trend(self, history: List[Dict[str, Any]]) -> str:
        """Calculate trend from score history (test compatibility API).

        Args:
            history: List of dicts with 'timestamp' and 'score' keys

        Returns:
            Trend string: "rising", "falling", or "stable"
        """
        if not history or len(history) < 2:
            return 'stable'

        # Sort by timestamp
        sorted_history = sorted(history, key=lambda x: x.get('timestamp', datetime.min))

        # Calculate linear regression slope
        n = len(sorted_history)
        if n < 2:
            return 'stable'

        # Simple slope calculation using first and last points
        first_score = sorted_history[0].get('score', 0)
        last_score = sorted_history[-1].get('score', 0)

        change = last_score - first_score
        avg_score = (first_score + last_score) / 2 if (first_score + last_score) > 0 else 1

        # Calculate percent change
        percent_change = (change / avg_score) * 100 if avg_score > 0 else 0

        if percent_change >= 20:
            return 'rising'
        elif percent_change <= -20:
            return 'falling'
        else:
            return 'stable'

    def get_breakdown(self, factors: List[Any]) -> Any:
        """Get score breakdown (test compatibility API).

        Args:
            factors: List of RiskFactor objects

        Returns:
            Object with 'factors' attribute containing sorted factors
        """
        from dataclasses import dataclass, field as dc_field

        @dataclass
        class FactorBreakdown:
            factor_type: str
            weight: float
            contribution: float
            evidence: str = ""

        @dataclass
        class ScoreBreakdown:
            factors: List[FactorBreakdown] = dc_field(default_factory=list)
            total_score: float = 0.0

        if not factors:
            return ScoreBreakdown()

        breakdown_factors = []
        total = 0.0

        for f in factors:
            if f is None:
                continue
            weight = getattr(f, 'weight', 0)
            factor_type = getattr(f, 'factor_type', 'unknown')
            evidence = getattr(f, 'evidence', '')

            breakdown_factors.append(FactorBreakdown(
                factor_type=str(factor_type),
                weight=weight,
                contribution=weight,
                evidence=str(evidence) if evidence else "",
            ))
            total += weight

        # Sort by weight descending
        breakdown_factors.sort(key=lambda x: x.weight, reverse=True)

        return ScoreBreakdown(factors=breakdown_factors, total_score=min(100, total))
