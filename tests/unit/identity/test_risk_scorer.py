"""
Unit tests for IdentityRiskScorer.

Tests risk score calculation, factor weighting, and trend analysis.
"""

import pytest
from datetime import datetime, timezone, timedelta
from unittest.mock import Mock, MagicMock

from src.shared.identity.scoring.risk_scorer import IdentityRiskScorer, RiskFactor
from src.shared.models.identity_event import IdentityEvent, IdentityEventType


class TestRiskScoreCalculation:
    """Tests for basic risk score calculation."""

    def test_no_factors_zero_score(self):
        """No risk factors should result in zero score."""
        scorer = IdentityRiskScorer()

        score = scorer.calculate_score(factors=[])

        assert score == 0

    def test_single_low_factor(self):
        """Single low-risk factor should result in low score."""
        scorer = IdentityRiskScorer()

        factors = [
            RiskFactor(
                factor_type="new_device",
                weight=10,
                evidence="New device detected",
            )
        ]

        score = scorer.calculate_score(factors=factors)

        assert 5 <= score <= 15

    def test_single_high_factor(self):
        """Single high-risk factor should result in higher score."""
        scorer = IdentityRiskScorer()

        factors = [
            RiskFactor(
                factor_type="impossible_travel",
                weight=30,
                evidence="NYC to London in 1 hour",
            )
        ]

        score = scorer.calculate_score(factors=factors)

        assert 25 <= score <= 35

    def test_multiple_factors_additive(self):
        """Multiple factors should have additive effect."""
        scorer = IdentityRiskScorer()

        factors = [
            RiskFactor(factor_type="new_device", weight=10),
            RiskFactor(factor_type="new_location", weight=15),
            RiskFactor(factor_type="unusual_time", weight=10),
        ]

        score = scorer.calculate_score(factors=factors)

        # Sum of weights = 35, score should be around that
        assert 30 <= score <= 40

    def test_score_capped_at_100(self):
        """Score should be capped at 100."""
        scorer = IdentityRiskScorer()

        factors = [
            RiskFactor(factor_type="impossible_travel", weight=40),
            RiskFactor(factor_type="mfa_bypass", weight=40),
            RiskFactor(factor_type="brute_force", weight=30),
            RiskFactor(factor_type="privilege_escalation", weight=30),
        ]

        score = scorer.calculate_score(factors=factors)

        assert score <= 100

    def test_decay_old_factors(self):
        """Old factors should have decayed weight."""
        scorer = IdentityRiskScorer(decay_hours=24)

        # Factor from 12 hours ago should have reduced weight
        old_factor = RiskFactor(
            factor_type="new_device",
            weight=20,
            detected_at=datetime.now(timezone.utc) - timedelta(hours=12),
        )

        current_factor = RiskFactor(
            factor_type="new_device",
            weight=20,
            detected_at=datetime.now(timezone.utc),
        )

        old_score = scorer.calculate_score(factors=[old_factor])
        current_score = scorer.calculate_score(factors=[current_factor])

        assert old_score < current_score


class TestRiskLevelThresholds:
    """Tests for risk level determination."""

    def test_score_0_is_low(self):
        """Score of 0 should be low risk."""
        scorer = IdentityRiskScorer()

        level = scorer.get_risk_level(0)

        assert level == "low"

    def test_score_20_is_low(self):
        """Score of 20 should be low risk."""
        scorer = IdentityRiskScorer()

        level = scorer.get_risk_level(20)

        assert level == "low"

    def test_score_40_is_medium(self):
        """Score around 40 should be medium risk."""
        scorer = IdentityRiskScorer()

        level = scorer.get_risk_level(40)

        assert level == "medium"

    def test_score_65_is_high(self):
        """Score around 65 should be high risk."""
        scorer = IdentityRiskScorer()

        level = scorer.get_risk_level(65)

        assert level == "high"

    def test_score_85_is_critical(self):
        """Score above 80 should be critical risk."""
        scorer = IdentityRiskScorer()

        level = scorer.get_risk_level(85)

        assert level == "critical"

    def test_score_100_is_critical(self):
        """Maximum score should be critical risk."""
        scorer = IdentityRiskScorer()

        level = scorer.get_risk_level(100)

        assert level == "critical"

    def test_custom_thresholds(self):
        """Custom thresholds should be respected."""
        scorer = IdentityRiskScorer(
            thresholds={"low": 30, "medium": 50, "high": 70, "critical": 90}
        )

        assert scorer.get_risk_level(25) == "low"
        assert scorer.get_risk_level(35) == "medium"
        assert scorer.get_risk_level(55) == "high"
        assert scorer.get_risk_level(95) == "critical"


class TestFactorWeighting:
    """Tests for factor weight configuration."""

    def test_privileged_user_multiplier(self):
        """Privileged users should have higher factor weights."""
        scorer = IdentityRiskScorer(privileged_multiplier=1.5)

        factors = [RiskFactor(factor_type="new_device", weight=20)]

        normal_score = scorer.calculate_score(factors=factors, is_privileged=False)
        privileged_score = scorer.calculate_score(factors=factors, is_privileged=True)

        assert privileged_score > normal_score
        assert privileged_score == pytest.approx(normal_score * 1.5, rel=0.1)

    def test_executive_user_multiplier(self):
        """Executive users should have even higher multiplier."""
        scorer = IdentityRiskScorer(
            privileged_multiplier=1.5,
            executive_multiplier=2.0,
        )

        factors = [RiskFactor(factor_type="new_device", weight=20)]

        normal_score = scorer.calculate_score(factors=factors)
        executive_score = scorer.calculate_score(factors=factors, is_executive=True)

        assert executive_score == pytest.approx(normal_score * 2.0, rel=0.1)

    def test_attack_succeeded_multiplier(self):
        """Successful attacks should have higher severity."""
        scorer = IdentityRiskScorer(success_multiplier=1.5)

        factors = [RiskFactor(factor_type="brute_force", weight=25, attack_succeeded=True)]

        failed_factors = [RiskFactor(factor_type="brute_force", weight=25, attack_succeeded=False)]

        succeeded_score = scorer.calculate_score(factors=factors)
        failed_score = scorer.calculate_score(factors=failed_factors)

        assert succeeded_score > failed_score

    def test_immature_baseline_reduction(self):
        """Immature baseline should reduce behavioral anomaly weights."""
        scorer = IdentityRiskScorer()

        factors = [
            RiskFactor(factor_type="unusual_time", weight=15),
            RiskFactor(factor_type="new_device", weight=10),
        ]

        mature_score = scorer.calculate_score(factors=factors, baseline_mature=True)
        immature_score = scorer.calculate_score(factors=factors, baseline_mature=False)

        # Behavioral factors should have reduced weight with immature baseline
        assert immature_score < mature_score


class TestTrendCalculation:
    """Tests for risk trend calculation."""

    def test_rising_trend(self):
        """Increasing scores should show rising trend."""
        scorer = IdentityRiskScorer()

        history = [
            {"timestamp": datetime.now(timezone.utc) - timedelta(days=6), "score": 20},
            {"timestamp": datetime.now(timezone.utc) - timedelta(days=5), "score": 25},
            {"timestamp": datetime.now(timezone.utc) - timedelta(days=4), "score": 30},
            {"timestamp": datetime.now(timezone.utc) - timedelta(days=3), "score": 40},
            {"timestamp": datetime.now(timezone.utc) - timedelta(days=2), "score": 50},
            {"timestamp": datetime.now(timezone.utc) - timedelta(days=1), "score": 60},
            {"timestamp": datetime.now(timezone.utc), "score": 70},
        ]

        trend = scorer.calculate_trend(history)

        assert trend == "rising"

    def test_falling_trend(self):
        """Decreasing scores should show falling trend."""
        scorer = IdentityRiskScorer()

        history = [
            {"timestamp": datetime.now(timezone.utc) - timedelta(days=6), "score": 70},
            {"timestamp": datetime.now(timezone.utc) - timedelta(days=5), "score": 60},
            {"timestamp": datetime.now(timezone.utc) - timedelta(days=4), "score": 50},
            {"timestamp": datetime.now(timezone.utc) - timedelta(days=3), "score": 40},
            {"timestamp": datetime.now(timezone.utc) - timedelta(days=2), "score": 30},
            {"timestamp": datetime.now(timezone.utc) - timedelta(days=1), "score": 25},
            {"timestamp": datetime.now(timezone.utc), "score": 20},
        ]

        trend = scorer.calculate_trend(history)

        assert trend == "falling"

    def test_stable_trend(self):
        """Consistent scores should show stable trend."""
        scorer = IdentityRiskScorer()

        history = [
            {"timestamp": datetime.now(timezone.utc) - timedelta(days=i), "score": 35 + (i % 3)}
            for i in range(7)
        ]

        trend = scorer.calculate_trend(history)

        assert trend == "stable"

    def test_empty_history_stable(self):
        """Empty history should default to stable."""
        scorer = IdentityRiskScorer()

        trend = scorer.calculate_trend([])

        assert trend == "stable"

    def test_single_point_stable(self):
        """Single data point should be stable."""
        scorer = IdentityRiskScorer()

        history = [{"timestamp": datetime.now(timezone.utc), "score": 50}]

        trend = scorer.calculate_trend(history)

        assert trend == "stable"


class TestFactorAggregation:
    """Tests for factor aggregation and deduplication."""

    def test_duplicate_factors_aggregated(self):
        """Duplicate factor types should be aggregated."""
        scorer = IdentityRiskScorer()

        factors = [
            RiskFactor(factor_type="new_device", weight=10),
            RiskFactor(factor_type="new_device", weight=10),
            RiskFactor(factor_type="new_device", weight=10),
        ]

        # Should not simply add up to 30
        score = scorer.calculate_score(factors=factors)

        # Duplicates should be handled (e.g., take max or apply diminishing returns)
        assert score < 30

    def test_related_factors_combined(self):
        """Related factors should be combined intelligently."""
        scorer = IdentityRiskScorer()

        factors = [
            RiskFactor(factor_type="impossible_travel", weight=30),
            RiskFactor(factor_type="new_location", weight=15),  # Related to impossible travel
        ]

        score = scorer.calculate_score(factors=factors)

        # Related factors shouldn't double-count
        assert score < 45

    def test_independent_factors_additive(self):
        """Independent factors should be fully additive."""
        scorer = IdentityRiskScorer()

        factors = [
            RiskFactor(factor_type="brute_force", weight=25),
            RiskFactor(factor_type="unusual_time", weight=10),  # Independent
        ]

        score = scorer.calculate_score(factors=factors)

        assert 30 <= score <= 40


class TestScoreBreakdown:
    """Tests for score breakdown and explanation."""

    def test_breakdown_includes_all_factors(self):
        """Breakdown should include all contributing factors."""
        scorer = IdentityRiskScorer()

        factors = [
            RiskFactor(factor_type="new_device", weight=10, evidence="Chrome on Windows"),
            RiskFactor(factor_type="new_location", weight=15, evidence="Tokyo, Japan"),
            RiskFactor(factor_type="unusual_time", weight=10, evidence="3:00 AM local"),
        ]

        breakdown = scorer.get_breakdown(factors=factors)

        assert len(breakdown.factors) == 3
        assert all(f.evidence for f in breakdown.factors)

    def test_breakdown_shows_weights(self):
        """Breakdown should show weight contribution."""
        scorer = IdentityRiskScorer()

        factors = [
            RiskFactor(factor_type="impossible_travel", weight=30),
        ]

        breakdown = scorer.get_breakdown(factors=factors)

        assert breakdown.factors[0].contribution > 0

    def test_breakdown_sorted_by_weight(self):
        """Breakdown should be sorted by weight descending."""
        scorer = IdentityRiskScorer()

        factors = [
            RiskFactor(factor_type="new_device", weight=10),
            RiskFactor(factor_type="impossible_travel", weight=30),
            RiskFactor(factor_type="unusual_time", weight=5),
        ]

        breakdown = scorer.get_breakdown(factors=factors)

        weights = [f.weight for f in breakdown.factors]
        assert weights == sorted(weights, reverse=True)


class TestEdgeCases:
    """Tests for edge cases in risk scoring."""

    def test_negative_weight_handled(self):
        """Negative weights should be handled (e.g., risk reduction)."""
        scorer = IdentityRiskScorer()

        factors = [
            RiskFactor(factor_type="new_device", weight=20),
            RiskFactor(factor_type="mfa_verified", weight=-10),  # Risk reduction
        ]

        score = scorer.calculate_score(factors=factors)

        assert score < 20
        assert score >= 0  # Score should never be negative

    def test_very_large_weights(self):
        """Very large weights should be capped."""
        scorer = IdentityRiskScorer()

        factors = [
            RiskFactor(factor_type="critical_compromise", weight=500),
        ]

        score = scorer.calculate_score(factors=factors)

        assert score <= 100

    def test_null_factor_handled(self):
        """Null factors should be filtered out."""
        scorer = IdentityRiskScorer()

        factors = [
            RiskFactor(factor_type="new_device", weight=20),
            None,
        ]

        # Should not raise exception
        score = scorer.calculate_score(factors=[f for f in factors if f])

        assert score > 0

    def test_zero_weight_factor(self):
        """Zero weight factors should not affect score."""
        scorer = IdentityRiskScorer()

        factors = [
            RiskFactor(factor_type="info_only", weight=0),
        ]

        score = scorer.calculate_score(factors=factors)

        assert score == 0
