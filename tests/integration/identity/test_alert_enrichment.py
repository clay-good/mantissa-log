"""
Integration tests for identity alert enrichment.

Tests that alerts are properly enriched with risk context and baseline comparison.
"""

import pytest
from datetime import datetime, timezone, timedelta
from unittest.mock import Mock, MagicMock

from src.shared.models.identity_event import IdentityEvent, IdentityEventType, GeoLocation
from src.shared.identity.enrichment.alert_enricher import IdentityAlertEnricher
from src.shared.identity.enrichment.risk_context import RiskContextProvider
from src.shared.identity.enrichment.baseline_comparator import BaselineComparator

from tests.fixtures.identity.sample_events import (
    create_auth_success_event,
    create_auth_failure_event,
    create_privilege_grant_event,
    GEO_NYC,
    GEO_TOKYO,
    GEO_MOSCOW,
)
from tests.fixtures.identity.sample_baselines import (
    create_office_worker_baseline,
    create_remote_worker_baseline,
    create_executive_baseline,
    create_service_account_baseline,
    create_dormant_account_baseline,
)
from tests.fixtures.identity.attack_scenarios import (
    BruteForceScenario,
    ImpossibleTravelScenario,
)


class TestRiskContextEnrichment:
    """Tests for risk context enrichment."""

    def test_enrich_with_user_risk_level(self):
        """Test enrichment with user risk level."""
        enricher = IdentityAlertEnricher()

        alert = {
            "id": "alert-001",
            "type": "unusual_login",
            "user_email": "worker@example.com",
            "timestamp": datetime.now(timezone.utc),
            "severity": "medium",
        }

        user_context = {
            "risk_score": 75,
            "risk_level": "high",
            "recent_alerts": 5,
        }

        enriched = enricher.enrich_with_user_context(alert, user_context)

        assert enriched["user_risk_score"] == 75
        assert enriched["user_risk_level"] == "high"
        assert enriched["user_recent_alerts"] == 5

    def test_enrich_executive_user_higher_priority(self):
        """Test that executive users get higher priority."""
        enricher = IdentityAlertEnricher()

        alert = {
            "id": "alert-001",
            "type": "unusual_login",
            "user_email": "ceo@example.com",
            "timestamp": datetime.now(timezone.utc),
            "severity": "medium",
        }

        user_context = {
            "is_executive": True,
            "is_vip": True,
            "department": "Executive",
        }

        enriched = enricher.enrich_with_user_context(alert, user_context)

        assert enriched["is_vip_user"] is True
        assert enriched["priority_boost"] is True
        # Priority should be elevated
        assert enriched.get("priority") in ["p1", "high"]

    def test_enrich_privileged_user_context(self):
        """Test enrichment for privileged users."""
        enricher = IdentityAlertEnricher()

        alert = {
            "id": "alert-001",
            "type": "unusual_login",
            "user_email": "admin@example.com",
            "timestamp": datetime.now(timezone.utc),
            "severity": "medium",
        }

        user_context = {
            "is_privileged": True,
            "is_admin": True,
            "admin_roles": ["Global Administrator", "Security Administrator"],
        }

        enriched = enricher.enrich_with_user_context(alert, user_context)

        assert enriched["is_privileged"] is True
        assert enriched["admin_roles"] == ["Global Administrator", "Security Administrator"]

    def test_enrich_service_account_context(self):
        """Test enrichment for service accounts."""
        enricher = IdentityAlertEnricher()

        alert = {
            "id": "alert-001",
            "type": "unusual_activity",
            "user_email": "svc-automation@example.com",
            "timestamp": datetime.now(timezone.utc),
            "severity": "medium",
        }

        user_context = {
            "is_service_account": True,
            "owner": "devops-team@example.com",
            "purpose": "CI/CD automation",
        }

        enriched = enricher.enrich_with_user_context(alert, user_context)

        assert enriched["is_service_account"] is True
        assert enriched["service_account_owner"] == "devops-team@example.com"


class TestBaselineComparisonEnrichment:
    """Tests for baseline comparison enrichment."""

    def test_enrich_with_hour_deviation(self):
        """Test enrichment with login hour deviation."""
        comparator = BaselineComparator()

        baseline = create_office_worker_baseline(user_email="worker@example.com")
        # Baseline has typical hours 8-18

        event = create_auth_success_event(
            user_email="worker@example.com",
            timestamp=datetime.now(timezone.utc).replace(hour=3),  # 3 AM
        )

        comparison = comparator.compare(event, baseline)

        assert comparison["is_unusual_hour"] is True
        assert comparison["login_hour"] == 3
        assert comparison["typical_hours"] == baseline.typical_hours
        assert comparison["hour_deviation_score"] > 0

    def test_enrich_with_location_deviation(self):
        """Test enrichment with location deviation."""
        comparator = BaselineComparator()

        baseline = create_office_worker_baseline(
            user_email="worker@example.com",
            location=GEO_NYC,
        )

        event = create_auth_success_event(
            user_email="worker@example.com",
            source_geo=GEO_TOKYO,  # New location
        )

        comparison = comparator.compare(event, baseline)

        assert comparison["is_new_location"] is True
        assert comparison["login_location"]["city"] == "Tokyo"
        assert comparison["is_new_country"] is True
        assert comparison["login_location"]["country"] == "JP"

    def test_enrich_with_device_deviation(self):
        """Test enrichment with device deviation."""
        comparator = BaselineComparator()

        baseline = create_office_worker_baseline(user_email="worker@example.com")

        event = create_auth_success_event(
            user_email="worker@example.com",
            device_id="unknown-device-xyz",
            user_agent="SuspiciousBrowser/1.0",
        )

        comparison = comparator.compare(event, baseline)

        assert comparison["is_new_device"] is True
        assert comparison["device_id"] == "unknown-device-xyz"

    def test_enrich_with_volume_deviation(self):
        """Test enrichment with activity volume deviation."""
        comparator = BaselineComparator()

        baseline = create_office_worker_baseline(user_email="worker@example.com")
        baseline.avg_events_per_day = 15
        baseline.events_std_dev = 4

        # Simulate high activity day (50 events, far above normal)
        comparison = comparator.compare_daily_volume(
            user_email="worker@example.com",
            event_count=50,
            baseline=baseline,
        )

        assert comparison["is_volume_anomaly"] is True
        assert comparison["z_score"] > 2  # More than 2 std devs above mean
        assert comparison["actual_count"] == 50
        assert comparison["expected_count"] == 15

    def test_compare_with_mature_baseline(self):
        """Test comparison confidence with mature baseline."""
        comparator = BaselineComparator()

        baseline = create_office_worker_baseline(user_email="worker@example.com")
        baseline.first_seen = datetime.now(timezone.utc) - timedelta(days=90)
        baseline.event_count = 1000

        event = create_auth_success_event(
            user_email="worker@example.com",
            source_geo=GEO_TOKYO,
        )

        comparison = comparator.compare(event, baseline)

        # Should have high confidence due to mature baseline
        assert comparison["baseline_maturity"] == "mature"
        assert comparison["comparison_confidence"] > 0.8

    def test_compare_with_immature_baseline(self):
        """Test comparison with immature baseline has lower confidence."""
        comparator = BaselineComparator()

        baseline = create_office_worker_baseline(user_email="worker@example.com")
        baseline.first_seen = datetime.now(timezone.utc) - timedelta(days=5)
        baseline.event_count = 30

        event = create_auth_success_event(
            user_email="worker@example.com",
            source_geo=GEO_TOKYO,
        )

        comparison = comparator.compare(event, baseline)

        # Should have lower confidence due to immature baseline
        assert comparison["baseline_maturity"] in ["new", "learning"]
        assert comparison["comparison_confidence"] < 0.5


class TestFullAlertEnrichment:
    """Tests for complete alert enrichment pipeline."""

    def test_full_enrichment_brute_force_alert(self):
        """Test full enrichment of brute force alert."""
        enricher = IdentityAlertEnricher()

        # Generate brute force scenario
        scenario = BruteForceScenario(
            target_user="victim@example.com",
            attacker_ip="203.0.113.50",
            source_geo=GEO_MOSCOW,
        )
        result = scenario.generate()

        alert = {
            "id": "alert-001",
            "type": "brute_force",
            "user_email": "victim@example.com",
            "source_ip": "203.0.113.50",
            "attempt_count": 10,
            "timestamp": datetime.now(timezone.utc),
            "severity": "high",
        }

        baseline = create_office_worker_baseline(
            user_email="victim@example.com",
            location=GEO_NYC,
        )

        user_context = {
            "department": "Engineering",
            "is_privileged": False,
        }

        enriched = enricher.enrich_alert(
            alert=alert,
            baseline=baseline,
            user_context=user_context,
            events=result.events,
        )

        # Check enrichment completeness
        assert enriched["attack_source_location"]["country"] == "RU"
        assert enriched["is_new_location"] is True
        assert enriched["baseline_comparison"] is not None
        assert enriched["user_context"]["department"] == "Engineering"
        assert "attack_timeline" in enriched

    def test_full_enrichment_impossible_travel_alert(self):
        """Test full enrichment of impossible travel alert."""
        enricher = IdentityAlertEnricher()

        scenario = ImpossibleTravelScenario(
            target_user="traveler@example.com",
            first_location=GEO_NYC,
            second_location=GEO_TOKYO,
            time_gap_minutes=60,
        )
        result = scenario.generate()

        alert = {
            "id": "alert-002",
            "type": "impossible_travel",
            "user_email": "traveler@example.com",
            "first_location": GEO_NYC,
            "second_location": GEO_TOKYO,
            "time_gap_minutes": 60,
            "timestamp": datetime.now(timezone.utc),
            "severity": "high",
        }

        baseline = create_office_worker_baseline(
            user_email="traveler@example.com",
            location=GEO_NYC,
        )

        enriched = enricher.enrich_alert(
            alert=alert,
            baseline=baseline,
            events=result.events,
        )

        assert enriched["travel_distance_km"] > 10000
        assert enriched["required_speed_kmh"] > 10000
        assert enriched["is_physically_impossible"] is True

    def test_enrichment_dormant_account_context(self):
        """Test enrichment for dormant account alert."""
        enricher = IdentityAlertEnricher()

        baseline = create_dormant_account_baseline(
            user_email="former@example.com",
            dormant_days=90,
        )

        alert = {
            "id": "alert-003",
            "type": "dormant_account_login",
            "user_email": "former@example.com",
            "source_ip": "203.0.113.60",
            "timestamp": datetime.now(timezone.utc),
            "severity": "high",
        }

        enriched = enricher.enrich_alert(
            alert=alert,
            baseline=baseline,
        )

        assert enriched["is_dormant_account"] is True
        assert enriched["days_since_last_activity"] >= 90
        assert enriched["account_status"] == "stale"


class TestRiskContextProvider:
    """Tests for risk context provider."""

    def test_get_historical_risk_trend(self):
        """Test retrieval of historical risk trend."""
        provider = RiskContextProvider()

        # Mock historical data
        historical_scores = [30, 35, 40, 55, 70, 85]

        trend = provider.calculate_trend(historical_scores)

        assert trend["direction"] == "rising"
        assert trend["change_rate"] > 0
        assert trend["current"] == 85
        assert trend["previous_avg"] < 85

    def test_get_peer_group_comparison(self):
        """Test peer group risk comparison."""
        provider = RiskContextProvider()

        user_score = 75
        peer_scores = [20, 25, 30, 35, 40, 45, 50]  # Engineering department

        comparison = provider.compare_to_peers(user_score, peer_scores)

        assert comparison["user_score"] == 75
        assert comparison["peer_avg"] < 50
        assert comparison["percentile"] > 90  # Above most peers
        assert comparison["is_outlier"] is True

    def test_get_recent_alert_history(self):
        """Test retrieval of recent alert history."""
        provider = RiskContextProvider()

        alerts = [
            {"type": "unusual_login", "timestamp": datetime.now(timezone.utc) - timedelta(days=5)},
            {"type": "new_device", "timestamp": datetime.now(timezone.utc) - timedelta(days=3)},
            {"type": "brute_force_target", "timestamp": datetime.now(timezone.utc) - timedelta(days=1)},
        ]

        history = provider.get_alert_history(alerts, days=7)

        assert history["alert_count"] == 3
        assert history["unique_types"] == 3
        assert "brute_force_target" in history["alert_types"]


class TestEnrichmentEdgeCases:
    """Tests for enrichment edge cases."""

    def test_enrich_without_baseline(self):
        """Test enrichment when no baseline exists."""
        enricher = IdentityAlertEnricher()

        alert = {
            "id": "alert-001",
            "type": "unusual_login",
            "user_email": "new.user@example.com",
            "timestamp": datetime.now(timezone.utc),
            "severity": "medium",
        }

        enriched = enricher.enrich_alert(
            alert=alert,
            baseline=None,  # No baseline
        )

        assert enriched["has_baseline"] is False
        assert enriched.get("baseline_comparison") is None
        # Should still work, just without baseline context

    def test_enrich_with_partial_user_context(self):
        """Test enrichment with partial user context."""
        enricher = IdentityAlertEnricher()

        alert = {
            "id": "alert-001",
            "type": "unusual_login",
            "user_email": "worker@example.com",
            "timestamp": datetime.now(timezone.utc),
            "severity": "medium",
        }

        # Minimal user context
        user_context = {
            "department": "Unknown",
        }

        enriched = enricher.enrich_with_user_context(alert, user_context)

        # Should handle missing fields gracefully
        assert enriched.get("is_vip_user", False) is False
        assert enriched.get("is_privileged", False) is False

    def test_enrich_event_with_missing_geo(self):
        """Test enrichment when event has no geo data."""
        comparator = BaselineComparator()

        baseline = create_office_worker_baseline(
            user_email="worker@example.com",
            location=GEO_NYC,
        )

        # Event without geo
        event = create_auth_success_event(
            user_email="worker@example.com",
        )
        event.source_geo = None

        comparison = comparator.compare(event, baseline)

        # Should handle missing geo gracefully
        assert comparison.get("is_new_location") is None or comparison.get("location_unknown") is True
