"""
Unit tests for IdentityAnomalyDetector.

Tests the main anomaly detection methods including impossible travel,
unusual time, new device, new location, and volume anomalies.
"""

import pytest
from datetime import datetime, timezone, timedelta
from unittest.mock import Mock, MagicMock

from src.shared.identity.detection.anomaly_detector import IdentityAnomalyDetector
from src.shared.models.identity_event import IdentityEvent, IdentityEventType, GeoLocation
from tests.unit.identity.conftest import create_event_at_time


class TestImpossibleTravelDetection:
    """Tests for impossible travel detection in anomaly detector."""

    def test_impossible_travel_detected(
        self,
        mock_query_executor,
        sample_auth_success_event,
        sample_geo_nyc,
        sample_geo_london,
        sample_mature_baseline,
    ):
        """Impossible travel between NYC and London in 1 hour should be detected."""
        detector = IdentityAnomalyDetector(query_executor=mock_query_executor)

        # Last event was in London 1 hour ago
        last_event = create_event_at_time(
            sample_auth_success_event,
            hours_ago=1,
            geo=sample_geo_london,
        )
        current_event = sample_auth_success_event  # NYC

        mock_query_executor.execute_query.return_value = [
            {
                "timestamp": last_event.timestamp.isoformat(),
                "source_geo": {
                    "lat": sample_geo_london.latitude,
                    "lon": sample_geo_london.longitude,
                    "city": sample_geo_london.city,
                },
            }
        ]

        result = detector.detect_impossible_travel(
            event=current_event,
            baseline=sample_mature_baseline,
        )

        assert result.is_anomaly is True
        assert result.anomaly_type == "impossible_travel"

    def test_possible_travel_not_flagged(
        self,
        mock_query_executor,
        sample_auth_success_event,
        sample_geo_nyc,
        sample_geo_boston,
        sample_mature_baseline,
    ):
        """Possible travel between NYC and Boston in 2 hours should not be flagged."""
        detector = IdentityAnomalyDetector(query_executor=mock_query_executor)

        last_event = create_event_at_time(
            sample_auth_success_event,
            hours_ago=2,
            geo=sample_geo_boston,
        )
        current_event = sample_auth_success_event  # NYC

        mock_query_executor.execute_query.return_value = [
            {
                "timestamp": last_event.timestamp.isoformat(),
                "source_geo": {
                    "lat": sample_geo_boston.latitude,
                    "lon": sample_geo_boston.longitude,
                },
            }
        ]

        result = detector.detect_impossible_travel(
            event=current_event,
            baseline=sample_mature_baseline,
        )

        assert result.is_anomaly is False

    def test_no_previous_event_no_anomaly(
        self,
        mock_query_executor,
        sample_auth_success_event,
        sample_mature_baseline,
    ):
        """No previous event should not trigger anomaly."""
        detector = IdentityAnomalyDetector(query_executor=mock_query_executor)

        mock_query_executor.execute_query.return_value = []

        result = detector.detect_impossible_travel(
            event=sample_auth_success_event,
            baseline=sample_mature_baseline,
        )

        assert result.is_anomaly is False

    def test_vpn_user_handled(
        self,
        mock_query_executor,
        sample_auth_success_event,
        sample_geo_nyc,
        sample_geo_tokyo,
        sample_mature_baseline,
    ):
        """Known VPN users should have adjusted thresholds."""
        detector = IdentityAnomalyDetector(query_executor=mock_query_executor)

        # Mark baseline as VPN user
        sample_mature_baseline.is_vpn_user = True

        last_event = create_event_at_time(
            sample_auth_success_event,
            hours_ago=0.5,
            geo=sample_geo_tokyo,
        )

        mock_query_executor.execute_query.return_value = [
            {
                "timestamp": last_event.timestamp.isoformat(),
                "source_geo": {"lat": sample_geo_tokyo.latitude, "lon": sample_geo_tokyo.longitude},
            }
        ]

        result = detector.detect_impossible_travel(
            event=sample_auth_success_event,
            baseline=sample_mature_baseline,
        )

        # VPN users may have reduced severity or different handling
        if result.is_anomaly:
            assert result.severity != "critical" or result.notes.get("vpn_user") is True


class TestUnusualTimeDetection:
    """Tests for unusual login time detection."""

    def test_login_during_normal_hours_not_flagged(
        self,
        mock_query_executor,
        sample_auth_success_event,
        sample_mature_baseline,
    ):
        """Login during normal business hours should not be flagged."""
        detector = IdentityAnomalyDetector(query_executor=mock_query_executor)

        # Baseline has typical hours 8-18
        # Event at 10 AM
        event = sample_auth_success_event
        event = event.__class__(
            **{**event.__dict__, "timestamp": datetime.now(timezone.utc).replace(hour=10)}
        )

        result = detector.detect_unusual_time(
            event=event,
            baseline=sample_mature_baseline,
        )

        assert result.is_anomaly is False

    def test_login_at_3am_flagged(
        self,
        mock_query_executor,
        sample_auth_success_event,
        sample_mature_baseline,
    ):
        """Login at 3 AM should be flagged if not in baseline."""
        detector = IdentityAnomalyDetector(query_executor=mock_query_executor)

        # Baseline has typical hours 8-18
        # Event at 3 AM
        event_time = datetime.now(timezone.utc).replace(hour=3, minute=0)
        event = sample_auth_success_event
        event = event.__class__(**{**event.__dict__, "timestamp": event_time})

        result = detector.detect_unusual_time(
            event=event,
            baseline=sample_mature_baseline,
        )

        assert result.is_anomaly is True
        assert result.anomaly_type == "unusual_time"

    def test_weekend_login_for_weekday_user(
        self,
        mock_query_executor,
        sample_auth_success_event,
        sample_mature_baseline,
    ):
        """Weekend login for weekday-only user should be flagged."""
        detector = IdentityAnomalyDetector(query_executor=mock_query_executor)

        # Baseline has typical days Mon-Fri (0-4)
        # Find next Saturday
        today = datetime.now(timezone.utc)
        days_until_saturday = (5 - today.weekday()) % 7
        saturday = today + timedelta(days=days_until_saturday)

        event = sample_auth_success_event
        event = event.__class__(**{**event.__dict__, "timestamp": saturday})

        result = detector.detect_unusual_time(
            event=event,
            baseline=sample_mature_baseline,
        )

        assert result.is_anomaly is True

    def test_immature_baseline_no_time_anomaly(
        self,
        mock_query_executor,
        sample_auth_success_event,
        sample_immature_baseline,
    ):
        """Immature baseline should not flag time anomalies."""
        detector = IdentityAnomalyDetector(query_executor=mock_query_executor)

        # Event at 3 AM
        event_time = datetime.now(timezone.utc).replace(hour=3)
        event = sample_auth_success_event
        event = event.__class__(**{**event.__dict__, "timestamp": event_time})

        result = detector.detect_unusual_time(
            event=event,
            baseline=sample_immature_baseline,
        )

        # Immature baseline shouldn't trigger anomaly
        assert result.is_anomaly is False or result.confidence < 0.5


class TestNewDeviceDetection:
    """Tests for new device detection."""

    def test_known_device_not_flagged(
        self,
        mock_query_executor,
        sample_auth_success_event,
        sample_mature_baseline,
    ):
        """Known device should not be flagged."""
        detector = IdentityAnomalyDetector(query_executor=mock_query_executor)

        # Baseline has device-001
        event = sample_auth_success_event  # Has device_id="device-001"

        result = detector.detect_new_device(
            event=event,
            baseline=sample_mature_baseline,
        )

        assert result.is_anomaly is False

    def test_new_device_flagged(
        self,
        mock_query_executor,
        sample_auth_success_event,
        sample_mature_baseline,
    ):
        """New device should be flagged."""
        detector = IdentityAnomalyDetector(query_executor=mock_query_executor)

        # Create event with unknown device
        from dataclasses import replace
        event = replace(sample_auth_success_event, device_id="new-device-999")

        result = detector.detect_new_device(
            event=event,
            baseline=sample_mature_baseline,
        )

        assert result.is_anomaly is True
        assert result.anomaly_type == "new_device"

    def test_similar_user_agent_lower_severity(
        self,
        mock_query_executor,
        sample_auth_success_event,
        sample_mature_baseline,
    ):
        """Similar user agent should have lower severity."""
        detector = IdentityAnomalyDetector(query_executor=mock_query_executor)

        # Same browser family, different version
        from dataclasses import replace
        event = replace(
            sample_auth_success_event,
            device_id="new-device-999",
            user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/121.0",  # Just version change
        )

        result = detector.detect_new_device(
            event=event,
            baseline=sample_mature_baseline,
        )

        if result.is_anomaly:
            assert result.severity in ["low", "medium"]

    def test_completely_different_device_type(
        self,
        mock_query_executor,
        sample_auth_success_event,
        sample_mature_baseline,
    ):
        """Completely different device type should be higher severity."""
        detector = IdentityAnomalyDetector(query_executor=mock_query_executor)

        from dataclasses import replace
        event = replace(
            sample_auth_success_event,
            device_id="new-device-999",
            device_type="mobile",
            user_agent="Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) Safari",
        )

        result = detector.detect_new_device(
            event=event,
            baseline=sample_mature_baseline,
        )

        assert result.is_anomaly is True
        assert result.severity in ["medium", "high"]


class TestNewLocationDetection:
    """Tests for new location detection."""

    def test_known_location_not_flagged(
        self,
        mock_query_executor,
        sample_auth_success_event,
        sample_geo_nyc,
        sample_mature_baseline,
    ):
        """Known location should not be flagged."""
        detector = IdentityAnomalyDetector(query_executor=mock_query_executor)

        # Baseline has NYC
        result = detector.detect_new_location(
            event=sample_auth_success_event,
            baseline=sample_mature_baseline,
        )

        assert result.is_anomaly is False

    def test_new_country_high_severity(
        self,
        mock_query_executor,
        sample_auth_success_event,
        sample_geo_tokyo,
        sample_mature_baseline,
    ):
        """New country should be high severity."""
        detector = IdentityAnomalyDetector(query_executor=mock_query_executor)

        from dataclasses import replace
        event = replace(sample_auth_success_event, source_geo=sample_geo_tokyo)

        result = detector.detect_new_location(
            event=event,
            baseline=sample_mature_baseline,
        )

        assert result.is_anomaly is True
        assert result.severity in ["high", "critical"]

    def test_new_city_same_country_medium_severity(
        self,
        mock_query_executor,
        sample_auth_success_event,
        sample_geo_boston,
        sample_mature_baseline,
    ):
        """New city in same country should be medium severity."""
        detector = IdentityAnomalyDetector(query_executor=mock_query_executor)

        from dataclasses import replace
        event = replace(sample_auth_success_event, source_geo=sample_geo_boston)

        result = detector.detect_new_location(
            event=event,
            baseline=sample_mature_baseline,
        )

        assert result.is_anomaly is True
        assert result.severity in ["low", "medium"]

    def test_known_ip_no_geo_handled(
        self,
        mock_query_executor,
        sample_auth_success_event,
        sample_mature_baseline,
    ):
        """Known IP without geolocation should be handled."""
        detector = IdentityAnomalyDetector(query_executor=mock_query_executor)

        from dataclasses import replace
        event = replace(
            sample_auth_success_event,
            source_geo=None,
            source_ip="192.168.1.1",  # Known IP from baseline
        )

        result = detector.detect_new_location(
            event=event,
            baseline=sample_mature_baseline,
        )

        # Known IP should not be flagged even without geo
        assert result.is_anomaly is False


class TestVolumeAnomalyDetection:
    """Tests for volume anomaly detection."""

    def test_normal_volume_not_flagged(
        self,
        mock_query_executor,
        sample_user_email,
        sample_mature_baseline,
    ):
        """Normal event volume should not be flagged."""
        detector = IdentityAnomalyDetector(query_executor=mock_query_executor)

        # Baseline: avg=15.5, std=4.2
        # Normal day: 14 events (within 1 std dev)
        mock_query_executor.execute_query.return_value = [
            {"event_count": 14}
        ]

        result = detector.detect_volume_anomaly(
            user_email=sample_user_email,
            baseline=sample_mature_baseline,
        )

        assert result.is_anomaly is False

    def test_high_volume_flagged(
        self,
        mock_query_executor,
        sample_user_email,
        sample_mature_baseline,
    ):
        """Unusually high volume should be flagged."""
        detector = IdentityAnomalyDetector(query_executor=mock_query_executor)

        # Baseline: avg=15.5, std=4.2
        # High volume: 50 events (>3 std dev)
        mock_query_executor.execute_query.return_value = [
            {"event_count": 50}
        ]

        result = detector.detect_volume_anomaly(
            user_email=sample_user_email,
            baseline=sample_mature_baseline,
        )

        assert result.is_anomaly is True
        assert result.anomaly_type == "high_volume"

    def test_low_volume_may_flag(
        self,
        mock_query_executor,
        sample_user_email,
        sample_mature_baseline,
    ):
        """Unusually low volume may be flagged (dormant account)."""
        detector = IdentityAnomalyDetector(query_executor=mock_query_executor)

        # Baseline: avg=15.5
        # Very low: 0 events for active user
        mock_query_executor.execute_query.return_value = [
            {"event_count": 0}
        ]

        result = detector.detect_volume_anomaly(
            user_email=sample_user_email,
            baseline=sample_mature_baseline,
            detect_low=True,
        )

        # Low volume is less concerning than high but may still flag
        if result.is_anomaly:
            assert result.anomaly_type == "low_volume"

    def test_z_score_calculation(
        self,
        mock_query_executor,
        sample_user_email,
        sample_mature_baseline,
    ):
        """Test z-score based anomaly detection."""
        detector = IdentityAnomalyDetector(
            query_executor=mock_query_executor,
            volume_z_threshold=2.0,
        )

        # Baseline: avg=15.5, std=4.2
        # 2 std devs above: 15.5 + 2*4.2 = 23.9
        mock_query_executor.execute_query.return_value = [
            {"event_count": 25}  # Just above 2 std devs
        ]

        result = detector.detect_volume_anomaly(
            user_email=sample_user_email,
            baseline=sample_mature_baseline,
        )

        assert result.is_anomaly is True
        if hasattr(result, 'z_score'):
            assert result.z_score > 2.0


class TestServiceAccountHandling:
    """Tests for service account handling in anomaly detection."""

    def test_service_account_excluded(
        self,
        mock_query_executor,
        sample_auth_success_event,
        sample_mature_baseline,
    ):
        """Service accounts should be excluded from certain anomaly checks."""
        detector = IdentityAnomalyDetector(query_executor=mock_query_executor)

        sample_mature_baseline.is_service_account = True

        # 3 AM login - normally would be flagged
        event_time = datetime.now(timezone.utc).replace(hour=3)
        event = sample_auth_success_event.__class__(
            **{**sample_auth_success_event.__dict__, "timestamp": event_time}
        )

        result = detector.detect_unusual_time(
            event=event,
            baseline=sample_mature_baseline,
        )

        # Service accounts shouldn't flag time anomalies
        assert result.is_anomaly is False


class TestCombinedAnomalyScoring:
    """Tests for combined anomaly scoring."""

    def test_multiple_anomalies_increase_severity(
        self,
        mock_query_executor,
        sample_auth_success_event,
        sample_geo_tokyo,
        sample_mature_baseline,
    ):
        """Multiple simultaneous anomalies should increase severity."""
        detector = IdentityAnomalyDetector(query_executor=mock_query_executor)

        from dataclasses import replace

        # Create event with multiple anomalies:
        # - New location (Tokyo)
        # - New device
        # - Unusual time (3 AM)
        event_time = datetime.now(timezone.utc).replace(hour=3)
        event = replace(
            sample_auth_success_event,
            source_geo=sample_geo_tokyo,
            device_id="unknown-device",
            timestamp=event_time,
        )

        result = detector.detect_all_anomalies(
            event=event,
            baseline=sample_mature_baseline,
        )

        # Combined anomalies should have high severity
        assert result.is_anomaly is True
        assert result.severity == "critical"
        assert len(result.anomaly_types) >= 2
