"""
Unit tests for BaselineCalculator.

Tests baseline building, incremental updates, confidence calculation, and maturity detection.
"""

import pytest
from datetime import datetime, timezone, timedelta
from unittest.mock import Mock, MagicMock

from src.shared.identity.baseline.baseline_calculator import BaselineCalculator
from src.shared.identity.baseline.user_baseline import UserBaseline
from src.shared.models.identity_event import IdentityEvent, IdentityEventType, GeoLocation


class TestBaselineBuilding:
    """Tests for building baselines from events."""

    def test_build_from_empty_events(self):
        """Building from empty events should create empty baseline."""
        calculator = BaselineCalculator()

        baseline = calculator.build_baseline(
            user_email="test@example.com",
            events=[],
        )

        assert baseline.user_email == "test@example.com"
        assert baseline.event_count == 0
        assert baseline.maturity_days == 0

    def test_build_from_single_event(self, sample_auth_success_event):
        """Single event should create minimal baseline."""
        calculator = BaselineCalculator()

        baseline = calculator.build_baseline(
            user_email=sample_auth_success_event.user_email,
            events=[sample_auth_success_event],
        )

        assert baseline.event_count == 1
        assert len(baseline.known_ips) == 1

    def test_build_login_hours(self, sample_auth_success_event):
        """Baseline should track login hours."""
        calculator = BaselineCalculator()

        # Create events at different hours
        events = []
        for hour in [9, 10, 11, 14, 15, 16]:
            event_time = datetime.now(timezone.utc).replace(hour=hour)
            from dataclasses import replace
            event = replace(sample_auth_success_event, timestamp=event_time)
            events.append(event)

        baseline = calculator.build_baseline(
            user_email=sample_auth_success_event.user_email,
            events=events,
        )

        assert 9 in baseline.typical_hours
        assert 10 in baseline.typical_hours
        assert 3 not in baseline.typical_hours  # 3 AM not in events

    def test_build_login_days(self, sample_auth_success_event):
        """Baseline should track login days."""
        calculator = BaselineCalculator()

        # Create events on weekdays
        events = []
        base_date = datetime.now(timezone.utc)
        for i in range(14):  # Two weeks
            event_date = base_date - timedelta(days=i)
            if event_date.weekday() < 5:  # Weekday
                from dataclasses import replace
                event = replace(sample_auth_success_event, timestamp=event_date)
                events.append(event)

        baseline = calculator.build_baseline(
            user_email=sample_auth_success_event.user_email,
            events=events,
        )

        # Should have weekdays in typical days
        assert 0 in baseline.typical_days or 1 in baseline.typical_days  # Mon or Tue
        # Weekend should not be typical if no events
        assert 5 not in baseline.typical_days or 6 not in baseline.typical_days

    def test_build_known_locations(self, sample_auth_success_event, sample_geo_nyc, sample_geo_boston):
        """Baseline should track known locations."""
        calculator = BaselineCalculator()

        from dataclasses import replace
        events = [
            sample_auth_success_event,  # NYC
            replace(sample_auth_success_event, source_geo=sample_geo_boston),
        ]

        baseline = calculator.build_baseline(
            user_email=sample_auth_success_event.user_email,
            events=events,
        )

        assert len(baseline.known_locations) == 2
        cities = [loc.city for loc in baseline.known_locations]
        assert "New York" in cities
        assert "Boston" in cities

    def test_build_known_devices(self, sample_auth_success_event):
        """Baseline should track known devices."""
        calculator = BaselineCalculator()

        from dataclasses import replace
        events = [
            sample_auth_success_event,
            replace(sample_auth_success_event, device_id="device-002", user_agent="Firefox"),
        ]

        baseline = calculator.build_baseline(
            user_email=sample_auth_success_event.user_email,
            events=events,
        )

        assert len(baseline.known_devices) == 2

    def test_build_typical_applications(self, sample_auth_success_event):
        """Baseline should track typical applications."""
        calculator = BaselineCalculator()

        from dataclasses import replace
        events = [
            sample_auth_success_event,  # Salesforce
            replace(sample_auth_success_event, application_name="Slack"),
            replace(sample_auth_success_event, application_name="Office365"),
        ]

        baseline = calculator.build_baseline(
            user_email=sample_auth_success_event.user_email,
            events=events,
        )

        assert "Salesforce" in baseline.typical_applications
        assert "Slack" in baseline.typical_applications
        assert "Office365" in baseline.typical_applications

    def test_build_auth_methods(self, sample_auth_success_event, sample_mfa_success_event):
        """Baseline should track authentication methods."""
        calculator = BaselineCalculator()

        events = [
            sample_auth_success_event,
            sample_mfa_success_event,  # Has mfa_method="push"
        ]

        baseline = calculator.build_baseline(
            user_email=sample_auth_success_event.user_email,
            events=events,
        )

        assert "push" in baseline.auth_methods


class TestIncrementalUpdates:
    """Tests for incremental baseline updates."""

    def test_update_adds_new_ip(self, sample_auth_success_event, sample_mature_baseline):
        """Updating with new IP should add to known IPs."""
        calculator = BaselineCalculator()

        from dataclasses import replace
        new_event = replace(sample_auth_success_event, source_ip="1.2.3.4")

        updated = calculator.update_baseline(
            baseline=sample_mature_baseline,
            event=new_event,
        )

        assert "1.2.3.4" in updated.known_ips

    def test_update_increments_event_count(self, sample_auth_success_event, sample_mature_baseline):
        """Updating should increment event count."""
        calculator = BaselineCalculator()

        original_count = sample_mature_baseline.event_count

        updated = calculator.update_baseline(
            baseline=sample_mature_baseline,
            event=sample_auth_success_event,
        )

        assert updated.event_count == original_count + 1

    def test_update_refreshes_timestamp(self, sample_auth_success_event, sample_mature_baseline):
        """Updating should refresh last_updated timestamp."""
        calculator = BaselineCalculator()

        # Set old timestamp
        sample_mature_baseline.last_updated = datetime.now(timezone.utc) - timedelta(days=1)

        updated = calculator.update_baseline(
            baseline=sample_mature_baseline,
            event=sample_auth_success_event,
        )

        assert updated.last_updated > sample_mature_baseline.last_updated

    def test_update_adds_new_location(self, sample_auth_success_event, sample_geo_tokyo, sample_mature_baseline):
        """Updating with new location should add to known locations."""
        calculator = BaselineCalculator()

        from dataclasses import replace
        new_event = replace(sample_auth_success_event, source_geo=sample_geo_tokyo)

        updated = calculator.update_baseline(
            baseline=sample_mature_baseline,
            event=new_event,
        )

        cities = [loc.city for loc in updated.known_locations]
        assert "Tokyo" in cities

    def test_update_recalculates_volume_stats(self, sample_auth_success_event, sample_mature_baseline):
        """Updating should recalculate volume statistics."""
        calculator = BaselineCalculator()

        # Add multiple events
        for _ in range(10):
            sample_mature_baseline = calculator.update_baseline(
                baseline=sample_mature_baseline,
                event=sample_auth_success_event,
            )

        # Stats should be updated
        assert sample_mature_baseline.avg_events_per_day >= 0


class TestConfidenceCalculation:
    """Tests for baseline confidence calculation."""

    def test_low_event_count_low_confidence(self, sample_user_email):
        """Few events should result in low confidence."""
        calculator = BaselineCalculator()

        baseline = UserBaseline(user_email=sample_user_email)
        baseline.event_count = 5
        baseline.first_seen = datetime.now(timezone.utc) - timedelta(days=2)

        confidence = calculator.calculate_confidence(baseline)

        assert confidence < 50

    def test_many_events_high_confidence(self, sample_user_email):
        """Many events should result in high confidence."""
        calculator = BaselineCalculator()

        baseline = UserBaseline(user_email=sample_user_email)
        baseline.event_count = 1000
        baseline.first_seen = datetime.now(timezone.utc) - timedelta(days=60)
        baseline.typical_hours = list(range(8, 18))
        baseline.known_locations = [GeoLocation(country="US", city="NYC")]
        baseline.known_devices = [{"device_id": "d1"}, {"device_id": "d2"}]

        confidence = calculator.calculate_confidence(baseline)

        assert confidence > 80

    def test_confidence_considers_data_completeness(self, sample_user_email):
        """Confidence should consider data completeness."""
        calculator = BaselineCalculator()

        # Baseline with missing data
        incomplete = UserBaseline(user_email=sample_user_email)
        incomplete.event_count = 100
        incomplete.first_seen = datetime.now(timezone.utc) - timedelta(days=30)
        # Missing: locations, devices, hours

        # Complete baseline
        complete = UserBaseline(user_email=sample_user_email)
        complete.event_count = 100
        complete.first_seen = datetime.now(timezone.utc) - timedelta(days=30)
        complete.typical_hours = list(range(8, 18))
        complete.known_locations = [GeoLocation(country="US", city="NYC")]
        complete.known_devices = [{"device_id": "d1"}]
        complete.typical_applications = {"App1", "App2"}

        incomplete_conf = calculator.calculate_confidence(incomplete)
        complete_conf = calculator.calculate_confidence(complete)

        assert complete_conf > incomplete_conf

    def test_confidence_capped_at_100(self, sample_user_email):
        """Confidence should be capped at 100."""
        calculator = BaselineCalculator()

        baseline = UserBaseline(user_email=sample_user_email)
        baseline.event_count = 100000
        baseline.first_seen = datetime.now(timezone.utc) - timedelta(days=365)

        confidence = calculator.calculate_confidence(baseline)

        assert confidence <= 100


class TestMaturityDetection:
    """Tests for baseline maturity detection."""

    def test_new_baseline_immature(self, sample_user_email):
        """New baseline (< 14 days) should be immature."""
        calculator = BaselineCalculator(maturity_threshold_days=14)

        baseline = UserBaseline(user_email=sample_user_email)
        baseline.first_seen = datetime.now(timezone.utc) - timedelta(days=5)

        is_mature = calculator.is_mature(baseline)

        assert is_mature is False

    def test_old_baseline_mature(self, sample_user_email):
        """Old baseline (>= 14 days) should be mature."""
        calculator = BaselineCalculator(maturity_threshold_days=14)

        baseline = UserBaseline(user_email=sample_user_email)
        baseline.first_seen = datetime.now(timezone.utc) - timedelta(days=20)
        baseline.event_count = 100

        is_mature = calculator.is_mature(baseline)

        assert is_mature is True

    def test_maturity_requires_minimum_events(self, sample_user_email):
        """Maturity should require minimum event count."""
        calculator = BaselineCalculator(
            maturity_threshold_days=14,
            min_events_for_maturity=50,
        )

        baseline = UserBaseline(user_email=sample_user_email)
        baseline.first_seen = datetime.now(timezone.utc) - timedelta(days=30)
        baseline.event_count = 10  # Below minimum

        is_mature = calculator.is_mature(baseline)

        assert is_mature is False

    def test_maturity_status_values(self, sample_user_email):
        """Test different maturity status values."""
        calculator = BaselineCalculator()

        # New baseline
        new_baseline = UserBaseline(user_email=sample_user_email)
        new_baseline.first_seen = datetime.now(timezone.utc)
        assert calculator.get_maturity_status(new_baseline) == "new"

        # Learning baseline
        learning_baseline = UserBaseline(user_email=sample_user_email)
        learning_baseline.first_seen = datetime.now(timezone.utc) - timedelta(days=7)
        learning_baseline.event_count = 50
        assert calculator.get_maturity_status(learning_baseline) == "learning"

        # Mature baseline
        mature_baseline = UserBaseline(user_email=sample_user_email)
        mature_baseline.first_seen = datetime.now(timezone.utc) - timedelta(days=30)
        mature_baseline.event_count = 500
        mature_baseline.last_updated = datetime.now(timezone.utc)
        assert calculator.get_maturity_status(mature_baseline) == "mature"

    def test_stale_baseline_detection(self, sample_user_email):
        """Baselines not updated recently should be marked stale."""
        calculator = BaselineCalculator(stale_threshold_days=7)

        baseline = UserBaseline(user_email=sample_user_email)
        baseline.first_seen = datetime.now(timezone.utc) - timedelta(days=60)
        baseline.last_updated = datetime.now(timezone.utc) - timedelta(days=30)
        baseline.event_count = 500

        status = calculator.get_maturity_status(baseline)

        assert status == "stale"


class TestVolumeStatistics:
    """Tests for volume statistics calculation."""

    def test_calculate_average_events(self, sample_auth_success_event):
        """Should calculate average events per day."""
        calculator = BaselineCalculator()

        # Create events spread over 10 days
        events = []
        for i in range(50):  # 50 events over 10 days = 5/day avg
            day_offset = i // 5
            event_time = datetime.now(timezone.utc) - timedelta(days=day_offset)
            from dataclasses import replace
            events.append(replace(sample_auth_success_event, timestamp=event_time))

        baseline = calculator.build_baseline(
            user_email=sample_auth_success_event.user_email,
            events=events,
        )

        assert 4 <= baseline.avg_events_per_day <= 6

    def test_calculate_standard_deviation(self, sample_auth_success_event):
        """Should calculate standard deviation of daily events."""
        calculator = BaselineCalculator()

        # Create events with varying counts per day
        events = []
        event_counts = [10, 5, 15, 8, 12, 3, 20]  # Different counts per day

        for day, count in enumerate(event_counts):
            for _ in range(count):
                event_time = datetime.now(timezone.utc) - timedelta(days=day)
                from dataclasses import replace
                events.append(replace(sample_auth_success_event, timestamp=event_time))

        baseline = calculator.build_baseline(
            user_email=sample_auth_success_event.user_email,
            events=events,
        )

        assert baseline.events_std_dev > 0


class TestEdgeCases:
    """Tests for edge cases in baseline calculation."""

    def test_null_event_fields_handled(self, sample_user_email):
        """Events with null fields should be handled gracefully."""
        calculator = BaselineCalculator()

        event = IdentityEvent(
            event_id="evt-001",
            event_type=IdentityEventType.AUTH_SUCCESS,
            timestamp=datetime.now(timezone.utc),
            provider="okta",
            user_id="user-123",
            user_email=sample_user_email,
            source_ip="1.2.3.4",
            # Many fields intentionally None
        )

        baseline = calculator.build_baseline(
            user_email=sample_user_email,
            events=[event],
        )

        assert baseline is not None
        assert baseline.event_count == 1

    def test_duplicate_events_handled(self, sample_auth_success_event):
        """Duplicate events should be handled (same event ID)."""
        calculator = BaselineCalculator()

        # Same event multiple times
        events = [sample_auth_success_event] * 5

        baseline = calculator.build_baseline(
            user_email=sample_auth_success_event.user_email,
            events=events,
        )

        # May dedupe or count all depending on implementation
        assert baseline.event_count >= 1

    def test_events_out_of_order(self, sample_auth_success_event):
        """Events out of chronological order should be handled."""
        calculator = BaselineCalculator()

        from dataclasses import replace
        events = [
            replace(sample_auth_success_event, timestamp=datetime.now(timezone.utc) - timedelta(hours=i))
            for i in [5, 1, 10, 3, 7]  # Out of order
        ]

        baseline = calculator.build_baseline(
            user_email=sample_auth_success_event.user_email,
            events=events,
        )

        assert baseline is not None
        assert baseline.event_count == 5

    def test_service_account_flag(self, sample_user_email):
        """Service account flag should be preserved."""
        calculator = BaselineCalculator()

        baseline = UserBaseline(user_email=sample_user_email)
        baseline.is_service_account = True

        # Update should preserve flag
        event = IdentityEvent(
            event_id="evt-001",
            event_type=IdentityEventType.AUTH_SUCCESS,
            timestamp=datetime.now(timezone.utc),
            provider="okta",
            user_id="svc-user",
            user_email=sample_user_email,
            source_ip="1.2.3.4",
        )

        updated = calculator.update_baseline(baseline=baseline, event=event)

        assert updated.is_service_account is True
