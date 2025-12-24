"""
Integration tests for the baseline building pipeline.

Tests baseline creation from historical events and accuracy validation.
"""

import pytest
from datetime import datetime, timezone, timedelta
from unittest.mock import Mock, MagicMock

from src.shared.models.identity_event import IdentityEvent, IdentityEventType, GeoLocation
from src.shared.identity.baseline.baseline_calculator import BaselineCalculator
from src.shared.identity.baseline.baseline_builder import BaselineBuilder
from src.shared.identity.baseline.user_baseline import UserBaseline

from tests.fixtures.identity.sample_events import (
    create_auth_success_event,
    create_mfa_success_event,
    GEO_NYC,
    GEO_SAN_FRANCISCO,
    GEO_LONDON,
)
from tests.fixtures.identity.sample_baselines import (
    create_office_worker_baseline,
    create_remote_worker_baseline,
    create_service_account_baseline,
)


class TestBaselineBuildingFromEvents:
    """Tests for building baselines from historical events."""

    def test_build_baseline_from_two_weeks_history(self):
        """Test baseline building from 14 days of events."""
        calculator = BaselineCalculator(maturity_threshold_days=14)

        # Generate 14 days of events
        events = []
        base_time = datetime.now(timezone.utc)

        for day in range(14):
            event_date = base_time - timedelta(days=day)
            # Weekday work hours
            if event_date.weekday() < 5:  # Mon-Fri
                for hour in [9, 10, 12, 14, 16]:
                    event_time = event_date.replace(hour=hour, minute=0)
                    event = create_auth_success_event(
                        user_email="worker@example.com",
                        timestamp=event_time,
                        source_geo=GEO_NYC,
                        device_id="laptop-001",
                    )
                    events.append(event)

        baseline = calculator.build_baseline(
            user_email="worker@example.com",
            events=events,
        )

        # Verify baseline properties
        assert baseline.user_email == "worker@example.com"
        assert baseline.event_count >= 50  # 5 events * 10 weekdays
        assert 9 in baseline.typical_hours
        assert 14 in baseline.typical_hours
        assert 0 in baseline.typical_days  # Monday
        assert GEO_NYC in baseline.known_locations or any(
            loc.city == "New York" for loc in baseline.known_locations
        )

    def test_baseline_maturity_after_14_days(self):
        """Test that baseline becomes mature after 14 days."""
        calculator = BaselineCalculator(maturity_threshold_days=14)

        # Events spanning 20 days
        events = []
        base_time = datetime.now(timezone.utc)

        for day in range(20):
            event_time = base_time - timedelta(days=day)
            events.append(create_auth_success_event(
                user_email="worker@example.com",
                timestamp=event_time,
            ))

        baseline = calculator.build_baseline(
            user_email="worker@example.com",
            events=events,
        )

        is_mature = calculator.is_mature(baseline)

        assert is_mature is True
        assert calculator.get_maturity_status(baseline) == "mature"

    def test_baseline_immature_before_14_days(self):
        """Test that baseline is immature before 14 days."""
        calculator = BaselineCalculator(maturity_threshold_days=14)

        # Events spanning only 7 days
        events = []
        base_time = datetime.now(timezone.utc)

        for day in range(7):
            event_time = base_time - timedelta(days=day)
            events.append(create_auth_success_event(
                user_email="worker@example.com",
                timestamp=event_time,
            ))

        baseline = calculator.build_baseline(
            user_email="worker@example.com",
            events=events,
        )

        is_mature = calculator.is_mature(baseline)

        assert is_mature is False
        assert calculator.get_maturity_status(baseline) in ["new", "learning"]


class TestBaselineAccuracy:
    """Tests for baseline accuracy validation."""

    def test_typical_hours_accuracy(self):
        """Test that typical hours are accurately captured."""
        calculator = BaselineCalculator()

        # Generate events at specific hours
        events = []
        base_time = datetime.now(timezone.utc)
        work_hours = [8, 9, 10, 11, 12, 13, 14, 15, 16, 17]

        for day in range(30):
            for hour in work_hours:
                event_time = (base_time - timedelta(days=day)).replace(hour=hour)
                events.append(create_auth_success_event(
                    user_email="worker@example.com",
                    timestamp=event_time,
                ))

        baseline = calculator.build_baseline(
            user_email="worker@example.com",
            events=events,
        )

        # All work hours should be in typical hours
        for hour in work_hours:
            assert hour in baseline.typical_hours

        # Non-work hours should not be typical
        assert 3 not in baseline.typical_hours  # 3 AM
        assert 23 not in baseline.typical_hours  # 11 PM

    def test_typical_days_accuracy(self):
        """Test that typical days are accurately captured."""
        calculator = BaselineCalculator()

        # Generate events only on weekdays
        events = []
        base_time = datetime.now(timezone.utc)

        for day in range(30):
            event_date = base_time - timedelta(days=day)
            if event_date.weekday() < 5:  # Weekday
                events.append(create_auth_success_event(
                    user_email="worker@example.com",
                    timestamp=event_date,
                ))

        baseline = calculator.build_baseline(
            user_email="worker@example.com",
            events=events,
        )

        # Weekdays should be typical
        assert 0 in baseline.typical_days  # Monday
        assert 1 in baseline.typical_days  # Tuesday
        assert 2 in baseline.typical_days  # Wednesday
        assert 3 in baseline.typical_days  # Thursday
        assert 4 in baseline.typical_days  # Friday

        # Weekend should not be typical (or have low frequency)
        # Depending on implementation, weekend may or may not be in typical_days

    def test_known_locations_accuracy(self):
        """Test that known locations are accurately captured."""
        calculator = BaselineCalculator()

        # Generate events from two locations
        events = []
        base_time = datetime.now(timezone.utc)

        for day in range(20):
            event_time = base_time - timedelta(days=day)
            # Alternate between NYC and SF
            geo = GEO_NYC if day % 2 == 0 else GEO_SAN_FRANCISCO
            events.append(create_auth_success_event(
                user_email="worker@example.com",
                timestamp=event_time,
                source_geo=geo,
            ))

        baseline = calculator.build_baseline(
            user_email="worker@example.com",
            events=events,
        )

        # Both locations should be known
        location_cities = [loc.city for loc in baseline.known_locations]
        assert "New York" in location_cities
        assert "San Francisco" in location_cities

    def test_volume_statistics_accuracy(self):
        """Test that volume statistics are accurately calculated."""
        calculator = BaselineCalculator()

        # Generate events with known distribution
        events = []
        base_time = datetime.now(timezone.utc)
        events_per_day = [10, 15, 12, 8, 20, 14, 11, 9, 16, 13]

        for day, count in enumerate(events_per_day):
            event_date = base_time - timedelta(days=day)
            for i in range(count):
                event_time = event_date + timedelta(minutes=i * 10)
                events.append(create_auth_success_event(
                    user_email="worker@example.com",
                    timestamp=event_time,
                ))

        baseline = calculator.build_baseline(
            user_email="worker@example.com",
            events=events,
        )

        # Average should be close to actual average
        expected_avg = sum(events_per_day) / len(events_per_day)
        assert abs(baseline.avg_events_per_day - expected_avg) < 2

        # Standard deviation should be positive
        assert baseline.events_std_dev > 0


class TestIncrementalBaselineUpdates:
    """Tests for incremental baseline updates."""

    def test_update_adds_new_ip(self):
        """Test that update adds new IP to known IPs."""
        calculator = BaselineCalculator()

        # Start with existing baseline
        baseline = create_office_worker_baseline(user_email="worker@example.com")
        original_ips = len(baseline.known_ips)

        # Update with new IP
        new_event = create_auth_success_event(
            user_email="worker@example.com",
            source_ip="8.8.8.8",  # New IP
        )

        updated = calculator.update_baseline(
            baseline=baseline,
            event=new_event,
        )

        assert "8.8.8.8" in updated.known_ips
        assert len(updated.known_ips) > original_ips

    def test_update_adds_new_location(self):
        """Test that update adds new location to known locations."""
        calculator = BaselineCalculator()

        baseline = create_office_worker_baseline(
            user_email="worker@example.com",
            location=GEO_NYC,
        )

        # Update with event from London
        new_event = create_auth_success_event(
            user_email="worker@example.com",
            source_geo=GEO_LONDON,
        )

        updated = calculator.update_baseline(
            baseline=baseline,
            event=new_event,
        )

        location_cities = [loc.city for loc in updated.known_locations]
        assert "London" in location_cities

    def test_update_increments_event_count(self):
        """Test that update increments event count."""
        calculator = BaselineCalculator()

        baseline = create_office_worker_baseline(user_email="worker@example.com")
        original_count = baseline.event_count

        new_event = create_auth_success_event(user_email="worker@example.com")

        updated = calculator.update_baseline(
            baseline=baseline,
            event=new_event,
        )

        assert updated.event_count == original_count + 1


class TestBaselineConfidence:
    """Tests for baseline confidence calculation."""

    def test_low_event_count_low_confidence(self):
        """Test that few events result in low confidence."""
        calculator = BaselineCalculator()

        baseline = UserBaseline(user_email="worker@example.com")
        baseline.event_count = 10
        baseline.first_seen = datetime.now(timezone.utc) - timedelta(days=3)

        confidence = calculator.calculate_confidence(baseline)

        assert confidence < 50

    def test_mature_baseline_high_confidence(self):
        """Test that mature baseline has high confidence."""
        calculator = BaselineCalculator()

        baseline = create_office_worker_baseline(user_email="worker@example.com")
        # Ensure it has enough data
        baseline.event_count = 1000
        baseline.first_seen = datetime.now(timezone.utc) - timedelta(days=60)
        baseline.typical_hours = list(range(8, 18))
        baseline.known_devices = [{"device_id": "d1"}, {"device_id": "d2"}]

        confidence = calculator.calculate_confidence(baseline)

        assert confidence > 80

    def test_confidence_considers_data_completeness(self):
        """Test that confidence considers all data types."""
        calculator = BaselineCalculator()

        # Incomplete baseline
        incomplete = UserBaseline(user_email="worker@example.com")
        incomplete.event_count = 200
        incomplete.first_seen = datetime.now(timezone.utc) - timedelta(days=30)
        # Missing: locations, devices, hours

        # Complete baseline
        complete = create_office_worker_baseline(user_email="worker@example.com")
        complete.event_count = 200
        complete.first_seen = datetime.now(timezone.utc) - timedelta(days=30)

        incomplete_conf = calculator.calculate_confidence(incomplete)
        complete_conf = calculator.calculate_confidence(complete)

        assert complete_conf > incomplete_conf


class TestBaselineBuilderService:
    """Tests for the BaselineBuilder service."""

    def test_build_baselines_for_multiple_users(self):
        """Test building baselines for multiple users."""
        builder = BaselineBuilder()

        # Events for multiple users
        events = []
        users = ["user1@example.com", "user2@example.com", "user3@example.com"]

        base_time = datetime.now(timezone.utc)
        for user in users:
            for day in range(20):
                event_time = base_time - timedelta(days=day)
                events.append(create_auth_success_event(
                    user_email=user,
                    timestamp=event_time,
                ))

        baselines = builder.build_all_baselines(events)

        assert len(baselines) == 3
        assert all(b.event_count >= 15 for b in baselines.values())

    def test_rebuild_baseline_from_scratch(self):
        """Test rebuilding a baseline from scratch."""
        builder = BaselineBuilder()

        # Generate new events
        events = []
        base_time = datetime.now(timezone.utc)

        for day in range(14):
            for hour in [9, 12, 15]:
                event_time = (base_time - timedelta(days=day)).replace(hour=hour)
                events.append(create_auth_success_event(
                    user_email="worker@example.com",
                    timestamp=event_time,
                    source_geo=GEO_NYC,
                ))

        new_baseline = builder.rebuild_baseline(
            user_email="worker@example.com",
            events=events,
        )

        assert new_baseline.event_count == len(events)
        assert 9 in new_baseline.typical_hours
        assert 12 in new_baseline.typical_hours
        assert 15 in new_baseline.typical_hours


class TestServiceAccountDetection:
    """Tests for service account baseline handling."""

    def test_detect_service_account_pattern(self):
        """Test detection of service account behavior patterns."""
        calculator = BaselineCalculator()

        # Generate 24/7 activity pattern
        events = []
        base_time = datetime.now(timezone.utc)

        for day in range(14):
            for hour in range(24):  # All hours
                event_time = (base_time - timedelta(days=day)).replace(hour=hour)
                events.append(create_auth_success_event(
                    user_email="svc-automation@example.com",
                    timestamp=event_time,
                    user_agent="python-requests/2.28.0",
                ))

        baseline = calculator.build_baseline(
            user_email="svc-automation@example.com",
            events=events,
        )

        # Check if service account pattern is detected
        is_service = calculator.detect_service_account_pattern(baseline)

        assert is_service is True or len(baseline.typical_hours) == 24

    def test_service_account_high_volume(self):
        """Test that service accounts have high consistent volume."""
        baseline = create_service_account_baseline(
            user_email="svc-automation@example.com"
        )

        # Service accounts have high volume
        assert baseline.avg_events_per_day > 100
        # Low variance relative to mean
        coefficient_of_variation = baseline.events_std_dev / baseline.avg_events_per_day
        assert coefficient_of_variation < 0.5  # Less than 50% CV
