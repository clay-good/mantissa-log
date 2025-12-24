"""
Integration tests for the ITDR detection pipeline.

Tests the full flow: events -> detection -> alerts.
"""

import pytest
from datetime import datetime, timezone, timedelta
from unittest.mock import Mock, MagicMock, patch

from src.shared.models.identity_event import IdentityEvent, IdentityEventType, GeoLocation
from src.shared.identity.detection.brute_force_detector import BruteForceDetector
from src.shared.identity.detection.mfa_detector import MFADetector
from src.shared.identity.detection.anomaly_detector import IdentityAnomalyDetector
from src.shared.identity.detection.travel_analyzer import ImpossibleTravelAnalyzer
from src.shared.identity.risk.risk_scorer import IdentityRiskScorer
from src.shared.identity.baseline.baseline_calculator import BaselineCalculator

from tests.fixtures.identity.sample_events import (
    create_auth_success_event,
    create_auth_failure_event,
    create_mfa_challenge_event,
    create_mfa_success_event,
    GEO_NYC,
    GEO_TOKYO,
    GEO_MOSCOW,
)
from tests.fixtures.identity.attack_scenarios import (
    BruteForceScenario,
    PasswordSprayScenario,
    MFAFatigueScenario,
    ImpossibleTravelScenario,
    CredentialStuffingScenario,
)
from tests.fixtures.identity.sample_baselines import (
    create_office_worker_baseline,
    create_remote_worker_baseline,
)


class TestBruteForceDetectionPipeline:
    """End-to-end tests for brute force detection."""

    def test_single_user_brute_force_flow(self):
        """Test brute force detection full pipeline."""
        # Generate attack scenario
        scenario = BruteForceScenario(
            target_user="victim@example.com",
            attacker_ip="203.0.113.50",
            attempt_count=10,
            include_success=True,
        )
        result = scenario.generate()

        # Create detector
        detector = BruteForceDetector(
            threshold=5,
            time_window_minutes=10,
        )

        # Process events
        detections = []
        for event in result.events:
            if event.event_type == IdentityEventType.AUTH_FAILURE:
                detection = detector.analyze(event, recent_events=result.events)
                if detection:
                    detections.append(detection)

        # Verify detection occurred
        assert len(detections) > 0
        assert any(d.get("attack_type") == "brute_force" for d in detections)

        # Verify detection metadata
        detection = detections[-1]
        assert detection.get("target_user") == "victim@example.com"
        assert detection.get("source_ip") == "203.0.113.50"
        assert detection.get("attempt_count") >= 5

    def test_password_spray_detection_flow(self):
        """Test password spray detection pipeline."""
        scenario = PasswordSprayScenario(
            target_users=[f"user{i}@example.com" for i in range(20)],
            attacker_ip="203.0.113.51",
            attempts_per_user=2,
        )
        result = scenario.generate()

        detector = BruteForceDetector(
            threshold=5,
            time_window_minutes=60,
            spray_threshold=10,  # Detect spray with >10 unique users
        )

        # Count unique users in failures
        unique_users = set()
        for event in result.events:
            if event.event_type == IdentityEventType.AUTH_FAILURE:
                unique_users.add(event.user_email)

        # Should detect password spray pattern
        detection = detector.detect_password_spray(
            events=result.events,
            source_ip=result.attacker_ip,
        )

        assert detection is not None
        assert detection.get("attack_type") == "password_spray"
        assert detection.get("unique_users") >= 10


class TestMFAFatigueDetectionPipeline:
    """End-to-end tests for MFA fatigue detection."""

    def test_mfa_fatigue_with_success_flow(self):
        """Test MFA fatigue detection when user gives in."""
        scenario = MFAFatigueScenario(
            target_user="victim@example.com",
            push_count=5,
            include_success=True,
        )
        result = scenario.generate()

        detector = MFADetector(
            fatigue_threshold=3,
            time_window_minutes=10,
        )

        # Process events
        detections = []
        for event in result.events:
            detection = detector.analyze(event, recent_events=result.events)
            if detection:
                detections.append(detection)

        # Should detect MFA fatigue
        assert len(detections) > 0
        fatigue_detection = next(
            (d for d in detections if d.get("attack_type") == "mfa_fatigue"),
            None
        )
        assert fatigue_detection is not None

    def test_mfa_fatigue_with_eventual_success_critical_severity(self):
        """MFA fatigue followed by success should be critical severity."""
        scenario = MFAFatigueScenario(
            target_user="victim@example.com",
            push_count=5,
            include_success=True,
        )
        result = scenario.generate()

        detector = MFADetector(fatigue_threshold=3)

        # Find the MFA success event
        mfa_success_events = [
            e for e in result.events
            if e.event_type == IdentityEventType.MFA_SUCCESS
        ]

        assert len(mfa_success_events) > 0

        # Detection on success after fatigue should be critical
        detection = detector.detect_success_after_fatigue(
            success_event=mfa_success_events[0],
            recent_events=result.events,
        )

        assert detection is not None
        assert detection.get("severity") in ["high", "critical"]


class TestImpossibleTravelPipeline:
    """End-to-end tests for impossible travel detection."""

    def test_impossible_travel_nyc_to_tokyo(self):
        """Test impossible travel detection NYC to Tokyo in 1 hour."""
        scenario = ImpossibleTravelScenario(
            target_user="victim@example.com",
            first_location=GEO_NYC,
            second_location=GEO_TOKYO,
            time_gap_minutes=60,
        )
        result = scenario.generate()

        analyzer = ImpossibleTravelAnalyzer(
            max_speed_kmh=900,  # Commercial flight speed
        )

        # Get the two events
        first_event = result.events[0]
        second_event = result.events[1]

        # Check for impossible travel
        detection = analyzer.analyze(
            current_event=second_event,
            previous_event=first_event,
        )

        assert detection is not None
        assert detection.get("is_impossible") is True
        assert detection.get("distance_km") > 10000
        assert detection.get("required_speed_kmh") > 900

    def test_possible_travel_same_city(self):
        """Test no detection for logins from same city."""
        analyzer = ImpossibleTravelAnalyzer(max_speed_kmh=900)

        first_event = create_auth_success_event(
            source_geo=GEO_NYC,
            timestamp=datetime.now(timezone.utc) - timedelta(hours=1),
        )
        second_event = create_auth_success_event(
            source_geo=GEO_NYC,
            timestamp=datetime.now(timezone.utc),
        )

        detection = analyzer.analyze(
            current_event=second_event,
            previous_event=first_event,
        )

        # Should not detect (same location)
        assert detection is None or detection.get("is_impossible") is False


class TestCredentialStuffingPipeline:
    """End-to-end tests for credential stuffing detection."""

    def test_credential_stuffing_many_unknown_users(self):
        """Test detection of credential stuffing with many unknown users."""
        scenario = CredentialStuffingScenario(
            attacker_ip="203.0.113.55",
            unique_users=100,
            success_rate=0.02,
        )
        result = scenario.generate()

        detector = BruteForceDetector(
            credential_stuffing_threshold=20,  # >20 unknown users
        )

        # Detect credential stuffing
        unknown_users = [
            e for e in result.events
            if e.event_type == IdentityEventType.AUTH_FAILURE
            and e.failure_reason == "user_not_found"
        ]

        detection = detector.detect_credential_stuffing(
            events=result.events,
            source_ip=result.attacker_ip,
        )

        assert detection is not None
        assert detection.get("attack_type") == "credential_stuffing"
        assert detection.get("unique_unknown_users") > 20


class TestAnomalyDetectionPipeline:
    """End-to-end tests for behavioral anomaly detection."""

    def test_unusual_hour_login(self):
        """Test detection of login at unusual hour."""
        baseline = create_office_worker_baseline(
            user_email="worker@example.com"
        )
        # Baseline has typical hours 8-18

        detector = IdentityAnomalyDetector()

        # Create event at 3 AM
        event = create_auth_success_event(
            user_email="worker@example.com",
            timestamp=datetime.now(timezone.utc).replace(hour=3),
        )

        detection = detector.detect_unusual_time(
            event=event,
            baseline=baseline,
        )

        assert detection is not None
        assert detection.get("anomaly_type") == "unusual_hour"

    def test_new_location_login(self):
        """Test detection of login from new location."""
        baseline = create_office_worker_baseline(
            user_email="worker@example.com",
            location=GEO_NYC,
        )

        detector = IdentityAnomalyDetector()

        # Create event from Tokyo (not in baseline)
        event = create_auth_success_event(
            user_email="worker@example.com",
            source_geo=GEO_TOKYO,
        )

        detection = detector.detect_new_location(
            event=event,
            baseline=baseline,
        )

        assert detection is not None
        assert detection.get("anomaly_type") == "new_location"
        assert "Tokyo" in str(detection.get("new_location"))

    def test_new_device_login(self):
        """Test detection of login from new device."""
        baseline = create_office_worker_baseline(
            user_email="worker@example.com"
        )

        detector = IdentityAnomalyDetector()

        # Create event with unknown device
        event = create_auth_success_event(
            user_email="worker@example.com",
            device_id="unknown-device-xyz",
            user_agent="SuspiciousBrowser/1.0",
        )

        detection = detector.detect_new_device(
            event=event,
            baseline=baseline,
        )

        assert detection is not None
        assert detection.get("anomaly_type") == "new_device"


class TestRiskScoringPipeline:
    """End-to-end tests for risk scoring."""

    def test_risk_score_accumulation(self):
        """Test risk score accumulates from multiple factors."""
        scorer = IdentityRiskScorer()

        factors = [
            {"type": "unusual_hour", "weight": 15},
            {"type": "new_location", "weight": 25},
            {"type": "new_device", "weight": 20},
        ]

        score = scorer.calculate_score(factors)

        # Should sum to 60
        assert score.total_score == 60
        assert score.risk_level == "high"  # 60 is high risk

    def test_risk_score_capped_at_100(self):
        """Test risk score is capped at 100."""
        scorer = IdentityRiskScorer()

        # Many high-weight factors
        factors = [
            {"type": "impossible_travel", "weight": 40},
            {"type": "mfa_fatigue_success", "weight": 50},
            {"type": "new_country", "weight": 30},
            {"type": "brute_force_success", "weight": 40},
        ]

        score = scorer.calculate_score(factors)

        assert score.total_score == 100  # Capped
        assert score.risk_level == "critical"


class TestFullDetectionWorkflow:
    """Tests for complete detection workflows combining multiple detectors."""

    def test_brute_force_to_account_compromise_workflow(self):
        """Test full workflow: brute force -> success -> anomaly detection."""
        # Generate brute force scenario
        scenario = BruteForceScenario(
            target_user="victim@example.com",
            attacker_ip="203.0.113.50",
            source_geo=GEO_MOSCOW,
            attempt_count=10,
            include_success=True,
        )
        result = scenario.generate()

        # Create baseline for victim (NYC-based worker)
        baseline = create_office_worker_baseline(
            user_email="victim@example.com",
            location=GEO_NYC,
        )

        # Initialize detectors
        brute_force_detector = BruteForceDetector(threshold=5)
        anomaly_detector = IdentityAnomalyDetector()
        risk_scorer = IdentityRiskScorer()

        all_detections = []

        # Process all events
        for event in result.events:
            # Brute force detection
            if event.event_type == IdentityEventType.AUTH_FAILURE:
                detection = brute_force_detector.analyze(event, recent_events=result.events)
                if detection:
                    all_detections.append(detection)

            # Anomaly detection on success
            if event.event_type == IdentityEventType.AUTH_SUCCESS:
                # Check location anomaly
                location_detection = anomaly_detector.detect_new_location(event, baseline)
                if location_detection:
                    all_detections.append(location_detection)

                # Check for success after brute force
                if brute_force_detector.has_recent_brute_force(event.user_email):
                    all_detections.append({
                        "type": "success_after_brute_force",
                        "user": event.user_email,
                        "ip": event.source_ip,
                    })

        # Should have multiple detections
        assert len(all_detections) >= 2

        # Calculate total risk
        risk_factors = [{"type": d.get("type", d.get("anomaly_type", "unknown")), "weight": 30} for d in all_detections]
        risk = risk_scorer.calculate_score(risk_factors)

        assert risk.risk_level in ["high", "critical"]

    def test_mfa_fatigue_to_privilege_escalation_workflow(self):
        """Test workflow: MFA fatigue -> success -> privilege escalation."""
        # This tests a kill chain scenario

        mfa_scenario = MFAFatigueScenario(
            target_user="victim@example.com",
            push_count=5,
            include_success=True,
        )
        mfa_result = mfa_scenario.generate()

        mfa_detector = MFADetector(fatigue_threshold=3)
        risk_scorer = IdentityRiskScorer()

        # Detect MFA fatigue
        mfa_detections = []
        for event in mfa_result.events:
            detection = mfa_detector.analyze(event, recent_events=mfa_result.events)
            if detection:
                mfa_detections.append(detection)

        # Should detect MFA fatigue
        assert len(mfa_detections) > 0

        # Now add privilege escalation event
        from tests.fixtures.identity.sample_events import create_privilege_grant_event
        priv_event = create_privilege_grant_event(
            user_email="victim@example.com",
            role_name="Global Administrator",
            source_geo=GEO_MOSCOW,
        )

        # Calculate combined risk
        risk_factors = [
            {"type": "mfa_fatigue_success", "weight": 50},
            {"type": "privilege_escalation", "weight": 40},
            {"type": "suspicious_location", "weight": 25},
        ]

        risk = risk_scorer.calculate_score(risk_factors)

        # Should be critical risk
        assert risk.risk_level == "critical"
        assert risk.total_score == 100  # Capped at 100
