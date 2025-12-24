"""
Integration tests for alert correlation into incidents.

Tests that related alerts are properly grouped and correlated.
"""

import pytest
from datetime import datetime, timezone, timedelta
from unittest.mock import Mock, MagicMock

from src.shared.models.identity_event import IdentityEvent, IdentityEventType, GeoLocation
from src.shared.identity.correlation.identity_correlator import IdentityCorrelator
from src.shared.identity.correlation.kill_chain_detector import KillChainDetector
from src.shared.identity.correlation.incident_manager import IdentityIncidentManager

from tests.fixtures.identity.sample_events import (
    create_auth_success_event,
    create_auth_failure_event,
    create_mfa_challenge_event,
    create_mfa_success_event,
    create_privilege_grant_event,
    GEO_NYC,
    GEO_MOSCOW,
)
from tests.fixtures.identity.attack_scenarios import (
    BruteForceScenario,
    MFAFatigueScenario,
    PrivilegeEscalationScenario,
    ImpossibleTravelScenario,
)


class TestAlertCorrelation:
    """Tests for correlating related alerts into incidents."""

    def test_brute_force_alerts_grouped(self):
        """Multiple brute force alerts against same user should group."""
        correlator = IdentityCorrelator(
            time_window_minutes=30,
            user_grouping=True,
        )

        # Create multiple related alerts
        alerts = [
            {
                "id": "alert-001",
                "type": "brute_force",
                "user_email": "victim@example.com",
                "source_ip": "203.0.113.50",
                "timestamp": datetime.now(timezone.utc) - timedelta(minutes=25),
                "severity": "medium",
            },
            {
                "id": "alert-002",
                "type": "brute_force",
                "user_email": "victim@example.com",
                "source_ip": "203.0.113.50",
                "timestamp": datetime.now(timezone.utc) - timedelta(minutes=20),
                "severity": "high",
            },
            {
                "id": "alert-003",
                "type": "successful_login_after_failures",
                "user_email": "victim@example.com",
                "source_ip": "203.0.113.50",
                "timestamp": datetime.now(timezone.utc) - timedelta(minutes=15),
                "severity": "critical",
            },
        ]

        # Correlate alerts
        incidents = correlator.correlate(alerts)

        # Should produce single incident
        assert len(incidents) == 1
        assert len(incidents[0]["alerts"]) == 3
        assert incidents[0]["severity"] == "critical"  # Highest severity

    def test_different_users_not_grouped(self):
        """Alerts for different users should not be grouped."""
        correlator = IdentityCorrelator(
            time_window_minutes=30,
            user_grouping=True,
        )

        alerts = [
            {
                "id": "alert-001",
                "type": "brute_force",
                "user_email": "user1@example.com",
                "source_ip": "203.0.113.50",
                "timestamp": datetime.now(timezone.utc),
                "severity": "medium",
            },
            {
                "id": "alert-002",
                "type": "brute_force",
                "user_email": "user2@example.com",
                "source_ip": "203.0.113.51",
                "timestamp": datetime.now(timezone.utc),
                "severity": "medium",
            },
        ]

        incidents = correlator.correlate(alerts)

        # Should produce two separate incidents
        assert len(incidents) == 2

    def test_same_attacker_ip_grouped(self):
        """Alerts from same attacker IP can be grouped."""
        correlator = IdentityCorrelator(
            time_window_minutes=30,
            ip_grouping=True,
        )

        # Same IP attacking multiple users (password spray)
        alerts = [
            {
                "id": "alert-001",
                "type": "auth_failure",
                "user_email": "user1@example.com",
                "source_ip": "203.0.113.50",
                "timestamp": datetime.now(timezone.utc),
                "severity": "low",
            },
            {
                "id": "alert-002",
                "type": "auth_failure",
                "user_email": "user2@example.com",
                "source_ip": "203.0.113.50",
                "timestamp": datetime.now(timezone.utc),
                "severity": "low",
            },
            {
                "id": "alert-003",
                "type": "auth_failure",
                "user_email": "user3@example.com",
                "source_ip": "203.0.113.50",
                "timestamp": datetime.now(timezone.utc),
                "severity": "low",
            },
        ]

        incidents = correlator.correlate(alerts)

        # Should group by attacker IP
        assert len(incidents) == 1
        assert incidents[0]["correlation_key"] == "ip:203.0.113.50"


class TestKillChainDetection:
    """Tests for kill chain stage detection."""

    def test_detect_initial_access_stage(self):
        """Test detection of initial access stage."""
        detector = KillChainDetector()

        events = [
            create_auth_failure_event(
                user_email="victim@example.com",
                timestamp=datetime.now(timezone.utc) - timedelta(minutes=10),
            ),
            create_auth_failure_event(
                user_email="victim@example.com",
                timestamp=datetime.now(timezone.utc) - timedelta(minutes=8),
            ),
            create_auth_success_event(
                user_email="victim@example.com",
                source_geo=GEO_MOSCOW,
                timestamp=datetime.now(timezone.utc),
            ),
        ]

        stage = detector.detect_stage(events)

        assert stage == "initial_access"

    def test_detect_privilege_escalation_stage(self):
        """Test detection of privilege escalation stage."""
        detector = KillChainDetector()

        events = [
            create_auth_success_event(
                user_email="victim@example.com",
                timestamp=datetime.now(timezone.utc) - timedelta(minutes=30),
            ),
            create_privilege_grant_event(
                user_email="victim@example.com",
                role_name="Security Reader",
                timestamp=datetime.now(timezone.utc) - timedelta(minutes=20),
            ),
            create_privilege_grant_event(
                user_email="victim@example.com",
                role_name="Global Administrator",
                timestamp=datetime.now(timezone.utc),
            ),
        ]

        stage = detector.detect_stage(events)

        assert stage == "privilege_escalation"

    def test_full_kill_chain_progression(self):
        """Test detection of full kill chain progression."""
        detector = KillChainDetector()

        # Build full attack chain
        base_time = datetime.now(timezone.utc)

        events = [
            # Reconnaissance (failed login probing)
            create_auth_failure_event(
                user_email="victim@example.com",
                timestamp=base_time - timedelta(hours=2),
            ),
            # Initial access (brute force success)
            create_auth_failure_event(
                user_email="victim@example.com",
                timestamp=base_time - timedelta(hours=1, minutes=50),
            ),
            create_auth_failure_event(
                user_email="victim@example.com",
                timestamp=base_time - timedelta(hours=1, minutes=45),
            ),
            create_auth_success_event(
                user_email="victim@example.com",
                source_geo=GEO_MOSCOW,
                timestamp=base_time - timedelta(hours=1, minutes=40),
            ),
            # Privilege escalation
            create_privilege_grant_event(
                user_email="victim@example.com",
                role_name="User Administrator",
                timestamp=base_time - timedelta(hours=1),
            ),
            create_privilege_grant_event(
                user_email="victim@example.com",
                role_name="Global Administrator",
                timestamp=base_time - timedelta(minutes=30),
            ),
        ]

        chain = detector.analyze_chain(events)

        assert "initial_access" in chain["stages"]
        assert "privilege_escalation" in chain["stages"]
        assert chain["severity"] == "critical"


class TestIncidentManagement:
    """Tests for incident creation and management."""

    def test_create_incident_from_alerts(self):
        """Test incident creation from correlated alerts."""
        manager = IdentityIncidentManager()

        alerts = [
            {
                "id": "alert-001",
                "type": "brute_force",
                "user_email": "victim@example.com",
                "severity": "medium",
                "timestamp": datetime.now(timezone.utc),
            },
            {
                "id": "alert-002",
                "type": "successful_login",
                "user_email": "victim@example.com",
                "severity": "high",
                "timestamp": datetime.now(timezone.utc),
            },
        ]

        incident = manager.create_incident(
            alerts=alerts,
            incident_type="account_compromise",
        )

        assert incident is not None
        assert incident["status"] == "open"
        assert incident["severity"] == "high"
        assert len(incident["alerts"]) == 2
        assert incident["affected_user"] == "victim@example.com"

    def test_incident_severity_escalation(self):
        """Test that incident severity escalates with new alerts."""
        manager = IdentityIncidentManager()

        # Initial incident
        incident = manager.create_incident(
            alerts=[{
                "id": "alert-001",
                "type": "unusual_login",
                "user_email": "victim@example.com",
                "severity": "low",
                "timestamp": datetime.now(timezone.utc),
            }],
            incident_type="suspicious_activity",
        )

        assert incident["severity"] == "low"

        # Add critical alert
        updated = manager.add_alert_to_incident(
            incident_id=incident["id"],
            alert={
                "id": "alert-002",
                "type": "privilege_escalation",
                "user_email": "victim@example.com",
                "severity": "critical",
                "timestamp": datetime.now(timezone.utc),
            },
        )

        assert updated["severity"] == "critical"

    def test_incident_timeline_ordering(self):
        """Test that incident timeline is properly ordered."""
        manager = IdentityIncidentManager()

        base_time = datetime.now(timezone.utc)

        alerts = [
            {
                "id": "alert-002",
                "type": "login",
                "user_email": "victim@example.com",
                "severity": "medium",
                "timestamp": base_time - timedelta(minutes=5),
            },
            {
                "id": "alert-001",
                "type": "brute_force",
                "user_email": "victim@example.com",
                "severity": "medium",
                "timestamp": base_time - timedelta(minutes=10),
            },
            {
                "id": "alert-003",
                "type": "privilege_grant",
                "user_email": "victim@example.com",
                "severity": "high",
                "timestamp": base_time,
            },
        ]

        incident = manager.create_incident(
            alerts=alerts,
            incident_type="attack_chain",
        )

        # Timeline should be chronologically ordered
        timeline = incident["timeline"]
        assert len(timeline) == 3
        assert timeline[0]["id"] == "alert-001"  # Earliest
        assert timeline[2]["id"] == "alert-003"  # Latest


class TestCrossProviderCorrelation:
    """Tests for correlating attacks across identity providers."""

    def test_correlate_across_okta_and_azure(self):
        """Test correlation of attacks across Okta and Azure."""
        correlator = IdentityCorrelator(
            cross_provider=True,
        )

        alerts = [
            {
                "id": "alert-001",
                "type": "brute_force",
                "provider": "okta",
                "user_email": "victim@example.com",
                "source_ip": "203.0.113.50",
                "timestamp": datetime.now(timezone.utc) - timedelta(minutes=10),
                "severity": "medium",
            },
            {
                "id": "alert-002",
                "type": "brute_force",
                "provider": "azure",
                "user_email": "victim@example.com",
                "source_ip": "203.0.113.50",
                "timestamp": datetime.now(timezone.utc) - timedelta(minutes=5),
                "severity": "medium",
            },
            {
                "id": "alert-003",
                "type": "login_success",
                "provider": "azure",
                "user_email": "victim@example.com",
                "source_ip": "203.0.113.50",
                "timestamp": datetime.now(timezone.utc),
                "severity": "high",
            },
        ]

        incidents = correlator.correlate(alerts)

        # Should correlate as single cross-provider attack
        assert len(incidents) == 1
        assert incidents[0]["is_cross_provider"] is True
        assert set(incidents[0]["providers"]) == {"okta", "azure"}

    def test_mfa_fatigue_across_providers(self):
        """Test detection of MFA fatigue attack across providers."""
        correlator = IdentityCorrelator(cross_provider=True)

        # Attacker tries MFA fatigue on multiple providers
        alerts = [
            {
                "id": "alert-001",
                "type": "mfa_challenge",
                "provider": "okta",
                "user_email": "victim@example.com",
                "timestamp": datetime.now(timezone.utc) - timedelta(minutes=5),
                "severity": "low",
            },
            {
                "id": "alert-002",
                "type": "mfa_challenge",
                "provider": "duo",
                "user_email": "victim@example.com",
                "timestamp": datetime.now(timezone.utc) - timedelta(minutes=4),
                "severity": "low",
            },
            {
                "id": "alert-003",
                "type": "mfa_fatigue",
                "provider": "okta",
                "user_email": "victim@example.com",
                "timestamp": datetime.now(timezone.utc),
                "severity": "high",
            },
        ]

        incidents = correlator.correlate(alerts)

        assert len(incidents) == 1
        assert "okta" in incidents[0]["providers"]
        assert "duo" in incidents[0]["providers"]


class TestIncidentEnrichment:
    """Tests for incident enrichment with context."""

    def test_enrich_with_user_context(self):
        """Test incident enrichment with user risk context."""
        manager = IdentityIncidentManager()

        incident = manager.create_incident(
            alerts=[{
                "id": "alert-001",
                "type": "privilege_escalation",
                "user_email": "executive@example.com",
                "severity": "high",
                "timestamp": datetime.now(timezone.utc),
            }],
            incident_type="privilege_abuse",
        )

        # Enrich with user context
        user_context = {
            "is_executive": True,
            "is_privileged": True,
            "department": "Executive",
            "risk_score": 85,
        }

        enriched = manager.enrich_incident(
            incident_id=incident["id"],
            user_context=user_context,
        )

        assert enriched["user_context"]["is_executive"] is True
        assert enriched["priority"] == "p1"  # High priority for executives

    def test_enrich_with_baseline_comparison(self):
        """Test incident enrichment with baseline deviation."""
        manager = IdentityIncidentManager()

        incident = manager.create_incident(
            alerts=[{
                "id": "alert-001",
                "type": "unusual_login",
                "user_email": "worker@example.com",
                "severity": "medium",
                "timestamp": datetime.now(timezone.utc),
            }],
            incident_type="anomaly",
        )

        # Add baseline comparison
        baseline_comparison = {
            "typical_hours": [9, 10, 11, 12, 13, 14, 15, 16, 17],
            "login_hour": 3,
            "is_unusual_hour": True,
            "typical_location": "New York",
            "login_location": "Moscow",
            "is_new_location": True,
        }

        enriched = manager.enrich_incident(
            incident_id=incident["id"],
            baseline_comparison=baseline_comparison,
        )

        assert enriched["baseline_deviation"]["is_unusual_hour"] is True
        assert enriched["baseline_deviation"]["is_new_location"] is True
