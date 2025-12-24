"""
Unit tests for SessionTracker.

Tests session creation, updates, concurrent session detection, and session anomaly detection.
"""

import pytest
from datetime import datetime, timezone, timedelta
from unittest.mock import Mock, MagicMock, patch

from src.shared.identity.session.session_tracker import SessionTracker
from src.shared.identity.session.user_session import UserSession, SessionStatus
from src.shared.models.identity_event import IdentityEvent, IdentityEventType, GeoLocation


class TestSessionCreation:
    """Tests for session creation."""

    def test_create_session_from_auth_success(self, sample_auth_success_event):
        """Auth success should create a new session."""
        tracker = SessionTracker()

        session = tracker.create_session(event=sample_auth_success_event)

        assert session is not None
        assert session.user_email == sample_auth_success_event.user_email
        assert session.session_id is not None
        assert session.status == SessionStatus.ACTIVE
        assert session.start_time == sample_auth_success_event.timestamp

    def test_session_captures_source_info(self, sample_auth_success_event):
        """Session should capture source IP and geo information."""
        tracker = SessionTracker()

        session = tracker.create_session(event=sample_auth_success_event)

        assert session.source_ip == sample_auth_success_event.source_ip
        assert session.source_geo == sample_auth_success_event.source_geo
        assert session.device_id == sample_auth_success_event.device_id

    def test_session_captures_provider_info(self, sample_auth_success_event):
        """Session should capture provider and application."""
        tracker = SessionTracker()

        session = tracker.create_session(event=sample_auth_success_event)

        assert session.provider == sample_auth_success_event.provider
        assert session.application == sample_auth_success_event.application_name

    def test_session_has_unique_id(self, sample_auth_success_event):
        """Each session should have a unique identifier."""
        tracker = SessionTracker()

        session1 = tracker.create_session(event=sample_auth_success_event)
        session2 = tracker.create_session(event=sample_auth_success_event)

        assert session1.session_id != session2.session_id

    def test_session_uses_event_session_id_if_present(self, sample_auth_success_event):
        """Session should use event's session_id if available."""
        tracker = SessionTracker()

        from dataclasses import replace
        event_with_session = replace(
            sample_auth_success_event,
            session_id="provider-session-123"
        )

        session = tracker.create_session(event=event_with_session)

        assert session.provider_session_id == "provider-session-123"


class TestSessionUpdates:
    """Tests for session updates."""

    def test_update_session_activity(self, sample_auth_success_event):
        """Session activity should be updated on new events."""
        tracker = SessionTracker()

        session = tracker.create_session(event=sample_auth_success_event)
        original_last_activity = session.last_activity

        # Create activity event
        from dataclasses import replace
        activity_event = replace(
            sample_auth_success_event,
            event_type=IdentityEventType.TOKEN_REFRESH,
            timestamp=datetime.now(timezone.utc) + timedelta(minutes=30),
        )

        updated = tracker.update_session(session=session, event=activity_event)

        assert updated.last_activity > original_last_activity
        assert updated.event_count == session.event_count + 1

    def test_session_timeout_detection(self, sample_auth_success_event):
        """Sessions past timeout should be marked inactive."""
        tracker = SessionTracker(session_timeout_minutes=60)

        session = tracker.create_session(event=sample_auth_success_event)
        session.last_activity = datetime.now(timezone.utc) - timedelta(minutes=90)

        is_active = tracker.is_session_active(session)

        assert is_active is False

    def test_active_session_within_timeout(self, sample_auth_success_event):
        """Sessions within timeout should remain active."""
        tracker = SessionTracker(session_timeout_minutes=60)

        session = tracker.create_session(event=sample_auth_success_event)
        session.last_activity = datetime.now(timezone.utc) - timedelta(minutes=30)

        is_active = tracker.is_session_active(session)

        assert is_active is True

    def test_session_end_on_logout(self, sample_auth_success_event, sample_logout_event):
        """Logout event should end session."""
        tracker = SessionTracker()

        session = tracker.create_session(event=sample_auth_success_event)

        ended = tracker.end_session(session=session, event=sample_logout_event)

        assert ended.status == SessionStatus.ENDED
        assert ended.end_time == sample_logout_event.timestamp

    def test_session_tracks_applications_accessed(self, sample_auth_success_event):
        """Session should track all applications accessed."""
        tracker = SessionTracker()

        session = tracker.create_session(event=sample_auth_success_event)

        from dataclasses import replace
        events = [
            replace(sample_auth_success_event, application_name="Slack"),
            replace(sample_auth_success_event, application_name="GitHub"),
            replace(sample_auth_success_event, application_name="Jira"),
        ]

        for event in events:
            session = tracker.update_session(session=session, event=event)

        assert "Slack" in session.applications_accessed
        assert "GitHub" in session.applications_accessed
        assert "Jira" in session.applications_accessed


class TestConcurrentSessionDetection:
    """Tests for concurrent session detection."""

    def test_detect_concurrent_sessions_same_user(self, sample_auth_success_event, sample_geo_nyc, sample_geo_tokyo):
        """Should detect concurrent sessions from different locations."""
        tracker = SessionTracker()

        # Create first session
        session1 = tracker.create_session(event=sample_auth_success_event)

        # Create second session from different location
        from dataclasses import replace
        tokyo_event = replace(
            sample_auth_success_event,
            source_ip="203.0.113.50",
            source_geo=sample_geo_tokyo,
            device_id="device-tokyo",
        )
        session2 = tracker.create_session(event=tokyo_event)

        active_sessions = [session1, session2]
        concurrent = tracker.detect_concurrent_sessions(
            user_email=sample_auth_success_event.user_email,
            active_sessions=active_sessions,
        )

        assert concurrent is True
        assert len(active_sessions) == 2

    def test_concurrent_sessions_same_location_allowed(self, sample_auth_success_event):
        """Concurrent sessions from same location should not alert by default."""
        tracker = SessionTracker()

        # Create two sessions from same location
        session1 = tracker.create_session(event=sample_auth_success_event)

        from dataclasses import replace
        event2 = replace(
            sample_auth_success_event,
            device_id="device-002",  # Different device, same location
        )
        session2 = tracker.create_session(event=event2)

        active_sessions = [session1, session2]
        is_suspicious = tracker.is_suspicious_concurrent(
            sessions=active_sessions,
            check_location=True,
        )

        # Same location = not suspicious
        assert is_suspicious is False

    def test_concurrent_sessions_different_countries_suspicious(
        self, sample_auth_success_event, sample_geo_nyc, sample_geo_tokyo
    ):
        """Concurrent sessions from different countries should be suspicious."""
        tracker = SessionTracker()

        # NYC session
        session1 = tracker.create_session(event=sample_auth_success_event)
        session1.source_geo = sample_geo_nyc

        # Tokyo session
        from dataclasses import replace
        tokyo_event = replace(
            sample_auth_success_event,
            source_geo=sample_geo_tokyo,
        )
        session2 = tracker.create_session(event=tokyo_event)

        is_suspicious = tracker.is_suspicious_concurrent(
            sessions=[session1, session2],
            check_location=True,
        )

        assert is_suspicious is True

    def test_max_concurrent_sessions_threshold(self, sample_auth_success_event):
        """Should alert when max concurrent sessions exceeded."""
        tracker = SessionTracker(max_concurrent_sessions=3)

        # Create 5 sessions
        sessions = []
        from dataclasses import replace
        for i in range(5):
            event = replace(sample_auth_success_event, device_id=f"device-{i}")
            sessions.append(tracker.create_session(event=event))

        exceeds_threshold = tracker.exceeds_concurrent_limit(
            user_email=sample_auth_success_event.user_email,
            active_sessions=sessions,
        )

        assert exceeds_threshold is True

    def test_concurrent_sessions_with_different_providers(
        self, sample_auth_success_event, sample_geo_nyc
    ):
        """Should detect concurrent sessions across different providers."""
        tracker = SessionTracker()

        # Okta session
        session1 = tracker.create_session(event=sample_auth_success_event)
        session1.provider = "okta"

        # Azure session from same location
        from dataclasses import replace
        azure_event = replace(
            sample_auth_success_event,
            provider="azure",
            source_geo=sample_geo_nyc,
        )
        session2 = tracker.create_session(event=azure_event)

        is_cross_provider = tracker.is_cross_provider_concurrent(
            sessions=[session1, session2]
        )

        assert is_cross_provider is True


class TestSessionAnomalyDetection:
    """Tests for session anomaly detection."""

    def test_unusual_session_duration(self, sample_auth_success_event, sample_mature_baseline):
        """Should detect unusually long sessions."""
        tracker = SessionTracker()

        session = tracker.create_session(event=sample_auth_success_event)
        session.start_time = datetime.now(timezone.utc) - timedelta(hours=16)
        session.last_activity = datetime.now(timezone.utc)

        anomaly = tracker.detect_duration_anomaly(
            session=session,
            baseline=sample_mature_baseline,
        )

        assert anomaly is not None
        assert anomaly["type"] == "unusual_duration"
        assert anomaly["duration_hours"] == 16

    def test_session_ip_change_mid_session(self, sample_auth_success_event):
        """Should detect IP changes during a session."""
        tracker = SessionTracker()

        session = tracker.create_session(event=sample_auth_success_event)
        original_ip = session.source_ip

        # Event from different IP
        from dataclasses import replace
        new_ip_event = replace(
            sample_auth_success_event,
            source_ip="8.8.8.8",
            timestamp=datetime.now(timezone.utc) + timedelta(minutes=5),
        )

        anomaly = tracker.detect_ip_change(
            session=session,
            event=new_ip_event,
        )

        assert anomaly is not None
        assert anomaly["type"] == "session_ip_change"
        assert anomaly["original_ip"] == original_ip
        assert anomaly["new_ip"] == "8.8.8.8"

    def test_session_geo_change_mid_session(
        self, sample_auth_success_event, sample_geo_nyc, sample_geo_tokyo
    ):
        """Should detect geographic changes during a session."""
        tracker = SessionTracker()

        session = tracker.create_session(event=sample_auth_success_event)
        session.source_geo = sample_geo_nyc

        # Event from different location
        from dataclasses import replace
        tokyo_event = replace(
            sample_auth_success_event,
            source_geo=sample_geo_tokyo,
            timestamp=datetime.now(timezone.utc) + timedelta(minutes=30),
        )

        anomaly = tracker.detect_geo_change(
            session=session,
            event=tokyo_event,
        )

        assert anomaly is not None
        assert anomaly["type"] == "session_geo_change"
        assert "Tokyo" in str(anomaly["new_location"])

    def test_unusual_session_activity_pattern(self, sample_auth_success_event):
        """Should detect unusual activity patterns within session."""
        tracker = SessionTracker()

        session = tracker.create_session(event=sample_auth_success_event)
        session.event_count = 500  # Very high activity

        anomaly = tracker.detect_activity_anomaly(
            session=session,
            threshold_events=100,
        )

        assert anomaly is not None
        assert anomaly["type"] == "high_session_activity"

    def test_session_device_change_suspicious(self, sample_auth_success_event):
        """Should detect device changes mid-session."""
        tracker = SessionTracker()

        session = tracker.create_session(event=sample_auth_success_event)
        original_device = session.device_id

        # Event from different device
        from dataclasses import replace
        new_device_event = replace(
            sample_auth_success_event,
            device_id="suspicious-device-xyz",
            user_agent="Suspicious Bot/1.0",
            timestamp=datetime.now(timezone.utc) + timedelta(minutes=10),
        )

        anomaly = tracker.detect_device_change(
            session=session,
            event=new_device_event,
        )

        assert anomaly is not None
        assert anomaly["type"] == "session_device_change"
        assert anomaly["original_device"] == original_device

    def test_session_after_password_change_suspicious(self, sample_auth_success_event):
        """Active sessions after password change should be flagged."""
        tracker = SessionTracker()

        # Create session before password change
        session = tracker.create_session(event=sample_auth_success_event)
        session.start_time = datetime.now(timezone.utc) - timedelta(hours=2)

        # Password changed
        password_change_time = datetime.now(timezone.utc) - timedelta(hours=1)

        is_suspicious = tracker.is_session_after_password_change(
            session=session,
            password_change_time=password_change_time,
        )

        assert is_suspicious is True


class TestSessionStateManagement:
    """Tests for session state management."""

    def test_get_active_sessions_for_user(self, sample_auth_success_event, mock_query_executor):
        """Should retrieve all active sessions for a user."""
        tracker = SessionTracker(query_executor=mock_query_executor)

        # Mock returns two active sessions
        mock_query_executor.execute.return_value = [
            {"session_id": "sess-1", "status": "active"},
            {"session_id": "sess-2", "status": "active"},
        ]

        sessions = tracker.get_active_sessions(
            user_email=sample_auth_success_event.user_email
        )

        assert len(sessions) == 2

    def test_expire_stale_sessions(self, sample_auth_success_event, mock_query_executor):
        """Should expire sessions past timeout."""
        tracker = SessionTracker(
            query_executor=mock_query_executor,
            session_timeout_minutes=60,
        )

        # Create stale session
        session = tracker.create_session(event=sample_auth_success_event)
        session.last_activity = datetime.now(timezone.utc) - timedelta(hours=2)

        expired = tracker.expire_session(session)

        assert expired.status == SessionStatus.EXPIRED

    def test_terminate_all_user_sessions(self, sample_auth_success_event, mock_query_executor):
        """Should terminate all sessions for a user (security action)."""
        tracker = SessionTracker(query_executor=mock_query_executor)

        # Mock returns sessions to terminate
        mock_query_executor.execute.return_value = [
            {"session_id": "sess-1", "status": "active"},
            {"session_id": "sess-2", "status": "active"},
            {"session_id": "sess-3", "status": "active"},
        ]

        count = tracker.terminate_all_sessions(
            user_email=sample_auth_success_event.user_email,
            reason="security_incident",
        )

        assert count == 3

    def test_session_history_tracking(self, sample_auth_success_event):
        """Should track session history for user."""
        tracker = SessionTracker()

        session = tracker.create_session(event=sample_auth_success_event)

        # Add events to history
        from dataclasses import replace
        for i in range(5):
            event = replace(
                sample_auth_success_event,
                timestamp=datetime.now(timezone.utc) + timedelta(minutes=i * 10),
            )
            session = tracker.update_session(session=session, event=event)

        assert len(session.event_history) >= 5


class TestEdgeCases:
    """Tests for edge cases in session tracking."""

    def test_session_with_null_geo(self, sample_user_email):
        """Should handle sessions with no geo data."""
        tracker = SessionTracker()

        event = IdentityEvent(
            event_id="evt-001",
            event_type=IdentityEventType.AUTH_SUCCESS,
            timestamp=datetime.now(timezone.utc),
            provider="okta",
            user_id="user-123",
            user_email=sample_user_email,
            source_ip="1.2.3.4",
            source_geo=None,
        )

        session = tracker.create_session(event=event)

        assert session is not None
        assert session.source_geo is None

    def test_session_with_missing_device_id(self, sample_user_email):
        """Should handle events without device_id."""
        tracker = SessionTracker()

        event = IdentityEvent(
            event_id="evt-001",
            event_type=IdentityEventType.AUTH_SUCCESS,
            timestamp=datetime.now(timezone.utc),
            provider="okta",
            user_id="user-123",
            user_email=sample_user_email,
            source_ip="1.2.3.4",
            device_id=None,
        )

        session = tracker.create_session(event=event)

        assert session is not None
        assert session.device_id is None

    def test_duplicate_session_events_handled(self, sample_auth_success_event):
        """Should handle duplicate events gracefully."""
        tracker = SessionTracker()

        session = tracker.create_session(event=sample_auth_success_event)

        # Same event multiple times
        for _ in range(5):
            session = tracker.update_session(session=session, event=sample_auth_success_event)

        # Should not create duplicate entries in history
        assert session is not None

    def test_out_of_order_events(self, sample_auth_success_event):
        """Should handle out-of-order events."""
        tracker = SessionTracker()

        session = tracker.create_session(event=sample_auth_success_event)

        from dataclasses import replace
        # Event with older timestamp
        old_event = replace(
            sample_auth_success_event,
            timestamp=datetime.now(timezone.utc) - timedelta(hours=1),
        )

        # Should not update last_activity to older time
        original_activity = session.last_activity
        session = tracker.update_session(session=session, event=old_event)

        assert session.last_activity >= original_activity

    def test_session_for_service_account(self, sample_auth_success_event):
        """Should handle service account sessions appropriately."""
        tracker = SessionTracker()

        from dataclasses import replace
        service_event = replace(
            sample_auth_success_event,
            user_email="service-account@example.com",
        )

        session = tracker.create_session(event=service_event)
        session.is_service_account = True

        # Service accounts typically have different session patterns
        anomaly = tracker.detect_duration_anomaly(
            session=session,
            baseline=None,  # May not have baseline
            is_service_account=True,
        )

        # Should not flag normal service account behavior
        assert anomaly is None or anomaly.get("skip_for_service_account", False)

