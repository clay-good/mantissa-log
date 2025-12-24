"""Pytest fixtures for identity threat detection tests."""

import pytest
from datetime import datetime, timezone, timedelta
from unittest.mock import Mock, MagicMock

from src.shared.models.identity_event import (
    IdentityEvent,
    IdentityEventType,
    GeoLocation,
)
from src.shared.identity.baseline.user_baseline import UserBaseline


@pytest.fixture
def sample_geo_nyc():
    """Sample geolocation for New York City."""
    return GeoLocation(
        country="US",
        city="New York",
        latitude=40.7128,
        longitude=-74.0060,
    )


@pytest.fixture
def sample_geo_london():
    """Sample geolocation for London."""
    return GeoLocation(
        country="GB",
        city="London",
        latitude=51.5074,
        longitude=-0.1278,
    )


@pytest.fixture
def sample_geo_tokyo():
    """Sample geolocation for Tokyo."""
    return GeoLocation(
        country="JP",
        city="Tokyo",
        latitude=35.6762,
        longitude=139.6503,
    )


@pytest.fixture
def sample_geo_boston():
    """Sample geolocation for Boston."""
    return GeoLocation(
        country="US",
        city="Boston",
        latitude=42.3601,
        longitude=-71.0589,
    )


@pytest.fixture
def sample_user_email():
    """Sample user email for testing."""
    return "john.doe@example.com"


@pytest.fixture
def sample_auth_success_event(sample_user_email, sample_geo_nyc):
    """Sample successful authentication event."""
    return IdentityEvent(
        event_id="evt-001",
        event_type=IdentityEventType.AUTH_SUCCESS,
        timestamp=datetime.now(timezone.utc),
        provider="okta",
        user_id="user-123",
        user_email=sample_user_email,
        user_display_name="John Doe",
        source_ip="192.168.1.1",
        source_geo=sample_geo_nyc,
        device_id="device-001",
        device_type="desktop",
        user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0",
        session_id="session-001",
        application_id="app-001",
        application_name="Salesforce",
    )


@pytest.fixture
def sample_auth_failure_event(sample_user_email, sample_geo_nyc):
    """Sample failed authentication event."""
    return IdentityEvent(
        event_id="evt-002",
        event_type=IdentityEventType.AUTH_FAILURE,
        timestamp=datetime.now(timezone.utc),
        provider="okta",
        user_id="user-123",
        user_email=sample_user_email,
        source_ip="192.168.1.1",
        source_geo=sample_geo_nyc,
        failure_reason="invalid_password",
    )


@pytest.fixture
def sample_mfa_challenge_event(sample_user_email, sample_geo_nyc):
    """Sample MFA challenge event."""
    return IdentityEvent(
        event_id="evt-003",
        event_type=IdentityEventType.MFA_CHALLENGE,
        timestamp=datetime.now(timezone.utc),
        provider="okta",
        user_id="user-123",
        user_email=sample_user_email,
        source_ip="192.168.1.1",
        source_geo=sample_geo_nyc,
        mfa_method="push",
    )


@pytest.fixture
def sample_mfa_success_event(sample_user_email, sample_geo_nyc):
    """Sample MFA success event."""
    return IdentityEvent(
        event_id="evt-004",
        event_type=IdentityEventType.MFA_SUCCESS,
        timestamp=datetime.now(timezone.utc),
        provider="okta",
        user_id="user-123",
        user_email=sample_user_email,
        source_ip="192.168.1.1",
        source_geo=sample_geo_nyc,
        mfa_method="push",
    )


@pytest.fixture
def sample_privilege_grant_event(sample_user_email, sample_geo_nyc):
    """Sample privilege grant event."""
    return IdentityEvent(
        event_id="evt-005",
        event_type=IdentityEventType.PRIVILEGE_GRANT,
        timestamp=datetime.now(timezone.utc),
        provider="azure",
        user_id="user-123",
        user_email=sample_user_email,
        source_ip="192.168.1.1",
        source_geo=sample_geo_nyc,
    )


@pytest.fixture
def sample_logout_event(sample_user_email, sample_geo_nyc):
    """Sample logout event."""
    return IdentityEvent(
        event_id="evt-006",
        event_type=IdentityEventType.LOGOUT,
        timestamp=datetime.now(timezone.utc),
        provider="okta",
        user_id="user-123",
        user_email=sample_user_email,
        source_ip="192.168.1.1",
        source_geo=sample_geo_nyc,
        session_id="session-001",
    )


@pytest.fixture
def sample_mature_baseline(sample_user_email, sample_geo_nyc):
    """Sample mature user baseline (14+ days)."""
    baseline = UserBaseline(user_email=sample_user_email)

    # Set as mature
    baseline.first_seen = datetime.now(timezone.utc) - timedelta(days=30)
    baseline.last_updated = datetime.now(timezone.utc)
    baseline.event_count = 500

    # Set typical behavior
    baseline.typical_hours = list(range(8, 18))  # 8 AM to 6 PM
    baseline.typical_days = [0, 1, 2, 3, 4]  # Mon-Fri
    baseline.known_locations = [sample_geo_nyc]
    baseline.known_devices = [
        {"device_id": "device-001", "user_agent": "Mozilla/5.0 Chrome/120.0", "first_seen": datetime.now(timezone.utc) - timedelta(days=20)}
    ]
    baseline.known_ips = {"192.168.1.1", "10.0.0.1"}
    baseline.typical_applications = {"Salesforce", "Slack", "Office365"}
    baseline.auth_methods = {"password", "push"}
    baseline.avg_events_per_day = 15.5
    baseline.events_std_dev = 4.2

    return baseline


@pytest.fixture
def sample_immature_baseline(sample_user_email):
    """Sample immature user baseline (<14 days)."""
    baseline = UserBaseline(user_email=sample_user_email)

    # Set as immature
    baseline.first_seen = datetime.now(timezone.utc) - timedelta(days=5)
    baseline.last_updated = datetime.now(timezone.utc)
    baseline.event_count = 50

    return baseline


@pytest.fixture
def mock_query_executor():
    """Mock query executor for database operations."""
    executor = Mock()
    executor.execute_query = MagicMock(return_value=[])
    return executor


@pytest.fixture
def mock_baseline_store():
    """Mock baseline store for testing."""
    store = Mock()
    store.get_baseline = MagicMock(return_value=None)
    store.save_baseline = MagicMock()
    return store


def create_event_at_time(
    base_event: IdentityEvent,
    hours_ago: float = 0,
    geo: GeoLocation = None,
    event_type: IdentityEventType = None,
) -> IdentityEvent:
    """Create a copy of an event with modified timestamp and optional geo."""
    from dataclasses import replace

    new_timestamp = datetime.now(timezone.utc) - timedelta(hours=hours_ago)

    kwargs = {"timestamp": new_timestamp}
    if geo:
        kwargs["source_geo"] = geo
    if event_type:
        kwargs["event_type"] = event_type

    return replace(base_event, **kwargs)


def generate_failed_login_sequence(
    user_email: str,
    count: int,
    source_ip: str = "1.2.3.4",
    interval_seconds: int = 10,
) -> list:
    """Generate a sequence of failed login events for testing."""
    events = []
    base_time = datetime.now(timezone.utc)

    for i in range(count):
        event = IdentityEvent(
            event_id=f"evt-fail-{i}",
            event_type=IdentityEventType.AUTH_FAILURE,
            timestamp=base_time - timedelta(seconds=i * interval_seconds),
            provider="okta",
            user_id=f"user-{user_email}",
            user_email=user_email,
            source_ip=source_ip,
            failure_reason="invalid_password",
        )
        events.append(event)

    return events


def generate_mfa_challenge_sequence(
    user_email: str,
    count: int,
    interval_seconds: int = 30,
    include_success: bool = False,
) -> list:
    """Generate a sequence of MFA challenge events for testing MFA fatigue."""
    events = []
    base_time = datetime.now(timezone.utc)

    for i in range(count):
        event = IdentityEvent(
            event_id=f"evt-mfa-{i}",
            event_type=IdentityEventType.MFA_CHALLENGE,
            timestamp=base_time - timedelta(seconds=i * interval_seconds),
            provider="okta",
            user_id=f"user-{user_email}",
            user_email=user_email,
            source_ip="1.2.3.4",
            mfa_method="push",
        )
        events.append(event)

    if include_success:
        success_event = IdentityEvent(
            event_id=f"evt-mfa-success",
            event_type=IdentityEventType.MFA_SUCCESS,
            timestamp=base_time,
            provider="okta",
            user_id=f"user-{user_email}",
            user_email=user_email,
            source_ip="1.2.3.4",
            mfa_method="push",
        )
        events.insert(0, success_event)

    return events
