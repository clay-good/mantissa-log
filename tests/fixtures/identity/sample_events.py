"""
Sample IdentityEvents for testing.

Provides factory functions to create realistic identity events for each event type.
"""

import uuid
from datetime import datetime, timezone, timedelta
from typing import Optional, Dict, Any

from src.shared.models.identity_event import (
    IdentityEvent,
    IdentityEventType,
    GeoLocation,
    PrivilegeChange,
)


# Default geolocations for testing
GEO_NYC = GeoLocation(
    country="US",
    city="New York",
    region="New York",
    latitude=40.7128,
    longitude=-74.0060,
    asn="AS7922",
)

GEO_LONDON = GeoLocation(
    country="GB",
    city="London",
    region="England",
    latitude=51.5074,
    longitude=-0.1278,
    asn="AS5089",
)

GEO_TOKYO = GeoLocation(
    country="JP",
    city="Tokyo",
    region="Tokyo",
    latitude=35.6762,
    longitude=139.6503,
    asn="AS2516",
)

GEO_MOSCOW = GeoLocation(
    country="RU",
    city="Moscow",
    region="Moscow",
    latitude=55.7558,
    longitude=37.6173,
    asn="AS8402",
)

GEO_SAN_FRANCISCO = GeoLocation(
    country="US",
    city="San Francisco",
    region="California",
    latitude=37.7749,
    longitude=-122.4194,
    asn="AS36351",
)


def _generate_event_id() -> str:
    """Generate a unique event ID."""
    return f"evt-{uuid.uuid4().hex[:12]}"


def create_auth_success_event(
    user_email: str = "john.doe@example.com",
    user_id: str = "user-001",
    source_ip: str = "192.168.1.100",
    source_geo: GeoLocation = None,
    provider: str = "okta",
    timestamp: datetime = None,
    device_id: str = "device-001",
    user_agent: str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0",
    application_name: str = "Salesforce",
    mfa_method: str = "push",
    session_id: str = None,
) -> IdentityEvent:
    """Create a successful authentication event."""
    return IdentityEvent(
        event_id=_generate_event_id(),
        event_type=IdentityEventType.AUTH_SUCCESS,
        timestamp=timestamp or datetime.now(timezone.utc),
        provider=provider,
        user_id=user_id,
        user_email=user_email,
        user_display_name=user_email.split("@")[0].replace(".", " ").title(),
        source_ip=source_ip,
        source_geo=source_geo or GEO_NYC,
        device_id=device_id,
        device_type="desktop",
        user_agent=user_agent,
        session_id=session_id or f"session-{uuid.uuid4().hex[:8]}",
        mfa_method=mfa_method,
        auth_protocol="OIDC",
        application_id=f"app-{application_name.lower().replace(' ', '-')}",
        application_name=application_name,
        risk_level="none",
    )


def create_auth_failure_event(
    user_email: str = "john.doe@example.com",
    user_id: str = "user-001",
    source_ip: str = "192.168.1.100",
    source_geo: GeoLocation = None,
    provider: str = "okta",
    timestamp: datetime = None,
    failure_reason: str = "invalid_password",
    device_id: str = None,
    user_agent: str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0",
    application_name: str = "Salesforce",
) -> IdentityEvent:
    """Create a failed authentication event."""
    return IdentityEvent(
        event_id=_generate_event_id(),
        event_type=IdentityEventType.AUTH_FAILURE,
        timestamp=timestamp or datetime.now(timezone.utc),
        provider=provider,
        user_id=user_id,
        user_email=user_email,
        source_ip=source_ip,
        source_geo=source_geo or GEO_NYC,
        device_id=device_id,
        device_type="unknown",
        user_agent=user_agent,
        failure_reason=failure_reason,
        application_id=f"app-{application_name.lower().replace(' ', '-')}",
        application_name=application_name,
        risk_level="medium",
    )


def create_mfa_challenge_event(
    user_email: str = "john.doe@example.com",
    user_id: str = "user-001",
    source_ip: str = "192.168.1.100",
    source_geo: GeoLocation = None,
    provider: str = "okta",
    timestamp: datetime = None,
    mfa_method: str = "push",
) -> IdentityEvent:
    """Create an MFA challenge event."""
    return IdentityEvent(
        event_id=_generate_event_id(),
        event_type=IdentityEventType.MFA_CHALLENGE,
        timestamp=timestamp or datetime.now(timezone.utc),
        provider=provider,
        user_id=user_id,
        user_email=user_email,
        source_ip=source_ip,
        source_geo=source_geo or GEO_NYC,
        mfa_method=mfa_method,
    )


def create_mfa_success_event(
    user_email: str = "john.doe@example.com",
    user_id: str = "user-001",
    source_ip: str = "192.168.1.100",
    source_geo: GeoLocation = None,
    provider: str = "okta",
    timestamp: datetime = None,
    mfa_method: str = "push",
    session_id: str = None,
) -> IdentityEvent:
    """Create a successful MFA event."""
    return IdentityEvent(
        event_id=_generate_event_id(),
        event_type=IdentityEventType.MFA_SUCCESS,
        timestamp=timestamp or datetime.now(timezone.utc),
        provider=provider,
        user_id=user_id,
        user_email=user_email,
        source_ip=source_ip,
        source_geo=source_geo or GEO_NYC,
        mfa_method=mfa_method,
        session_id=session_id or f"session-{uuid.uuid4().hex[:8]}",
    )


def create_mfa_failure_event(
    user_email: str = "john.doe@example.com",
    user_id: str = "user-001",
    source_ip: str = "192.168.1.100",
    source_geo: GeoLocation = None,
    provider: str = "okta",
    timestamp: datetime = None,
    mfa_method: str = "push",
    failure_reason: str = "denied",
) -> IdentityEvent:
    """Create a failed MFA event."""
    return IdentityEvent(
        event_id=_generate_event_id(),
        event_type=IdentityEventType.MFA_FAILURE,
        timestamp=timestamp or datetime.now(timezone.utc),
        provider=provider,
        user_id=user_id,
        user_email=user_email,
        source_ip=source_ip,
        source_geo=source_geo or GEO_NYC,
        mfa_method=mfa_method,
        failure_reason=failure_reason,
        risk_level="medium",
    )


def create_privilege_grant_event(
    user_email: str = "john.doe@example.com",
    user_id: str = "user-001",
    source_ip: str = "192.168.1.100",
    source_geo: GeoLocation = None,
    provider: str = "azure",
    timestamp: datetime = None,
    role_name: str = "Global Administrator",
    granted_by: str = "admin@example.com",
) -> IdentityEvent:
    """Create a privilege grant event."""
    return IdentityEvent(
        event_id=_generate_event_id(),
        event_type=IdentityEventType.PRIVILEGE_GRANT,
        timestamp=timestamp or datetime.now(timezone.utc),
        provider=provider,
        user_id=user_id,
        user_email=user_email,
        source_ip=source_ip,
        source_geo=source_geo or GEO_NYC,
        privilege_changes=[
            PrivilegeChange(
                action="grant",
                role_name=role_name,
                granted_by=granted_by,
                timestamp=timestamp or datetime.now(timezone.utc),
            )
        ],
        risk_level="high",
        risk_reasons=[f"Granted privileged role: {role_name}"],
    )


def create_session_start_event(
    user_email: str = "john.doe@example.com",
    user_id: str = "user-001",
    source_ip: str = "192.168.1.100",
    source_geo: GeoLocation = None,
    provider: str = "okta",
    timestamp: datetime = None,
    session_id: str = None,
    device_id: str = "device-001",
    application_name: str = "Corporate Portal",
) -> IdentityEvent:
    """Create a session start event."""
    return IdentityEvent(
        event_id=_generate_event_id(),
        event_type=IdentityEventType.SESSION_START,
        timestamp=timestamp or datetime.now(timezone.utc),
        provider=provider,
        user_id=user_id,
        user_email=user_email,
        source_ip=source_ip,
        source_geo=source_geo or GEO_NYC,
        session_id=session_id or f"session-{uuid.uuid4().hex[:8]}",
        device_id=device_id,
        application_name=application_name,
    )


def create_logout_event(
    user_email: str = "john.doe@example.com",
    user_id: str = "user-001",
    source_ip: str = "192.168.1.100",
    source_geo: GeoLocation = None,
    provider: str = "okta",
    timestamp: datetime = None,
    session_id: str = None,
) -> IdentityEvent:
    """Create a logout event."""
    return IdentityEvent(
        event_id=_generate_event_id(),
        event_type=IdentityEventType.LOGOUT,
        timestamp=timestamp or datetime.now(timezone.utc),
        provider=provider,
        user_id=user_id,
        user_email=user_email,
        source_ip=source_ip,
        source_geo=source_geo or GEO_NYC,
        session_id=session_id or f"session-{uuid.uuid4().hex[:8]}",
    )


def create_password_change_event(
    user_email: str = "john.doe@example.com",
    user_id: str = "user-001",
    source_ip: str = "192.168.1.100",
    source_geo: GeoLocation = None,
    provider: str = "okta",
    timestamp: datetime = None,
    initiated_by: str = "self",
) -> IdentityEvent:
    """Create a password change event."""
    risk_level = "medium" if initiated_by == "admin" else "low"

    return IdentityEvent(
        event_id=_generate_event_id(),
        event_type=IdentityEventType.PASSWORD_CHANGE,
        timestamp=timestamp or datetime.now(timezone.utc),
        provider=provider,
        user_id=user_id,
        user_email=user_email,
        source_ip=source_ip,
        source_geo=source_geo or GEO_NYC,
        risk_level=risk_level,
        raw_event={"initiated_by": initiated_by},
    )


def create_token_issued_event(
    user_email: str = "john.doe@example.com",
    user_id: str = "user-001",
    source_ip: str = "192.168.1.100",
    source_geo: GeoLocation = None,
    provider: str = "azure",
    timestamp: datetime = None,
    application_name: str = "API Client",
    token_type: str = "access_token",
) -> IdentityEvent:
    """Create a token issued event."""
    return IdentityEvent(
        event_id=_generate_event_id(),
        event_type=IdentityEventType.TOKEN_ISSUED,
        timestamp=timestamp or datetime.now(timezone.utc),
        provider=provider,
        user_id=user_id,
        user_email=user_email,
        source_ip=source_ip,
        source_geo=source_geo or GEO_NYC,
        application_name=application_name,
        raw_event={"token_type": token_type},
    )


def create_account_locked_event(
    user_email: str = "john.doe@example.com",
    user_id: str = "user-001",
    source_ip: str = "192.168.1.100",
    source_geo: GeoLocation = None,
    provider: str = "okta",
    timestamp: datetime = None,
    lock_reason: str = "too_many_failed_attempts",
) -> IdentityEvent:
    """Create an account locked event."""
    return IdentityEvent(
        event_id=_generate_event_id(),
        event_type=IdentityEventType.ACCOUNT_LOCKED,
        timestamp=timestamp or datetime.now(timezone.utc),
        provider=provider,
        user_id=user_id,
        user_email=user_email,
        source_ip=source_ip,
        source_geo=source_geo or GEO_NYC,
        failure_reason=lock_reason,
        risk_level="high",
        risk_reasons=[f"Account locked: {lock_reason}"],
    )


def create_events_sequence(
    event_types: list,
    user_email: str = "john.doe@example.com",
    provider: str = "okta",
    interval_seconds: int = 60,
) -> list:
    """Create a sequence of events with specified types."""
    events = []
    base_time = datetime.now(timezone.utc)

    for i, event_type in enumerate(event_types):
        timestamp = base_time - timedelta(seconds=(len(event_types) - i) * interval_seconds)

        if event_type == IdentityEventType.AUTH_SUCCESS:
            event = create_auth_success_event(user_email=user_email, provider=provider, timestamp=timestamp)
        elif event_type == IdentityEventType.AUTH_FAILURE:
            event = create_auth_failure_event(user_email=user_email, provider=provider, timestamp=timestamp)
        elif event_type == IdentityEventType.MFA_CHALLENGE:
            event = create_mfa_challenge_event(user_email=user_email, provider=provider, timestamp=timestamp)
        elif event_type == IdentityEventType.MFA_SUCCESS:
            event = create_mfa_success_event(user_email=user_email, provider=provider, timestamp=timestamp)
        elif event_type == IdentityEventType.MFA_FAILURE:
            event = create_mfa_failure_event(user_email=user_email, provider=provider, timestamp=timestamp)
        elif event_type == IdentityEventType.PRIVILEGE_GRANT:
            event = create_privilege_grant_event(user_email=user_email, provider=provider, timestamp=timestamp)
        else:
            event = create_auth_success_event(user_email=user_email, provider=provider, timestamp=timestamp)

        events.append(event)

    return events
