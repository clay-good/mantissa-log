"""
Attack scenario fixtures for testing ITDR detection.

Provides pre-built attack scenarios with realistic event sequences.
"""

import uuid
from datetime import datetime, timezone, timedelta
from typing import List, Optional
from dataclasses import dataclass

from src.shared.models.identity_event import (
    IdentityEvent,
    IdentityEventType,
    GeoLocation,
    PrivilegeChange,
)

from .sample_events import (
    GEO_NYC,
    GEO_LONDON,
    GEO_TOKYO,
    GEO_MOSCOW,
    GEO_SAN_FRANCISCO,
    create_auth_success_event,
    create_auth_failure_event,
    create_mfa_challenge_event,
    create_mfa_success_event,
    create_mfa_failure_event,
    create_privilege_grant_event,
)


@dataclass
class AttackScenarioResult:
    """Result of an attack scenario generation."""

    events: List[IdentityEvent]
    target_users: List[str]
    attacker_ip: str
    attack_type: str
    expected_detections: List[str]
    description: str


class BruteForceScenario:
    """
    Brute force attack scenario generator.

    Generates a sequence of failed login attempts against a single user
    followed by an optional success (account compromise).
    """

    def __init__(
        self,
        target_user: str = "victim@example.com",
        attacker_ip: str = "203.0.113.50",
        provider: str = "okta",
        attempt_count: int = 10,
        interval_seconds: int = 5,
        include_success: bool = True,
        source_geo: GeoLocation = None,
    ):
        self.target_user = target_user
        self.attacker_ip = attacker_ip
        self.provider = provider
        self.attempt_count = attempt_count
        self.interval_seconds = interval_seconds
        self.include_success = include_success
        self.source_geo = source_geo or GEO_MOSCOW

    def generate(self) -> AttackScenarioResult:
        """Generate brute force attack events."""
        events = []
        base_time = datetime.now(timezone.utc)

        # Generate failed login attempts
        for i in range(self.attempt_count):
            timestamp = base_time - timedelta(
                seconds=(self.attempt_count - i) * self.interval_seconds
            )
            event = create_auth_failure_event(
                user_email=self.target_user,
                source_ip=self.attacker_ip,
                source_geo=self.source_geo,
                provider=self.provider,
                timestamp=timestamp,
                failure_reason="invalid_password",
            )
            events.append(event)

        # Optional successful login after brute force
        if self.include_success:
            success_event = create_auth_success_event(
                user_email=self.target_user,
                source_ip=self.attacker_ip,
                source_geo=self.source_geo,
                provider=self.provider,
                timestamp=base_time,
                device_id=None,  # Unknown device
            )
            events.append(success_event)

        return AttackScenarioResult(
            events=events,
            target_users=[self.target_user],
            attacker_ip=self.attacker_ip,
            attack_type="brute_force",
            expected_detections=[
                "brute_force_single_user",
                "failed_login_spike",
                "new_location_login" if self.include_success else None,
            ],
            description=f"Brute force attack: {self.attempt_count} failed attempts "
            f"{'followed by success' if self.include_success else ''}",
        )


class PasswordSprayScenario:
    """
    Password spray attack scenario generator.

    Generates login attempts against many users with few attempts each,
    simulating an attacker trying common passwords across many accounts.
    """

    def __init__(
        self,
        target_users: List[str] = None,
        attacker_ip: str = "203.0.113.51",
        provider: str = "okta",
        attempts_per_user: int = 2,
        interval_seconds: int = 30,
        success_user: str = None,
        source_geo: GeoLocation = None,
    ):
        self.target_users = target_users or [
            f"user{i}@example.com" for i in range(1, 51)
        ]
        self.attacker_ip = attacker_ip
        self.provider = provider
        self.attempts_per_user = attempts_per_user
        self.interval_seconds = interval_seconds
        self.success_user = success_user
        self.source_geo = source_geo or GEO_MOSCOW

    def generate(self) -> AttackScenarioResult:
        """Generate password spray attack events."""
        events = []
        base_time = datetime.now(timezone.utc)
        event_index = 0

        # Generate failed attempts across all users
        for attempt in range(self.attempts_per_user):
            for user in self.target_users:
                timestamp = base_time - timedelta(
                    seconds=(len(self.target_users) * self.attempts_per_user - event_index)
                    * self.interval_seconds
                )
                event = create_auth_failure_event(
                    user_email=user,
                    source_ip=self.attacker_ip,
                    source_geo=self.source_geo,
                    provider=self.provider,
                    timestamp=timestamp,
                    failure_reason="invalid_password",
                )
                events.append(event)
                event_index += 1

        # Optional successful login for one user
        if self.success_user:
            success_event = create_auth_success_event(
                user_email=self.success_user,
                source_ip=self.attacker_ip,
                source_geo=self.source_geo,
                provider=self.provider,
                timestamp=base_time,
            )
            events.append(success_event)

        return AttackScenarioResult(
            events=events,
            target_users=self.target_users,
            attacker_ip=self.attacker_ip,
            attack_type="password_spray",
            expected_detections=[
                "password_spray",
                "distributed_auth_failure",
                "many_users_single_ip",
            ],
            description=f"Password spray: {len(self.target_users)} users, "
            f"{self.attempts_per_user} attempts each",
        )


class MFAFatigueScenario:
    """
    MFA fatigue attack scenario generator.

    Generates repeated MFA push requests to exhaust the user
    until they accept to stop the notifications.
    """

    def __init__(
        self,
        target_user: str = "victim@example.com",
        attacker_ip: str = "203.0.113.52",
        provider: str = "okta",
        push_count: int = 5,
        interval_seconds: int = 30,
        include_success: bool = True,
        mfa_method: str = "push",
        source_geo: GeoLocation = None,
    ):
        self.target_user = target_user
        self.attacker_ip = attacker_ip
        self.provider = provider
        self.push_count = push_count
        self.interval_seconds = interval_seconds
        self.include_success = include_success
        self.mfa_method = mfa_method
        self.source_geo = source_geo or GEO_MOSCOW

    def generate(self) -> AttackScenarioResult:
        """Generate MFA fatigue attack events."""
        events = []
        base_time = datetime.now(timezone.utc)

        # Generate MFA challenge/denial sequence
        for i in range(self.push_count):
            timestamp = base_time - timedelta(
                seconds=(self.push_count - i + 1) * self.interval_seconds
            )

            # MFA challenge
            challenge = create_mfa_challenge_event(
                user_email=self.target_user,
                source_ip=self.attacker_ip,
                source_geo=self.source_geo,
                provider=self.provider,
                timestamp=timestamp,
                mfa_method=self.mfa_method,
            )
            events.append(challenge)

            # MFA denial (user rejects push)
            denial_timestamp = timestamp + timedelta(seconds=5)
            denial = create_mfa_failure_event(
                user_email=self.target_user,
                source_ip=self.attacker_ip,
                source_geo=self.source_geo,
                provider=self.provider,
                timestamp=denial_timestamp,
                mfa_method=self.mfa_method,
                failure_reason="denied",
            )
            events.append(denial)

        # User gives in and accepts MFA
        if self.include_success:
            # Final challenge
            final_challenge = create_mfa_challenge_event(
                user_email=self.target_user,
                source_ip=self.attacker_ip,
                source_geo=self.source_geo,
                provider=self.provider,
                timestamp=base_time - timedelta(seconds=10),
                mfa_method=self.mfa_method,
            )
            events.append(final_challenge)

            # Success after fatigue
            success = create_mfa_success_event(
                user_email=self.target_user,
                source_ip=self.attacker_ip,
                source_geo=self.source_geo,
                provider=self.provider,
                timestamp=base_time,
                mfa_method=self.mfa_method,
            )
            events.append(success)

            # Attacker gets access
            auth_success = create_auth_success_event(
                user_email=self.target_user,
                source_ip=self.attacker_ip,
                source_geo=self.source_geo,
                provider=self.provider,
                timestamp=base_time + timedelta(seconds=5),
            )
            events.append(auth_success)

        return AttackScenarioResult(
            events=events,
            target_users=[self.target_user],
            attacker_ip=self.attacker_ip,
            attack_type="mfa_fatigue",
            expected_detections=[
                "mfa_fatigue",
                "mfa_push_bombardment",
                "mfa_success_after_denials",
            ],
            description=f"MFA fatigue: {self.push_count} push attempts "
            f"{'followed by success' if self.include_success else ''}",
        )


class ImpossibleTravelScenario:
    """
    Impossible travel attack scenario generator.

    Generates logins from geographically distant locations
    within a time frame too short for physical travel.
    """

    def __init__(
        self,
        target_user: str = "victim@example.com",
        first_location: GeoLocation = None,
        second_location: GeoLocation = None,
        first_ip: str = "192.168.1.100",
        second_ip: str = "203.0.113.53",
        provider: str = "okta",
        time_gap_minutes: int = 60,
    ):
        self.target_user = target_user
        self.first_location = first_location or GEO_NYC
        self.second_location = second_location or GEO_TOKYO
        self.first_ip = first_ip
        self.second_ip = second_ip
        self.provider = provider
        self.time_gap_minutes = time_gap_minutes

    def generate(self) -> AttackScenarioResult:
        """Generate impossible travel events."""
        events = []
        base_time = datetime.now(timezone.utc)

        # First legitimate login
        first_login = create_auth_success_event(
            user_email=self.target_user,
            source_ip=self.first_ip,
            source_geo=self.first_location,
            provider=self.provider,
            timestamp=base_time - timedelta(minutes=self.time_gap_minutes),
            device_id="device-legitimate",
        )
        events.append(first_login)

        # Second login from distant location (attacker)
        second_login = create_auth_success_event(
            user_email=self.target_user,
            source_ip=self.second_ip,
            source_geo=self.second_location,
            provider=self.provider,
            timestamp=base_time,
            device_id="device-attacker",
        )
        events.append(second_login)

        # Calculate expected travel speed for description
        # NYC to Tokyo is approximately 10,800 km
        distance_km = 10800
        speed_kmh = distance_km / (self.time_gap_minutes / 60)

        return AttackScenarioResult(
            events=events,
            target_users=[self.target_user],
            attacker_ip=self.second_ip,
            attack_type="impossible_travel",
            expected_detections=[
                "impossible_travel",
                "new_location_login",
                "new_device_login",
            ],
            description=f"Impossible travel: {self.first_location.city} to "
            f"{self.second_location.city} in {self.time_gap_minutes} minutes "
            f"(~{speed_kmh:.0f} km/h)",
        )


class PrivilegeEscalationScenario:
    """
    Privilege escalation attack scenario generator.

    Generates a sequence of events showing privilege escalation:
    normal user login -> granted admin role -> suspicious activities.
    """

    def __init__(
        self,
        target_user: str = "compromised@example.com",
        attacker_ip: str = "203.0.113.54",
        provider: str = "azure",
        escalation_path: List[str] = None,
        source_geo: GeoLocation = None,
    ):
        self.target_user = target_user
        self.attacker_ip = attacker_ip
        self.provider = provider
        self.escalation_path = escalation_path or [
            "User",
            "Security Reader",
            "User Administrator",
            "Global Administrator",
        ]
        self.source_geo = source_geo or GEO_MOSCOW

    def generate(self) -> AttackScenarioResult:
        """Generate privilege escalation events."""
        events = []
        base_time = datetime.now(timezone.utc)
        interval = timedelta(minutes=5)

        # Initial login
        initial_login = create_auth_success_event(
            user_email=self.target_user,
            source_ip=self.attacker_ip,
            source_geo=self.source_geo,
            provider=self.provider,
            timestamp=base_time - interval * len(self.escalation_path),
        )
        events.append(initial_login)

        # Privilege escalation steps
        for i, role in enumerate(self.escalation_path[1:], 1):
            timestamp = base_time - interval * (len(self.escalation_path) - i)
            grant_event = create_privilege_grant_event(
                user_email=self.target_user,
                source_ip=self.attacker_ip,
                source_geo=self.source_geo,
                provider=self.provider,
                timestamp=timestamp,
                role_name=role,
                granted_by=self.target_user if i > 1 else "admin@example.com",
            )
            events.append(grant_event)

        return AttackScenarioResult(
            events=events,
            target_users=[self.target_user],
            attacker_ip=self.attacker_ip,
            attack_type="privilege_escalation",
            expected_detections=[
                "privilege_escalation_chain",
                "rapid_privilege_grant",
                "self_privilege_grant",
                "global_admin_grant",
            ],
            description=f"Privilege escalation: {' -> '.join(self.escalation_path)}",
        )


class CredentialStuffingScenario:
    """
    Credential stuffing attack scenario generator.

    Generates login attempts with many unique usernames from a single IP,
    simulating an attacker testing stolen credentials.
    """

    def __init__(
        self,
        attacker_ip: str = "203.0.113.55",
        provider: str = "okta",
        unique_users: int = 100,
        success_rate: float = 0.05,
        interval_seconds: int = 2,
        source_geo: GeoLocation = None,
    ):
        self.attacker_ip = attacker_ip
        self.provider = provider
        self.unique_users = unique_users
        self.success_rate = success_rate
        self.interval_seconds = interval_seconds
        self.source_geo = source_geo or GEO_MOSCOW
        # Generate random usernames (simulating stolen credential list)
        self.usernames = [
            f"{uuid.uuid4().hex[:8]}@unknowndomain{i % 10}.com"
            for i in range(unique_users)
        ]

    def generate(self) -> AttackScenarioResult:
        """Generate credential stuffing attack events."""
        events = []
        base_time = datetime.now(timezone.utc)
        successful_users = []

        for i, username in enumerate(self.usernames):
            timestamp = base_time - timedelta(
                seconds=(self.unique_users - i) * self.interval_seconds
            )

            # Determine if this attempt succeeds (based on success_rate)
            import random
            is_success = random.random() < self.success_rate

            if is_success:
                event = create_auth_success_event(
                    user_email=username,
                    source_ip=self.attacker_ip,
                    source_geo=self.source_geo,
                    provider=self.provider,
                    timestamp=timestamp,
                )
                successful_users.append(username)
            else:
                event = create_auth_failure_event(
                    user_email=username,
                    source_ip=self.attacker_ip,
                    source_geo=self.source_geo,
                    provider=self.provider,
                    timestamp=timestamp,
                    failure_reason="user_not_found",
                )

            events.append(event)

        return AttackScenarioResult(
            events=events,
            target_users=self.usernames,
            attacker_ip=self.attacker_ip,
            attack_type="credential_stuffing",
            expected_detections=[
                "credential_stuffing",
                "many_unknown_users_single_ip",
                "high_auth_volume_single_ip",
            ],
            description=f"Credential stuffing: {self.unique_users} unique users, "
            f"{len(successful_users)} compromised ({self.success_rate*100:.0f}% success)",
        )


class SessionHijackingScenario:
    """
    Session hijacking attack scenario generator.

    Generates events showing a legitimate session being hijacked:
    user logs in, then session appears from different location/device.
    """

    def __init__(
        self,
        target_user: str = "victim@example.com",
        legitimate_ip: str = "192.168.1.100",
        attacker_ip: str = "203.0.113.56",
        legitimate_geo: GeoLocation = None,
        attacker_geo: GeoLocation = None,
        provider: str = "okta",
    ):
        self.target_user = target_user
        self.legitimate_ip = legitimate_ip
        self.attacker_ip = attacker_ip
        self.legitimate_geo = legitimate_geo or GEO_NYC
        self.attacker_geo = attacker_geo or GEO_MOSCOW
        self.provider = provider

    def generate(self) -> AttackScenarioResult:
        """Generate session hijacking events."""
        events = []
        base_time = datetime.now(timezone.utc)
        session_id = f"session-{uuid.uuid4().hex[:8]}"

        # Legitimate user login
        legitimate_login = create_auth_success_event(
            user_email=self.target_user,
            source_ip=self.legitimate_ip,
            source_geo=self.legitimate_geo,
            provider=self.provider,
            timestamp=base_time - timedelta(hours=1),
            session_id=session_id,
            device_id="device-legitimate",
        )
        events.append(legitimate_login)

        # Legitimate activity
        for i in range(3):
            activity = create_auth_success_event(
                user_email=self.target_user,
                source_ip=self.legitimate_ip,
                source_geo=self.legitimate_geo,
                provider=self.provider,
                timestamp=base_time - timedelta(minutes=45 - i * 10),
                session_id=session_id,
                device_id="device-legitimate",
                application_name=["Salesforce", "Slack", "Office365"][i],
            )
            events.append(activity)

        # Session appears from attacker (same session_id, different IP/location)
        hijacked_activity = create_auth_success_event(
            user_email=self.target_user,
            source_ip=self.attacker_ip,
            source_geo=self.attacker_geo,
            provider=self.provider,
            timestamp=base_time,
            session_id=session_id,
            device_id="device-attacker",
        )
        events.append(hijacked_activity)

        return AttackScenarioResult(
            events=events,
            target_users=[self.target_user],
            attacker_ip=self.attacker_ip,
            attack_type="session_hijacking",
            expected_detections=[
                "session_ip_change",
                "session_geo_change",
                "session_device_change",
                "concurrent_session_anomaly",
            ],
            description=f"Session hijacking: session {session_id[:12]} stolen, "
            f"appeared from {self.attacker_geo.city}",
        )
