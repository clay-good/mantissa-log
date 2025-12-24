"""
Test data generator for rule validation.

Generates test events for validating Sigma detection rules.
"""

import uuid
from datetime import datetime, timezone, timedelta
from typing import List, Dict, Any, Optional
from dataclasses import dataclass

from src.shared.models.identity_event import GeoLocation


@dataclass
class GeneratedEvent:
    """Container for a generated test event."""

    event: Dict[str, Any]
    should_match: bool
    description: str


class EventGenerator:
    """
    Generator for creating test events for rule validation.

    Provides methods to generate events that should or should not
    trigger specific detection rules.
    """

    def __init__(self):
        self.default_geo_us = {
            "country": "US",
            "city": "New York",
            "latitude": 40.7128,
            "longitude": -74.0060,
        }
        self.default_geo_ru = {
            "country": "RU",
            "city": "Moscow",
            "latitude": 55.7558,
            "longitude": 37.6173,
        }

    def _generate_event_id(self) -> str:
        """Generate unique event ID."""
        return f"evt-{uuid.uuid4().hex[:12]}"

    def _base_event(
        self,
        provider: str = "okta",
        event_type: str = "authentication",
        timestamp: datetime = None,
    ) -> Dict[str, Any]:
        """Create base event structure."""
        return {
            "event_id": self._generate_event_id(),
            "timestamp": (timestamp or datetime.now(timezone.utc)).isoformat(),
            "provider": provider,
            "event_type": event_type,
        }

    # =========================================================================
    # Brute Force Events
    # =========================================================================

    def generate_brute_force_events(
        self,
        count: int,
        user: str,
        ip: str,
        provider: str = "okta",
        interval_seconds: int = 5,
    ) -> List[Dict[str, Any]]:
        """
        Generate brute force attack events.

        Args:
            count: Number of failed login attempts
            user: Target user email
            ip: Source IP address
            provider: Identity provider
            interval_seconds: Time between attempts

        Returns:
            List of event dictionaries
        """
        events = []
        base_time = datetime.now(timezone.utc)

        for i in range(count):
            timestamp = base_time - timedelta(seconds=(count - i) * interval_seconds)
            event = {
                **self._base_event(provider, "user.session.start", timestamp),
                "outcome": "FAILURE",
                "user_email": user,
                "source_ip": ip,
                "failure_reason": "INVALID_CREDENTIALS",
                "actor": {
                    "alternateId": user,
                    "displayName": user.split("@")[0],
                },
                "client": {
                    "ipAddress": ip,
                    "geographicalContext": self.default_geo_ru,
                },
            }
            events.append(event)

        return events

    def generate_brute_force_with_success(
        self,
        failed_count: int,
        user: str,
        ip: str,
        provider: str = "okta",
    ) -> List[Dict[str, Any]]:
        """Generate brute force followed by successful login."""
        events = self.generate_brute_force_events(failed_count, user, ip, provider)

        # Add successful login
        success_event = {
            **self._base_event(provider, "user.session.start"),
            "outcome": "SUCCESS",
            "user_email": user,
            "source_ip": ip,
            "actor": {
                "alternateId": user,
                "displayName": user.split("@")[0],
            },
            "client": {
                "ipAddress": ip,
                "geographicalContext": self.default_geo_ru,
            },
        }
        events.append(success_event)

        return events

    # =========================================================================
    # Password Spray Events
    # =========================================================================

    def generate_password_spray_events(
        self,
        users: List[str],
        ip: str,
        provider: str = "okta",
        attempts_per_user: int = 2,
    ) -> List[Dict[str, Any]]:
        """
        Generate password spray attack events.

        Args:
            users: List of target user emails
            ip: Source IP address
            provider: Identity provider
            attempts_per_user: Number of attempts per user

        Returns:
            List of event dictionaries
        """
        events = []
        base_time = datetime.now(timezone.utc)
        event_index = 0

        for attempt in range(attempts_per_user):
            for user in users:
                timestamp = base_time - timedelta(seconds=(len(users) * attempts_per_user - event_index) * 30)
                event = {
                    **self._base_event(provider, "user.session.start", timestamp),
                    "outcome": "FAILURE",
                    "user_email": user,
                    "source_ip": ip,
                    "failure_reason": "INVALID_CREDENTIALS",
                    "actor": {
                        "alternateId": user,
                    },
                    "client": {
                        "ipAddress": ip,
                    },
                }
                events.append(event)
                event_index += 1

        return events

    # =========================================================================
    # Impossible Travel Events
    # =========================================================================

    def generate_impossible_travel_events(
        self,
        user: str,
        locations: List[Dict[str, Any]],
        time_gap_minutes: int = 60,
        provider: str = "okta",
    ) -> List[Dict[str, Any]]:
        """
        Generate impossible travel events.

        Args:
            user: User email
            locations: List of location dicts (first is origin, rest are destinations)
            time_gap_minutes: Time between logins
            provider: Identity provider

        Returns:
            List of event dictionaries
        """
        events = []
        base_time = datetime.now(timezone.utc)

        for i, location in enumerate(locations):
            timestamp = base_time - timedelta(minutes=(len(locations) - i - 1) * time_gap_minutes)
            event = {
                **self._base_event(provider, "user.session.start", timestamp),
                "outcome": "SUCCESS",
                "user_email": user,
                "source_ip": f"192.168.{i}.{i+1}",
                "actor": {
                    "alternateId": user,
                },
                "client": {
                    "ipAddress": f"192.168.{i}.{i+1}",
                    "geographicalContext": location,
                },
            }
            events.append(event)

        return events

    # =========================================================================
    # MFA Fatigue Events
    # =========================================================================

    def generate_mfa_fatigue_events(
        self,
        user: str,
        count: int,
        include_success: bool = True,
        provider: str = "okta",
    ) -> List[Dict[str, Any]]:
        """
        Generate MFA fatigue attack events.

        Args:
            user: Target user email
            count: Number of MFA push attempts
            include_success: Whether to include final success
            provider: Identity provider

        Returns:
            List of event dictionaries
        """
        events = []
        base_time = datetime.now(timezone.utc)

        # Generate MFA challenges and denials
        for i in range(count):
            timestamp = base_time - timedelta(seconds=(count - i + 1) * 30)

            # MFA challenge
            challenge = {
                **self._base_event(provider, "user.mfa.factor.verify", timestamp),
                "outcome": "CHALLENGE",
                "user_email": user,
                "mfa_method": "push",
                "actor": {
                    "alternateId": user,
                },
                "authenticationContext": {
                    "authenticationStep": "mfa",
                },
            }
            events.append(challenge)

            # MFA denial
            denial = {
                **self._base_event(provider, "user.mfa.factor.verify", timestamp + timedelta(seconds=5)),
                "outcome": "FAILURE",
                "user_email": user,
                "mfa_method": "push",
                "failure_reason": "DENIED",
                "actor": {
                    "alternateId": user,
                },
            }
            events.append(denial)

        # Optional success
        if include_success:
            # Final challenge
            final_challenge = {
                **self._base_event(provider, "user.mfa.factor.verify", base_time - timedelta(seconds=10)),
                "outcome": "CHALLENGE",
                "user_email": user,
                "mfa_method": "push",
                "actor": {
                    "alternateId": user,
                },
            }
            events.append(final_challenge)

            # Success
            success = {
                **self._base_event(provider, "user.mfa.factor.verify", base_time),
                "outcome": "SUCCESS",
                "user_email": user,
                "mfa_method": "push",
                "actor": {
                    "alternateId": user,
                },
            }
            events.append(success)

        return events

    # =========================================================================
    # Privilege Escalation Events
    # =========================================================================

    def generate_privilege_escalation_events(
        self,
        user: str,
        roles: List[str],
        provider: str = "azure",
    ) -> List[Dict[str, Any]]:
        """
        Generate privilege escalation events.

        Args:
            user: User email
            roles: List of roles in escalation order
            provider: Identity provider

        Returns:
            List of event dictionaries
        """
        events = []
        base_time = datetime.now(timezone.utc)

        for i, role in enumerate(roles):
            timestamp = base_time - timedelta(minutes=(len(roles) - i) * 5)
            event = {
                **self._base_event(provider, "Add member to role", timestamp),
                "outcome": "SUCCESS",
                "user_email": user,
                "target_user": user,
                "role_name": role,
                "actor": {
                    "alternateId": user if i > 0 else "admin@example.com",
                },
                "target": {
                    "alternateId": user,
                    "role": role,
                },
            }
            events.append(event)

        return events

    # =========================================================================
    # Credential Stuffing Events
    # =========================================================================

    def generate_credential_stuffing_events(
        self,
        ip: str,
        user_count: int,
        success_rate: float = 0.05,
        provider: str = "okta",
    ) -> List[Dict[str, Any]]:
        """
        Generate credential stuffing attack events.

        Args:
            ip: Source IP address
            user_count: Number of unique users
            success_rate: Percentage of successful logins
            provider: Identity provider

        Returns:
            List of event dictionaries
        """
        import random

        events = []
        base_time = datetime.now(timezone.utc)

        for i in range(user_count):
            user = f"user{uuid.uuid4().hex[:6]}@unknowndomain.com"
            timestamp = base_time - timedelta(seconds=(user_count - i) * 2)

            is_success = random.random() < success_rate

            event = {
                **self._base_event(provider, "user.session.start", timestamp),
                "outcome": "SUCCESS" if is_success else "FAILURE",
                "user_email": user,
                "source_ip": ip,
                "failure_reason": None if is_success else "USER_NOT_FOUND",
                "actor": {
                    "alternateId": user,
                },
                "client": {
                    "ipAddress": ip,
                },
            }
            events.append(event)

        return events

    # =========================================================================
    # Non-Matching Events (for negative testing)
    # =========================================================================

    def generate_normal_login_events(
        self,
        user: str,
        count: int = 10,
        provider: str = "okta",
    ) -> List[Dict[str, Any]]:
        """
        Generate normal, legitimate login events.

        These should NOT trigger attack detection rules.
        """
        events = []
        base_time = datetime.now(timezone.utc)

        for i in range(count):
            # Spread across work hours
            timestamp = base_time - timedelta(hours=i * 2)
            if timestamp.hour < 8:
                timestamp = timestamp.replace(hour=9)
            elif timestamp.hour > 18:
                timestamp = timestamp.replace(hour=15)

            event = {
                **self._base_event(provider, "user.session.start", timestamp),
                "outcome": "SUCCESS",
                "user_email": user,
                "source_ip": "192.168.1.100",
                "actor": {
                    "alternateId": user,
                    "displayName": user.split("@")[0],
                },
                "client": {
                    "ipAddress": "192.168.1.100",
                    "geographicalContext": self.default_geo_us,
                },
            }
            events.append(event)

        return events

    def generate_normal_mfa_events(
        self,
        user: str,
        count: int = 5,
        provider: str = "okta",
    ) -> List[Dict[str, Any]]:
        """
        Generate normal MFA challenge/success events.

        Single challenge followed by success - should NOT trigger MFA fatigue.
        """
        events = []
        base_time = datetime.now(timezone.utc)

        for i in range(count):
            timestamp = base_time - timedelta(hours=i * 3)

            # Single challenge
            challenge = {
                **self._base_event(provider, "user.mfa.factor.verify", timestamp),
                "outcome": "CHALLENGE",
                "user_email": user,
                "mfa_method": "push",
                "actor": {
                    "alternateId": user,
                },
            }
            events.append(challenge)

            # Immediate success
            success = {
                **self._base_event(provider, "user.mfa.factor.verify", timestamp + timedelta(seconds=5)),
                "outcome": "SUCCESS",
                "user_email": user,
                "mfa_method": "push",
                "actor": {
                    "alternateId": user,
                },
            }
            events.append(success)

        return events


def generate_test_cases_for_rule(rule_type: str) -> List[GeneratedEvent]:
    """
    Generate matching and non-matching test cases for a rule type.

    Args:
        rule_type: Type of detection rule

    Returns:
        List of GeneratedEvent objects with should_match flags
    """
    generator = EventGenerator()
    test_cases = []

    if rule_type == "brute_force":
        # Matching: 10 failed logins
        for event in generator.generate_brute_force_events(
            count=10, user="victim@example.com", ip="203.0.113.50"
        ):
            test_cases.append(GeneratedEvent(
                event=event,
                should_match=True,
                description="Brute force attack - failed login",
            ))

        # Non-matching: normal logins
        for event in generator.generate_normal_login_events("normal@example.com"):
            test_cases.append(GeneratedEvent(
                event=event,
                should_match=False,
                description="Normal login - should not match brute force",
            ))

    elif rule_type == "mfa_fatigue":
        # Matching: 5 MFA push denials
        for event in generator.generate_mfa_fatigue_events(
            user="victim@example.com", count=5
        ):
            test_cases.append(GeneratedEvent(
                event=event,
                should_match=True,
                description="MFA fatigue attack - push bombardment",
            ))

        # Non-matching: normal MFA
        for event in generator.generate_normal_mfa_events("normal@example.com"):
            test_cases.append(GeneratedEvent(
                event=event,
                should_match=False,
                description="Normal MFA - should not match fatigue",
            ))

    elif rule_type == "password_spray":
        # Matching: many users, single IP
        users = [f"user{i}@example.com" for i in range(20)]
        for event in generator.generate_password_spray_events(users, "203.0.113.51"):
            test_cases.append(GeneratedEvent(
                event=event,
                should_match=True,
                description="Password spray attack",
            ))

    elif rule_type == "impossible_travel":
        # Matching: NYC to Tokyo in 1 hour
        locations = [
            {"country": "US", "city": "New York", "latitude": 40.7128, "longitude": -74.0060},
            {"country": "JP", "city": "Tokyo", "latitude": 35.6762, "longitude": 139.6503},
        ]
        for event in generator.generate_impossible_travel_events(
            "traveler@example.com", locations, time_gap_minutes=60
        ):
            test_cases.append(GeneratedEvent(
                event=event,
                should_match=True,
                description="Impossible travel - NYC to Tokyo",
            ))

    return test_cases
