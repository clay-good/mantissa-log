"""Baseline calculator for identity behavioral patterns.

Calculates and updates user baselines from identity events.
"""

import hashlib
import logging
import math
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Optional

from ..models.identity_event import IdentityEvent, IdentityEventType
from .user_baseline import IdentityBaseline

logger = logging.getLogger(__name__)


class BaselineCalculator:
    """Calculates and updates identity baselines from events.

    Supports both batch calculation and incremental updates using
    exponential moving average for numeric fields.
    """

    # Class constants
    LEARNING_PERIOD_DAYS = 14
    MIN_EVENTS_FOR_CONFIDENCE = 50
    MAX_IPS_TO_STORE = 100
    MAX_CITIES_TO_STORE = 50
    MAX_DEVICES_TO_STORE = 20
    MAX_USER_AGENTS_TO_STORE = 20
    MAX_SESSION_DURATIONS_TO_STORE = 100

    # Exponential moving average alpha (higher = more weight on recent data)
    EMA_ALPHA = 0.1

    def __init__(
        self,
        learning_period_days: int = 14,
        min_events_for_confidence: int = 50,
    ):
        """Initialize BaselineCalculator.

        Args:
            learning_period_days: Days of data collection before baseline matures
            min_events_for_confidence: Minimum events for reliable baseline
        """
        self.learning_period_days = learning_period_days
        self.min_events_for_confidence = min_events_for_confidence

    def calculate_baseline(
        self, user_email: str, events: List[IdentityEvent]
    ) -> IdentityBaseline:
        """Calculate a complete baseline from a list of events.

        Args:
            user_email: User's email address
            events: List of IdentityEvents to analyze

        Returns:
            Calculated IdentityBaseline
        """
        if not events:
            return IdentityBaseline(
                user_id=user_email,
                email=user_email,
            )

        # Sort events by timestamp
        events = sorted(events, key=lambda e: e.timestamp)

        baseline = IdentityBaseline(
            user_id=events[0].user_id or user_email,
            email=user_email,
            baseline_start_date=events[0].timestamp,
            last_updated=events[-1].timestamp,
        )

        # Process all events
        for event in events:
            baseline = self._process_event(baseline, event)

        # Calculate derived metrics
        baseline = self._calculate_derived_metrics(baseline)

        # Calculate confidence score
        baseline.confidence_score = self.get_baseline_confidence(baseline)

        # Check if baseline is mature
        if self.is_baseline_mature(baseline):
            baseline.baseline_end_date = baseline.last_updated

        return baseline

    def update_baseline_incremental(
        self, baseline: IdentityBaseline, event: IdentityEvent
    ) -> IdentityBaseline:
        """Update existing baseline with a new event using rolling window.

        Uses exponential moving average for numeric fields and adds new
        values to sets with size limits.

        Args:
            baseline: Existing baseline to update
            event: New event to incorporate

        Returns:
            Updated IdentityBaseline
        """
        # Initialize baseline if needed
        if not baseline.baseline_start_date:
            baseline.baseline_start_date = event.timestamp

        # Process the event
        baseline = self._process_event(baseline, event)

        # Update derived metrics using EMA
        baseline = self._update_derived_metrics_ema(baseline)

        # Update confidence score
        baseline.confidence_score = self.get_baseline_confidence(baseline)

        # Check if baseline just became mature
        if not baseline.baseline_end_date and self.is_baseline_mature(baseline):
            baseline.baseline_end_date = datetime.now(timezone.utc)

        baseline.last_updated = datetime.now(timezone.utc)

        return baseline

    def get_baseline_confidence(self, baseline: IdentityBaseline) -> float:
        """Calculate confidence score for baseline.

        Returns:
            0.0 if less than 7 days of data
            0.5 if 7-14 days
            1.0 if 14+ days AND sufficient event count
        """
        age_days = baseline.get_baseline_age_days()

        if age_days < 7:
            return 0.0

        if age_days < 14:
            # Partial confidence based on days and events
            day_factor = age_days / 14
            event_factor = min(1.0, baseline.event_count / self.min_events_for_confidence)
            return 0.5 * (day_factor + event_factor)

        # 14+ days
        if baseline.event_count >= self.min_events_for_confidence:
            # Full confidence, possibly boosted by diversity
            diversity = baseline.get_diversity_score()
            return min(1.0, 0.8 + 0.2 * diversity)
        else:
            # Reduce confidence if few events
            event_factor = baseline.event_count / self.min_events_for_confidence
            return 0.5 + 0.5 * event_factor

    def is_baseline_mature(self, baseline: IdentityBaseline) -> bool:
        """Check if baseline is mature enough for reliable detection.

        Args:
            baseline: Baseline to check

        Returns:
            True if baseline_age >= learning_period_days AND
            event_count >= min_events_for_confidence
        """
        return (
            baseline.get_baseline_age_days() >= self.learning_period_days
            and baseline.event_count >= self.min_events_for_confidence
        )

    def compare_to_peer_group(
        self, baseline: IdentityBaseline, peer_baselines: List[IdentityBaseline]
    ) -> Dict[str, Any]:
        """Compare a user's baseline to their peer group.

        Identifies how this user differs from peers (same department/team).

        Args:
            baseline: User's baseline
            peer_baselines: Baselines of peer users

        Returns:
            Dictionary with comparison metrics
        """
        if not peer_baselines:
            return {"has_peers": False}

        comparison = {
            "has_peers": True,
            "peer_count": len(peer_baselines),
            "deviations": [],
        }

        # Calculate peer averages
        peer_avg_session_duration = sum(
            p.typical_session_duration_minutes for p in peer_baselines
        ) / len(peer_baselines)

        peer_avg_failed_rate = sum(
            p.failed_auth_rate for p in peer_baselines
        ) / len(peer_baselines)

        peer_avg_mfa_rate = sum(
            p.mfa_challenge_rate for p in peer_baselines
        ) / len(peer_baselines)

        # Common applications across peers
        peer_apps = set()
        for p in peer_baselines:
            peer_apps.update(p.known_applications)

        # Common providers across peers
        peer_providers = set()
        for p in peer_baselines:
            peer_providers.update(p.typical_providers)

        # Check for deviations
        if baseline.typical_session_duration_minutes > peer_avg_session_duration * 2:
            comparison["deviations"].append({
                "type": "session_duration",
                "description": "Session duration significantly longer than peers",
                "user_value": baseline.typical_session_duration_minutes,
                "peer_avg": peer_avg_session_duration,
            })

        if baseline.failed_auth_rate > peer_avg_failed_rate * 3:
            comparison["deviations"].append({
                "type": "failed_auth_rate",
                "description": "Failed authentication rate much higher than peers",
                "user_value": baseline.failed_auth_rate,
                "peer_avg": peer_avg_failed_rate,
            })

        if baseline.mfa_challenge_rate < peer_avg_mfa_rate * 0.5 and peer_avg_mfa_rate > 0.1:
            comparison["deviations"].append({
                "type": "mfa_rate",
                "description": "MFA challenge rate lower than peers",
                "user_value": baseline.mfa_challenge_rate,
                "peer_avg": peer_avg_mfa_rate,
            })

        # Check for unusual applications
        user_apps = baseline.known_applications
        unusual_apps = user_apps - peer_apps
        if unusual_apps:
            comparison["unusual_applications"] = list(unusual_apps)

        # Check for unusual providers
        user_providers = baseline.typical_providers
        unusual_providers = user_providers - peer_providers
        if unusual_providers:
            comparison["unusual_providers"] = list(unusual_providers)

        comparison["peer_avg_session_duration"] = peer_avg_session_duration
        comparison["peer_avg_failed_rate"] = peer_avg_failed_rate
        comparison["peer_avg_mfa_rate"] = peer_avg_mfa_rate

        return comparison

    def _process_event(
        self, baseline: IdentityBaseline, event: IdentityEvent
    ) -> IdentityBaseline:
        """Process a single event and update baseline."""
        # Update event count
        baseline.event_count += 1

        # Update time patterns
        event_time = event.timestamp
        if event_time.tzinfo is None:
            event_time = event_time.replace(tzinfo=timezone.utc)

        baseline.typical_login_hours.add(event_time.hour)
        baseline.typical_login_days.add(event_time.weekday())

        # Update location patterns
        if event.source_ip:
            baseline.known_source_ips.add(event.source_ip)
            # Limit size
            if len(baseline.known_source_ips) > self.MAX_IPS_TO_STORE:
                baseline.known_source_ips = set(list(baseline.known_source_ips)[-self.MAX_IPS_TO_STORE:])

        if event.source_geo:
            if event.source_geo.country:
                baseline.known_countries.add(event.source_geo.country)
            if event.source_geo.city:
                baseline.known_cities.add(event.source_geo.city)
                if len(baseline.known_cities) > self.MAX_CITIES_TO_STORE:
                    baseline.known_cities = set(list(baseline.known_cities)[-self.MAX_CITIES_TO_STORE:])

        # Update device patterns
        if event.device_type:
            baseline.known_devices.add(event.device_type)

        if event.user_agent:
            # Store hash to save space
            ua_hash = hashlib.md5(event.user_agent.encode()).hexdigest()[:16]
            baseline.known_user_agents.add(ua_hash)
            if len(baseline.known_user_agents) > self.MAX_USER_AGENTS_TO_STORE:
                baseline.known_user_agents = set(list(baseline.known_user_agents)[-self.MAX_USER_AGENTS_TO_STORE:])

        # Update application patterns
        if event.application_name:
            baseline.known_applications.add(event.application_name)

        # Update identity-specific patterns
        if event.mfa_method:
            baseline.typical_auth_methods.add(event.mfa_method)

        if event.provider:
            baseline.typical_providers.add(event.provider)

        # Update authentication counters
        if event.event_type in (
            IdentityEventType.AUTH_SUCCESS,
            IdentityEventType.AUTH_FAILURE,
        ):
            baseline.total_auth_attempts += 1

            if event.event_type == IdentityEventType.AUTH_FAILURE:
                baseline.failed_auth_attempts += 1

        # Update MFA counter
        if event.event_type in (
            IdentityEventType.MFA_CHALLENGE,
            IdentityEventType.MFA_SUCCESS,
            IdentityEventType.MFA_FAILURE,
        ):
            baseline.mfa_challenges += 1

        # Update password change counter
        if event.event_type in (
            IdentityEventType.PASSWORD_CHANGE,
            IdentityEventType.PASSWORD_RESET,
        ):
            baseline.password_change_count += 1

        # Check for API token usage
        if event.event_type in (
            IdentityEventType.API_KEY_CREATED,
            IdentityEventType.TOKEN_ISSUED,
        ):
            baseline.api_token_usage = True

        # Update privilege level
        if event.event_type == IdentityEventType.PRIVILEGE_GRANT:
            if event.privilege_changes:
                for change in event.privilege_changes:
                    if "admin" in change.role_name.lower():
                        baseline.typical_privilege_level = "admin"

        return baseline

    def _calculate_derived_metrics(self, baseline: IdentityBaseline) -> IdentityBaseline:
        """Calculate derived metrics from raw counters."""
        # Calculate failed auth rate
        if baseline.total_auth_attempts > 0:
            baseline.failed_auth_rate = (
                baseline.failed_auth_attempts / baseline.total_auth_attempts
            )
        else:
            baseline.failed_auth_rate = 0.0

        # Calculate MFA challenge rate
        if baseline.total_auth_attempts > 0:
            baseline.mfa_challenge_rate = (
                baseline.mfa_challenges / baseline.total_auth_attempts
            )
        else:
            baseline.mfa_challenge_rate = 0.0

        # Calculate password changes per period (per 14 days)
        age_days = baseline.get_baseline_age_days()
        if age_days > 0:
            baseline.password_changes_per_period = (
                baseline.password_change_count / (age_days / 14)
            )
        else:
            baseline.password_changes_per_period = 0.0

        # Calculate session duration stats if we have data
        if baseline.session_durations:
            durations = baseline.session_durations
            baseline.typical_session_duration_minutes = sum(durations) / len(durations)

            if len(durations) > 1:
                mean = baseline.typical_session_duration_minutes
                variance = sum((d - mean) ** 2 for d in durations) / len(durations)
                baseline.session_duration_stddev = math.sqrt(variance)
            else:
                baseline.session_duration_stddev = 0.0

        return baseline

    def _update_derived_metrics_ema(self, baseline: IdentityBaseline) -> IdentityBaseline:
        """Update derived metrics using exponential moving average."""
        # Calculate current rates
        if baseline.total_auth_attempts > 0:
            current_failed_rate = baseline.failed_auth_attempts / baseline.total_auth_attempts
            current_mfa_rate = baseline.mfa_challenges / baseline.total_auth_attempts

            # Apply EMA
            baseline.failed_auth_rate = (
                self.EMA_ALPHA * current_failed_rate +
                (1 - self.EMA_ALPHA) * baseline.failed_auth_rate
            )

            baseline.mfa_challenge_rate = (
                self.EMA_ALPHA * current_mfa_rate +
                (1 - self.EMA_ALPHA) * baseline.mfa_challenge_rate
            )

        # Update password changes per period
        age_days = baseline.get_baseline_age_days()
        if age_days > 0:
            current_rate = baseline.password_change_count / (age_days / 14)
            baseline.password_changes_per_period = (
                self.EMA_ALPHA * current_rate +
                (1 - self.EMA_ALPHA) * baseline.password_changes_per_period
            )

        # Update session duration (if we have new data)
        if baseline.session_durations:
            durations = baseline.session_durations[-self.MAX_SESSION_DURATIONS_TO_STORE:]
            if durations:
                latest_avg = sum(durations) / len(durations)
                baseline.typical_session_duration_minutes = (
                    self.EMA_ALPHA * latest_avg +
                    (1 - self.EMA_ALPHA) * baseline.typical_session_duration_minutes
                )

                if len(durations) > 1:
                    mean = sum(durations) / len(durations)
                    variance = sum((d - mean) ** 2 for d in durations) / len(durations)
                    latest_stddev = math.sqrt(variance)
                    baseline.session_duration_stddev = (
                        self.EMA_ALPHA * latest_stddev +
                        (1 - self.EMA_ALPHA) * baseline.session_duration_stddev
                    )

        return baseline

    def add_session_duration(
        self, baseline: IdentityBaseline, duration_minutes: float
    ) -> IdentityBaseline:
        """Add a session duration to the baseline.

        Args:
            baseline: Baseline to update
            duration_minutes: Session duration in minutes

        Returns:
            Updated baseline
        """
        baseline.session_durations.append(duration_minutes)

        # Limit stored durations
        if len(baseline.session_durations) > self.MAX_SESSION_DURATIONS_TO_STORE:
            baseline.session_durations = baseline.session_durations[-self.MAX_SESSION_DURATIONS_TO_STORE:]

        # Update metrics
        baseline = self._update_derived_metrics_ema(baseline)
        baseline.last_updated = datetime.now(timezone.utc)

        return baseline
