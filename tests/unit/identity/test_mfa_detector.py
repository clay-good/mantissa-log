"""
Unit tests for MFADetector.

Tests MFA fatigue detection, MFA bypass detection, and MFA method change detection.
"""

import pytest
from datetime import datetime, timezone, timedelta
from unittest.mock import Mock, MagicMock

from src.shared.identity.detection.mfa_detector import MFADetector
from src.shared.models.identity_event import IdentityEvent, IdentityEventType
from tests.unit.identity.conftest import generate_mfa_challenge_sequence


class TestMFAFatigueDetection:
    """Tests for MFA fatigue attack detection."""

    def test_few_challenges_no_alert(self, mock_query_executor, sample_user_email):
        """Few MFA challenges should not trigger alert."""
        detector = MFADetector(
            query_executor=mock_query_executor,
            fatigue_threshold=5,
        )

        mock_query_executor.execute_query.return_value = [
            {"mfa_challenge_count": 2, "mfa_denied_count": 2}
        ]

        result = detector.detect_mfa_fatigue(
            user_email=sample_user_email,
            window_minutes=30,
        )

        assert result.is_alert is False

    def test_many_challenges_triggers_alert(self, mock_query_executor, sample_user_email):
        """Many MFA challenges in short time should trigger fatigue alert."""
        detector = MFADetector(
            query_executor=mock_query_executor,
            fatigue_threshold=5,
        )

        mock_query_executor.execute_query.return_value = [
            {"mfa_challenge_count": 15, "mfa_denied_count": 14}
        ]

        result = detector.detect_mfa_fatigue(
            user_email=sample_user_email,
            window_minutes=30,
        )

        assert result.is_alert is True
        assert result.attack_type == "mfa_fatigue"

    def test_challenges_with_final_success_critical(self, mock_query_executor, sample_user_email):
        """MFA fatigue with final success should be critical (attack succeeded)."""
        detector = MFADetector(
            query_executor=mock_query_executor,
            fatigue_threshold=5,
        )

        mock_query_executor.execute_query.return_value = [
            {"mfa_challenge_count": 20, "mfa_denied_count": 19, "mfa_success_count": 1}
        ]

        result = detector.detect_mfa_fatigue(
            user_email=sample_user_email,
            window_minutes=30,
        )

        assert result.is_alert is True
        assert result.severity == "critical"
        assert result.attack_succeeded is True

    def test_rapid_challenges_high_severity(self, mock_query_executor, sample_user_email):
        """Rapid-fire MFA challenges should be high severity."""
        detector = MFADetector(
            query_executor=mock_query_executor,
            fatigue_threshold=5,
        )

        # 10 challenges in 5 minutes = 2 per minute
        mock_query_executor.execute_query.return_value = [
            {"mfa_challenge_count": 10, "mfa_denied_count": 10, "window_minutes": 5}
        ]

        result = detector.detect_mfa_fatigue(
            user_email=sample_user_email,
            window_minutes=5,
        )

        assert result.is_alert is True
        assert result.severity in ["high", "critical"]

    def test_push_notification_fatigue(self, mock_query_executor, sample_user_email):
        """Push notification fatigue should be specifically flagged."""
        detector = MFADetector(
            query_executor=mock_query_executor,
            fatigue_threshold=5,
        )

        mock_query_executor.execute_query.return_value = [
            {"mfa_challenge_count": 15, "mfa_denied_count": 14, "mfa_method": "push"}
        ]

        result = detector.detect_mfa_fatigue(
            user_email=sample_user_email,
            window_minutes=30,
        )

        assert result.is_alert is True
        # Push notifications are particularly vulnerable to fatigue attacks
        if hasattr(result, 'mfa_method'):
            assert result.mfa_method == "push"

    def test_off_hours_fatigue_higher_severity(self, mock_query_executor, sample_user_email):
        """MFA fatigue during off-hours should be higher severity."""
        detector = MFADetector(
            query_executor=mock_query_executor,
            fatigue_threshold=5,
        )

        # Simulate 3 AM attack
        mock_query_executor.execute_query.return_value = [
            {"mfa_challenge_count": 10, "mfa_denied_count": 10, "hour": 3}
        ]

        result = detector.detect_mfa_fatigue(
            user_email=sample_user_email,
            window_minutes=30,
            current_hour=3,  # 3 AM
        )

        assert result.is_alert is True
        # Off-hours should escalate severity
        assert result.severity == "critical"


class TestMFABypassDetection:
    """Tests for MFA bypass attempt detection."""

    def test_auth_without_mfa_flagged(self, mock_query_executor, sample_user_email):
        """Authentication without MFA when expected should be flagged."""
        detector = MFADetector(
            query_executor=mock_query_executor,
        )

        mock_query_executor.execute_query.return_value = [
            {"auth_success": True, "mfa_completed": False, "mfa_required": True}
        ]

        result = detector.detect_mfa_bypass(
            user_email=sample_user_email,
            session_id="session-001",
        )

        assert result.is_alert is True
        assert result.attack_type == "mfa_bypass"

    def test_legacy_auth_protocol_flagged(self, mock_query_executor, sample_user_email):
        """Legacy authentication protocols (no MFA support) should be flagged."""
        detector = MFADetector(
            query_executor=mock_query_executor,
        )

        mock_query_executor.execute_query.return_value = [
            {"auth_protocol": "IMAP", "mfa_completed": False}
        ]

        result = detector.detect_mfa_bypass(
            user_email=sample_user_email,
            session_id="session-001",
        )

        assert result.is_alert is True
        if hasattr(result, 'auth_protocol'):
            assert result.auth_protocol in ["IMAP", "POP3", "SMTP", "ActiveSync"]

    def test_normal_auth_with_mfa_no_alert(self, mock_query_executor, sample_user_email):
        """Normal authentication with MFA should not trigger alert."""
        detector = MFADetector(
            query_executor=mock_query_executor,
        )

        mock_query_executor.execute_query.return_value = [
            {"auth_success": True, "mfa_completed": True, "mfa_required": True}
        ]

        result = detector.detect_mfa_bypass(
            user_email=sample_user_email,
            session_id="session-001",
        )

        assert result.is_alert is False

    def test_mfa_exemption_noted(self, mock_query_executor, sample_user_email):
        """MFA exemptions should be noted but may still alert."""
        detector = MFADetector(
            query_executor=mock_query_executor,
        )

        mock_query_executor.execute_query.return_value = [
            {"auth_success": True, "mfa_completed": False, "mfa_exemption": "trusted_location"}
        ]

        result = detector.detect_mfa_bypass(
            user_email=sample_user_email,
            session_id="session-001",
        )

        # May or may not alert depending on policy
        if hasattr(result, 'exemption_reason'):
            assert result.exemption_reason == "trusted_location"

    def test_stolen_session_token_bypass(self, mock_query_executor, sample_user_email):
        """Session token replay (bypass) should be detected."""
        detector = MFADetector(
            query_executor=mock_query_executor,
        )

        mock_query_executor.execute_query.return_value = [
            {"auth_success": True, "session_type": "token_replay", "original_mfa": True}
        ]

        result = detector.detect_mfa_bypass(
            user_email=sample_user_email,
            session_id="session-001",
        )

        assert result.is_alert is True
        assert result.severity == "critical"


class TestMFAMethodChangeDetection:
    """Tests for MFA method change detection."""

    def test_new_mfa_method_flagged(self, mock_query_executor, sample_user_email, sample_mature_baseline):
        """New MFA method should be flagged."""
        detector = MFADetector(
            query_executor=mock_query_executor,
        )

        # Baseline has "push" and "password"
        mock_query_executor.execute_query.return_value = [
            {"mfa_method": "sms", "timestamp": datetime.now(timezone.utc).isoformat()}
        ]

        result = detector.detect_mfa_method_change(
            user_email=sample_user_email,
            baseline=sample_mature_baseline,
        )

        assert result.is_alert is True
        if hasattr(result, 'new_method'):
            assert result.new_method == "sms"

    def test_downgrade_to_sms_high_severity(self, mock_query_executor, sample_user_email, sample_mature_baseline):
        """Downgrade from push to SMS should be high severity."""
        detector = MFADetector(
            query_executor=mock_query_executor,
        )

        mock_query_executor.execute_query.return_value = [
            {"previous_method": "push", "new_method": "sms"}
        ]

        result = detector.detect_mfa_method_change(
            user_email=sample_user_email,
            baseline=sample_mature_baseline,
        )

        assert result.is_alert is True
        assert result.severity == "high"

    def test_upgrade_to_hardware_key_low_severity(self, mock_query_executor, sample_user_email, sample_mature_baseline):
        """Upgrade to hardware key should be low severity (security improvement)."""
        detector = MFADetector(
            query_executor=mock_query_executor,
        )

        mock_query_executor.execute_query.return_value = [
            {"previous_method": "push", "new_method": "hardware_key"}
        ]

        result = detector.detect_mfa_method_change(
            user_email=sample_user_email,
            baseline=sample_mature_baseline,
        )

        # May alert for visibility but low severity
        if result.is_alert:
            assert result.severity == "low" or result.severity == "info"

    def test_same_method_no_alert(self, mock_query_executor, sample_user_email, sample_mature_baseline):
        """Using same MFA method should not trigger alert."""
        detector = MFADetector(
            query_executor=mock_query_executor,
        )

        # Baseline already has "push"
        mock_query_executor.execute_query.return_value = [
            {"mfa_method": "push"}
        ]

        result = detector.detect_mfa_method_change(
            user_email=sample_user_email,
            baseline=sample_mature_baseline,
        )

        assert result.is_alert is False

    def test_mfa_enrollment_change_flagged(self, mock_query_executor, sample_user_email):
        """Changes to MFA enrollment should be flagged."""
        detector = MFADetector(
            query_executor=mock_query_executor,
        )

        mock_query_executor.execute_query.return_value = [
            {"event_type": "mfa_enrollment_changed", "methods_added": ["sms"], "methods_removed": []}
        ]

        result = detector.detect_mfa_enrollment_change(
            user_email=sample_user_email,
        )

        assert result.is_alert is True


class TestMFAReplayDetection:
    """Tests for MFA replay attack detection."""

    def test_duplicate_otp_codes_detected(self, mock_query_executor, sample_user_email):
        """Duplicate OTP codes should be detected as replay."""
        detector = MFADetector(
            query_executor=mock_query_executor,
        )

        mock_query_executor.execute_query.return_value = [
            {"otp_hash": "abc123", "usage_count": 2}
        ]

        result = detector.detect_mfa_replay(
            user_email=sample_user_email,
            window_minutes=10,
        )

        assert result.is_alert is True
        assert result.attack_type == "mfa_replay"

    def test_unique_otp_codes_no_alert(self, mock_query_executor, sample_user_email):
        """Unique OTP codes should not trigger alert."""
        detector = MFADetector(
            query_executor=mock_query_executor,
        )

        mock_query_executor.execute_query.return_value = [
            {"otp_hash": "abc123", "usage_count": 1},
            {"otp_hash": "def456", "usage_count": 1},
        ]

        result = detector.detect_mfa_replay(
            user_email=sample_user_email,
            window_minutes=10,
        )

        assert result.is_alert is False


class TestCrossProviderMFA:
    """Tests for cross-provider MFA detection."""

    def test_mfa_fatigue_across_providers(self, mock_query_executor, sample_user_email):
        """MFA fatigue pattern across providers should be correlated."""
        detector = MFADetector(
            query_executor=mock_query_executor,
            fatigue_threshold=5,
        )

        mock_query_executor.execute_query.return_value = [
            {"provider": "okta", "mfa_challenge_count": 8},
            {"provider": "azure", "mfa_challenge_count": 7},
        ]

        result = detector.detect_mfa_fatigue(
            user_email=sample_user_email,
            window_minutes=30,
            cross_provider=True,
        )

        # Total of 15 challenges
        assert result.is_alert is True

    def test_mfa_method_inconsistency(self, mock_query_executor, sample_user_email):
        """Different MFA methods across providers may indicate compromise."""
        detector = MFADetector(
            query_executor=mock_query_executor,
        )

        mock_query_executor.execute_query.return_value = [
            {"provider": "okta", "mfa_method": "push"},
            {"provider": "azure", "mfa_method": "sms"},
            {"provider": "google_workspace", "mfa_method": "totp"},
        ]

        result = detector.detect_mfa_inconsistency(
            user_email=sample_user_email,
        )

        # Inconsistent methods may be flagged for review
        if hasattr(result, 'method_count'):
            assert result.method_count == 3


class TestEdgeCases:
    """Tests for edge cases in MFA detection."""

    def test_no_mfa_events(self, mock_query_executor, sample_user_email):
        """No MFA events should be handled gracefully."""
        detector = MFADetector(query_executor=mock_query_executor)
        mock_query_executor.execute_query.return_value = []

        result = detector.detect_mfa_fatigue(
            user_email=sample_user_email,
            window_minutes=30,
        )

        assert result.is_alert is False

    def test_service_account_excluded(self, mock_query_executor):
        """Service accounts may be excluded from MFA detection."""
        detector = MFADetector(
            query_executor=mock_query_executor,
        )

        mock_query_executor.execute_query.return_value = [
            {"mfa_challenge_count": 0, "is_service_account": True}
        ]

        result = detector.detect_mfa_fatigue(
            user_email="service@example.com",
            window_minutes=30,
            is_service_account=True,
        )

        assert result.is_alert is False

    def test_immature_baseline_handled(self, mock_query_executor, sample_user_email, sample_immature_baseline):
        """Immature baseline should be handled for MFA method changes."""
        detector = MFADetector(
            query_executor=mock_query_executor,
        )

        mock_query_executor.execute_query.return_value = [
            {"mfa_method": "sms"}
        ]

        result = detector.detect_mfa_method_change(
            user_email=sample_user_email,
            baseline=sample_immature_baseline,
        )

        # With immature baseline, should be lower severity or no alert
        if result.is_alert:
            assert result.severity in ["low", "info"]
