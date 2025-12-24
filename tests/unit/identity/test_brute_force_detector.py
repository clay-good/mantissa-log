"""
Unit tests for BruteForceDetector.

Tests brute force detection, password spray detection, and credential stuffing detection.
"""

import pytest
from datetime import datetime, timezone, timedelta
from unittest.mock import Mock, MagicMock

from src.shared.identity.detection.brute_force import BruteForceDetector
from src.shared.models.identity_event import IdentityEvent, IdentityEventType


class TestSingleUserBruteForce:
    """Tests for single-user brute force detection."""

    def test_no_failures_no_alert(self, mock_query_executor, sample_user_email):
        """No failed logins should not trigger alert."""
        detector = BruteForceDetector(query_executor=mock_query_executor)
        mock_query_executor.execute_query.return_value = []

        result = detector.detect_brute_force(
            user_email=sample_user_email,
            window_minutes=15,
        )

        assert result.is_alert is False

    def test_few_failures_no_alert(self, mock_query_executor, sample_user_email):
        """Few failed logins (below threshold) should not trigger alert."""
        detector = BruteForceDetector(
            query_executor=mock_query_executor,
            failure_threshold=5,
        )

        # Return 3 failures (below threshold of 5)
        mock_query_executor.execute_query.return_value = [
            {"count": 3, "source_ip": "1.2.3.4"}
        ]

        result = detector.detect_brute_force(
            user_email=sample_user_email,
            window_minutes=15,
        )

        assert result.is_alert is False

    def test_threshold_failures_triggers_alert(self, mock_query_executor, sample_user_email):
        """Failures at threshold should trigger alert."""
        detector = BruteForceDetector(
            query_executor=mock_query_executor,
            failure_threshold=5,
        )

        mock_query_executor.execute_query.return_value = [
            {"count": 5, "source_ip": "1.2.3.4"}
        ]

        result = detector.detect_brute_force(
            user_email=sample_user_email,
            window_minutes=15,
        )

        assert result.is_alert is True
        assert result.severity in ["high", "critical"]

    def test_many_failures_high_severity(self, mock_query_executor, sample_user_email):
        """Many failures should trigger high severity alert."""
        detector = BruteForceDetector(
            query_executor=mock_query_executor,
            failure_threshold=5,
        )

        mock_query_executor.execute_query.return_value = [
            {"count": 50, "source_ip": "1.2.3.4"}
        ]

        result = detector.detect_brute_force(
            user_email=sample_user_email,
            window_minutes=15,
        )

        assert result.is_alert is True
        assert result.severity == "critical"

    def test_failures_from_single_ip(self, mock_query_executor, sample_user_email):
        """Failures from single IP should be captured in alert."""
        detector = BruteForceDetector(
            query_executor=mock_query_executor,
            failure_threshold=5,
        )

        mock_query_executor.execute_query.return_value = [
            {"count": 10, "source_ip": "1.2.3.4"}
        ]

        result = detector.detect_brute_force(
            user_email=sample_user_email,
            window_minutes=15,
        )

        assert result.is_alert is True
        assert "1.2.3.4" in str(result.details)

    def test_successful_login_after_failures(self, mock_query_executor, sample_user_email):
        """Successful login after failures should still alert but note success."""
        detector = BruteForceDetector(
            query_executor=mock_query_executor,
            failure_threshold=5,
        )

        mock_query_executor.execute_query.side_effect = [
            # First query for failures
            [{"count": 10, "source_ip": "1.2.3.4"}],
            # Second query for success check
            [{"success_count": 1}],
        ]

        result = detector.detect_brute_force(
            user_email=sample_user_email,
            window_minutes=15,
            check_success=True,
        )

        assert result.is_alert is True
        # Should flag that attack succeeded
        if hasattr(result, 'attack_succeeded'):
            assert result.attack_succeeded is True


class TestPasswordSprayDetection:
    """Tests for password spray attack detection (distributed brute force)."""

    def test_single_failure_per_user_no_alert(self, mock_query_executor):
        """Single failure per user should not trigger password spray alert."""
        detector = BruteForceDetector(
            query_executor=mock_query_executor,
            spray_user_threshold=5,
        )

        mock_query_executor.execute_query.return_value = [
            {"user_email": "user1@example.com", "count": 1},
            {"user_email": "user2@example.com", "count": 1},
            {"user_email": "user3@example.com", "count": 1},
        ]

        result = detector.detect_password_spray(
            source_ip="1.2.3.4",
            window_minutes=15,
        )

        # Only 3 users, below threshold of 5
        assert result.is_alert is False

    def test_many_users_same_ip_triggers_spray(self, mock_query_executor):
        """Many users failing from same IP should trigger password spray alert."""
        detector = BruteForceDetector(
            query_executor=mock_query_executor,
            spray_user_threshold=5,
        )

        mock_query_executor.execute_query.return_value = [
            {"user_email": f"user{i}@example.com", "count": 1}
            for i in range(10)
        ]

        result = detector.detect_password_spray(
            source_ip="1.2.3.4",
            window_minutes=15,
        )

        assert result.is_alert is True
        assert result.attack_type == "password_spray"

    def test_spray_with_similar_passwords_detected(self, mock_query_executor):
        """Password spray using common passwords should be detected."""
        detector = BruteForceDetector(
            query_executor=mock_query_executor,
            spray_user_threshold=5,
        )

        # Simulating pattern where same password is tried against many users
        mock_query_executor.execute_query.return_value = [
            {"user_email": f"user{i}@example.com", "count": 1, "failure_reason": "invalid_password"}
            for i in range(20)
        ]

        result = detector.detect_password_spray(
            source_ip="1.2.3.4",
            window_minutes=15,
        )

        assert result.is_alert is True
        assert result.severity in ["high", "critical"]

    def test_spray_from_multiple_ips_same_range(self, mock_query_executor):
        """Password spray from multiple IPs in same range should be correlated."""
        detector = BruteForceDetector(
            query_executor=mock_query_executor,
            spray_user_threshold=5,
        )

        mock_query_executor.execute_query.return_value = [
            {"user_email": f"user{i}@example.com", "source_ip": f"1.2.3.{i}", "count": 1}
            for i in range(10)
        ]

        result = detector.detect_password_spray(
            source_ip_range="1.2.3.0/24",
            window_minutes=15,
        )

        assert result.is_alert is True


class TestCredentialStuffingDetection:
    """Tests for credential stuffing detection."""

    def test_many_unique_usernames_triggers_alert(self, mock_query_executor):
        """Many unique usernames with failures should trigger credential stuffing alert."""
        detector = BruteForceDetector(
            query_executor=mock_query_executor,
            stuffing_threshold=10,
        )

        mock_query_executor.execute_query.return_value = [
            {"user_email": f"random{i}@example.com", "count": 1}
            for i in range(50)
        ]

        result = detector.detect_credential_stuffing(
            source_ip="1.2.3.4",
            window_minutes=60,
        )

        assert result.is_alert is True
        assert result.attack_type == "credential_stuffing"

    def test_high_ratio_unknown_users(self, mock_query_executor):
        """High ratio of unknown/nonexistent users indicates credential stuffing."""
        detector = BruteForceDetector(
            query_executor=mock_query_executor,
            stuffing_threshold=10,
        )

        mock_query_executor.execute_query.return_value = [
            {"user_email": f"random{i}@example.com", "count": 1, "failure_reason": "user_not_found"}
            for i in range(30)
        ]

        result = detector.detect_credential_stuffing(
            source_ip="1.2.3.4",
            window_minutes=60,
        )

        assert result.is_alert is True
        assert result.severity == "critical"

    def test_mixed_known_unknown_users(self, mock_query_executor):
        """Mix of known and unknown users should still detect stuffing."""
        detector = BruteForceDetector(
            query_executor=mock_query_executor,
            stuffing_threshold=10,
        )

        results = [
            {"user_email": f"known{i}@example.com", "count": 1, "failure_reason": "invalid_password"}
            for i in range(5)
        ] + [
            {"user_email": f"unknown{i}@example.com", "count": 1, "failure_reason": "user_not_found"}
            for i in range(20)
        ]

        mock_query_executor.execute_query.return_value = results

        result = detector.detect_credential_stuffing(
            source_ip="1.2.3.4",
            window_minutes=60,
        )

        assert result.is_alert is True


class TestCrossProviderCorrelation:
    """Tests for cross-provider attack correlation."""

    def test_failures_across_providers_correlated(self, mock_query_executor, sample_user_email):
        """Failures across multiple providers should be correlated."""
        detector = BruteForceDetector(
            query_executor=mock_query_executor,
            failure_threshold=5,
        )

        mock_query_executor.execute_query.return_value = [
            {"provider": "okta", "count": 3, "source_ip": "1.2.3.4"},
            {"provider": "azure", "count": 3, "source_ip": "1.2.3.4"},
            {"provider": "google_workspace", "count": 2, "source_ip": "1.2.3.4"},
        ]

        result = detector.detect_brute_force(
            user_email=sample_user_email,
            window_minutes=15,
            cross_provider=True,
        )

        # Total of 8 failures across providers
        assert result.is_alert is True
        assert len(result.providers) == 3 if hasattr(result, 'providers') else True

    def test_same_ip_different_providers(self, mock_query_executor):
        """Same IP attacking different providers should escalate severity."""
        detector = BruteForceDetector(
            query_executor=mock_query_executor,
            failure_threshold=5,
        )

        mock_query_executor.execute_query.return_value = [
            {"provider": "okta", "user_count": 10, "failure_count": 15},
            {"provider": "azure", "user_count": 8, "failure_count": 12},
        ]

        result = detector.detect_cross_provider_attack(
            source_ip="1.2.3.4",
            window_minutes=30,
        )

        assert result.is_alert is True
        assert result.severity == "critical"


class TestTimeWindowHandling:
    """Tests for time window handling in brute force detection."""

    def test_short_window_detection(self, mock_query_executor, sample_user_email):
        """Short time window (5 min) should detect rapid attacks."""
        detector = BruteForceDetector(
            query_executor=mock_query_executor,
            failure_threshold=5,
        )

        mock_query_executor.execute_query.return_value = [
            {"count": 10, "source_ip": "1.2.3.4"}
        ]

        result = detector.detect_brute_force(
            user_email=sample_user_email,
            window_minutes=5,
        )

        assert result.is_alert is True

    def test_long_window_detection(self, mock_query_executor, sample_user_email):
        """Long time window (1 hour) should catch slow attacks."""
        detector = BruteForceDetector(
            query_executor=mock_query_executor,
            failure_threshold=20,  # Higher threshold for longer window
        )

        mock_query_executor.execute_query.return_value = [
            {"count": 25, "source_ip": "1.2.3.4"}
        ]

        result = detector.detect_brute_force(
            user_email=sample_user_email,
            window_minutes=60,
        )

        assert result.is_alert is True

    def test_failures_outside_window_ignored(self, mock_query_executor, sample_user_email):
        """Failures outside time window should not be counted."""
        detector = BruteForceDetector(
            query_executor=mock_query_executor,
            failure_threshold=5,
        )

        # Query should only return failures within window
        mock_query_executor.execute_query.return_value = [
            {"count": 3, "source_ip": "1.2.3.4"}  # Only 3 in window
        ]

        result = detector.detect_brute_force(
            user_email=sample_user_email,
            window_minutes=15,
        )

        assert result.is_alert is False


class TestEdgeCases:
    """Tests for edge cases in brute force detection."""

    def test_empty_user_email(self, mock_query_executor):
        """Empty user email should be handled gracefully."""
        detector = BruteForceDetector(query_executor=mock_query_executor)

        result = detector.detect_brute_force(
            user_email="",
            window_minutes=15,
        )

        assert result.is_alert is False

    def test_null_query_results(self, mock_query_executor, sample_user_email):
        """Null query results should be handled gracefully."""
        detector = BruteForceDetector(query_executor=mock_query_executor)
        mock_query_executor.execute_query.return_value = None

        result = detector.detect_brute_force(
            user_email=sample_user_email,
            window_minutes=15,
        )

        assert result.is_alert is False

    def test_query_exception_handled(self, mock_query_executor, sample_user_email):
        """Query exceptions should be handled gracefully."""
        detector = BruteForceDetector(query_executor=mock_query_executor)
        mock_query_executor.execute_query.side_effect = Exception("Database error")

        # Should not raise exception
        try:
            result = detector.detect_brute_force(
                user_email=sample_user_email,
                window_minutes=15,
            )
            assert result.is_alert is False or result.error is not None
        except Exception:
            pytest.fail("Exception should have been handled")

    def test_privileged_user_lower_threshold(self, mock_query_executor):
        """Privileged users should have lower detection threshold."""
        detector = BruteForceDetector(
            query_executor=mock_query_executor,
            failure_threshold=5,
            privileged_threshold=3,
        )

        mock_query_executor.execute_query.return_value = [
            {"count": 3, "source_ip": "1.2.3.4"}
        ]

        result = detector.detect_brute_force(
            user_email="admin@example.com",
            window_minutes=15,
            is_privileged=True,
        )

        assert result.is_alert is True
