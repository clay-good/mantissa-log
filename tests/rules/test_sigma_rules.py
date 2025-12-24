"""
Automated tests for ITDR Sigma rules.

Tests that each rule:
- Parses correctly
- Triggers on expected events
- Does NOT trigger on benign events
"""

import pytest
from pathlib import Path
from datetime import datetime, timezone, timedelta

from .rule_test_runner import RuleTestRunner, SigmaRule, SigmaConditionMatcher
from .test_data_generator import EventGenerator, generate_test_cases_for_rule


# Path to rules directory (adjust based on project structure)
RULES_DIR = Path(__file__).parent.parent.parent / "rules" / "sigma"


class TestRuleLoading:
    """Tests for rule loading and parsing."""

    def test_load_single_rule(self, tmp_path):
        """Test loading a single Sigma rule."""
        # Create a test rule file
        rule_content = """
title: Test Brute Force Rule
id: test-001
status: test
level: high
description: Test rule for brute force detection
logsource:
    product: okta
    service: authentication
detection:
    selection:
        outcome: FAILURE
    condition: selection
"""
        rule_file = tmp_path / "test_rule.yml"
        rule_file.write_text(rule_content)

        runner = RuleTestRunner()
        rule = runner.load_rule(str(rule_file))

        assert rule.title == "Test Brute Force Rule"
        assert rule.id == "test-001"
        assert rule.level == "high"
        assert "selection" in rule.detection

    def test_rule_with_multiple_selections(self, tmp_path):
        """Test rule with multiple selection criteria."""
        rule_content = """
title: Complex Detection Rule
id: test-002
status: test
level: medium
logsource:
    product: okta
detection:
    selection:
        outcome: FAILURE
    filter:
        failure_reason: LOCKED_OUT
    condition: selection and not filter
"""
        rule_file = tmp_path / "complex_rule.yml"
        rule_file.write_text(rule_content)

        runner = RuleTestRunner()
        rule = runner.load_rule(str(rule_file))

        assert "selection" in rule.detection
        assert "filter" in rule.detection
        assert "and not" in rule.detection.get("condition", "")


class TestConditionMatching:
    """Tests for Sigma condition matching."""

    def test_simple_field_match(self):
        """Test matching simple field values."""
        matcher = SigmaConditionMatcher()

        event = {"outcome": "FAILURE", "user_email": "test@example.com"}
        selection = {"outcome": "FAILURE"}

        assert matcher.match_selection(event, selection) is True

    def test_field_not_matching(self):
        """Test non-matching field values."""
        matcher = SigmaConditionMatcher()

        event = {"outcome": "SUCCESS", "user_email": "test@example.com"}
        selection = {"outcome": "FAILURE"}

        assert matcher.match_selection(event, selection) is False

    def test_contains_modifier(self):
        """Test 'contains' field modifier."""
        matcher = SigmaConditionMatcher()

        event = {"user_agent": "Mozilla/5.0 (Windows NT 10.0) Chrome/120.0"}
        selection = {"user_agent|contains": "Chrome"}

        assert matcher.match_selection(event, selection) is True

    def test_startswith_modifier(self):
        """Test 'startswith' field modifier."""
        matcher = SigmaConditionMatcher()

        event = {"source_ip": "192.168.1.100"}
        selection = {"source_ip|startswith": "192.168"}

        assert matcher.match_selection(event, selection) is True

    def test_endswith_modifier(self):
        """Test 'endswith' field modifier."""
        matcher = SigmaConditionMatcher()

        event = {"user_email": "admin@example.com"}
        selection = {"user_email|endswith": "@example.com"}

        assert matcher.match_selection(event, selection) is True

    def test_list_value_or_matching(self):
        """Test matching against list of values (OR logic)."""
        matcher = SigmaConditionMatcher()

        event = {"outcome": "FAILURE"}
        selection = {"outcome": ["SUCCESS", "FAILURE", "CHALLENGE"]}

        assert matcher.match_selection(event, selection) is True

    def test_nested_field_matching(self):
        """Test matching nested field values."""
        matcher = SigmaConditionMatcher()

        event = {
            "actor": {
                "alternateId": "test@example.com",
                "displayName": "Test User",
            }
        }
        selection = {"actor.alternateId": "test@example.com"}

        assert matcher.match_selection(event, selection) is True

    def test_and_condition(self):
        """Test AND condition evaluation."""
        matcher = SigmaConditionMatcher()

        event = {"outcome": "FAILURE", "source_ip": "1.2.3.4"}
        detection = {
            "selection": {"outcome": "FAILURE"},
            "filter": {"source_ip": "1.2.3.4"},
            "condition": "selection and filter",
        }

        assert matcher.evaluate_condition(event, detection) is True

    def test_or_condition(self):
        """Test OR condition evaluation."""
        matcher = SigmaConditionMatcher()

        event = {"outcome": "SUCCESS"}
        detection = {
            "selection1": {"outcome": "FAILURE"},
            "selection2": {"outcome": "SUCCESS"},
            "condition": "selection1 or selection2",
        }

        assert matcher.evaluate_condition(event, detection) is True

    def test_not_condition(self):
        """Test NOT condition evaluation."""
        matcher = SigmaConditionMatcher()

        event = {"outcome": "FAILURE", "source_ip": "192.168.1.1"}
        detection = {
            "selection": {"outcome": "FAILURE"},
            "filter": {"source_ip|startswith": "10."},
            "condition": "selection and not filter",
        }

        # Should match: FAILURE and NOT internal IP
        assert matcher.evaluate_condition(event, detection) is True


class TestBruteForceRules:
    """Tests for brute force detection rules."""

    def test_brute_force_detection_triggers(self):
        """Test that brute force events trigger detection."""
        generator = EventGenerator()
        matcher = SigmaConditionMatcher()

        events = generator.generate_brute_force_events(
            count=10,
            user="victim@example.com",
            ip="203.0.113.50",
        )

        # Simple brute force detection
        detection = {
            "selection": {
                "outcome": "FAILURE",
            },
            "condition": "selection",
        }

        matches = [matcher.evaluate_condition(e, detection) for e in events]

        # All events should match (they're all failures)
        assert all(matches)

    def test_brute_force_with_success_not_trigger_alone(self):
        """Test that single success doesn't trigger brute force."""
        generator = EventGenerator()
        matcher = SigmaConditionMatcher()

        events = generator.generate_normal_login_events(
            user="normal@example.com",
            count=1,
        )

        detection = {
            "selection": {
                "outcome": "FAILURE",
            },
            "condition": "selection",
        }

        matches = [matcher.evaluate_condition(e, detection) for e in events]

        # Normal login should NOT match failure detection
        assert not any(matches)


class TestPasswordSprayRules:
    """Tests for password spray detection rules."""

    def test_password_spray_events_generated(self):
        """Test password spray event generation."""
        generator = EventGenerator()

        users = [f"user{i}@example.com" for i in range(20)]
        events = generator.generate_password_spray_events(
            users=users,
            ip="203.0.113.51",
        )

        # Should have events for all users
        unique_users = set(e.get("user_email") for e in events)
        assert len(unique_users) == 20

        # All from same IP
        unique_ips = set(e.get("source_ip") for e in events)
        assert len(unique_ips) == 1
        assert "203.0.113.51" in unique_ips


class TestMFAFatigueRules:
    """Tests for MFA fatigue detection rules."""

    def test_mfa_fatigue_events_generated(self):
        """Test MFA fatigue event generation."""
        generator = EventGenerator()

        events = generator.generate_mfa_fatigue_events(
            user="victim@example.com",
            count=5,
            include_success=True,
        )

        # Should have challenges, denials, and final success
        outcomes = [e.get("outcome") for e in events]
        assert "CHALLENGE" in outcomes
        assert "FAILURE" in outcomes
        assert "SUCCESS" in outcomes

    def test_mfa_denial_pattern_detected(self):
        """Test that MFA denial pattern is detected."""
        generator = EventGenerator()
        matcher = SigmaConditionMatcher()

        events = generator.generate_mfa_fatigue_events(
            user="victim@example.com",
            count=5,
            include_success=False,
        )

        detection = {
            "selection": {
                "event_type": "user.mfa.factor.verify",
                "outcome": "FAILURE",
                "failure_reason": "DENIED",
            },
            "condition": "selection",
        }

        denials = [e for e in events if e.get("outcome") == "FAILURE"]
        matches = [matcher.evaluate_condition(e, detection) for e in denials]

        assert len(denials) > 0
        assert all(matches)


class TestImpossibleTravelRules:
    """Tests for impossible travel detection rules."""

    def test_impossible_travel_events_generated(self):
        """Test impossible travel event generation."""
        generator = EventGenerator()

        locations = [
            {"country": "US", "city": "New York", "latitude": 40.7128, "longitude": -74.0060},
            {"country": "JP", "city": "Tokyo", "latitude": 35.6762, "longitude": 139.6503},
        ]

        events = generator.generate_impossible_travel_events(
            user="traveler@example.com",
            locations=locations,
            time_gap_minutes=60,
        )

        assert len(events) == 2

        # Check different locations
        geo1 = events[0].get("client", {}).get("geographicalContext", {})
        geo2 = events[1].get("client", {}).get("geographicalContext", {})

        assert geo1.get("country") == "US"
        assert geo2.get("country") == "JP"


class TestPrivilegeEscalationRules:
    """Tests for privilege escalation detection rules."""

    def test_privilege_escalation_events_generated(self):
        """Test privilege escalation event generation."""
        generator = EventGenerator()

        events = generator.generate_privilege_escalation_events(
            user="victim@example.com",
            roles=["User", "Security Reader", "Global Administrator"],
        )

        assert len(events) == 3

        roles = [e.get("role_name") for e in events]
        assert "Global Administrator" in roles

    def test_global_admin_grant_detected(self):
        """Test detection of Global Administrator grant."""
        generator = EventGenerator()
        matcher = SigmaConditionMatcher()

        events = generator.generate_privilege_escalation_events(
            user="victim@example.com",
            roles=["User", "Global Administrator"],
        )

        detection = {
            "selection": {
                "role_name": "Global Administrator",
            },
            "condition": "selection",
        }

        matches = [matcher.evaluate_condition(e, detection) for e in events]

        # At least one event should match
        assert any(matches)


class TestCredentialStuffingRules:
    """Tests for credential stuffing detection rules."""

    def test_credential_stuffing_events_generated(self):
        """Test credential stuffing event generation."""
        generator = EventGenerator()

        events = generator.generate_credential_stuffing_events(
            ip="203.0.113.55",
            user_count=100,
            success_rate=0.05,
        )

        assert len(events) == 100

        # All from same IP
        unique_ips = set(e.get("source_ip") for e in events)
        assert len(unique_ips) == 1

        # Many unique users
        unique_users = set(e.get("user_email") for e in events)
        assert len(unique_users) == 100


class TestNegativeDetection:
    """Tests that benign events do NOT trigger detection rules."""

    def test_normal_login_not_detected_as_brute_force(self):
        """Normal logins should not trigger brute force detection."""
        generator = EventGenerator()
        matcher = SigmaConditionMatcher()

        events = generator.generate_normal_login_events(
            user="normal@example.com",
            count=10,
        )

        # Brute force detection looks for failures
        detection = {
            "selection": {
                "outcome": "FAILURE",
            },
            "condition": "selection",
        }

        matches = [matcher.evaluate_condition(e, detection) for e in events]

        # Normal logins (SUCCESS) should NOT match
        assert not any(matches)

    def test_normal_mfa_not_detected_as_fatigue(self):
        """Normal MFA should not trigger fatigue detection."""
        generator = EventGenerator()
        matcher = SigmaConditionMatcher()

        events = generator.generate_normal_mfa_events(
            user="normal@example.com",
            count=5,
        )

        # MFA fatigue looks for denials
        detection = {
            "selection": {
                "outcome": "FAILURE",
                "failure_reason": "DENIED",
            },
            "condition": "selection",
        }

        matches = [matcher.evaluate_condition(e, detection) for e in events]

        # Normal MFA (no denials) should NOT match
        assert not any(matches)


class TestRuleValidation:
    """End-to-end rule validation tests."""

    def test_run_all_tests_empty_directory(self, tmp_path):
        """Test running against empty directory."""
        runner = RuleTestRunner()

        report = runner.run_all_tests(str(tmp_path))

        assert report.total_rules == 0
        assert report.total_tests == 0

    def test_run_all_tests_with_rules(self, tmp_path):
        """Test running against directory with rules."""
        # Create test rules
        rule1 = """
title: Test Rule 1
id: test-001
status: test
level: high
logsource:
    product: okta
detection:
    selection:
        outcome: FAILURE
    condition: selection
"""
        rule2 = """
title: Test Rule 2
id: test-002
status: test
level: medium
logsource:
    product: okta
detection:
    selection:
        outcome: SUCCESS
    condition: selection
"""
        (tmp_path / "rule1.yml").write_text(rule1)
        (tmp_path / "rule2.yml").write_text(rule2)

        runner = RuleTestRunner()
        report = runner.run_all_tests(str(tmp_path))

        assert report.total_rules == 2
        assert report.total_tests == 4  # 2 tests per rule (match + no-match)
