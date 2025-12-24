"""
Rule test runner for ITDR Sigma rules.

Provides utilities for loading, testing, and validating detection rules.
"""

import os
import yaml
import re
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, field
from pathlib import Path

from .test_data_generator import EventGenerator, generate_test_cases_for_rule


@dataclass
class SigmaRule:
    """Parsed Sigma rule."""

    title: str
    id: str
    status: str
    level: str
    description: str
    logsource: Dict[str, str]
    detection: Dict[str, Any]
    falsepositives: List[str] = field(default_factory=list)
    tags: List[str] = field(default_factory=list)
    references: List[str] = field(default_factory=list)
    raw_yaml: Dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_yaml(cls, yaml_content: Dict[str, Any]) -> "SigmaRule":
        """Parse Sigma rule from YAML content."""
        return cls(
            title=yaml_content.get("title", "Unknown"),
            id=yaml_content.get("id", ""),
            status=yaml_content.get("status", "experimental"),
            level=yaml_content.get("level", "medium"),
            description=yaml_content.get("description", ""),
            logsource=yaml_content.get("logsource", {}),
            detection=yaml_content.get("detection", {}),
            falsepositives=yaml_content.get("falsepositives", []),
            tags=yaml_content.get("tags", []),
            references=yaml_content.get("references", []),
            raw_yaml=yaml_content,
        )


@dataclass
class TestResult:
    """Result of a single rule test."""

    rule_id: str
    rule_title: str
    test_case: str
    expected_match: bool
    actual_match: bool
    passed: bool
    error: Optional[str] = None
    event: Dict[str, Any] = field(default_factory=dict)


@dataclass
class TestReport:
    """Aggregated test report for multiple rules."""

    total_rules: int
    total_tests: int
    passed_tests: int
    failed_tests: int
    results: List[TestResult] = field(default_factory=list)
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    @property
    def success_rate(self) -> float:
        """Calculate success rate percentage."""
        if self.total_tests == 0:
            return 0.0
        return (self.passed_tests / self.total_tests) * 100

    def to_dict(self) -> Dict[str, Any]:
        """Convert report to dictionary."""
        return {
            "total_rules": self.total_rules,
            "total_tests": self.total_tests,
            "passed_tests": self.passed_tests,
            "failed_tests": self.failed_tests,
            "success_rate": self.success_rate,
            "timestamp": self.timestamp.isoformat(),
            "results": [
                {
                    "rule_id": r.rule_id,
                    "rule_title": r.rule_title,
                    "test_case": r.test_case,
                    "expected_match": r.expected_match,
                    "actual_match": r.actual_match,
                    "passed": r.passed,
                    "error": r.error,
                }
                for r in self.results
            ],
        }


class SigmaConditionMatcher:
    """
    Simple Sigma condition matcher.

    Evaluates Sigma detection conditions against events.
    """

    def match_selection(
        self,
        event: Dict[str, Any],
        selection: Dict[str, Any],
    ) -> bool:
        """
        Check if event matches a selection criteria.

        Args:
            event: Event to check
            selection: Selection criteria from Sigma rule

        Returns:
            True if event matches selection
        """
        for field_name, expected_value in selection.items():
            # Handle field modifiers (contains, startswith, endswith)
            modifier = None
            actual_field = field_name

            if "|" in field_name:
                parts = field_name.split("|")
                actual_field = parts[0]
                modifier = parts[1] if len(parts) > 1 else None

            # Get actual value from event (supports nested fields)
            actual_value = self._get_nested_value(event, actual_field)

            if actual_value is None:
                return False

            # Apply modifier-based matching
            if not self._match_value(actual_value, expected_value, modifier):
                return False

        return True

    def _get_nested_value(self, obj: Dict[str, Any], path: str) -> Any:
        """Get value from nested dict using dot notation."""
        keys = path.split(".")
        value = obj

        for key in keys:
            if isinstance(value, dict):
                value = value.get(key)
            else:
                return None

            if value is None:
                return None

        return value

    def _match_value(
        self,
        actual: Any,
        expected: Any,
        modifier: Optional[str] = None,
    ) -> bool:
        """Match actual value against expected with optional modifier."""
        # Handle list of expected values (OR logic)
        if isinstance(expected, list):
            return any(
                self._match_value(actual, exp, modifier)
                for exp in expected
            )

        # Convert to string for comparison
        actual_str = str(actual).lower()
        expected_str = str(expected).lower()

        if modifier == "contains":
            return expected_str in actual_str
        elif modifier == "startswith":
            return actual_str.startswith(expected_str)
        elif modifier == "endswith":
            return actual_str.endswith(expected_str)
        elif modifier == "re":
            return bool(re.match(expected_str, actual_str))
        else:
            # Exact match (case-insensitive)
            return actual_str == expected_str

    def evaluate_condition(
        self,
        event: Dict[str, Any],
        detection: Dict[str, Any],
    ) -> bool:
        """
        Evaluate Sigma detection condition.

        Args:
            event: Event to evaluate
            detection: Detection block from Sigma rule

        Returns:
            True if detection condition matches
        """
        condition = detection.get("condition", "selection")

        # Parse simple conditions
        # This is a simplified parser - real implementation would be more complex

        # Handle "selection"
        if condition == "selection":
            selection = detection.get("selection", {})
            return self.match_selection(event, selection)

        # Handle "selection and filter"
        if " and " in condition:
            parts = condition.split(" and ")
            return all(
                self._evaluate_part(event, detection, part.strip())
                for part in parts
            )

        # Handle "selection or selection2"
        if " or " in condition:
            parts = condition.split(" or ")
            return any(
                self._evaluate_part(event, detection, part.strip())
                for part in parts
            )

        # Handle "not filter"
        if condition.startswith("not "):
            part = condition[4:]
            return not self._evaluate_part(event, detection, part)

        # Handle threshold conditions like "selection | count() > 5"
        if "|" in condition and "count" in condition:
            # For threshold conditions, we'd need multiple events
            # For single event testing, just check the selection part
            base_condition = condition.split("|")[0].strip()
            return self._evaluate_part(event, detection, base_condition)

        return self._evaluate_part(event, detection, condition)

    def _evaluate_part(
        self,
        event: Dict[str, Any],
        detection: Dict[str, Any],
        part: str,
    ) -> bool:
        """Evaluate a single condition part."""
        part = part.strip()

        # Handle negation
        if part.startswith("not "):
            inner = part[4:]
            return not self._evaluate_part(event, detection, inner)

        # Handle parentheses
        if part.startswith("(") and part.endswith(")"):
            inner = part[1:-1]
            return self.evaluate_condition(event, {**detection, "condition": inner})

        # Look up selection by name
        if part in detection:
            return self.match_selection(event, detection[part])

        return False


class RuleTestRunner:
    """
    Test runner for Sigma detection rules.

    Loads rules, generates test cases, and validates detection.
    """

    def __init__(self):
        self.matcher = SigmaConditionMatcher()
        self.generator = EventGenerator()

    def load_rule(self, rule_path: str) -> SigmaRule:
        """
        Load a Sigma rule from file.

        Args:
            rule_path: Path to YAML rule file

        Returns:
            Parsed SigmaRule object
        """
        with open(rule_path, "r") as f:
            content = yaml.safe_load(f)

        return SigmaRule.from_yaml(content)

    def load_rules_from_directory(self, directory: str) -> List[SigmaRule]:
        """
        Load all Sigma rules from a directory.

        Args:
            directory: Path to directory containing YAML rules

        Returns:
            List of parsed SigmaRule objects
        """
        rules = []
        dir_path = Path(directory)

        for yaml_file in dir_path.glob("**/*.yml"):
            try:
                rule = self.load_rule(str(yaml_file))
                rules.append(rule)
            except Exception as e:
                print(f"Error loading {yaml_file}: {e}")

        return rules

    def generate_matching_event(self, rule: SigmaRule) -> Dict[str, Any]:
        """
        Generate an event that should match the rule.

        Args:
            rule: Sigma rule to generate matching event for

        Returns:
            Event dictionary that should trigger the rule
        """
        # Determine rule type from tags or title
        rule_type = self._determine_rule_type(rule)

        if rule_type == "brute_force":
            events = self.generator.generate_brute_force_events(
                count=10, user="victim@example.com", ip="203.0.113.50"
            )
            return events[-1] if events else {}

        elif rule_type == "password_spray":
            events = self.generator.generate_password_spray_events(
                users=[f"user{i}@example.com" for i in range(20)],
                ip="203.0.113.51",
            )
            return events[0] if events else {}

        elif rule_type == "mfa_fatigue":
            events = self.generator.generate_mfa_fatigue_events(
                user="victim@example.com", count=5
            )
            # Return an MFA denial event
            return next((e for e in events if e.get("outcome") == "FAILURE"), events[0])

        elif rule_type == "impossible_travel":
            events = self.generator.generate_impossible_travel_events(
                user="victim@example.com",
                locations=[
                    {"country": "US", "city": "New York"},
                    {"country": "JP", "city": "Tokyo"},
                ],
            )
            return events[-1] if events else {}

        elif rule_type == "privilege_escalation":
            events = self.generator.generate_privilege_escalation_events(
                user="victim@example.com",
                roles=["User", "Global Administrator"],
            )
            return events[-1] if events else {}

        else:
            # Generate generic auth failure event
            return self.generator.generate_brute_force_events(
                count=1, user="test@example.com", ip="1.2.3.4"
            )[0]

    def generate_non_matching_event(self, rule: SigmaRule) -> Dict[str, Any]:
        """
        Generate an event that should NOT match the rule.

        Args:
            rule: Sigma rule to generate non-matching event for

        Returns:
            Event dictionary that should not trigger the rule
        """
        # Generate normal, benign login
        events = self.generator.generate_normal_login_events(
            user="normal@example.com", count=1
        )
        return events[0] if events else {}

    def test_rule_detection(
        self,
        rule: SigmaRule,
        events: List[Dict[str, Any]],
    ) -> List[TestResult]:
        """
        Test a rule against a list of events.

        Args:
            rule: Sigma rule to test
            events: List of events to test against

        Returns:
            List of TestResult objects
        """
        results = []

        for i, event in enumerate(events):
            try:
                matches = self.matcher.evaluate_condition(
                    event, rule.detection
                )

                results.append(TestResult(
                    rule_id=rule.id,
                    rule_title=rule.title,
                    test_case=f"Event {i+1}",
                    expected_match=True,  # Assuming test events should match
                    actual_match=matches,
                    passed=matches,
                    event=event,
                ))

            except Exception as e:
                results.append(TestResult(
                    rule_id=rule.id,
                    rule_title=rule.title,
                    test_case=f"Event {i+1}",
                    expected_match=True,
                    actual_match=False,
                    passed=False,
                    error=str(e),
                    event=event,
                ))

        return results

    def run_all_tests(self, rules_dir: str) -> TestReport:
        """
        Run tests for all rules in a directory.

        Args:
            rules_dir: Path to directory containing Sigma rules

        Returns:
            TestReport with aggregated results
        """
        rules = self.load_rules_from_directory(rules_dir)

        all_results = []
        passed = 0
        failed = 0

        for rule in rules:
            # Generate test events
            matching_event = self.generate_matching_event(rule)
            non_matching_event = self.generate_non_matching_event(rule)

            # Test matching event
            try:
                matches = self.matcher.evaluate_condition(
                    matching_event, rule.detection
                )
                test_passed = matches
            except Exception as e:
                matches = False
                test_passed = False

            all_results.append(TestResult(
                rule_id=rule.id,
                rule_title=rule.title,
                test_case="Should match",
                expected_match=True,
                actual_match=matches,
                passed=test_passed,
            ))

            if test_passed:
                passed += 1
            else:
                failed += 1

            # Test non-matching event
            try:
                matches = self.matcher.evaluate_condition(
                    non_matching_event, rule.detection
                )
                test_passed = not matches  # Should NOT match
            except Exception:
                test_passed = True  # Error means no match

            all_results.append(TestResult(
                rule_id=rule.id,
                rule_title=rule.title,
                test_case="Should not match",
                expected_match=False,
                actual_match=matches,
                passed=test_passed,
            ))

            if test_passed:
                passed += 1
            else:
                failed += 1

        return TestReport(
            total_rules=len(rules),
            total_tests=len(all_results),
            passed_tests=passed,
            failed_tests=failed,
            results=all_results,
        )

    def _determine_rule_type(self, rule: SigmaRule) -> str:
        """Determine rule type from tags or title."""
        title_lower = rule.title.lower()
        tags = [t.lower() for t in rule.tags]

        if "brute" in title_lower or "attack.t1110" in tags:
            return "brute_force"
        elif "spray" in title_lower:
            return "password_spray"
        elif "mfa" in title_lower or "fatigue" in title_lower:
            return "mfa_fatigue"
        elif "travel" in title_lower:
            return "impossible_travel"
        elif "privilege" in title_lower or "escalation" in title_lower:
            return "privilege_escalation"
        elif "credential" in title_lower and "stuffing" in title_lower:
            return "credential_stuffing"
        else:
            return "generic"


def print_test_report(report: TestReport) -> None:
    """Print formatted test report."""
    print("\n" + "=" * 60)
    print("SIGMA RULE VALIDATION REPORT")
    print("=" * 60)
    print(f"Timestamp: {report.timestamp.isoformat()}")
    print(f"Total Rules: {report.total_rules}")
    print(f"Total Tests: {report.total_tests}")
    print(f"Passed: {report.passed_tests}")
    print(f"Failed: {report.failed_tests}")
    print(f"Success Rate: {report.success_rate:.1f}%")
    print("-" * 60)

    if report.failed_tests > 0:
        print("\nFailed Tests:")
        for result in report.results:
            if not result.passed:
                print(f"  - {result.rule_title}: {result.test_case}")
                if result.error:
                    print(f"    Error: {result.error}")

    print("=" * 60)
