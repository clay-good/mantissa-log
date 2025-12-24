"""Integration tests for APM detection system.

Tests:
- Loading APM detection rules from YAML
- Rule evaluation with sample data
- Alert generation from detection results
- Alert formatting for different destinations
"""

import json
import os
import tempfile
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any, Dict, List
from unittest.mock import MagicMock, patch

import pytest

# Import APM detection components
from src.shared.apm.apm_detector import APMDetector, APMDetectionResult, APMRule
from src.shared.detection.alert_generator import Alert, AlertGenerator


# Sample APM rules for testing
SAMPLE_LATENCY_RULE = """
title: Service Latency Spike Detected
id: apm-test-latency-001
status: stable
description: Test rule for latency detection
author: Test
date: 2025-01-27
level: medium

logsource:
  product: apm
  service: traces

detection:
  selection:
    kind: server
  timeframe: 5m
  condition: selection | aggregate by service_name where p95(duration_ms) > 2000

fields:
  - service_name
  - operation_name
  - p95_duration_ms

falsepositives:
  - Test scenarios

tags:
  - latency
  - apm
"""

SAMPLE_ERROR_RULE = """
title: Service Error Rate Spike
id: apm-test-error-001
status: stable
description: Test rule for error rate detection
author: Test
date: 2025-01-27
level: high

logsource:
  product: apm
  service: traces

detection:
  selection:
    kind: server
  timeframe: 5m
  condition: selection | aggregate by service_name where (count(status='error') / count(*)) > 0.05

fields:
  - service_name
  - error_count
  - error_rate

falsepositives:
  - Test scenarios

tags:
  - errors
  - apm
"""


class TestAPMRuleLoading:
    """Tests for APM rule loading functionality."""

    def test_load_single_rule_from_yaml(self, tmp_path):
        """Test loading a single APM rule from YAML file."""
        # Create temp rule file
        rule_file = tmp_path / "test_rule.yml"
        rule_file.write_text(SAMPLE_LATENCY_RULE)

        # Load rules
        detector = APMDetector()
        rules = detector.load_apm_rules(str(tmp_path))

        assert len(rules) == 1
        assert rules[0].id == "apm-test-latency-001"
        assert rules[0].title == "Service Latency Spike Detected"
        assert rules[0].level == "medium"
        assert "latency" in rules[0].tags

    def test_load_multiple_rules(self, tmp_path):
        """Test loading multiple APM rules from directory."""
        # Create temp rule files
        (tmp_path / "latency.yml").write_text(SAMPLE_LATENCY_RULE)
        (tmp_path / "errors.yml").write_text(SAMPLE_ERROR_RULE)

        detector = APMDetector()
        rules = detector.load_apm_rules(str(tmp_path))

        assert len(rules) == 2
        rule_ids = [r.id for r in rules]
        assert "apm-test-latency-001" in rule_ids
        assert "apm-test-error-001" in rule_ids

    def test_skip_non_apm_rules(self, tmp_path):
        """Test that non-APM rules are skipped."""
        non_apm_rule = """
title: CloudTrail Rule
id: aws-cloudtrail-001
status: stable
logsource:
  product: aws
  service: cloudtrail
detection:
  selection:
    eventName: ConsoleLogin
  condition: selection
level: medium
"""
        (tmp_path / "cloudtrail.yml").write_text(non_apm_rule)
        (tmp_path / "apm_latency.yml").write_text(SAMPLE_LATENCY_RULE)

        detector = APMDetector()
        rules = detector.load_apm_rules(str(tmp_path))

        # Only APM rule should be loaded
        assert len(rules) == 1
        assert rules[0].id == "apm-test-latency-001"

    def test_handle_invalid_yaml(self, tmp_path):
        """Test handling of invalid YAML files."""
        (tmp_path / "invalid.yml").write_text("this is: not: valid: yaml:")
        (tmp_path / "valid.yml").write_text(SAMPLE_LATENCY_RULE)

        detector = APMDetector()
        rules = detector.load_apm_rules(str(tmp_path))

        # Should load valid rule only
        assert len(rules) == 1

    def test_rule_from_dict(self):
        """Test creating APMRule from dictionary."""
        import yaml
        rule_dict = yaml.safe_load(SAMPLE_LATENCY_RULE)

        rule = APMRule.from_dict(rule_dict)

        assert rule.id == "apm-test-latency-001"
        assert rule.title == "Service Latency Spike Detected"
        assert rule.level == "medium"
        assert rule.timeframe == "5m"
        assert rule.enabled is True


class TestAPMRuleEvaluation:
    """Tests for APM rule evaluation."""

    def test_evaluate_latency_rule_triggered(self, tmp_path):
        """Test latency rule evaluation when threshold exceeded."""
        (tmp_path / "latency.yml").write_text(SAMPLE_LATENCY_RULE)

        # Mock query results with high latency
        mock_results = [
            {
                "service_name": "api-gateway",
                "operation_name": "GET /users",
                "p95_duration_ms": 3500,  # Above 2000ms threshold
                "avg_duration_ms": 2000,
                "request_count": 100,
            }
        ]

        def mock_query_executor(query):
            return mock_results

        detector = APMDetector(query_executor=mock_query_executor)
        rules = detector.load_apm_rules(str(tmp_path))

        start_time = datetime.utcnow() - timedelta(minutes=5)
        end_time = datetime.utcnow()

        result = detector.evaluate_latency_rule(rules[0], start_time, end_time)

        assert result.triggered is True
        assert "api-gateway" in result.services_affected
        assert result.severity == "medium"

    def test_evaluate_latency_rule_not_triggered(self, tmp_path):
        """Test latency rule evaluation when within threshold."""
        (tmp_path / "latency.yml").write_text(SAMPLE_LATENCY_RULE)

        # Mock query results with normal latency
        mock_results = [
            {
                "service_name": "api-gateway",
                "operation_name": "GET /users",
                "p95_duration_ms": 500,  # Below 2000ms threshold
                "avg_duration_ms": 200,
                "request_count": 100,
            }
        ]

        def mock_query_executor(query):
            return mock_results

        detector = APMDetector(query_executor=mock_query_executor)
        rules = detector.load_apm_rules(str(tmp_path))

        start_time = datetime.utcnow() - timedelta(minutes=5)
        end_time = datetime.utcnow()

        result = detector.evaluate_latency_rule(rules[0], start_time, end_time)

        assert result.triggered is False
        assert len(result.services_affected) == 0

    def test_evaluate_error_rate_rule_triggered(self, tmp_path):
        """Test error rate rule evaluation when threshold exceeded."""
        (tmp_path / "errors.yml").write_text(SAMPLE_ERROR_RULE)

        # Mock query results with high error rate
        mock_results = [
            {
                "service_name": "payment-service",
                "total_count": 100,
                "error_count": 10,  # 10% error rate, above 5% threshold
            }
        ]

        def mock_query_executor(query):
            return mock_results

        detector = APMDetector(query_executor=mock_query_executor)
        rules = detector.load_apm_rules(str(tmp_path))

        start_time = datetime.utcnow() - timedelta(minutes=5)
        end_time = datetime.utcnow()

        result = detector.evaluate_error_rate_rule(rules[0], start_time, end_time)

        assert result.triggered is True
        assert "payment-service" in result.services_affected
        assert result.severity == "high"
        assert result.metrics["payment-service"]["error_rate"] == 10.0

    def test_run_all_apm_rules(self, tmp_path):
        """Test running all APM rules at once."""
        (tmp_path / "latency.yml").write_text(SAMPLE_LATENCY_RULE)
        (tmp_path / "errors.yml").write_text(SAMPLE_ERROR_RULE)

        # Mock mixed results
        mock_results = {
            "latency": [
                {
                    "service_name": "api-gateway",
                    "operation_name": "GET /users",
                    "p95_duration_ms": 3500,
                    "avg_duration_ms": 2000,
                    "request_count": 100,
                }
            ],
            "error": [
                {
                    "service_name": "payment-service",
                    "total_count": 100,
                    "error_count": 2,  # 2% - below threshold
                }
            ]
        }

        def mock_query_executor(query):
            if "APPROX_PERCENTILE" in query:
                return mock_results["latency"]
            return mock_results["error"]

        detector = APMDetector(query_executor=mock_query_executor)
        detector.load_apm_rules(str(tmp_path))

        start_time = datetime.utcnow() - timedelta(minutes=5)
        end_time = datetime.utcnow()

        results = detector.run_all_apm_rules(start_time, end_time)

        assert len(results) == 2
        # Only latency rule should trigger
        triggered = [r for r in results if r.triggered]
        assert len(triggered) == 1
        assert triggered[0].rule_id == "apm-test-latency-001"


class TestAPMAlertGeneration:
    """Tests for APM alert generation."""

    def test_generate_apm_alert_single_service(self):
        """Test generating alert for single service."""
        result = APMDetectionResult(
            rule_id="apm-test-latency-001",
            rule_name="Service Latency Spike Detected",
            triggered=True,
            severity="medium",
            services_affected=["api-gateway"],
            metrics={
                "api-gateway:GET /users": {
                    "p95_duration_ms": 3500,
                    "request_count": 100,
                }
            },
            dashboard_link="http://localhost/apm?view=latency",
        )

        generator = AlertGenerator()
        alert = generator.generate_alert(
            rule_id=result.rule_id,
            rule_name=result.rule_name,
            severity=result.severity,
            title=f"[APM] {result.rule_name}: {result.services_affected[0]}",
            description="Latency spike detected",
            results=[result.to_dict()],
            tags=["apm", "latency"],
        )

        assert alert.rule_id == "apm-test-latency-001"
        assert alert.severity == "medium"
        assert "api-gateway" in alert.title

    def test_generate_apm_alert_multiple_services(self):
        """Test generating alert for multiple services."""
        result = APMDetectionResult(
            rule_id="apm-test-cascade-001",
            rule_name="Cascade Failure Detected",
            triggered=True,
            severity="critical",
            services_affected=["api-gateway", "user-service", "db-proxy"],
        )

        generator = AlertGenerator()
        alert = generator.generate_alert(
            rule_id=result.rule_id,
            rule_name=result.rule_name,
            severity=result.severity,
            title=f"[APM] {result.rule_name}: {len(result.services_affected)} services affected",
            description="Multiple services showing errors",
            results=[result.to_dict()],
            tags=["apm", "cascade"],
        )

        assert "3 services affected" in alert.title
        assert alert.severity == "critical"


class TestAPMAlertFormatting:
    """Tests for APM alert formatting."""

    def test_format_for_slack(self):
        """Test Slack message formatting for APM alerts."""
        generator = AlertGenerator()

        alert = Alert(
            id="test-alert-001",
            rule_id="apm-test-latency-001",
            rule_name="Service Latency Spike",
            severity="medium",
            title="[APM] Service Latency Spike: api-gateway",
            description="P95 latency exceeded threshold",
            timestamp=datetime.utcnow(),
            tags=["apm", "latency"],
            metadata={
                "services_affected": ["api-gateway"],
                "apm_metrics": {
                    "api-gateway": {"p95_duration_ms": 3500}
                },
            }
        )

        slack_message = generator.format_for_slack(alert)

        assert "attachments" in slack_message
        attachment = slack_message["attachments"][0]
        assert attachment["color"] == "#ffaa00"  # Medium severity
        assert "[APM]" in attachment["title"]
        assert attachment["footer"] == "Mantissa Log"

    def test_format_for_pagerduty(self):
        """Test PagerDuty event formatting for APM alerts."""
        generator = AlertGenerator()

        alert = Alert(
            id="test-alert-001",
            rule_id="apm-test-error-001",
            rule_name="Service Error Rate Spike",
            severity="high",
            title="[APM] Service Error Rate Spike",
            description="Error rate exceeded threshold",
            timestamp=datetime.utcnow(),
            tags=["apm", "errors"],
            suppression_key="apm-test-error-001:payment-service:2025012712",
        )

        pd_event = generator.format_for_pagerduty(alert)

        assert pd_event["event_action"] == "trigger"
        assert pd_event["payload"]["severity"] == "error"  # high -> error
        assert "mantissa-log" in pd_event["payload"]["source"]


class TestAPMDetectionResultSerialization:
    """Tests for APM detection result serialization."""

    def test_result_to_dict(self):
        """Test converting detection result to dictionary."""
        result = APMDetectionResult(
            rule_id="apm-test-001",
            rule_name="Test Rule",
            triggered=True,
            severity="high",
            services_affected=["service-a", "service-b"],
            metrics={"service-a": {"latency": 1000}},
            trace_ids=["trace-001", "trace-002"],
        )

        result_dict = result.to_dict()

        assert result_dict["rule_id"] == "apm-test-001"
        assert result_dict["triggered"] is True
        assert len(result_dict["services_affected"]) == 2
        assert "service-a" in result_dict["metrics"]

    def test_result_to_json(self):
        """Test that detection result can be serialized to JSON."""
        result = APMDetectionResult(
            rule_id="apm-test-001",
            rule_name="Test Rule",
            triggered=True,
            severity="medium",
        )

        # Should not raise
        json_str = json.dumps(result.to_dict())
        parsed = json.loads(json_str)

        assert parsed["rule_id"] == "apm-test-001"


class TestAPMDetectorHelpers:
    """Tests for APM detector helper methods."""

    def test_parse_timeframe_minutes(self):
        """Test parsing timeframe in minutes."""
        detector = APMDetector()

        assert detector._parse_timeframe("5m") == 5
        assert detector._parse_timeframe("15m") == 15

    def test_parse_timeframe_hours(self):
        """Test parsing timeframe in hours."""
        detector = APMDetector()

        assert detector._parse_timeframe("1h") == 60
        assert detector._parse_timeframe("2h") == 120

    def test_parse_timeframe_days(self):
        """Test parsing timeframe in days."""
        detector = APMDetector()

        assert detector._parse_timeframe("1d") == 1440

    def test_build_dashboard_link(self):
        """Test building dashboard link with filters."""
        detector = APMDetector(dashboard_base_url="http://localhost:3000")

        link = detector._build_dashboard_link(
            view_type="latency",
            services=["api-gateway", "user-service"],
            start_time=datetime(2025, 1, 27, 12, 0),
            end_time=datetime(2025, 1, 27, 13, 0),
        )

        assert "http://localhost:3000/apm?" in link
        assert "view=latency" in link
        assert "api-gateway" in link
        assert "user-service" in link

    def test_extract_threshold_from_condition(self):
        """Test extracting threshold from detection condition."""
        detector = APMDetector()

        detection = {"condition": "selection | aggregate by service_name where p95(duration_ms) > 2000"}
        threshold = detector._extract_threshold(detection, "p95", 1000)

        assert threshold == 2000

    def test_extract_threshold_default(self):
        """Test default threshold when not in condition."""
        detector = APMDetector()

        detection = {"condition": "selection"}
        threshold = detector._extract_threshold(detection, "p95", 1500)

        assert threshold == 1500  # Returns default


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
