"""Unit tests for detection rule loading and validation."""

import os
import tempfile
from datetime import datetime, timedelta

import pytest
import yaml

from src.shared.detection.rule import (
    DetectionRule,
    RuleLoader,
    SigmaRuleValidator,
    QueryConfig,
    ScheduleConfig,
    ThresholdConfig,
    AlertConfig,
)


@pytest.fixture
def sample_rule_dict():
    """Sample rule dictionary for testing."""
    return {
        "id": "test-001-sample",
        "name": "Test Detection Rule",
        "description": "A test rule for unit testing",
        "author": "Test Author",
        "created": "2025-01-27",
        "modified": "2025-01-27",
        "version": "1.0.0",
        "severity": "high",
        "query": {
            "type": "sql",
            "sql": "SELECT * FROM test_table WHERE timestamp >= '${time_window_start}' AND timestamp < '${time_window_end}'",
            "parameters": {
                "threshold": 10
            }
        },
        "schedule": {
            "interval": "5m"
        },
        "threshold": {
            "field": "count",
            "operator": ">=",
            "value": 1
        },
        "enabled": True,
        "alert": {
            "destinations": ["slack"],
            "title_template": "Test alert: ${count} events",
            "body_template": "Test alert body"
        },
        "tags": ["test", "sample"],
        "references": ["https://example.com/test"]
    }


@pytest.fixture
def sample_rule_yaml(tmp_path, sample_rule_dict):
    """Create a temporary YAML file with sample rule."""
    rule_file = tmp_path / "test_rule.yaml"
    with open(rule_file, 'w') as f:
        yaml.dump(sample_rule_dict, f)
    return rule_file


class TestSigmaRuleValidator:
    """Tests for SigmaRuleValidator class."""

    def test_validate_valid_rule(self, sample_rule_dict):
        """Test validation of a valid rule."""
        validator = SigmaRuleValidator()
        is_valid, errors = validator.validate_rule(sample_rule_dict)
        assert is_valid
        assert len(errors) == 0

    def test_validate_missing_required_field(self, sample_rule_dict):
        """Test validation fails when required field is missing."""
        del sample_rule_dict["severity"]
        validator = SigmaRuleValidator()
        is_valid, errors = validator.validate_rule(sample_rule_dict)
        assert not is_valid
        assert any("severity" in error.lower() for error in errors)

    def test_validate_invalid_severity(self, sample_rule_dict):
        """Test validation fails with invalid severity."""
        sample_rule_dict["severity"] = "invalid"
        validator = SigmaRuleValidator()
        is_valid, errors = validator.validate_rule(sample_rule_dict)
        assert not is_valid
        assert any("severity" in error.lower() for error in errors)

    def test_validate_missing_query_sql(self, sample_rule_dict):
        """Test validation fails when query SQL is missing."""
        del sample_rule_dict["query"]["sql"]
        validator = SigmaRuleValidator()
        is_valid, errors = validator.validate_rule(sample_rule_dict)
        assert not is_valid

    def test_validate_sql_select_only(self):
        """Test SQL validation only allows SELECT statements."""
        validator = SigmaRuleValidator()

        # Valid SELECT
        is_valid, errors = validator.validate_sql("SELECT * FROM table")
        assert is_valid

        # Invalid DROP
        is_valid, errors = validator.validate_sql("DROP TABLE users")
        assert not is_valid
        assert any("DROP" in error for error in errors)

        # Invalid DELETE
        is_valid, errors = validator.validate_sql("DELETE FROM users WHERE id = 1")
        assert not is_valid

    def test_validate_sql_dangerous_keywords(self):
        """Test SQL validation blocks dangerous keywords."""
        validator = SigmaRuleValidator()

        dangerous_sqls = [
            "SELECT * FROM users; DROP TABLE logs;",
            "SELECT * FROM users UNION SELECT * FROM admin; DELETE FROM logs;",
            "CREATE TABLE new_table AS SELECT * FROM users",
            "ALTER TABLE users ADD COLUMN admin BOOLEAN",
        ]

        for sql in dangerous_sqls:
            is_valid, errors = validator.validate_sql(sql)
            assert not is_valid, f"Should have blocked: {sql}"


class TestDetectionRule:
    """Tests for DetectionRule class."""

    def test_get_query_substitution(self, sample_rule_dict):
        """Test query parameter substitution."""
        loader = RuleLoader("/tmp")
        rule = loader._parse_rule(sample_rule_dict)

        start_time = datetime(2025, 1, 27, 10, 0, 0)
        end_time = datetime(2025, 1, 27, 11, 0, 0)

        query = rule.get_query(start_time, end_time)

        assert start_time.isoformat() in query
        assert end_time.isoformat() in query

    def test_evaluate_threshold_greater_than_equal(self, sample_rule_dict):
        """Test threshold evaluation with >= operator."""
        loader = RuleLoader("/tmp")
        rule = loader._parse_rule(sample_rule_dict)

        # Below threshold
        results = []
        assert not rule.evaluate_threshold(results)

        # At threshold
        results = [{"count": 1}]
        assert rule.evaluate_threshold(results)

        # Above threshold
        results = [{"count": 5}, {"count": 3}]
        assert rule.evaluate_threshold(results)

    def test_evaluate_threshold_operators(self):
        """Test different threshold operators."""
        base_dict = {
            "id": "test",
            "name": "Test",
            "description": "Test",
            "author": "Test",
            "created": "2025-01-27",
            "modified": "2025-01-27",
            "version": "1.0.0",
            "severity": "high",
            "query": {"sql": "SELECT 1"},
            "schedule": {"interval": "5m"}
        }

        loader = RuleLoader("/tmp")

        # Test >
        base_dict["threshold"] = {"field": "value", "operator": ">", "value": 10}
        rule = loader._parse_rule(base_dict)
        assert not rule.evaluate_threshold([{"value": 10}])
        assert rule.evaluate_threshold([{"value": 11}])

        # Test <
        base_dict["threshold"] = {"field": "value", "operator": "<", "value": 10}
        rule = loader._parse_rule(base_dict)
        assert rule.evaluate_threshold([{"value": 9}])
        assert not rule.evaluate_threshold([{"value": 10}])

        # Test ==
        base_dict["threshold"] = {"field": "value", "operator": "==", "value": 10}
        rule = loader._parse_rule(base_dict)
        assert rule.evaluate_threshold([{"value": 10}])
        assert not rule.evaluate_threshold([{"value": 9}])

    def test_generate_alert_content(self, sample_rule_dict):
        """Test alert content generation from templates."""
        loader = RuleLoader("/tmp")
        rule = loader._parse_rule(sample_rule_dict)

        results = [
            {"user": "testuser", "ip": "1.2.3.4", "count": 5}
        ]

        alert_content = rule.generate_alert_content(results)

        assert "title" in alert_content
        assert "body" in alert_content
        # Check that count was substituted
        assert "5" in alert_content["title"]

    def test_get_suppression_key(self, sample_rule_dict):
        """Test suppression key generation."""
        sample_rule_dict["suppression"] = {
            "key": "${user}-${ip}",
            "duration": "1h"
        }

        loader = RuleLoader("/tmp")
        rule = loader._parse_rule(sample_rule_dict)

        result = {"user": "testuser", "ip": "1.2.3.4"}
        key = rule.get_suppression_key(result)

        assert "testuser" in key
        assert "1.2.3.4" in key


class TestRuleLoader:
    """Tests for RuleLoader class."""

    def test_load_rule_from_file(self, sample_rule_yaml):
        """Test loading a rule from a YAML file."""
        loader = RuleLoader(str(sample_rule_yaml.parent))
        rule = loader.load_rule(str(sample_rule_yaml))

        assert isinstance(rule, DetectionRule)
        assert rule.id == "test-001-sample"
        assert rule.name == "Test Detection Rule"
        assert rule.severity == "high"

    def test_load_all_rules_from_directory(self, tmp_path, sample_rule_dict):
        """Test loading all rules from a directory."""
        # Create multiple rule files
        for i in range(3):
            rule_dict = sample_rule_dict.copy()
            rule_dict["id"] = f"test-{i:03d}"
            rule_file = tmp_path / f"rule_{i}.yaml"
            with open(rule_file, 'w') as f:
                yaml.dump(rule_dict, f)

        loader = RuleLoader(str(tmp_path))
        rules = loader.load_all_rules()

        assert len(rules) == 3
        assert all(isinstance(rule, DetectionRule) for rule in rules)

    def test_load_rules_recursive(self, tmp_path, sample_rule_dict):
        """Test loading rules from nested directories."""
        # Create nested directory structure
        subdir1 = tmp_path / "category1"
        subdir2 = tmp_path / "category2"
        subdir1.mkdir()
        subdir2.mkdir()

        # Create rules in different directories
        for i, subdir in enumerate([tmp_path, subdir1, subdir2]):
            rule_dict = sample_rule_dict.copy()
            rule_dict["id"] = f"test-{i:03d}"
            rule_file = subdir / f"rule_{i}.yaml"
            with open(rule_file, 'w') as f:
                yaml.dump(rule_dict, f)

        loader = RuleLoader(str(tmp_path))
        rules = loader.load_all_rules()

        assert len(rules) == 3

    def test_get_enabled_rules(self, tmp_path, sample_rule_dict):
        """Test filtering for enabled rules only."""
        # Create mix of enabled and disabled rules
        for i in range(4):
            rule_dict = sample_rule_dict.copy()
            rule_dict["id"] = f"test-{i:03d}"
            rule_dict["enabled"] = i % 2 == 0  # Even indices enabled
            rule_file = tmp_path / f"rule_{i}.yaml"
            with open(rule_file, 'w') as f:
                yaml.dump(rule_dict, f)

        loader = RuleLoader(str(tmp_path))
        loader.load_all_rules()
        enabled_rules = loader.get_enabled_rules()

        assert len(enabled_rules) == 2
        assert all(rule.enabled for rule in enabled_rules)

    def test_get_rule_by_id(self, tmp_path, sample_rule_dict):
        """Test retrieving a specific rule by ID."""
        rule_file = tmp_path / "rule.yaml"
        with open(rule_file, 'w') as f:
            yaml.dump(sample_rule_dict, f)

        loader = RuleLoader(str(tmp_path))
        loader.load_all_rules()

        rule = loader.get_rule_by_id("test-001-sample")
        assert rule is not None
        assert rule.id == "test-001-sample"

        # Test non-existent rule
        rule = loader.get_rule_by_id("nonexistent")
        assert rule is None
