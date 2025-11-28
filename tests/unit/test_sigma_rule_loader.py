"""Unit tests for Sigma rule loading in RuleLoader."""

import pytest
from pathlib import Path
from unittest.mock import Mock, patch, mock_open
import yaml

from src.shared.detection.rule import RuleLoader, DetectionRule
from src.shared.detection.sigma_converter import SIGMA_AVAILABLE


@pytest.fixture
def sigma_rule_yaml():
    """Sample Sigma rule in YAML format."""
    return """
title: AWS Console Login Brute Force
id: aws-brute-force-001
status: stable
description: Detects multiple failed login attempts
author: Test Author
date: 2025-01-27

logsource:
  product: aws
  service: cloudtrail

detection:
  selection_failed:
    eventName: ConsoleLogin
    errorCode:
      - Failed authentication
      - InvalidPassword
  condition: selection_failed

fields:
  - sourceIPAddress
  - userIdentity.principalId

level: high

tags:
  - attack.credential_access
  - attack.t1110
"""


@pytest.fixture
def legacy_rule_yaml():
    """Sample legacy rule in YAML format."""
    return """
name: Legacy Brute Force Rule
description: Detects brute force attempts
enabled: true
severity: high
category: authentication

query: |
  SELECT sourceipaddress, COUNT(*) as count
  FROM cloudtrail
  WHERE eventname = 'ConsoleLogin'
    AND errorcode IS NOT NULL
  GROUP BY sourceipaddress
  HAVING COUNT(*) >= 10

threshold:
  count: 1
  window: 15m

metadata:
  mitre_attack:
    - T1110
  tags:
    - authentication
    - brute-force
"""


@pytest.fixture
def temp_rules_dir(tmp_path):
    """Create temporary rules directory."""
    rules_dir = tmp_path / "rules"
    rules_dir.mkdir()
    return rules_dir


@pytest.mark.skipif(not SIGMA_AVAILABLE, reason="pySigma not installed")
class TestRuleLoaderSigmaSupport:
    """Tests for RuleLoader with Sigma format support."""

    def test_is_sigma_format_detection(self):
        """Test detection of Sigma vs legacy format."""
        loader = RuleLoader(rules_path="/tmp/rules", backend_type="athena")

        # Sigma format
        sigma_dict = {
            "title": "Test",
            "logsource": {"product": "aws"},
            "detection": {"selection": {}, "condition": "selection"}
        }
        assert loader._is_sigma_format(sigma_dict) is True

        # Legacy format
        legacy_dict = {
            "name": "Test",
            "query": {"sql": "SELECT * FROM table"}
        }
        assert loader._is_sigma_format(legacy_dict) is False

        # Ambiguous (both fields) - should prefer Sigma
        ambiguous_dict = {
            "logsource": {"product": "aws"},
            "detection": {"selection": {}},
            "query": {"sql": "SELECT * FROM table"}
        }
        assert loader._is_sigma_format(ambiguous_dict) is True

        # Neither format - should default to legacy
        neither_dict = {"title": "Test", "description": "Test"}
        assert loader._is_sigma_format(neither_dict) is False

    def test_map_sigma_level(self):
        """Test Sigma level to severity mapping."""
        loader = RuleLoader(rules_path="/tmp/rules")

        assert loader._map_sigma_level("critical") == "critical"
        assert loader._map_sigma_level("high") == "high"
        assert loader._map_sigma_level("medium") == "medium"
        assert loader._map_sigma_level("low") == "low"
        assert loader._map_sigma_level("informational") == "info"
        assert loader._map_sigma_level("unknown") == "medium"  # default

    @patch('builtins.open', new_callable=mock_open)
    @patch('yaml.safe_load')
    def test_load_sigma_rule(self, mock_yaml_load, mock_file, sigma_rule_yaml):
        """Test loading a Sigma format rule."""
        # Setup mocks
        sigma_dict = yaml.safe_load(sigma_rule_yaml)
        mock_yaml_load.return_value = sigma_dict

        loader = RuleLoader(rules_path="/tmp/rules", backend_type="athena")

        # Mock the sigma converter
        with patch.object(loader.sigma_converter, 'convert_rule_to_sql') as mock_convert:
            mock_convert.return_value = "SELECT * FROM cloudtrail WHERE eventName = 'ConsoleLogin'"

            rule = loader._load_sigma_rule("/tmp/rules/test.yml", sigma_dict)

            assert isinstance(rule, DetectionRule)
            assert rule.id == "aws-brute-force-001"
            assert rule.name == "AWS Console Login Brute Force"
            assert rule.description == "Detects multiple failed login attempts"
            assert rule.severity == "high"
            assert rule.enabled is True
            assert rule.query.sql is not None
            assert len(rule.query.sql) > 0

    @patch('builtins.open', new_callable=mock_open)
    @patch('yaml.safe_load')
    def test_load_legacy_rule(self, mock_yaml_load, mock_file, legacy_rule_yaml):
        """Test loading a legacy format rule."""
        # Setup mocks
        legacy_dict = yaml.safe_load(legacy_rule_yaml)
        # Add required fields for validation
        legacy_dict.update({
            "id": "legacy-001",
            "author": "Test",
            "created": "2025-01-27",
            "modified": "2025-01-27",
            "version": "1.0.0",
            "query": {"sql": legacy_dict["query"], "type": "sql"},
            "schedule": {"interval": "15m"}
        })
        mock_yaml_load.return_value = legacy_dict

        loader = RuleLoader(rules_path="/tmp/rules")

        rule = loader._load_legacy_rule(legacy_dict)

        assert isinstance(rule, DetectionRule)
        assert rule.name == "Legacy Brute Force Rule"
        assert rule.severity == "high"
        assert rule.enabled is True

    @patch('builtins.open', new_callable=mock_open)
    @patch('yaml.safe_load')
    def test_load_rule_auto_detect_sigma(self, mock_yaml_load, mock_file, sigma_rule_yaml):
        """Test automatic detection and loading of Sigma rule."""
        sigma_dict = yaml.safe_load(sigma_rule_yaml)
        mock_yaml_load.return_value = sigma_dict

        loader = RuleLoader(rules_path="/tmp/rules", backend_type="athena")

        with patch.object(loader, '_load_sigma_rule') as mock_load_sigma:
            mock_load_sigma.return_value = Mock(spec=DetectionRule)

            loader.load_rule("/tmp/rules/test.yml")

            # Should call _load_sigma_rule
            mock_load_sigma.assert_called_once()

    @patch('builtins.open', new_callable=mock_open)
    @patch('yaml.safe_load')
    def test_load_rule_auto_detect_legacy(self, mock_yaml_load, mock_file, legacy_rule_yaml):
        """Test automatic detection and loading of legacy rule."""
        legacy_dict = yaml.safe_load(legacy_rule_yaml)
        legacy_dict.update({
            "id": "legacy-001",
            "author": "Test",
            "created": "2025-01-27",
            "modified": "2025-01-27",
            "version": "1.0.0",
            "query": {"sql": legacy_dict["query"], "type": "sql"},
            "schedule": {"interval": "15m"}
        })
        mock_yaml_load.return_value = legacy_dict

        loader = RuleLoader(rules_path="/tmp/rules")

        with patch.object(loader, '_load_legacy_rule') as mock_load_legacy:
            mock_load_legacy.return_value = Mock(spec=DetectionRule)

            loader.load_rule("/tmp/rules/test.yaml")

            # Should call _load_legacy_rule
            mock_load_legacy.assert_called_once()

    def test_sigma_converter_initialization(self):
        """Test Sigma converter is initialized when available."""
        loader = RuleLoader(rules_path="/tmp/rules", backend_type="athena")

        if SIGMA_AVAILABLE:
            assert loader.sigma_converter is not None
            assert loader.sigma_converter.backend_type == "athena"

    def test_load_sigma_rule_without_converter(self):
        """Test loading Sigma rule fails gracefully without converter."""
        loader = RuleLoader(rules_path="/tmp/rules")
        loader.sigma_converter = None  # Simulate unavailable converter

        sigma_dict = {
            "title": "Test",
            "id": "test-001",
            "logsource": {"product": "aws"},
            "detection": {"selection": {}, "condition": "selection"}
        }

        with pytest.raises(ValueError, match="Sigma converter not available"):
            loader._load_sigma_rule("/tmp/test.yml", sigma_dict)


@pytest.mark.skipif(not SIGMA_AVAILABLE, reason="pySigma not installed")
class TestSigmaRuleFields:
    """Tests for Sigma rule field mapping."""

    def test_sigma_mitre_tags_extraction(self):
        """Test extraction of MITRE ATT&CK tags from Sigma rules."""
        loader = RuleLoader(rules_path="/tmp/rules", backend_type="athena")

        sigma_dict = {
            "title": "Test",
            "id": "test-001",
            "date": "2025-01-27",
            "author": "Test",
            "description": "Test",
            "logsource": {"product": "aws"},
            "detection": {"selection": {}, "condition": "selection"},
            "tags": [
                "attack.credential_access",
                "attack.t1110",
                "attack.t1110.001",
                "custom.tag"
            ]
        }

        with patch.object(loader.sigma_converter, 'convert_rule_to_sql') as mock_convert:
            mock_convert.return_value = "SELECT * FROM test"

            rule = loader._load_sigma_rule("/tmp/test.yml", sigma_dict)

            # Check MITRE tags were extracted
            assert "mitre_attack" in rule.metadata
            mitre_tags = rule.metadata["mitre_attack"]
            assert "CREDENTIAL-ACCESS" in mitre_tags
            assert "T1110" in mitre_tags
            assert "T1110.001" in mitre_tags

    def test_sigma_false_positives_mapping(self):
        """Test false positives mapping from Sigma to legacy."""
        loader = RuleLoader(rules_path="/tmp/rules", backend_type="athena")

        sigma_dict = {
            "title": "Test",
            "id": "test-001",
            "date": "2025-01-27",
            "author": "Test",
            "description": "Test",
            "logsource": {"product": "aws"},
            "detection": {"selection": {}, "condition": "selection"},
            "falsepositives": [
                "Legitimate admin activity",
                "Automated scripts"
            ]
        }

        with patch.object(loader.sigma_converter, 'convert_rule_to_sql') as mock_convert:
            mock_convert.return_value = "SELECT * FROM test"

            rule = loader._load_sigma_rule("/tmp/test.yml", sigma_dict)

            assert "false_positives" in rule.metadata
            assert rule.metadata["false_positives"] == sigma_dict["falsepositives"]

    def test_sigma_references_mapping(self):
        """Test references mapping from Sigma to legacy."""
        loader = RuleLoader(rules_path="/tmp/rules", backend_type="athena")

        sigma_dict = {
            "title": "Test",
            "id": "test-001",
            "date": "2025-01-27",
            "author": "Test",
            "description": "Test",
            "logsource": {"product": "aws"},
            "detection": {"selection": {}, "condition": "selection"},
            "references": [
                "https://attack.mitre.org/techniques/T1110/",
                "https://example.com/doc"
            ]
        }

        with patch.object(loader.sigma_converter, 'convert_rule_to_sql') as mock_convert:
            mock_convert.return_value = "SELECT * FROM test"

            rule = loader._load_sigma_rule("/tmp/test.yml", sigma_dict)

            assert "references" in rule.metadata
            assert rule.metadata["references"] == sigma_dict["references"]


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
