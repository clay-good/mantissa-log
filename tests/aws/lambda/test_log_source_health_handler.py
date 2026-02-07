"""Tests for the log source health Lambda handler.

Covers lambda_handler (5-min scheduled checks) and baseline_handler
(daily baseline computation) with mocked dependencies.
"""

import importlib
import json
import os
import sys
import pytest
from datetime import datetime, timezone
from unittest.mock import MagicMock, patch, ANY

# Add the lambda source directory to sys.path so we can import the handler
_LAMBDA_DIR = os.path.join(
    os.path.dirname(__file__), "../../../src/aws/lambda"
)
if _LAMBDA_DIR not in sys.path:
    sys.path.insert(0, os.path.abspath(_LAMBDA_DIR))

from shared.health.health_check_engine import HealthCheckResult
from shared.health.health_alerting import HealthAlertOutcome
from shared.health.log_source_health import LogSourceStatus

# Import the handler module using importlib since "lambda" is a reserved keyword
import log_source_health_handler as handler_module


# ======================================================================
# lambda_handler Tests
# ======================================================================


class TestLambdaHandler:
    """Test the main lambda_handler for scheduled health checks."""

    @pytest.fixture(autouse=True)
    def setup_env(self, monkeypatch):
        """Set environment variables for handler."""
        monkeypatch.setenv("LOG_SOURCE_HEALTH_TABLE", "test-health-table")
        monkeypatch.setenv("ATHENA_DATABASE", "test_db")
        monkeypatch.setenv("ATHENA_OUTPUT_LOCATION", "s3://test-bucket/output/")
        monkeypatch.setenv("AWS_REGION", "us-east-1")
        monkeypatch.setenv("TENANT_ID", "test-tenant")
        monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
        monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
        monkeypatch.setenv("AWS_DEFAULT_REGION", "us-east-1")

    @patch("log_source_health_handler._build_alert_router")
    @patch("log_source_health_handler._initialize_components")
    def test_health_check_success(self, mock_init, mock_router):
        """Successful health check returns 200 with summary."""
        mock_store = MagicMock()
        mock_executor = MagicMock()
        mock_init.return_value = (mock_store, mock_executor, {})
        mock_router.return_value = None

        mock_store.get_all_states.return_value = []

        event = {"source": "aws.events"}
        context = MagicMock()

        with patch("shared.health.HealthCheckEngine") as MockEngine:
            engine_instance = MockEngine.return_value
            engine_instance.check_all_sources.return_value = [
                HealthCheckResult(
                    source_type="okta",
                    old_status=LogSourceStatus.UNKNOWN,
                    new_status=LogSourceStatus.HEALTHY,
                    should_alert=False,
                    detail_message="OK",
                ),
            ]

            with patch("shared.health.HealthAlertGenerator") as MockAlertGen:
                alert_gen = MockAlertGen.return_value
                alert_gen.generate_health_alert.return_value = HealthAlertOutcome(
                    suppressed=True,
                    suppression_reason="Not flagged",
                )

                response = handler_module.lambda_handler(event, context)

        assert response["statusCode"] == 200
        body = json.loads(response["body"])
        assert body["tenant_id"] == "test-tenant"
        assert body["sources_checked"] == 1

    @patch("log_source_health_handler._initialize_components")
    def test_dispatches_to_baseline_handler(self, mock_init):
        """Event with action=compute_baselines routes to baseline_handler."""
        mock_store = MagicMock()
        mock_executor = MagicMock()
        mock_init.return_value = (mock_store, mock_executor, {})

        event = {"action": "compute_baselines"}
        context = MagicMock()

        with patch("shared.health.HealthCheckEngine") as MockEngine:
            engine_instance = MockEngine.return_value
            engine_instance.compute_baselines.return_value = {
                "okta": (500.0, 50.0),
            }

            response = handler_module.lambda_handler(event, context)

        assert response["statusCode"] == 200
        body = json.loads(response["body"])
        assert body["baselines_computed"] == 1
        assert "okta" in body["baselines"]

    @patch("log_source_health_handler._initialize_components")
    def test_fatal_error_returns_500(self, mock_init):
        """Fatal error in handler returns 500."""
        mock_init.side_effect = Exception("DynamoDB unavailable")

        event = {"source": "aws.events"}
        context = MagicMock()

        response = handler_module.lambda_handler(event, context)

        assert response["statusCode"] == 500
        body = json.loads(response["body"])
        assert "error" in body


# ======================================================================
# baseline_handler Tests
# ======================================================================


class TestBaselineHandler:
    """Test the baseline_handler for daily baseline computation."""

    @pytest.fixture(autouse=True)
    def setup_env(self, monkeypatch):
        monkeypatch.setenv("LOG_SOURCE_HEALTH_TABLE", "test-health-table")
        monkeypatch.setenv("ATHENA_DATABASE", "test_db")
        monkeypatch.setenv("ATHENA_OUTPUT_LOCATION", "s3://test-bucket/output/")
        monkeypatch.setenv("AWS_REGION", "us-east-1")
        monkeypatch.setenv("TENANT_ID", "test-tenant")
        monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
        monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
        monkeypatch.setenv("AWS_DEFAULT_REGION", "us-east-1")

    @patch("log_source_health_handler._initialize_components")
    def test_baseline_computation(self, mock_init):
        """Baseline handler computes and returns baselines."""
        mock_store = MagicMock()
        mock_executor = MagicMock()
        mock_init.return_value = (mock_store, mock_executor, {})

        event = {"action": "compute_baselines"}
        context = MagicMock()

        with patch("shared.health.HealthCheckEngine") as MockEngine:
            engine_instance = MockEngine.return_value
            engine_instance.compute_baselines.return_value = {
                "okta": (500.0, 50.0),
                "slack": (200.0, 25.0),
            }

            response = handler_module.baseline_handler(event, context)

        assert response["statusCode"] == 200
        body = json.loads(response["body"])
        assert body["baselines_computed"] == 2
        assert body["baselines"]["okta"]["mean"] == 500.0
        assert body["baselines"]["slack"]["stddev"] == 25.0

    @patch("log_source_health_handler._initialize_components")
    def test_baseline_error_returns_500(self, mock_init):
        """Fatal error in baseline handler returns 500."""
        mock_init.side_effect = Exception("Athena unavailable")

        event = {"action": "compute_baselines"}
        context = MagicMock()

        response = handler_module.baseline_handler(event, context)

        assert response["statusCode"] == 500
        body = json.loads(response["body"])
        assert "error" in body


# ======================================================================
# Configuration Tests
# ======================================================================


class TestConfiguration:
    """Test configuration loading and defaults."""

    @pytest.fixture(autouse=True)
    def setup_env(self, monkeypatch):
        monkeypatch.setenv("AWS_ACCESS_KEY_ID", "testing")
        monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "testing")
        monkeypatch.setenv("AWS_DEFAULT_REGION", "us-east-1")

    def test_get_config_defaults(self, monkeypatch):
        """_get_config returns sensible defaults."""
        monkeypatch.delenv("LOG_SOURCE_HEALTH_TABLE", raising=False)
        monkeypatch.delenv("TENANT_ID", raising=False)

        config = handler_module._get_config()
        assert config["log_source_health_table"] == "mantissa-log-source-health"
        assert config["tenant_id"] == "default"
        assert config["athena_database"] == "mantissa_logs"

    def test_get_config_from_env(self, monkeypatch):
        """_get_config reads from environment."""
        monkeypatch.setenv("LOG_SOURCE_HEALTH_TABLE", "custom-table")
        monkeypatch.setenv("TENANT_ID", "custom-tenant")

        config = handler_module._get_config()
        assert config["log_source_health_table"] == "custom-table"
        assert config["tenant_id"] == "custom-tenant"

    def test_load_health_configs_no_bucket(self):
        """No S3 bucket → empty config map."""
        result = handler_module._load_health_configs({
            "health_config_s3_bucket": None,
            "health_config_s3_key": "config/health.json",
            "aws_region": "us-east-1",
        })
        assert result == {}

    def test_get_default_destinations(self, monkeypatch):
        """Default destinations parsed from comma-separated env var."""
        monkeypatch.setenv("DEFAULT_DESTINATIONS", "slack,pagerduty,email")

        dests = handler_module._get_default_destinations()
        assert dests == ["slack", "pagerduty", "email"]

    def test_get_default_destinations_default(self, monkeypatch):
        """Default destinations defaults to slack."""
        monkeypatch.delenv("DEFAULT_DESTINATIONS", raising=False)

        dests = handler_module._get_default_destinations()
        assert dests == ["slack"]

    def test_get_severity_routing_default(self, monkeypatch):
        """Default severity routing has all levels."""
        monkeypatch.delenv("SEVERITY_ROUTING", raising=False)

        routing = handler_module._get_severity_routing()
        assert "critical" in routing
        assert "pagerduty" in routing["critical"]
        assert "low" in routing

    def test_get_severity_routing_from_env(self, monkeypatch):
        """Custom severity routing from environment JSON."""
        custom = json.dumps({"critical": ["pagerduty"], "high": ["slack"]})
        monkeypatch.setenv("SEVERITY_ROUTING", custom)

        routing = handler_module._get_severity_routing()
        assert routing == {"critical": ["pagerduty"], "high": ["slack"]}

    def test_build_response(self):
        """_build_response creates correct structure."""
        response = handler_module._build_response(200, {"key": "value"})
        assert response["statusCode"] == 200
        body = json.loads(response["body"])
        assert body["key"] == "value"
