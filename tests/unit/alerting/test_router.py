"""Unit tests for AlertRouter."""

from datetime import datetime
from unittest.mock import Mock, MagicMock

import pytest

from src.shared.alerting import AlertRouter, RouterConfig, RoutingResult
from src.shared.alerting.router import AlertHandler
from src.shared.detection.alert_generator import Alert


@pytest.fixture
def sample_alert():
    """Create a sample alert for testing."""
    return Alert(
        id="test-alert-123",
        rule_id="test-rule-001",
        rule_name="Test Detection Rule",
        severity="high",
        title="Test Alert",
        description="This is a test alert",
        timestamp=datetime(2025, 1, 27, 12, 0, 0),
        destinations=["slack", "email"],
        results=[{"field": "value"}],
        metadata={"result_count": 1},
        tags=["test"],
        suppression_key="test-key"
    )


@pytest.fixture
def mock_handler():
    """Create a mock alert handler."""
    handler = Mock(spec=AlertHandler)
    handler.send.return_value = True
    handler.validate_config.return_value = True
    return handler


@pytest.fixture
def router_config():
    """Create a router configuration."""
    return RouterConfig(
        default_destinations=["slack"],
        severity_routing={
            "critical": ["slack", "pagerduty"],
            "high": ["slack", "email"]
        },
        enrichment_enabled=False,
        max_concurrent_sends=5
    )


class TestAlertRouter:
    """Tests for AlertRouter class."""

    def test_route_alert_success(self, sample_alert, mock_handler, router_config):
        """Test successfully routing an alert."""
        handlers = {"slack": mock_handler, "email": mock_handler}
        router = AlertRouter(handlers, router_config)

        result = router.route_alert(sample_alert)

        assert result.success
        assert result.alert_id == "test-alert-123"
        assert len(result.destinations_succeeded) == 2
        assert "slack" in result.destinations_succeeded
        assert "email" in result.destinations_succeeded
        assert len(result.destinations_failed) == 0

        # Verify handler was called twice
        assert mock_handler.send.call_count == 2

    def test_route_alert_partial_failure(self, sample_alert, router_config):
        """Test routing when one handler fails."""
        success_handler = Mock(spec=AlertHandler)
        success_handler.send.return_value = True
        success_handler.validate_config.return_value = True

        failure_handler = Mock(spec=AlertHandler)
        failure_handler.send.return_value = False
        failure_handler.validate_config.return_value = True

        handlers = {
            "slack": success_handler,
            "email": failure_handler
        }
        router = AlertRouter(handlers, router_config)

        result = router.route_alert(sample_alert)

        assert result.success  # At least one succeeded
        assert len(result.destinations_succeeded) == 1
        assert len(result.destinations_failed) == 1
        assert "slack" in result.destinations_succeeded
        assert "email" in result.destinations_failed

    def test_route_alert_handler_exception(self):
        """Test routing when handler raises exception."""
        # Create alert with only slack destination
        alert = Alert(
            id="test-alert-123",
            rule_id="test-rule-001",
            rule_name="Test Detection Rule",
            severity="high",
            title="Test Alert",
            description="This is a test alert",
            timestamp=datetime(2025, 1, 27, 12, 0, 0),
            destinations=["slack"],  # Only slack
            results=[{"field": "value"}],
            metadata={"result_count": 1},
            tags=["test"],
            suppression_key="test-key"
        )

        error_handler = Mock(spec=AlertHandler)
        error_handler.send.side_effect = Exception("Connection error")
        error_handler.validate_config.return_value = True

        # Use config with only slack routing
        config = RouterConfig(
            default_destinations=["slack"],
            severity_routing={"high": ["slack"]},  # Only slack for high severity
            enrichment_enabled=False,
            max_concurrent_sends=5
        )

        handlers = {"slack": error_handler}
        router = AlertRouter(handlers, config)

        result = router.route_alert(alert)

        assert not result.success
        assert len(result.destinations_failed) == 1
        assert "Connection error" in result.destinations_failed["slack"]

    def test_route_alert_missing_handler(self, sample_alert, router_config):
        """Test routing to non-existent handler."""
        handlers = {}
        router = AlertRouter(handlers, router_config)

        result = router.route_alert(sample_alert)

        assert not result.success
        assert len(result.destinations_failed) == 2
        assert "Handler not found" in result.destinations_failed["slack"]

    def test_route_alert_with_enrichment(self, sample_alert, router_config, mock_handler):
        """Test routing with alert enrichment."""
        mock_enricher = Mock()
        mock_enricher.enrich.return_value = sample_alert

        router_config.enrichment_enabled = True
        handlers = {"slack": mock_handler}
        router = AlertRouter(handlers, router_config, enricher=mock_enricher)

        result = router.route_alert(sample_alert)

        assert result.success
        mock_enricher.enrich.assert_called_once_with(sample_alert)

    def test_route_alerts_multiple(self, sample_alert, mock_handler, router_config):
        """Test routing multiple alerts."""
        handlers = {"slack": mock_handler}
        router = AlertRouter(handlers, router_config)

        alerts = [sample_alert] * 3

        results = router.route_alerts(alerts)

        assert len(results) == 3
        assert all(r.success for r in results)

    def test_determine_destinations_from_alert(self, sample_alert, router_config):
        """Test destination determination from alert."""
        handlers = {}
        router = AlertRouter(handlers, router_config)

        # Alert has specific destinations
        destinations = router._determine_destinations(sample_alert)

        assert "slack" in destinations
        assert "email" in destinations

    def test_determine_destinations_from_severity(self, sample_alert, router_config):
        """Test destination determination from severity."""
        handlers = {}
        router = AlertRouter(handlers, router_config)

        # Alert with no specific destinations, use severity routing
        sample_alert.destinations = []

        destinations = router._determine_destinations(sample_alert)

        # Should use severity routing for "high"
        assert "slack" in destinations
        assert "email" in destinations

    def test_determine_destinations_default(self, router_config):
        """Test default destination when nothing else specified."""
        handlers = {}
        router = AlertRouter(handlers, router_config)

        # Alert with unknown severity and no destinations
        alert = Alert(
            id="test",
            rule_id="test",
            rule_name="test",
            severity="unknown",
            title="test",
            description="test",
            timestamp=datetime.utcnow(),
            destinations=[]
        )

        destinations = router._determine_destinations(alert)

        # Should use default destinations
        assert "slack" in destinations

    def test_register_handler(self, mock_handler, router_config):
        """Test registering a new handler."""
        router = AlertRouter({}, router_config)

        router.register_handler("new_handler", mock_handler)

        assert "new_handler" in router.handlers
        assert router.get_handler("new_handler") == mock_handler

    def test_unregister_handler(self, mock_handler, router_config):
        """Test unregistering a handler."""
        handlers = {"test": mock_handler}
        router = AlertRouter(handlers, router_config)

        router.unregister_handler("test")

        assert "test" not in router.handlers

    def test_list_handlers(self, mock_handler, router_config):
        """Test listing registered handlers."""
        handlers = {"slack": mock_handler, "email": mock_handler}
        router = AlertRouter(handlers, router_config)

        handler_names = router.list_handlers()

        assert len(handler_names) == 2
        assert "slack" in handler_names
        assert "email" in handler_names


class TestRouterConfig:
    """Tests for RouterConfig class."""

    def test_from_dict(self):
        """Test creating RouterConfig from dictionary."""
        config_dict = {
            "default_destinations": ["slack"],
            "severity_routing": {"critical": ["pagerduty"]},
            "enrichment_enabled": True,
            "max_concurrent_sends": 10
        }

        config = RouterConfig.from_dict(config_dict)

        assert config.default_destinations == ["slack"]
        assert config.severity_routing == {"critical": ["pagerduty"]}
        assert config.enrichment_enabled is True
        assert config.max_concurrent_sends == 10

    def test_from_dict_with_defaults(self):
        """Test creating RouterConfig with missing fields."""
        config_dict = {}

        config = RouterConfig.from_dict(config_dict)

        assert config.default_destinations == []
        assert config.severity_routing == {}
        assert config.enrichment_enabled is True
        assert config.max_concurrent_sends == 5


class TestRoutingResult:
    """Tests for RoutingResult class."""

    def test_success_property(self):
        """Test success property."""
        result = RoutingResult(
            alert_id="test",
            destinations_succeeded=["slack"]
        )

        assert result.success is True

        result2 = RoutingResult(
            alert_id="test",
            destinations_succeeded=[]
        )

        assert result2.success is False

    def test_total_destinations(self):
        """Test total_destinations property."""
        result = RoutingResult(
            alert_id="test",
            destinations_attempted=["slack", "email", "pagerduty"]
        )

        assert result.total_destinations == 3

    def test_to_dict(self):
        """Test converting result to dictionary."""
        result = RoutingResult(
            alert_id="test-123",
            destinations_attempted=["slack", "email"],
            destinations_succeeded=["slack"],
            destinations_failed={"email": "Connection error"}
        )

        result_dict = result.to_dict()

        assert result_dict["alert_id"] == "test-123"
        assert result_dict["destinations_attempted"] == ["slack", "email"]
        assert result_dict["destinations_succeeded"] == ["slack"]
        assert result_dict["destinations_failed"] == {"email": "Connection error"}
        assert result_dict["success"] is True
        assert result_dict["total_destinations"] == 2
