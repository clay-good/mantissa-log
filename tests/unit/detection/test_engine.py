"""Unit tests for detection engine."""

from datetime import datetime, timedelta
from unittest.mock import Mock, MagicMock

import pytest

from src.shared.detection.engine import (
    DetectionEngine,
    DetectionResult,
    QueryExecutor,
)
from src.shared.detection.rule import DetectionRule, QueryConfig, ScheduleConfig, ThresholdConfig, AlertConfig
from src.shared.detection.state_manager import InMemoryStateManager


class MockQueryExecutor(QueryExecutor):
    """Mock query executor for testing."""

    def __init__(self, results=None):
        """Initialize with optional predefined results."""
        self.results = results or []
        self.executed_queries = []

    def execute_query(self, query: str):
        """Return predefined results and track query."""
        self.executed_queries.append(query)
        return self.results

    def validate_query(self, query: str) -> bool:
        """Always validate queries as true for testing."""
        return True


@pytest.fixture
def sample_rule():
    """Create a sample detection rule for testing."""
    return DetectionRule(
        id="test-001",
        name="Test Rule",
        description="Test description",
        author="Test",
        created="2025-01-27",
        modified="2025-01-27",
        severity="high",
        query=QueryConfig(
            sql="SELECT * FROM test WHERE timestamp >= '${time_window_start}' AND timestamp < '${time_window_end}'",
            parameters={"threshold": 10}
        ),
        schedule=ScheduleConfig(interval="5m"),
        threshold=ThresholdConfig(field="count", operator=">=", value=1),
        alert=AlertConfig(
            destinations=["slack"],
            title_template="Alert: ${count} events detected",
            body_template="Test alert body"
        )
    )


@pytest.fixture
def mock_rule_loader(sample_rule):
    """Create a mock rule loader."""
    loader = Mock()
    loader.get_rule_by_id.return_value = sample_rule
    loader.get_enabled_rules.return_value = [sample_rule]
    return loader


class TestDetectionEngine:
    """Tests for DetectionEngine class."""

    def test_execute_rule_no_results(self, mock_rule_loader, sample_rule):
        """Test executing a rule that returns no results."""
        executor = MockQueryExecutor(results=[])
        engine = DetectionEngine(mock_rule_loader, executor)

        result = engine.execute_rule(sample_rule)

        assert isinstance(result, DetectionResult)
        assert result.rule_id == "test-001"
        assert not result.triggered
        assert len(result.results) == 0

    def test_execute_rule_below_threshold(self, mock_rule_loader, sample_rule):
        """Test executing a rule where results don't meet threshold."""
        # Threshold is >= 1, but we need count field
        executor = MockQueryExecutor(results=[])
        sample_rule.threshold.value = 5  # Need at least 5 results

        engine = DetectionEngine(mock_rule_loader, executor)
        result = engine.execute_rule(sample_rule)

        assert not result.triggered

    def test_execute_rule_above_threshold(self, mock_rule_loader, sample_rule):
        """Test executing a rule where results meet threshold."""
        mock_results = [
            {"user": "user1", "count": 15},
            {"user": "user2", "count": 20},
        ]
        executor = MockQueryExecutor(results=mock_results)

        engine = DetectionEngine(mock_rule_loader, executor)
        result = engine.execute_rule(sample_rule)

        assert result.triggered
        assert len(result.results) == 2
        assert result.alert_title != ""
        assert result.alert_body != ""

    def test_execute_rule_with_time_window(self, mock_rule_loader, sample_rule):
        """Test that time window is properly substituted in query."""
        executor = MockQueryExecutor(results=[{"count": 1}])
        engine = DetectionEngine(mock_rule_loader, executor)

        start_time = datetime(2025, 1, 27, 10, 0, 0)
        end_time = datetime(2025, 1, 27, 11, 0, 0)

        result = engine.execute_rule(sample_rule, start_time, end_time)

        # Check that query was executed with substituted times
        assert len(executor.executed_queries) == 1
        query = executor.executed_queries[0]
        assert start_time.isoformat() in query
        assert end_time.isoformat() in query

    def test_execute_rule_query_error(self, mock_rule_loader, sample_rule):
        """Test handling of query execution errors."""
        executor = Mock()
        executor.execute_query.side_effect = RuntimeError("Query failed")

        engine = DetectionEngine(mock_rule_loader, executor)
        result = engine.execute_rule(sample_rule)

        assert not result.triggered
        assert result.error is not None
        assert "Query execution failed" in result.error

    def test_execute_all_rules(self, mock_rule_loader):
        """Test executing all enabled rules."""
        executor = MockQueryExecutor(results=[{"count": 1}])
        engine = DetectionEngine(mock_rule_loader, executor)

        results = engine.execute_all_rules()

        assert len(results) == 1
        assert isinstance(results[0], DetectionResult)

    def test_execute_rule_by_id(self, mock_rule_loader, sample_rule):
        """Test executing a specific rule by ID."""
        executor = MockQueryExecutor(results=[{"count": 1}])
        engine = DetectionEngine(mock_rule_loader, executor)

        result = engine.execute_rule_by_id("test-001")

        assert result is not None
        assert result.rule_id == "test-001"

    def test_execute_rule_by_id_not_found(self, mock_rule_loader):
        """Test executing a non-existent rule."""
        mock_rule_loader.get_rule_by_id.return_value = None
        executor = MockQueryExecutor()
        engine = DetectionEngine(mock_rule_loader, executor)

        result = engine.execute_rule_by_id("nonexistent")

        assert result is None

    def test_get_triggered_alerts_no_suppression(self, mock_rule_loader, sample_rule):
        """Test filtering for triggered alerts without suppression."""
        mock_results = [{"count": 10}]
        executor = MockQueryExecutor(results=mock_results)
        engine = DetectionEngine(mock_rule_loader, executor)

        # Execute rule to get results
        result = engine.execute_rule(sample_rule)
        assert result.triggered

        # Filter for triggered alerts
        triggered = engine.get_triggered_alerts([result], check_suppression=False)

        assert len(triggered) == 1
        assert triggered[0].rule_id == "test-001"

    def test_get_triggered_alerts_with_suppression(self, mock_rule_loader, sample_rule):
        """Test alert suppression prevents duplicate alerts."""
        mock_results = [{"count": 10, "user": "testuser", "ip": "1.2.3.4"}]
        executor = MockQueryExecutor(results=mock_results)
        state_manager = InMemoryStateManager()

        # Add suppression to rule
        from src.shared.detection.rule import SuppressionConfig
        sample_rule.suppression = SuppressionConfig(
            key="${user}-${ip}",
            duration="1h"
        )

        engine = DetectionEngine(mock_rule_loader, executor, state_manager)

        # First execution should trigger
        result1 = engine.execute_rule(sample_rule)
        assert result1.triggered

        triggered1 = engine.get_triggered_alerts([result1], check_suppression=True)
        assert len(triggered1) == 1

        # Second execution should be suppressed
        result2 = engine.execute_rule(sample_rule)
        assert result2.triggered

        triggered2 = engine.get_triggered_alerts([result2], check_suppression=True)
        assert len(triggered2) == 0  # Suppressed

    def test_parse_interval(self, mock_rule_loader):
        """Test interval parsing."""
        executor = MockQueryExecutor()
        engine = DetectionEngine(mock_rule_loader, executor)

        # Test minutes
        delta = engine._parse_interval("5m")
        assert delta == timedelta(minutes=5)

        # Test hours
        delta = engine._parse_interval("2h")
        assert delta == timedelta(hours=2)

        # Test days
        delta = engine._parse_interval("1d")
        assert delta == timedelta(days=1)

        # Test seconds
        delta = engine._parse_interval("30s")
        assert delta == timedelta(seconds=30)

    def test_parse_interval_invalid(self, mock_rule_loader):
        """Test invalid interval format."""
        executor = MockQueryExecutor()
        engine = DetectionEngine(mock_rule_loader, executor)

        with pytest.raises(ValueError):
            engine._parse_interval("invalid")

        with pytest.raises(ValueError):
            engine._parse_interval("5x")


class TestDetectionResult:
    """Tests for DetectionResult class."""

    def test_to_dict(self):
        """Test converting DetectionResult to dictionary."""
        timestamp = datetime(2025, 1, 27, 12, 0, 0)
        result = DetectionResult(
            rule_id="test-001",
            rule_name="Test Rule",
            severity="high",
            triggered=True,
            timestamp=timestamp,
            results=[{"count": 5}],
            alert_title="Test Alert",
            alert_body="Test Body",
            suppression_key="test-key"
        )

        result_dict = result.to_dict()

        assert result_dict["rule_id"] == "test-001"
        assert result_dict["rule_name"] == "Test Rule"
        assert result_dict["severity"] == "high"
        assert result_dict["triggered"] is True
        assert result_dict["timestamp"] == timestamp.isoformat()
        assert result_dict["results"] == [{"count": 5}]
        assert result_dict["suppression_key"] == "test-key"


class TestQueryExecutor:
    """Tests for QueryExecutor base class."""

    def test_execute_query_not_implemented(self):
        """Test that base class raises NotImplementedError."""
        executor = QueryExecutor()

        with pytest.raises(NotImplementedError):
            executor.execute_query("SELECT 1")

    def test_validate_query_select_only(self):
        """Test query validation allows SELECT only."""
        executor = QueryExecutor()

        assert executor.validate_query("SELECT * FROM table")
        assert not executor.validate_query("DROP TABLE users")
        assert not executor.validate_query("DELETE FROM logs")
        assert not executor.validate_query("INSERT INTO users VALUES (1)")
        assert not executor.validate_query("UPDATE users SET admin=1")

    def test_validate_query_dangerous_keywords(self):
        """Test validation blocks dangerous keywords."""
        executor = QueryExecutor()

        dangerous_queries = [
            "SELECT * FROM users; DROP TABLE logs;",
            "CREATE TABLE new_table AS SELECT * FROM old_table",
            "ALTER TABLE users ADD admin BOOLEAN",
            "GRANT ALL ON * TO user",
        ]

        for query in dangerous_queries:
            assert not executor.validate_query(query), f"Should block: {query}"
