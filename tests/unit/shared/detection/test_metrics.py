"""Unit tests for detection metrics module.

Tests cover:
- Rule metrics calculation
- Portfolio metrics aggregation
- Time period handling
- Trend calculation
- Top contributors analysis
"""

from datetime import datetime, timedelta
from typing import Dict, List, Any

import pytest

from src.shared.detection.metrics import (
    MetricsCalculator,
    MetricsPeriod,
    RuleMetrics,
    PortfolioMetrics,
    AlertStatus,
    calculate_metrics,
    calculate_portfolio,
)


class TestMetricsPeriod:
    """Tests for MetricsPeriod enum."""

    def test_has_expected_values(self):
        """Should have hour, day, week, month periods."""
        assert MetricsPeriod.HOUR.value == "hour"
        assert MetricsPeriod.DAY.value == "day"
        assert MetricsPeriod.WEEK.value == "week"
        assert MetricsPeriod.MONTH.value == "month"

    def test_can_create_from_string(self):
        """Should create enum from string value."""
        assert MetricsPeriod("week") == MetricsPeriod.WEEK
        assert MetricsPeriod("day") == MetricsPeriod.DAY


class TestRuleMetrics:
    """Tests for RuleMetrics dataclass."""

    def test_default_values(self):
        """Should have sensible default values."""
        metrics = RuleMetrics(
            rule_id="test-rule",
            rule_name="Test Rule",
            period=MetricsPeriod.WEEK,
            period_start="2025-12-01T00:00:00Z",
            period_end="2025-12-08T00:00:00Z"
        )

        assert metrics.total_alerts == 0
        assert metrics.false_positive_rate == 0.0
        assert metrics.dismissal_rate == 0.0
        assert metrics.resolution_rate == 0.0
        assert metrics.mean_time_to_acknowledge is None

    def test_to_dict_returns_all_fields(self):
        """Should return all metrics fields in dict."""
        metrics = RuleMetrics(
            rule_id="test-rule",
            rule_name="Test Rule",
            period=MetricsPeriod.WEEK,
            period_start="2025-12-01T00:00:00Z",
            period_end="2025-12-08T00:00:00Z",
            total_alerts=100,
            false_positive_rate=0.15
        )

        result = metrics.to_dict()

        assert result['rule_id'] == "test-rule"
        assert result['rule_name'] == "Test Rule"
        assert result['period'] == "week"
        assert result['total_alerts'] == 100
        assert result['false_positive_rate'] == 0.15

    def test_rounds_rate_values(self):
        """Should round rate values to 4 decimal places."""
        metrics = RuleMetrics(
            rule_id="test-rule",
            rule_name="Test Rule",
            period=MetricsPeriod.WEEK,
            period_start="2025-12-01T00:00:00Z",
            period_end="2025-12-08T00:00:00Z",
            false_positive_rate=0.123456789
        )

        result = metrics.to_dict()

        assert result['false_positive_rate'] == 0.1235


class TestMetricsCalculator:
    """Tests for MetricsCalculator class."""

    @pytest.fixture
    def calculator(self):
        """Create a calculator instance."""
        return MetricsCalculator()

    @pytest.fixture
    def sample_alerts(self) -> List[Dict[str, Any]]:
        """Generate sample alert data."""
        now = datetime.utcnow()
        return [
            {
                "id": "alert-1",
                "timestamp": (now - timedelta(days=1)).isoformat() + "Z",
                "status": "resolved",
                "source_ip": "192.168.1.100",
                "user": "admin",
                "created_at": (now - timedelta(days=1, hours=2)).isoformat() + "Z",
                "acknowledged_at": (now - timedelta(days=1, hours=1)).isoformat() + "Z",
                "resolved_at": (now - timedelta(days=1)).isoformat() + "Z",
            },
            {
                "id": "alert-2",
                "timestamp": (now - timedelta(days=2)).isoformat() + "Z",
                "status": "false_positive",
                "source_ip": "192.168.1.100",
                "user": "service-account",
                "created_at": (now - timedelta(days=2)).isoformat() + "Z",
            },
            {
                "id": "alert-3",
                "timestamp": (now - timedelta(days=3)).isoformat() + "Z",
                "status": "resolved",
                "source_ip": "10.0.0.50",
                "user": "admin",
                "created_at": (now - timedelta(days=3, hours=4)).isoformat() + "Z",
                "acknowledged_at": (now - timedelta(days=3, hours=2)).isoformat() + "Z",
                "resolved_at": (now - timedelta(days=3)).isoformat() + "Z",
            },
            {
                "id": "alert-4",
                "timestamp": (now - timedelta(days=4)).isoformat() + "Z",
                "status": "new",
                "source_ip": "192.168.1.200",
                "user": "developer",
            },
        ]

    def test_calculates_total_alerts(self, calculator, sample_alerts):
        """Should count total alerts correctly."""
        metrics = calculator.calculate_rule_metrics(
            rule_id="test-rule",
            rule_name="Test Rule",
            alerts=sample_alerts
        )

        assert metrics.total_alerts == 4

    def test_returns_zero_alerts_for_empty_list(self, calculator):
        """Should handle empty alert list."""
        metrics = calculator.calculate_rule_metrics(
            rule_id="test-rule",
            rule_name="Test Rule",
            alerts=[]
        )

        assert metrics.total_alerts == 0
        assert metrics.false_positive_rate == 0.0

    def test_calculates_false_positive_rate(self, calculator, sample_alerts):
        """Should calculate FP rate correctly."""
        metrics = calculator.calculate_rule_metrics(
            rule_id="test-rule",
            rule_name="Test Rule",
            alerts=sample_alerts
        )

        # 1 out of 4 alerts is false positive = 25%
        assert metrics.false_positive_rate == 0.25

    def test_calculates_resolution_rate(self, calculator, sample_alerts):
        """Should calculate resolution rate correctly."""
        metrics = calculator.calculate_rule_metrics(
            rule_id="test-rule",
            rule_name="Test Rule",
            alerts=sample_alerts
        )

        # 2 out of 4 alerts have status "resolved" = 50%
        assert metrics.resolution_rate == 0.5

    def test_counts_unique_source_ips(self, calculator, sample_alerts):
        """Should count unique source IPs."""
        metrics = calculator.calculate_rule_metrics(
            rule_id="test-rule",
            rule_name="Test Rule",
            alerts=sample_alerts
        )

        # 192.168.1.100, 10.0.0.50, 192.168.1.200 = 3 unique IPs
        assert metrics.unique_source_ips == 3

    def test_counts_unique_users(self, calculator, sample_alerts):
        """Should count unique users."""
        metrics = calculator.calculate_rule_metrics(
            rule_id="test-rule",
            rule_name="Test Rule",
            alerts=sample_alerts
        )

        # admin, service-account, developer = 3 unique users
        assert metrics.unique_users == 3

    def test_calculates_mean_time_to_acknowledge(self, calculator, sample_alerts):
        """Should calculate MTTA correctly."""
        metrics = calculator.calculate_rule_metrics(
            rule_id="test-rule",
            rule_name="Test Rule",
            alerts=sample_alerts
        )

        # Alert 1: 1 hour, Alert 3: 2 hours = avg 1.5 hours = 90 minutes
        assert metrics.mean_time_to_acknowledge is not None
        assert metrics.mean_time_to_acknowledge == 90.0

    def test_calculates_mean_time_to_resolve(self, calculator, sample_alerts):
        """Should calculate MTTR correctly."""
        metrics = calculator.calculate_rule_metrics(
            rule_id="test-rule",
            rule_name="Test Rule",
            alerts=sample_alerts
        )

        # Alert 1: 2 hours, Alert 3: 4 hours = avg 3 hours = 180 minutes
        assert metrics.mean_time_to_resolve is not None
        assert metrics.mean_time_to_resolve == 180.0

    def test_identifies_top_source_ips(self, calculator, sample_alerts):
        """Should identify most frequent source IPs."""
        metrics = calculator.calculate_rule_metrics(
            rule_id="test-rule",
            rule_name="Test Rule",
            alerts=sample_alerts
        )

        assert len(metrics.top_source_ips) > 0
        # 192.168.1.100 appears twice
        assert metrics.top_source_ips[0]['value'] == "192.168.1.100"
        assert metrics.top_source_ips[0]['count'] == 2

    def test_identifies_top_users(self, calculator, sample_alerts):
        """Should identify most frequent users."""
        metrics = calculator.calculate_rule_metrics(
            rule_id="test-rule",
            rule_name="Test Rule",
            alerts=sample_alerts
        )

        assert len(metrics.top_users) > 0
        # admin appears twice
        assert metrics.top_users[0]['value'] == "admin"
        assert metrics.top_users[0]['count'] == 2

    def test_calculates_trend_when_previous_data_provided(self, calculator, sample_alerts):
        """Should calculate alert count trend."""
        previous_alerts = sample_alerts[:2]  # 2 alerts in previous period

        metrics = calculator.calculate_rule_metrics(
            rule_id="test-rule",
            rule_name="Test Rule",
            alerts=sample_alerts,  # 4 alerts in current period
            previous_period_alerts=previous_alerts
        )

        # 4 vs 2 = 100% increase
        assert metrics.alert_count_trend == 100.0

    def test_handles_alert_status_enum_values(self, calculator):
        """Should handle AlertStatus enum values in alert data."""
        alerts = [
            {"status": AlertStatus.FALSE_POSITIVE.value, "timestamp": datetime.utcnow().isoformat()},
            {"status": AlertStatus.RESOLVED.value, "timestamp": datetime.utcnow().isoformat()},
        ]

        metrics = calculator.calculate_rule_metrics(
            rule_id="test-rule",
            rule_name="Test Rule",
            alerts=alerts
        )

        # AlertStatus.FALSE_POSITIVE.value is "false_positive"
        # AlertStatus.RESOLVED.value is "resolved"
        # So 1 out of 2 for each = 50%
        assert metrics.false_positive_rate == 0.5
        assert metrics.resolution_rate == 0.5


class TestPortfolioMetrics:
    """Tests for PortfolioMetrics calculation."""

    @pytest.fixture
    def calculator(self):
        """Create a calculator instance."""
        return MetricsCalculator()

    @pytest.fixture
    def sample_rules(self) -> List[Dict[str, Any]]:
        """Generate sample rules."""
        return [
            {"id": "rule-1", "name": "Brute Force Detection"},
            {"id": "rule-2", "name": "Data Exfiltration"},
            {"id": "rule-3", "name": "Privilege Escalation"},
        ]

    @pytest.fixture
    def sample_alerts_by_rule(self) -> Dict[str, List[Dict[str, Any]]]:
        """Generate alerts grouped by rule."""
        now = datetime.utcnow()
        return {
            "rule-1": [
                {"status": "resolved", "timestamp": now.isoformat()},
                {"status": "false_positive", "timestamp": now.isoformat()},
            ],
            "rule-2": [
                {"status": "resolved", "timestamp": now.isoformat()},
            ],
            # rule-3 has no alerts
        }

    def test_calculates_total_rules(self, calculator, sample_rules, sample_alerts_by_rule):
        """Should count total rules."""
        portfolio = calculator.calculate_portfolio_metrics(
            rules=sample_rules,
            alerts_by_rule=sample_alerts_by_rule
        )

        assert portfolio.total_rules == 3

    def test_calculates_active_rules(self, calculator, sample_rules, sample_alerts_by_rule):
        """Should count rules that generated alerts."""
        portfolio = calculator.calculate_portfolio_metrics(
            rules=sample_rules,
            alerts_by_rule=sample_alerts_by_rule
        )

        assert portfolio.active_rules == 2  # rule-1 and rule-2

    def test_calculates_zero_alert_rules(self, calculator, sample_rules, sample_alerts_by_rule):
        """Should count rules with no alerts."""
        portfolio = calculator.calculate_portfolio_metrics(
            rules=sample_rules,
            alerts_by_rule=sample_alerts_by_rule
        )

        assert portfolio.zero_alert_rules == 1  # rule-3

    def test_calculates_total_alerts(self, calculator, sample_rules, sample_alerts_by_rule):
        """Should sum all alerts."""
        portfolio = calculator.calculate_portfolio_metrics(
            rules=sample_rules,
            alerts_by_rule=sample_alerts_by_rule
        )

        assert portfolio.total_alerts == 3

    def test_calculates_average_alerts_per_rule(self, calculator, sample_rules, sample_alerts_by_rule):
        """Should calculate average alerts per active rule."""
        portfolio = calculator.calculate_portfolio_metrics(
            rules=sample_rules,
            alerts_by_rule=sample_alerts_by_rule
        )

        # 3 alerts across 2 active rules = 1.5
        assert portfolio.avg_alerts_per_rule == 1.5

    def test_identifies_highest_volume_rules(self, calculator, sample_rules, sample_alerts_by_rule):
        """Should identify rules with most alerts."""
        portfolio = calculator.calculate_portfolio_metrics(
            rules=sample_rules,
            alerts_by_rule=sample_alerts_by_rule
        )

        assert len(portfolio.highest_volume_rules) > 0
        assert portfolio.highest_volume_rules[0]['rule_id'] == "rule-1"
        assert portfolio.highest_volume_rules[0]['alert_count'] == 2

    def test_portfolio_to_dict_returns_all_fields(self, calculator, sample_rules, sample_alerts_by_rule):
        """Should return complete portfolio data as dict."""
        portfolio = calculator.calculate_portfolio_metrics(
            rules=sample_rules,
            alerts_by_rule=sample_alerts_by_rule
        )

        result = portfolio.to_dict()

        assert 'total_rules' in result
        assert 'active_rules' in result
        assert 'zero_alert_rules' in result
        assert 'total_alerts' in result
        assert 'avg_alerts_per_rule' in result
        assert 'highest_volume_rules' in result


class TestConvenienceFunctions:
    """Tests for module-level convenience functions."""

    def test_calculate_metrics_returns_rule_metrics(self):
        """Should return RuleMetrics instance."""
        metrics = calculate_metrics(
            rule_id="test",
            rule_name="Test",
            alerts=[]
        )

        assert isinstance(metrics, RuleMetrics)

    def test_calculate_portfolio_returns_portfolio_metrics(self):
        """Should return PortfolioMetrics instance."""
        portfolio = calculate_portfolio(
            rules=[{"id": "r1", "name": "Rule 1"}],
            alerts_by_rule={}
        )

        assert isinstance(portfolio, PortfolioMetrics)


class TestEdgeCases:
    """Tests for edge cases and error handling."""

    @pytest.fixture
    def calculator(self):
        return MetricsCalculator()

    def test_handles_missing_timestamp_fields(self, calculator):
        """Should handle alerts without timing fields."""
        alerts = [
            {"status": "new"},
            {"status": "resolved"},
        ]

        metrics = calculator.calculate_rule_metrics(
            rule_id="test",
            rule_name="Test",
            alerts=alerts
        )

        assert metrics.total_alerts == 2
        assert metrics.mean_time_to_acknowledge is None
        assert metrics.mean_time_to_resolve is None

    def test_handles_malformed_timestamps(self, calculator):
        """Should handle invalid timestamp formats."""
        alerts = [
            {
                "status": "resolved",
                "timestamp": "not-a-timestamp",
                "created_at": "also-invalid"
            }
        ]

        # Should not raise exception
        metrics = calculator.calculate_rule_metrics(
            rule_id="test",
            rule_name="Test",
            alerts=alerts
        )

        assert metrics.total_alerts == 1

    def test_handles_nested_entity_fields(self, calculator):
        """Should extract values from nested entity objects."""
        alerts = [
            {
                "status": "new",
                "timestamp": datetime.utcnow().isoformat(),
                "source_ip": {"value": "10.0.0.1", "geo": "US"},
                "user": {"name": "john.doe", "department": "IT"}
            }
        ]

        metrics = calculator.calculate_rule_metrics(
            rule_id="test",
            rule_name="Test",
            alerts=alerts
        )

        assert metrics.unique_source_ips == 1
        assert metrics.unique_users == 1

    def test_calculates_median_time_to_resolve(self, calculator):
        """Should calculate median timing metrics."""
        now = datetime.utcnow()
        alerts = [
            {
                "status": "resolved",
                "created_at": (now - timedelta(hours=3)).isoformat(),
                "resolved_at": now.isoformat(),
            },
            {
                "status": "resolved",
                "created_at": (now - timedelta(hours=1)).isoformat(),
                "resolved_at": now.isoformat(),
            },
            {
                "status": "resolved",
                "created_at": (now - timedelta(hours=2)).isoformat(),
                "resolved_at": now.isoformat(),
            },
        ]

        metrics = calculator.calculate_rule_metrics(
            rule_id="test",
            rule_name="Test",
            alerts=alerts
        )

        # Median of [60, 120, 180] = 120 minutes
        assert metrics.median_time_to_resolve == 120.0

    def test_period_bounds_for_all_periods(self, calculator):
        """Should calculate correct period bounds."""
        now = datetime.utcnow()

        for period in MetricsPeriod:
            start, end = calculator._get_period_bounds(now, period)
            assert start < end
            assert end <= now
