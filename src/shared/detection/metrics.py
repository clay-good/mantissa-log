"""
Detection Rule Performance Metrics.

Tracks and reports on detection rule performance including:
- Alert counts over time
- Unique entities (IPs, users, assets)
- Dismissal/resolution rates
- False positive rates
- Mean time to acknowledge/resolve
"""

import logging
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional
from collections import Counter
from enum import Enum

logger = logging.getLogger(__name__)


class MetricsPeriod(Enum):
    """Time periods for metrics aggregation."""
    HOUR = "hour"
    DAY = "day"
    WEEK = "week"
    MONTH = "month"


class AlertStatus(Enum):
    """Alert status values."""
    NEW = "new"
    ACKNOWLEDGED = "acknowledged"
    INVESTIGATING = "investigating"
    RESOLVED = "resolved"
    FALSE_POSITIVE = "false_positive"
    DISMISSED = "dismissed"


@dataclass
class RuleMetrics:
    """Performance metrics for a single detection rule."""

    rule_id: str
    rule_name: str
    period: MetricsPeriod
    period_start: str
    period_end: str

    # Alert counts
    total_alerts: int = 0
    alerts_by_status: Dict[str, int] = field(default_factory=dict)

    # Unique entities
    unique_source_ips: int = 0
    unique_users: int = 0
    unique_assets: int = 0

    # Rates
    false_positive_rate: float = 0.0
    dismissal_rate: float = 0.0
    resolution_rate: float = 0.0

    # Timing metrics (in minutes)
    mean_time_to_acknowledge: Optional[float] = None
    mean_time_to_resolve: Optional[float] = None
    median_time_to_acknowledge: Optional[float] = None
    median_time_to_resolve: Optional[float] = None

    # Trends
    alert_count_trend: float = 0.0  # Percentage change from previous period
    fp_rate_trend: float = 0.0

    # Top contributors
    top_source_ips: List[Dict[str, Any]] = field(default_factory=list)
    top_users: List[Dict[str, Any]] = field(default_factory=list)
    top_assets: List[Dict[str, Any]] = field(default_factory=list)

    # Time distribution
    hourly_distribution: Dict[int, int] = field(default_factory=dict)
    daily_distribution: Dict[str, int] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "rule_id": self.rule_id,
            "rule_name": self.rule_name,
            "period": self.period.value,
            "period_start": self.period_start,
            "period_end": self.period_end,
            "total_alerts": self.total_alerts,
            "alerts_by_status": self.alerts_by_status,
            "unique_source_ips": self.unique_source_ips,
            "unique_users": self.unique_users,
            "unique_assets": self.unique_assets,
            "false_positive_rate": round(self.false_positive_rate, 4),
            "dismissal_rate": round(self.dismissal_rate, 4),
            "resolution_rate": round(self.resolution_rate, 4),
            "mean_time_to_acknowledge": self.mean_time_to_acknowledge,
            "mean_time_to_resolve": self.mean_time_to_resolve,
            "median_time_to_acknowledge": self.median_time_to_acknowledge,
            "median_time_to_resolve": self.median_time_to_resolve,
            "alert_count_trend": round(self.alert_count_trend, 2),
            "fp_rate_trend": round(self.fp_rate_trend, 2),
            "top_source_ips": self.top_source_ips,
            "top_users": self.top_users,
            "top_assets": self.top_assets,
            "hourly_distribution": self.hourly_distribution,
            "daily_distribution": self.daily_distribution,
        }


@dataclass
class PortfolioMetrics:
    """Aggregated metrics across all detection rules."""

    period: MetricsPeriod
    period_start: str
    period_end: str

    # Counts
    total_rules: int = 0
    active_rules: int = 0  # Rules that generated alerts
    zero_alert_rules: int = 0
    total_alerts: int = 0

    # Averages across rules
    avg_alerts_per_rule: float = 0.0
    avg_false_positive_rate: float = 0.0
    avg_resolution_rate: float = 0.0

    # Timing
    avg_time_to_acknowledge: Optional[float] = None
    avg_time_to_resolve: Optional[float] = None

    # Top performing/problematic rules
    highest_volume_rules: List[Dict[str, Any]] = field(default_factory=list)
    highest_fp_rate_rules: List[Dict[str, Any]] = field(default_factory=list)
    longest_resolution_rules: List[Dict[str, Any]] = field(default_factory=list)
    zero_alert_rule_ids: List[str] = field(default_factory=list)

    # Trends
    total_alert_trend: float = 0.0
    avg_fp_trend: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "period": self.period.value,
            "period_start": self.period_start,
            "period_end": self.period_end,
            "total_rules": self.total_rules,
            "active_rules": self.active_rules,
            "zero_alert_rules": self.zero_alert_rules,
            "total_alerts": self.total_alerts,
            "avg_alerts_per_rule": round(self.avg_alerts_per_rule, 2),
            "avg_false_positive_rate": round(self.avg_false_positive_rate, 4),
            "avg_resolution_rate": round(self.avg_resolution_rate, 4),
            "avg_time_to_acknowledge": self.avg_time_to_acknowledge,
            "avg_time_to_resolve": self.avg_time_to_resolve,
            "highest_volume_rules": self.highest_volume_rules,
            "highest_fp_rate_rules": self.highest_fp_rate_rules,
            "longest_resolution_rules": self.longest_resolution_rules,
            "zero_alert_rule_ids": self.zero_alert_rule_ids,
            "total_alert_trend": round(self.total_alert_trend, 2),
            "avg_fp_trend": round(self.avg_fp_trend, 2),
        }


class MetricsCalculator:
    """Calculates detection rule performance metrics."""

    def __init__(self):
        """Initialize metrics calculator."""
        pass

    def calculate_rule_metrics(
        self,
        rule_id: str,
        rule_name: str,
        alerts: List[Dict[str, Any]],
        period: MetricsPeriod = MetricsPeriod.WEEK,
        previous_period_alerts: Optional[List[Dict[str, Any]]] = None
    ) -> RuleMetrics:
        """
        Calculate metrics for a single rule.

        Args:
            rule_id: Rule identifier
            rule_name: Rule name
            alerts: List of alerts from the rule
            period: Time period for aggregation
            previous_period_alerts: Alerts from previous period for trend calculation

        Returns:
            RuleMetrics
        """
        now = datetime.utcnow()
        period_start, period_end = self._get_period_bounds(now, period)

        metrics = RuleMetrics(
            rule_id=rule_id,
            rule_name=rule_name,
            period=period,
            period_start=period_start.isoformat() + "Z",
            period_end=period_end.isoformat() + "Z",
            total_alerts=len(alerts)
        )

        if not alerts:
            return metrics

        # Count by status
        status_counts = Counter()
        source_ips = set()
        users = set()
        assets = set()
        acknowledgement_times = []
        resolution_times = []
        hourly_counts = Counter()
        daily_counts = Counter()

        for alert in alerts:
            # Status tracking
            status = alert.get("status", "new")
            status_counts[status] += 1

            # Entity extraction
            source_ip = self._extract_field(alert, ["source_ip", "sourceIPAddress", "srcaddr"])
            if source_ip:
                source_ips.add(source_ip)

            user = self._extract_field(alert, ["user", "userName", "principal"])
            if user:
                users.add(user)

            asset = self._extract_field(alert, ["asset_id", "resource_id", "instance_id"])
            if asset:
                assets.add(asset)

            # Timing calculation
            created_at = alert.get("created_at") or alert.get("timestamp")
            acknowledged_at = alert.get("acknowledged_at")
            resolved_at = alert.get("resolved_at")

            if created_at and acknowledged_at:
                tta = self._calculate_time_diff_minutes(created_at, acknowledged_at)
                if tta is not None and tta >= 0:
                    acknowledgement_times.append(tta)

            if created_at and resolved_at:
                ttr = self._calculate_time_diff_minutes(created_at, resolved_at)
                if ttr is not None and ttr >= 0:
                    resolution_times.append(ttr)

            # Time distribution
            timestamp = alert.get("timestamp") or alert.get("created_at")
            if timestamp:
                try:
                    dt = datetime.fromisoformat(timestamp.replace("Z", ""))
                    hourly_counts[dt.hour] += 1
                    daily_counts[dt.strftime("%A")] += 1
                except (ValueError, TypeError):
                    pass

        # Populate metrics
        metrics.alerts_by_status = dict(status_counts)
        metrics.unique_source_ips = len(source_ips)
        metrics.unique_users = len(users)
        metrics.unique_assets = len(assets)

        # Calculate rates
        # Note: We check both literal strings and enum values for compatibility
        # but since AlertStatus.FALSE_POSITIVE.value == "false_positive", they're the same key
        total = len(alerts)
        fp_count = status_counts.get("false_positive", 0)
        dismissed_count = status_counts.get("dismissed", 0)
        resolved_count = status_counts.get("resolved", 0)

        metrics.false_positive_rate = fp_count / total if total > 0 else 0.0
        metrics.dismissal_rate = dismissed_count / total if total > 0 else 0.0
        metrics.resolution_rate = resolved_count / total if total > 0 else 0.0

        # Timing metrics
        if acknowledgement_times:
            metrics.mean_time_to_acknowledge = round(sum(acknowledgement_times) / len(acknowledgement_times), 2)
            metrics.median_time_to_acknowledge = round(self._median(acknowledgement_times), 2)

        if resolution_times:
            metrics.mean_time_to_resolve = round(sum(resolution_times) / len(resolution_times), 2)
            metrics.median_time_to_resolve = round(self._median(resolution_times), 2)

        # Top contributors
        metrics.top_source_ips = self._get_top_contributors(alerts, ["source_ip", "sourceIPAddress", "srcaddr"], 5)
        metrics.top_users = self._get_top_contributors(alerts, ["user", "userName", "principal"], 5)
        metrics.top_assets = self._get_top_contributors(alerts, ["asset_id", "resource_id", "instance_id"], 5)

        # Time distribution
        metrics.hourly_distribution = dict(hourly_counts)
        metrics.daily_distribution = dict(daily_counts)

        # Calculate trends
        if previous_period_alerts is not None:
            prev_count = len(previous_period_alerts)
            if prev_count > 0:
                metrics.alert_count_trend = ((total - prev_count) / prev_count) * 100

            # Previous FP rate
            prev_fp_count = sum(
                1 for a in previous_period_alerts
                if a.get("status") in ["false_positive", AlertStatus.FALSE_POSITIVE.value]
            )
            prev_fp_rate = prev_fp_count / prev_count if prev_count > 0 else 0.0
            if prev_fp_rate > 0:
                metrics.fp_rate_trend = ((metrics.false_positive_rate - prev_fp_rate) / prev_fp_rate) * 100

        return metrics

    def calculate_portfolio_metrics(
        self,
        rules: List[Dict[str, Any]],
        alerts_by_rule: Dict[str, List[Dict[str, Any]]],
        period: MetricsPeriod = MetricsPeriod.WEEK,
        previous_alerts_by_rule: Optional[Dict[str, List[Dict[str, Any]]]] = None
    ) -> PortfolioMetrics:
        """
        Calculate aggregate metrics across all rules.

        Args:
            rules: List of all detection rules
            alerts_by_rule: Dictionary mapping rule_id to alerts
            period: Time period for aggregation
            previous_alerts_by_rule: Previous period alerts for trends

        Returns:
            PortfolioMetrics
        """
        now = datetime.utcnow()
        period_start, period_end = self._get_period_bounds(now, period)

        metrics = PortfolioMetrics(
            period=period,
            period_start=period_start.isoformat() + "Z",
            period_end=period_end.isoformat() + "Z",
            total_rules=len(rules)
        )

        # Calculate per-rule metrics
        rule_metrics_list = []
        zero_alert_rules = []

        for rule in rules:
            rule_id = rule.get("id", rule.get("rule_id", ""))
            rule_name = rule.get("name", rule.get("title", rule_id))
            alerts = alerts_by_rule.get(rule_id, [])

            prev_alerts = None
            if previous_alerts_by_rule:
                prev_alerts = previous_alerts_by_rule.get(rule_id, [])

            rule_metrics = self.calculate_rule_metrics(
                rule_id=rule_id,
                rule_name=rule_name,
                alerts=alerts,
                period=period,
                previous_period_alerts=prev_alerts
            )

            rule_metrics_list.append(rule_metrics)

            if rule_metrics.total_alerts == 0:
                zero_alert_rules.append(rule_id)

        # Aggregate metrics
        active_rules = [m for m in rule_metrics_list if m.total_alerts > 0]
        metrics.active_rules = len(active_rules)
        metrics.zero_alert_rules = len(zero_alert_rules)
        metrics.zero_alert_rule_ids = zero_alert_rules[:20]  # Limit for response size
        metrics.total_alerts = sum(m.total_alerts for m in rule_metrics_list)

        if active_rules:
            metrics.avg_alerts_per_rule = metrics.total_alerts / len(active_rules)
            metrics.avg_false_positive_rate = sum(m.false_positive_rate for m in active_rules) / len(active_rules)
            metrics.avg_resolution_rate = sum(m.resolution_rate for m in active_rules) / len(active_rules)

            # Average timing (only from rules with data)
            ack_times = [m.mean_time_to_acknowledge for m in active_rules if m.mean_time_to_acknowledge is not None]
            res_times = [m.mean_time_to_resolve for m in active_rules if m.mean_time_to_resolve is not None]

            if ack_times:
                metrics.avg_time_to_acknowledge = round(sum(ack_times) / len(ack_times), 2)
            if res_times:
                metrics.avg_time_to_resolve = round(sum(res_times) / len(res_times), 2)

        # Top rules
        sorted_by_volume = sorted(rule_metrics_list, key=lambda m: m.total_alerts, reverse=True)
        metrics.highest_volume_rules = [
            {"rule_id": m.rule_id, "rule_name": m.rule_name, "alert_count": m.total_alerts}
            for m in sorted_by_volume[:5]
        ]

        # Highest FP rate (only rules with > 10 alerts)
        rules_with_alerts = [m for m in rule_metrics_list if m.total_alerts >= 10]
        sorted_by_fp = sorted(rules_with_alerts, key=lambda m: m.false_positive_rate, reverse=True)
        metrics.highest_fp_rate_rules = [
            {"rule_id": m.rule_id, "rule_name": m.rule_name, "fp_rate": round(m.false_positive_rate, 4), "alert_count": m.total_alerts}
            for m in sorted_by_fp[:5]
        ]

        # Longest resolution time
        rules_with_resolution = [m for m in rule_metrics_list if m.mean_time_to_resolve is not None]
        sorted_by_resolution = sorted(rules_with_resolution, key=lambda m: m.mean_time_to_resolve or 0, reverse=True)
        metrics.longest_resolution_rules = [
            {"rule_id": m.rule_id, "rule_name": m.rule_name, "mean_time_to_resolve": m.mean_time_to_resolve}
            for m in sorted_by_resolution[:5]
        ]

        # Trends
        if previous_alerts_by_rule:
            prev_total = sum(len(alerts) for alerts in previous_alerts_by_rule.values())
            if prev_total > 0:
                metrics.total_alert_trend = ((metrics.total_alerts - prev_total) / prev_total) * 100

        return metrics

    def _get_period_bounds(self, now: datetime, period: MetricsPeriod) -> tuple:
        """Get start and end datetime for a period."""
        if period == MetricsPeriod.HOUR:
            start = now.replace(minute=0, second=0, microsecond=0) - timedelta(hours=1)
            end = now.replace(minute=0, second=0, microsecond=0)
        elif period == MetricsPeriod.DAY:
            start = now.replace(hour=0, minute=0, second=0, microsecond=0) - timedelta(days=1)
            end = now.replace(hour=0, minute=0, second=0, microsecond=0)
        elif period == MetricsPeriod.WEEK:
            start = now.replace(hour=0, minute=0, second=0, microsecond=0) - timedelta(days=7)
            end = now.replace(hour=0, minute=0, second=0, microsecond=0)
        else:  # MONTH
            start = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0) - timedelta(days=30)
            end = now.replace(hour=0, minute=0, second=0, microsecond=0)

        return start, end

    def _extract_field(self, alert: Dict[str, Any], field_names: List[str]) -> Optional[str]:
        """Extract a field value from alert using multiple possible field names."""
        for field_name in field_names:
            if field_name in alert and alert[field_name]:
                value = alert[field_name]
                if isinstance(value, dict):
                    return value.get("value") or value.get("name") or str(value)
                return str(value)
        return None

    def _calculate_time_diff_minutes(self, start: str, end: str) -> Optional[float]:
        """Calculate time difference in minutes between two ISO timestamps."""
        try:
            start_dt = datetime.fromisoformat(start.replace("Z", ""))
            end_dt = datetime.fromisoformat(end.replace("Z", ""))
            diff = end_dt - start_dt
            return diff.total_seconds() / 60
        except (ValueError, TypeError):
            return None

    def _median(self, values: List[float]) -> float:
        """Calculate median of a list of values."""
        sorted_values = sorted(values)
        n = len(sorted_values)
        if n == 0:
            return 0.0
        mid = n // 2
        if n % 2 == 0:
            return (sorted_values[mid - 1] + sorted_values[mid]) / 2
        return sorted_values[mid]

    def _get_top_contributors(
        self,
        alerts: List[Dict[str, Any]],
        field_names: List[str],
        limit: int = 5
    ) -> List[Dict[str, Any]]:
        """Get top contributors for a field."""
        counts = Counter()

        for alert in alerts:
            value = self._extract_field(alert, field_names)
            if value:
                counts[value] += 1

        return [
            {"value": value, "count": count, "percentage": round(count / len(alerts) * 100, 1)}
            for value, count in counts.most_common(limit)
        ]


class MetricsStore:
    """Abstract base class for metrics storage."""

    def store_rule_metrics(self, metrics: RuleMetrics) -> None:
        """Store rule metrics."""
        raise NotImplementedError

    def store_portfolio_metrics(self, metrics: PortfolioMetrics) -> None:
        """Store portfolio metrics."""
        raise NotImplementedError

    def get_rule_metrics(
        self,
        rule_id: str,
        period: MetricsPeriod,
        limit: int = 10
    ) -> List[RuleMetrics]:
        """Get historical rule metrics."""
        raise NotImplementedError

    def get_portfolio_metrics(
        self,
        period: MetricsPeriod,
        limit: int = 10
    ) -> List[PortfolioMetrics]:
        """Get historical portfolio metrics."""
        raise NotImplementedError


class DynamoDBMetricsStore(MetricsStore):
    """DynamoDB implementation of metrics store."""

    def __init__(self, table_name: str, region: str = "us-east-1"):
        """Initialize DynamoDB metrics store."""
        self.table_name = table_name
        self.region = region
        self._table = None

    @property
    def table(self):
        """Lazy-load DynamoDB table."""
        if self._table is None:
            import boto3
            dynamodb = boto3.resource("dynamodb", region_name=self.region)
            self._table = dynamodb.Table(self.table_name)
        return self._table

    def store_rule_metrics(self, metrics: RuleMetrics) -> None:
        """Store rule metrics in DynamoDB."""
        try:
            item = {
                "pk": f"rule#{metrics.rule_id}",
                "sk": f"metrics#{metrics.period.value}#{metrics.period_end}",
                **metrics.to_dict(),
                "ttl": int((datetime.utcnow() + timedelta(days=90)).timestamp())
            }
            self.table.put_item(Item=item)
        except Exception as e:
            logger.error(f"Failed to store rule metrics: {e}")

    def store_portfolio_metrics(self, metrics: PortfolioMetrics) -> None:
        """Store portfolio metrics in DynamoDB."""
        try:
            item = {
                "pk": "portfolio",
                "sk": f"metrics#{metrics.period.value}#{metrics.period_end}",
                **metrics.to_dict(),
                "ttl": int((datetime.utcnow() + timedelta(days=365)).timestamp())
            }
            self.table.put_item(Item=item)
        except Exception as e:
            logger.error(f"Failed to store portfolio metrics: {e}")

    def get_rule_metrics(
        self,
        rule_id: str,
        period: MetricsPeriod,
        limit: int = 10
    ) -> List[RuleMetrics]:
        """Get historical rule metrics from DynamoDB."""
        try:
            response = self.table.query(
                KeyConditionExpression="pk = :pk AND begins_with(sk, :sk_prefix)",
                ExpressionAttributeValues={
                    ":pk": f"rule#{rule_id}",
                    ":sk_prefix": f"metrics#{period.value}#"
                },
                ScanIndexForward=False,
                Limit=limit
            )

            results = []
            for item in response.get("Items", []):
                results.append(RuleMetrics(
                    rule_id=item["rule_id"],
                    rule_name=item["rule_name"],
                    period=MetricsPeriod(item["period"]),
                    period_start=item["period_start"],
                    period_end=item["period_end"],
                    total_alerts=item.get("total_alerts", 0),
                    alerts_by_status=item.get("alerts_by_status", {}),
                    unique_source_ips=item.get("unique_source_ips", 0),
                    unique_users=item.get("unique_users", 0),
                    unique_assets=item.get("unique_assets", 0),
                    false_positive_rate=item.get("false_positive_rate", 0.0),
                    dismissal_rate=item.get("dismissal_rate", 0.0),
                    resolution_rate=item.get("resolution_rate", 0.0),
                    mean_time_to_acknowledge=item.get("mean_time_to_acknowledge"),
                    mean_time_to_resolve=item.get("mean_time_to_resolve"),
                    alert_count_trend=item.get("alert_count_trend", 0.0),
                    fp_rate_trend=item.get("fp_rate_trend", 0.0),
                ))

            return results

        except Exception as e:
            logger.error(f"Failed to get rule metrics: {e}")
            return []

    def get_portfolio_metrics(
        self,
        period: MetricsPeriod,
        limit: int = 10
    ) -> List[PortfolioMetrics]:
        """Get historical portfolio metrics from DynamoDB."""
        try:
            response = self.table.query(
                KeyConditionExpression="pk = :pk AND begins_with(sk, :sk_prefix)",
                ExpressionAttributeValues={
                    ":pk": "portfolio",
                    ":sk_prefix": f"metrics#{period.value}#"
                },
                ScanIndexForward=False,
                Limit=limit
            )

            results = []
            for item in response.get("Items", []):
                results.append(PortfolioMetrics(
                    period=MetricsPeriod(item["period"]),
                    period_start=item["period_start"],
                    period_end=item["period_end"],
                    total_rules=item.get("total_rules", 0),
                    active_rules=item.get("active_rules", 0),
                    zero_alert_rules=item.get("zero_alert_rules", 0),
                    total_alerts=item.get("total_alerts", 0),
                    avg_alerts_per_rule=item.get("avg_alerts_per_rule", 0.0),
                    avg_false_positive_rate=item.get("avg_false_positive_rate", 0.0),
                    avg_resolution_rate=item.get("avg_resolution_rate", 0.0),
                    highest_volume_rules=item.get("highest_volume_rules", []),
                    highest_fp_rate_rules=item.get("highest_fp_rate_rules", []),
                    zero_alert_rule_ids=item.get("zero_alert_rule_ids", []),
                ))

            return results

        except Exception as e:
            logger.error(f"Failed to get portfolio metrics: {e}")
            return []


def calculate_metrics(
    rule_id: str,
    rule_name: str,
    alerts: List[Dict[str, Any]],
    period: MetricsPeriod = MetricsPeriod.WEEK
) -> RuleMetrics:
    """Convenience function to calculate rule metrics."""
    calculator = MetricsCalculator()
    return calculator.calculate_rule_metrics(rule_id, rule_name, alerts, period)


def calculate_portfolio(
    rules: List[Dict[str, Any]],
    alerts_by_rule: Dict[str, List[Dict[str, Any]]],
    period: MetricsPeriod = MetricsPeriod.WEEK
) -> PortfolioMetrics:
    """Convenience function to calculate portfolio metrics."""
    calculator = MetricsCalculator()
    return calculator.calculate_portfolio_metrics(rules, alerts_by_rule, period)
