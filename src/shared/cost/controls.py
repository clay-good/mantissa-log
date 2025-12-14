"""Cost control system for Mantissa Log.

Implements spending limits, query cost warnings, and automatic rule disabling
for expensive detection rules.
"""

import logging
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from decimal import Decimal
from enum import Enum
from typing import Any, Dict, List, Optional, Protocol

logger = logging.getLogger(__name__)


class CostAction(Enum):
    """Actions to take when cost thresholds are exceeded."""
    WARN = "warn"
    ALERT = "alert"
    DISABLE_RULE = "disable_rule"
    BLOCK_QUERY = "block_query"
    THROTTLE = "throttle"


class CostPeriod(Enum):
    """Cost tracking periods."""
    HOURLY = "hourly"
    DAILY = "daily"
    WEEKLY = "weekly"
    MONTHLY = "monthly"


@dataclass
class CostThreshold:
    """Defines a cost threshold and action."""
    amount: Decimal
    period: CostPeriod
    action: CostAction
    resource_type: str = "all"  # all, llm, query, storage
    enabled: bool = True
    notification_channels: List[str] = field(default_factory=list)


@dataclass
class SpendingLimit:
    """Spending limit configuration."""
    limit_id: str
    name: str
    thresholds: List[CostThreshold]
    scope: str = "global"  # global, rule, user
    scope_id: Optional[str] = None
    created_at: datetime = field(default_factory=datetime.utcnow)

    def get_threshold_for_amount(self, amount: Decimal, period: CostPeriod) -> Optional[CostThreshold]:
        """Get the threshold that applies for a given amount."""
        applicable = [
            t for t in self.thresholds
            if t.period == period and t.enabled and amount >= t.amount
        ]
        if applicable:
            return max(applicable, key=lambda t: t.amount)
        return None


@dataclass
class CostRecord:
    """Record of a cost event."""
    record_id: str
    timestamp: datetime
    amount: Decimal
    resource_type: str
    resource_id: str
    description: str
    metadata: Dict[str, Any] = field(default_factory=dict)


@dataclass
class CostSummary:
    """Summary of costs over a period."""
    period: CostPeriod
    start_time: datetime
    end_time: datetime
    total_cost: Decimal
    breakdown: Dict[str, Decimal]
    record_count: int
    top_resources: List[Dict[str, Any]]


@dataclass
class QueryCostEstimate:
    """Cost estimate for a query before execution."""
    estimated_data_scanned_gb: float
    estimated_cost_usd: Decimal
    warnings: List[str]
    recommendations: List[str]
    should_proceed: bool
    requires_approval: bool = False


class CostStore(Protocol):
    """Protocol for cost data persistence."""

    def record_cost(self, record: CostRecord) -> None:
        """Record a cost event."""
        ...

    def get_costs(
        self,
        start_time: datetime,
        end_time: datetime,
        resource_type: Optional[str] = None,
        resource_id: Optional[str] = None
    ) -> List[CostRecord]:
        """Get cost records for a time period."""
        ...

    def get_spending_limits(self, scope: str, scope_id: Optional[str] = None) -> List[SpendingLimit]:
        """Get spending limits for a scope."""
        ...

    def save_spending_limit(self, limit: SpendingLimit) -> None:
        """Save a spending limit."""
        ...

    def get_disabled_rules(self) -> List[str]:
        """Get list of rules disabled due to cost."""
        ...

    def disable_rule(self, rule_id: str, reason: str) -> None:
        """Disable a rule due to cost."""
        ...


class CostControlManager:
    """Manages cost controls, limits, and enforcement."""

    # Default cost rates
    ATHENA_COST_PER_TB = Decimal("5.00")
    BIGQUERY_COST_PER_TB = Decimal("5.00")
    SYNAPSE_COST_PER_TB = Decimal("5.00")

    # LLM costs (per 1M tokens)
    LLM_COSTS = {
        "gpt-4": Decimal("30.00"),
        "gpt-4-turbo": Decimal("10.00"),
        "gpt-3.5-turbo": Decimal("0.50"),
        "claude-3-opus": Decimal("15.00"),
        "claude-3-sonnet": Decimal("3.00"),
        "claude-3-haiku": Decimal("0.25"),
        "gemini-pro": Decimal("0.50"),
    }

    def __init__(
        self,
        store: CostStore,
        default_limits: Optional[List[SpendingLimit]] = None
    ):
        """Initialize cost control manager.

        Args:
            store: Cost data store
            default_limits: Default spending limits
        """
        self.store = store
        self.default_limits = default_limits or self._get_default_limits()

    def _get_default_limits(self) -> List[SpendingLimit]:
        """Get default spending limits."""
        return [
            SpendingLimit(
                limit_id="default-global",
                name="Default Global Limits",
                thresholds=[
                    CostThreshold(
                        amount=Decimal("50.00"),
                        period=CostPeriod.DAILY,
                        action=CostAction.WARN,
                        notification_channels=["slack", "email"]
                    ),
                    CostThreshold(
                        amount=Decimal("100.00"),
                        period=CostPeriod.DAILY,
                        action=CostAction.ALERT,
                        notification_channels=["slack", "email", "pagerduty"]
                    ),
                    CostThreshold(
                        amount=Decimal("500.00"),
                        period=CostPeriod.DAILY,
                        action=CostAction.THROTTLE,
                        notification_channels=["slack", "email", "pagerduty"]
                    ),
                    CostThreshold(
                        amount=Decimal("1000.00"),
                        period=CostPeriod.MONTHLY,
                        action=CostAction.WARN,
                    ),
                    CostThreshold(
                        amount=Decimal("5000.00"),
                        period=CostPeriod.MONTHLY,
                        action=CostAction.ALERT,
                    ),
                ]
            ),
            SpendingLimit(
                limit_id="default-llm",
                name="LLM API Limits",
                thresholds=[
                    CostThreshold(
                        amount=Decimal("10.00"),
                        period=CostPeriod.DAILY,
                        action=CostAction.WARN,
                        resource_type="llm"
                    ),
                    CostThreshold(
                        amount=Decimal("50.00"),
                        period=CostPeriod.DAILY,
                        action=CostAction.THROTTLE,
                        resource_type="llm"
                    ),
                ]
            ),
            SpendingLimit(
                limit_id="default-query",
                name="Query Cost Limits",
                thresholds=[
                    CostThreshold(
                        amount=Decimal("1.00"),
                        period=CostPeriod.HOURLY,
                        action=CostAction.WARN,
                        resource_type="query"
                    ),
                    CostThreshold(
                        amount=Decimal("5.00"),
                        period=CostPeriod.HOURLY,
                        action=CostAction.BLOCK_QUERY,
                        resource_type="query"
                    ),
                ]
            )
        ]

    def record_cost(
        self,
        resource_type: str,
        resource_id: str,
        amount: Decimal,
        description: str,
        metadata: Optional[Dict[str, Any]] = None
    ) -> Optional[CostAction]:
        """Record a cost and check for threshold violations.

        Args:
            resource_type: Type of resource (llm, query, storage)
            resource_id: ID of the specific resource
            amount: Cost amount in USD
            description: Description of the cost
            metadata: Additional metadata

        Returns:
            Action to take if threshold exceeded, None otherwise
        """
        record = CostRecord(
            record_id=f"{resource_type}-{resource_id}-{datetime.utcnow().isoformat()}",
            timestamp=datetime.utcnow(),
            amount=amount,
            resource_type=resource_type,
            resource_id=resource_id,
            description=description,
            metadata=metadata or {}
        )

        self.store.record_cost(record)

        # Check thresholds
        action = self._check_thresholds(resource_type, resource_id)
        if action:
            self._handle_threshold_action(action, resource_type, resource_id)

        return action

    def _check_thresholds(
        self,
        resource_type: str,
        resource_id: str
    ) -> Optional[CostAction]:
        """Check if any spending thresholds are exceeded."""
        now = datetime.utcnow()
        limits = self.store.get_spending_limits("global") + self.default_limits

        highest_action = None

        for limit in limits:
            for threshold in limit.thresholds:
                if not threshold.enabled:
                    continue

                if threshold.resource_type not in ("all", resource_type):
                    continue

                # Get period start time
                period_start = self._get_period_start(now, threshold.period)

                # Get costs for period
                costs = self.store.get_costs(
                    start_time=period_start,
                    end_time=now,
                    resource_type=resource_type if threshold.resource_type != "all" else None
                )

                total = sum(c.amount for c in costs)

                if total >= threshold.amount:
                    logger.warning(
                        f"Cost threshold exceeded: {threshold.action.value} "
                        f"({total:.2f} >= {threshold.amount:.2f} {threshold.period.value})"
                    )

                    if highest_action is None or self._action_priority(threshold.action) > self._action_priority(highest_action):
                        highest_action = threshold.action

        return highest_action

    def _action_priority(self, action: CostAction) -> int:
        """Get priority of an action (higher = more severe)."""
        priorities = {
            CostAction.WARN: 1,
            CostAction.ALERT: 2,
            CostAction.THROTTLE: 3,
            CostAction.BLOCK_QUERY: 4,
            CostAction.DISABLE_RULE: 5,
        }
        return priorities.get(action, 0)

    def _get_period_start(self, now: datetime, period: CostPeriod) -> datetime:
        """Get the start time for a cost period."""
        if period == CostPeriod.HOURLY:
            return now.replace(minute=0, second=0, microsecond=0)
        elif period == CostPeriod.DAILY:
            return now.replace(hour=0, minute=0, second=0, microsecond=0)
        elif period == CostPeriod.WEEKLY:
            days_since_monday = now.weekday()
            return (now - timedelta(days=days_since_monday)).replace(
                hour=0, minute=0, second=0, microsecond=0
            )
        elif period == CostPeriod.MONTHLY:
            return now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
        return now

    def _handle_threshold_action(
        self,
        action: CostAction,
        resource_type: str,
        resource_id: str
    ) -> None:
        """Handle a threshold action."""
        if action == CostAction.DISABLE_RULE and resource_type == "rule":
            self.store.disable_rule(
                rule_id=resource_id,
                reason=f"Automatic disable due to cost threshold"
            )
            logger.warning(f"Disabled rule {resource_id} due to cost threshold")

    def estimate_query_cost(
        self,
        estimated_data_gb: float,
        query_type: str = "athena"
    ) -> QueryCostEstimate:
        """Estimate the cost of a query before execution.

        Args:
            estimated_data_gb: Estimated data to scan in GB
            query_type: Query engine (athena, bigquery, synapse)

        Returns:
            Cost estimate with warnings and recommendations
        """
        # Calculate cost
        cost_per_tb = {
            "athena": self.ATHENA_COST_PER_TB,
            "bigquery": self.BIGQUERY_COST_PER_TB,
            "synapse": self.SYNAPSE_COST_PER_TB,
        }.get(query_type, self.ATHENA_COST_PER_TB)

        estimated_cost = (Decimal(str(estimated_data_gb)) / Decimal("1024")) * cost_per_tb

        warnings = []
        recommendations = []
        should_proceed = True
        requires_approval = False

        # Generate warnings based on cost
        if estimated_cost > Decimal("1.00"):
            warnings.append(f"Query estimated to cost ${estimated_cost:.2f}")

        if estimated_cost > Decimal("5.00"):
            warnings.append("High-cost query - consider optimizing")
            recommendations.append("Add time-based partition filters to reduce data scanned")
            recommendations.append("Select only required columns instead of SELECT *")

        if estimated_cost > Decimal("10.00"):
            warnings.append("Very high-cost query - approval may be required")
            requires_approval = True

        if estimated_cost > Decimal("50.00"):
            warnings.append("Extremely high-cost query - blocked by default")
            should_proceed = False
            recommendations.append("Break the query into smaller time ranges")
            recommendations.append("Use sampling for exploratory analysis")

        # Data-based recommendations
        if estimated_data_gb > 100:
            recommendations.append("Consider using columnar format (Parquet) for better compression")

        if estimated_data_gb > 500:
            recommendations.append("Query spans large dataset - ensure partitioning is effective")

        return QueryCostEstimate(
            estimated_data_scanned_gb=estimated_data_gb,
            estimated_cost_usd=estimated_cost,
            warnings=warnings,
            recommendations=recommendations,
            should_proceed=should_proceed,
            requires_approval=requires_approval
        )

    def estimate_llm_cost(
        self,
        model: str,
        input_tokens: int,
        estimated_output_tokens: int
    ) -> Decimal:
        """Estimate LLM API cost.

        Args:
            model: LLM model name
            input_tokens: Number of input tokens
            estimated_output_tokens: Estimated output tokens

        Returns:
            Estimated cost in USD
        """
        cost_per_million = self.LLM_COSTS.get(model, Decimal("10.00"))
        total_tokens = input_tokens + estimated_output_tokens
        cost = (Decimal(str(total_tokens)) / Decimal("1000000")) * cost_per_million
        return cost.quantize(Decimal("0.0001"))

    def get_cost_summary(
        self,
        period: CostPeriod,
        resource_type: Optional[str] = None
    ) -> CostSummary:
        """Get cost summary for a period.

        Args:
            period: Cost period
            resource_type: Optional filter by resource type

        Returns:
            Cost summary
        """
        now = datetime.utcnow()
        start_time = self._get_period_start(now, period)

        costs = self.store.get_costs(
            start_time=start_time,
            end_time=now,
            resource_type=resource_type
        )

        # Calculate breakdown
        breakdown: Dict[str, Decimal] = {}
        resource_costs: Dict[str, Decimal] = {}

        for cost in costs:
            breakdown[cost.resource_type] = breakdown.get(cost.resource_type, Decimal("0")) + cost.amount
            resource_costs[cost.resource_id] = resource_costs.get(cost.resource_id, Decimal("0")) + cost.amount

        # Get top resources
        top_resources = sorted(
            [{"resource_id": k, "cost": v} for k, v in resource_costs.items()],
            key=lambda x: x["cost"],
            reverse=True
        )[:10]

        return CostSummary(
            period=period,
            start_time=start_time,
            end_time=now,
            total_cost=sum(breakdown.values()),
            breakdown=breakdown,
            record_count=len(costs),
            top_resources=top_resources
        )

    def check_rule_cost_health(self, rule_id: str) -> Dict[str, Any]:
        """Check if a rule is within cost budgets.

        Args:
            rule_id: Detection rule ID

        Returns:
            Health check result with recommendations
        """
        now = datetime.utcnow()
        week_start = self._get_period_start(now, CostPeriod.WEEKLY)

        costs = self.store.get_costs(
            start_time=week_start,
            end_time=now,
            resource_id=rule_id
        )

        weekly_cost = sum(c.amount for c in costs)
        daily_avg = weekly_cost / max((now - week_start).days, 1)

        status = "healthy"
        recommendations = []

        if daily_avg > Decimal("5.00"):
            status = "warning"
            recommendations.append("Rule is expensive - consider query optimization")

        if daily_avg > Decimal("10.00"):
            status = "critical"
            recommendations.append("Rule cost is critical - review immediately")
            recommendations.append("Consider reducing execution frequency")

        # Check if rule is disabled
        disabled_rules = self.store.get_disabled_rules()
        if rule_id in disabled_rules:
            status = "disabled"
            recommendations.append("Rule was auto-disabled due to cost - manual review required")

        return {
            "rule_id": rule_id,
            "status": status,
            "weekly_cost": float(weekly_cost),
            "daily_average": float(daily_avg),
            "projected_monthly": float(daily_avg * 30),
            "recommendations": recommendations
        }


# Convenience functions

def create_cost_manager(store: CostStore) -> CostControlManager:
    """Create a cost control manager with default settings."""
    return CostControlManager(store=store)


def estimate_athena_cost(data_gb: float) -> Decimal:
    """Quick estimate for Athena query cost."""
    return (Decimal(str(data_gb)) / Decimal("1024")) * Decimal("5.00")


def estimate_bigquery_cost(data_gb: float) -> Decimal:
    """Quick estimate for BigQuery cost."""
    return (Decimal(str(data_gb)) / Decimal("1024")) * Decimal("5.00")
