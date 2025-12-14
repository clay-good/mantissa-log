"""
Automatic Rule Optimization System.

Provides functionality to:
- Apply accepted tuning recommendations automatically
- Version control for rule changes
- Rollback capability if alert volume spikes
- Safe deployment with gradual rollout
"""

import logging
import hashlib
import yaml
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional
from enum import Enum
from copy import deepcopy

logger = logging.getLogger(__name__)


class OptimizationType(Enum):
    """Types of rule optimizations."""
    ADD_EXCLUSION = "add_exclusion"
    MODIFY_THRESHOLD = "modify_threshold"
    UPDATE_FILTER = "update_filter"
    DISABLE_RULE = "disable_rule"
    ENABLE_RULE = "enable_rule"


class OptimizationStatus(Enum):
    """Status of optimization."""
    PENDING = "pending"
    APPROVED = "approved"
    APPLIED = "applied"
    ROLLED_BACK = "rolled_back"
    REJECTED = "rejected"


@dataclass
class RuleVersion:
    """A version of a detection rule."""

    rule_id: str
    version: int
    rule_content: Dict[str, Any]  # Full Sigma rule
    created_at: str
    created_by: str
    change_summary: str
    previous_version: Optional[int] = None

    # Metadata
    is_current: bool = True
    optimization_id: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "rule_id": self.rule_id,
            "version": self.version,
            "rule_content": self.rule_content,
            "created_at": self.created_at,
            "created_by": self.created_by,
            "change_summary": self.change_summary,
            "previous_version": self.previous_version,
            "is_current": self.is_current,
            "optimization_id": self.optimization_id,
        }


@dataclass
class Optimization:
    """An optimization to be applied to a rule."""

    optimization_id: str
    rule_id: str
    rule_name: str
    optimization_type: OptimizationType
    status: OptimizationStatus

    # Change details
    proposed_changes: Dict[str, Any]
    change_description: str

    # Source
    recommendation_id: Optional[str] = None  # From tuning system
    requested_by: str = "system"
    requested_at: str = ""

    # Approval
    approved_by: Optional[str] = None
    approved_at: Optional[str] = None
    rejection_reason: Optional[str] = None

    # Application
    applied_at: Optional[str] = None
    applied_version: Optional[int] = None
    previous_version: Optional[int] = None

    # Monitoring
    alert_baseline: Optional[int] = None  # Alerts before change
    alert_threshold_multiplier: float = 3.0  # Rollback if alerts > baseline * multiplier
    monitoring_end: Optional[str] = None  # When monitoring period ends

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "optimization_id": self.optimization_id,
            "rule_id": self.rule_id,
            "rule_name": self.rule_name,
            "optimization_type": self.optimization_type.value,
            "status": self.status.value,
            "proposed_changes": self.proposed_changes,
            "change_description": self.change_description,
            "recommendation_id": self.recommendation_id,
            "requested_by": self.requested_by,
            "requested_at": self.requested_at,
            "approved_by": self.approved_by,
            "approved_at": self.approved_at,
            "rejection_reason": self.rejection_reason,
            "applied_at": self.applied_at,
            "applied_version": self.applied_version,
            "previous_version": self.previous_version,
            "alert_baseline": self.alert_baseline,
            "alert_threshold_multiplier": self.alert_threshold_multiplier,
            "monitoring_end": self.monitoring_end,
        }


@dataclass
class RollbackResult:
    """Result of a rollback operation."""

    success: bool
    optimization_id: str
    rule_id: str
    rolled_back_to_version: Optional[int] = None
    reason: str = ""
    rolled_back_at: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "success": self.success,
            "optimization_id": self.optimization_id,
            "rule_id": self.rule_id,
            "rolled_back_to_version": self.rolled_back_to_version,
            "reason": self.reason,
            "rolled_back_at": self.rolled_back_at,
        }


class RuleOptimizer:
    """
    Applies and manages rule optimizations with versioning and rollback.

    Flow:
    1. Optimization requested (from tuning system or manual)
    2. Optimization approved (manual or auto-approve for high confidence)
    3. Optimization applied with version tracking
    4. Monitoring period begins
    5. Rollback if alert volume spikes
    """

    DEFAULT_MONITORING_DAYS = 7

    def __init__(
        self,
        store: Optional["OptimizationStore"] = None,
        auto_approve_high_confidence: bool = False,
        monitoring_days: int = 7
    ):
        """
        Initialize rule optimizer.

        Args:
            store: Storage backend
            auto_approve_high_confidence: Auto-approve HIGH confidence recommendations
            monitoring_days: Days to monitor after applying change
        """
        self.store = store
        self.auto_approve_high_confidence = auto_approve_high_confidence
        self.monitoring_days = monitoring_days

    def request_optimization(
        self,
        rule_id: str,
        rule_name: str,
        optimization_type: OptimizationType,
        proposed_changes: Dict[str, Any],
        change_description: str,
        recommendation_id: Optional[str] = None,
        requested_by: str = "system",
        confidence: str = "medium"
    ) -> Optimization:
        """
        Request an optimization for a rule.

        Args:
            rule_id: Rule identifier
            rule_name: Rule name
            optimization_type: Type of optimization
            proposed_changes: Changes to apply
            change_description: Human-readable description
            recommendation_id: Source recommendation ID
            requested_by: Who requested this
            confidence: Confidence level (high, medium, low)

        Returns:
            Optimization
        """
        now = datetime.utcnow().isoformat() + "Z"
        opt_id = f"opt-{rule_id}-{hashlib.md5(now.encode()).hexdigest()[:8]}"

        optimization = Optimization(
            optimization_id=opt_id,
            rule_id=rule_id,
            rule_name=rule_name,
            optimization_type=optimization_type,
            status=OptimizationStatus.PENDING,
            proposed_changes=proposed_changes,
            change_description=change_description,
            recommendation_id=recommendation_id,
            requested_by=requested_by,
            requested_at=now,
        )

        # Auto-approve high confidence if enabled
        if self.auto_approve_high_confidence and confidence == "high":
            optimization.status = OptimizationStatus.APPROVED
            optimization.approved_by = "auto-approve"
            optimization.approved_at = now
            logger.info(f"Auto-approved high confidence optimization {opt_id}")

        if self.store:
            self.store.save_optimization(optimization)

        return optimization

    def approve_optimization(
        self,
        optimization_id: str,
        approved_by: str
    ) -> Optional[Optimization]:
        """
        Approve a pending optimization.

        Args:
            optimization_id: Optimization identifier
            approved_by: User approving

        Returns:
            Updated Optimization or None
        """
        if not self.store:
            return None

        optimization = self.store.get_optimization(optimization_id)
        if not optimization:
            logger.warning(f"Optimization {optimization_id} not found")
            return None

        if optimization.status != OptimizationStatus.PENDING:
            logger.warning(f"Optimization {optimization_id} is not pending")
            return optimization

        optimization.status = OptimizationStatus.APPROVED
        optimization.approved_by = approved_by
        optimization.approved_at = datetime.utcnow().isoformat() + "Z"

        self.store.save_optimization(optimization)
        logger.info(f"Approved optimization {optimization_id} by {approved_by}")

        return optimization

    def reject_optimization(
        self,
        optimization_id: str,
        rejected_by: str,
        reason: str
    ) -> Optional[Optimization]:
        """
        Reject a pending optimization.

        Args:
            optimization_id: Optimization identifier
            rejected_by: User rejecting
            reason: Rejection reason

        Returns:
            Updated Optimization or None
        """
        if not self.store:
            return None

        optimization = self.store.get_optimization(optimization_id)
        if not optimization:
            return None

        optimization.status = OptimizationStatus.REJECTED
        optimization.rejection_reason = reason
        # Reuse approved_by/at for rejection tracking
        optimization.approved_by = rejected_by
        optimization.approved_at = datetime.utcnow().isoformat() + "Z"

        self.store.save_optimization(optimization)
        logger.info(f"Rejected optimization {optimization_id}: {reason}")

        return optimization

    def apply_optimization(
        self,
        optimization_id: str,
        current_rule: Dict[str, Any],
        alert_baseline: Optional[int] = None
    ) -> tuple:
        """
        Apply an approved optimization to a rule.

        Args:
            optimization_id: Optimization identifier
            current_rule: Current rule content (Sigma YAML dict)
            alert_baseline: Recent alert count for monitoring

        Returns:
            Tuple of (updated_rule, new_version, optimization)
        """
        if not self.store:
            return None, None, None

        optimization = self.store.get_optimization(optimization_id)
        if not optimization:
            logger.error(f"Optimization {optimization_id} not found")
            return None, None, None

        if optimization.status != OptimizationStatus.APPROVED:
            logger.error(f"Optimization {optimization_id} is not approved")
            return None, None, optimization

        # Get current version
        current_version = self.store.get_latest_version(optimization.rule_id)
        new_version_num = (current_version.version + 1) if current_version else 1
        previous_version_num = current_version.version if current_version else None

        # Apply changes
        updated_rule = self._apply_changes(
            current_rule,
            optimization.optimization_type,
            optimization.proposed_changes
        )

        if updated_rule is None:
            logger.error(f"Failed to apply changes for {optimization_id}")
            return None, None, optimization

        # Create new version
        now = datetime.utcnow().isoformat() + "Z"
        new_version = RuleVersion(
            rule_id=optimization.rule_id,
            version=new_version_num,
            rule_content=updated_rule,
            created_at=now,
            created_by=optimization.approved_by or "system",
            change_summary=optimization.change_description,
            previous_version=previous_version_num,
            is_current=True,
            optimization_id=optimization_id
        )

        # Update optimization status
        optimization.status = OptimizationStatus.APPLIED
        optimization.applied_at = now
        optimization.applied_version = new_version_num
        optimization.previous_version = previous_version_num
        optimization.alert_baseline = alert_baseline
        optimization.monitoring_end = (
            datetime.utcnow() + timedelta(days=self.monitoring_days)
        ).isoformat() + "Z"

        # Mark previous version as not current
        if current_version:
            current_version.is_current = False
            self.store.save_version(current_version)

        # Save new version and update optimization
        self.store.save_version(new_version)
        self.store.save_optimization(optimization)

        logger.info(f"Applied optimization {optimization_id} as version {new_version_num}")

        return updated_rule, new_version, optimization

    def check_and_rollback(
        self,
        optimization_id: str,
        current_alert_count: int
    ) -> Optional[RollbackResult]:
        """
        Check if optimization should be rolled back based on alert volume.

        Args:
            optimization_id: Optimization identifier
            current_alert_count: Current alert count since optimization

        Returns:
            RollbackResult if rollback occurred, None otherwise
        """
        if not self.store:
            return None

        optimization = self.store.get_optimization(optimization_id)
        if not optimization:
            return None

        if optimization.status != OptimizationStatus.APPLIED:
            return None

        # Check if still in monitoring period
        if optimization.monitoring_end:
            monitoring_end = datetime.fromisoformat(optimization.monitoring_end.replace("Z", ""))
            if datetime.utcnow() > monitoring_end:
                logger.info(f"Monitoring period ended for {optimization_id}")
                return None

        # Check alert threshold
        baseline = optimization.alert_baseline or 0
        threshold = baseline * optimization.alert_threshold_multiplier

        if current_alert_count <= threshold:
            return None

        # Need to rollback
        logger.warning(
            f"Alert spike detected for {optimization_id}: "
            f"{current_alert_count} > {threshold} (baseline: {baseline})"
        )

        return self.rollback_optimization(
            optimization_id,
            reason=f"Alert spike: {current_alert_count} alerts vs {baseline} baseline"
        )

    def rollback_optimization(
        self,
        optimization_id: str,
        reason: str = "Manual rollback"
    ) -> RollbackResult:
        """
        Rollback an applied optimization.

        Args:
            optimization_id: Optimization identifier
            reason: Reason for rollback

        Returns:
            RollbackResult
        """
        now = datetime.utcnow().isoformat() + "Z"

        if not self.store:
            return RollbackResult(
                success=False,
                optimization_id=optimization_id,
                rule_id="",
                reason="No store configured"
            )

        optimization = self.store.get_optimization(optimization_id)
        if not optimization:
            return RollbackResult(
                success=False,
                optimization_id=optimization_id,
                rule_id="",
                reason="Optimization not found"
            )

        if optimization.status != OptimizationStatus.APPLIED:
            return RollbackResult(
                success=False,
                optimization_id=optimization_id,
                rule_id=optimization.rule_id,
                reason=f"Cannot rollback: status is {optimization.status.value}"
            )

        if optimization.previous_version is None:
            return RollbackResult(
                success=False,
                optimization_id=optimization_id,
                rule_id=optimization.rule_id,
                reason="No previous version to rollback to"
            )

        # Get previous version
        previous = self.store.get_version(optimization.rule_id, optimization.previous_version)
        if not previous:
            return RollbackResult(
                success=False,
                optimization_id=optimization_id,
                rule_id=optimization.rule_id,
                reason=f"Previous version {optimization.previous_version} not found"
            )

        # Get current version
        current = self.store.get_version(optimization.rule_id, optimization.applied_version)

        # Update version flags
        if current:
            current.is_current = False
            self.store.save_version(current)

        previous.is_current = True
        self.store.save_version(previous)

        # Update optimization status
        optimization.status = OptimizationStatus.ROLLED_BACK

        self.store.save_optimization(optimization)

        logger.info(
            f"Rolled back optimization {optimization_id} to version {optimization.previous_version}"
        )

        return RollbackResult(
            success=True,
            optimization_id=optimization_id,
            rule_id=optimization.rule_id,
            rolled_back_to_version=optimization.previous_version,
            reason=reason,
            rolled_back_at=now
        )

    def _apply_changes(
        self,
        rule: Dict[str, Any],
        optimization_type: OptimizationType,
        proposed_changes: Dict[str, Any]
    ) -> Optional[Dict[str, Any]]:
        """Apply changes to a rule based on optimization type."""
        try:
            updated = deepcopy(rule)

            if optimization_type == OptimizationType.ADD_EXCLUSION:
                # Add filter to detection section
                detection = updated.get("detection", {})

                # Get or create filter section
                filter_name = proposed_changes.get("filter_name", "filter_exclusion")
                filter_content = proposed_changes.get("filter_content", {})

                detection[filter_name] = filter_content

                # Update condition
                condition = detection.get("condition", "selection")
                if "and not" not in condition.lower():
                    detection["condition"] = f"{condition} and not {filter_name}"
                else:
                    # Append to existing filter
                    detection["condition"] = f"{condition} and not {filter_name}"

                updated["detection"] = detection

            elif optimization_type == OptimizationType.MODIFY_THRESHOLD:
                # Update threshold in detection
                threshold = proposed_changes.get("threshold")
                timeframe = proposed_changes.get("timeframe")

                detection = updated.get("detection", {})

                if threshold is not None:
                    detection["count"] = threshold
                if timeframe:
                    detection["timeframe"] = timeframe

                updated["detection"] = detection

            elif optimization_type == OptimizationType.UPDATE_FILTER:
                # Update existing filter
                filter_name = proposed_changes.get("filter_name")
                filter_content = proposed_changes.get("filter_content")

                if filter_name and filter_content:
                    detection = updated.get("detection", {})
                    detection[filter_name] = filter_content
                    updated["detection"] = detection

            elif optimization_type == OptimizationType.DISABLE_RULE:
                updated["enabled"] = False

            elif optimization_type == OptimizationType.ENABLE_RULE:
                updated["enabled"] = True

            return updated

        except Exception as e:
            logger.error(f"Failed to apply changes: {e}")
            return None


class OptimizationStore:
    """Abstract base class for optimization storage."""

    def save_optimization(self, optimization: Optimization) -> None:
        """Save optimization."""
        raise NotImplementedError

    def get_optimization(self, optimization_id: str) -> Optional[Optimization]:
        """Get optimization by ID."""
        raise NotImplementedError

    def get_pending_optimizations(self, rule_id: Optional[str] = None) -> List[Optimization]:
        """Get pending optimizations."""
        raise NotImplementedError

    def get_applied_optimizations_in_monitoring(self) -> List[Optimization]:
        """Get applied optimizations still in monitoring period."""
        raise NotImplementedError

    def save_version(self, version: RuleVersion) -> None:
        """Save rule version."""
        raise NotImplementedError

    def get_version(self, rule_id: str, version: int) -> Optional[RuleVersion]:
        """Get specific rule version."""
        raise NotImplementedError

    def get_latest_version(self, rule_id: str) -> Optional[RuleVersion]:
        """Get latest rule version."""
        raise NotImplementedError

    def get_version_history(self, rule_id: str, limit: int = 10) -> List[RuleVersion]:
        """Get version history for a rule."""
        raise NotImplementedError


class DynamoDBOptimizationStore(OptimizationStore):
    """DynamoDB implementation of optimization store."""

    def __init__(self, table_name: str, region: str = "us-east-1"):
        """Initialize DynamoDB store."""
        self.table_name = table_name
        self.region = region
        self._table = None

    @property
    def table(self):
        """Lazy-load table."""
        if self._table is None:
            import boto3
            dynamodb = boto3.resource("dynamodb", region_name=self.region)
            self._table = dynamodb.Table(self.table_name)
        return self._table

    def save_optimization(self, optimization: Optimization) -> None:
        """Save optimization to DynamoDB."""
        try:
            item = {
                "pk": f"opt#{optimization.optimization_id}",
                "sk": "metadata",
                **optimization.to_dict(),
                "ttl": int((datetime.utcnow() + timedelta(days=365)).timestamp())
            }

            # Also create GSI entries for queries
            self.table.put_item(Item=item)

            # Rule-based index entry
            rule_item = {
                "pk": f"rule#{optimization.rule_id}",
                "sk": f"opt#{optimization.requested_at}#{optimization.optimization_id}",
                "optimization_id": optimization.optimization_id,
                "status": optimization.status.value,
                "ttl": int((datetime.utcnow() + timedelta(days=365)).timestamp())
            }
            self.table.put_item(Item=rule_item)

        except Exception as e:
            logger.error(f"Failed to save optimization: {e}")

    def get_optimization(self, optimization_id: str) -> Optional[Optimization]:
        """Get optimization from DynamoDB."""
        try:
            response = self.table.get_item(
                Key={"pk": f"opt#{optimization_id}", "sk": "metadata"}
            )

            if "Item" not in response:
                return None

            item = response["Item"]
            return Optimization(
                optimization_id=item["optimization_id"],
                rule_id=item["rule_id"],
                rule_name=item["rule_name"],
                optimization_type=OptimizationType(item["optimization_type"]),
                status=OptimizationStatus(item["status"]),
                proposed_changes=item["proposed_changes"],
                change_description=item["change_description"],
                recommendation_id=item.get("recommendation_id"),
                requested_by=item.get("requested_by", "system"),
                requested_at=item.get("requested_at", ""),
                approved_by=item.get("approved_by"),
                approved_at=item.get("approved_at"),
                rejection_reason=item.get("rejection_reason"),
                applied_at=item.get("applied_at"),
                applied_version=item.get("applied_version"),
                previous_version=item.get("previous_version"),
                alert_baseline=item.get("alert_baseline"),
                alert_threshold_multiplier=item.get("alert_threshold_multiplier", 3.0),
                monitoring_end=item.get("monitoring_end"),
            )

        except Exception as e:
            logger.error(f"Failed to get optimization: {e}")
            return None

    def get_pending_optimizations(self, rule_id: Optional[str] = None) -> List[Optimization]:
        """Get pending optimizations."""
        # This would need a GSI on status for efficient querying
        # Simplified implementation using scan
        try:
            if rule_id:
                response = self.table.query(
                    KeyConditionExpression="pk = :pk",
                    FilterExpression="#status = :status",
                    ExpressionAttributeNames={"#status": "status"},
                    ExpressionAttributeValues={
                        ":pk": f"rule#{rule_id}",
                        ":status": OptimizationStatus.PENDING.value
                    }
                )
            else:
                response = self.table.scan(
                    FilterExpression="#status = :status AND begins_with(pk, :pk_prefix)",
                    ExpressionAttributeNames={"#status": "status"},
                    ExpressionAttributeValues={
                        ":status": OptimizationStatus.PENDING.value,
                        ":pk_prefix": "opt#"
                    }
                )

            optimizations = []
            for item in response.get("Items", []):
                if "optimization_id" in item:
                    opt = self.get_optimization(item.get("optimization_id"))
                    if opt:
                        optimizations.append(opt)

            return optimizations

        except Exception as e:
            logger.error(f"Failed to get pending optimizations: {e}")
            return []

    def get_applied_optimizations_in_monitoring(self) -> List[Optimization]:
        """Get applied optimizations still in monitoring period."""
        try:
            now = datetime.utcnow().isoformat() + "Z"

            response = self.table.scan(
                FilterExpression="#status = :status AND monitoring_end > :now AND begins_with(pk, :pk_prefix)",
                ExpressionAttributeNames={"#status": "status"},
                ExpressionAttributeValues={
                    ":status": OptimizationStatus.APPLIED.value,
                    ":now": now,
                    ":pk_prefix": "opt#"
                }
            )

            optimizations = []
            for item in response.get("Items", []):
                opt = self.get_optimization(item.get("optimization_id"))
                if opt:
                    optimizations.append(opt)

            return optimizations

        except Exception as e:
            logger.error(f"Failed to get monitoring optimizations: {e}")
            return []

    def save_version(self, version: RuleVersion) -> None:
        """Save rule version to DynamoDB."""
        try:
            item = {
                "pk": f"rule#{version.rule_id}",
                "sk": f"version#{version.version:06d}",
                **version.to_dict(),
                "ttl": int((datetime.utcnow() + timedelta(days=365 * 2)).timestamp())
            }
            self.table.put_item(Item=item)

        except Exception as e:
            logger.error(f"Failed to save version: {e}")

    def get_version(self, rule_id: str, version: int) -> Optional[RuleVersion]:
        """Get specific rule version."""
        try:
            response = self.table.get_item(
                Key={"pk": f"rule#{rule_id}", "sk": f"version#{version:06d}"}
            )

            if "Item" not in response:
                return None

            item = response["Item"]
            return RuleVersion(
                rule_id=item["rule_id"],
                version=item["version"],
                rule_content=item["rule_content"],
                created_at=item["created_at"],
                created_by=item["created_by"],
                change_summary=item["change_summary"],
                previous_version=item.get("previous_version"),
                is_current=item.get("is_current", False),
                optimization_id=item.get("optimization_id"),
            )

        except Exception as e:
            logger.error(f"Failed to get version: {e}")
            return None

    def get_latest_version(self, rule_id: str) -> Optional[RuleVersion]:
        """Get latest rule version."""
        try:
            response = self.table.query(
                KeyConditionExpression="pk = :pk AND begins_with(sk, :sk_prefix)",
                ExpressionAttributeValues={
                    ":pk": f"rule#{rule_id}",
                    ":sk_prefix": "version#"
                },
                ScanIndexForward=False,
                Limit=1
            )

            items = response.get("Items", [])
            if not items:
                return None

            item = items[0]
            return RuleVersion(
                rule_id=item["rule_id"],
                version=item["version"],
                rule_content=item["rule_content"],
                created_at=item["created_at"],
                created_by=item["created_by"],
                change_summary=item["change_summary"],
                previous_version=item.get("previous_version"),
                is_current=item.get("is_current", False),
                optimization_id=item.get("optimization_id"),
            )

        except Exception as e:
            logger.error(f"Failed to get latest version: {e}")
            return None

    def get_version_history(self, rule_id: str, limit: int = 10) -> List[RuleVersion]:
        """Get version history for a rule."""
        try:
            response = self.table.query(
                KeyConditionExpression="pk = :pk AND begins_with(sk, :sk_prefix)",
                ExpressionAttributeValues={
                    ":pk": f"rule#{rule_id}",
                    ":sk_prefix": "version#"
                },
                ScanIndexForward=False,
                Limit=limit
            )

            versions = []
            for item in response.get("Items", []):
                versions.append(RuleVersion(
                    rule_id=item["rule_id"],
                    version=item["version"],
                    rule_content=item["rule_content"],
                    created_at=item["created_at"],
                    created_by=item["created_by"],
                    change_summary=item["change_summary"],
                    previous_version=item.get("previous_version"),
                    is_current=item.get("is_current", False),
                    optimization_id=item.get("optimization_id"),
                ))

            return versions

        except Exception as e:
            logger.error(f"Failed to get version history: {e}")
            return []
