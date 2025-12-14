"""DynamoDB-based cost store for AWS implementation."""

import json
import logging
from datetime import datetime
from decimal import Decimal
from typing import Any, Dict, List, Optional

import boto3
from boto3.dynamodb.conditions import Attr, Key

from ...shared.cost.controls import (
    CostAction,
    CostPeriod,
    CostRecord,
    CostThreshold,
    SpendingLimit,
)

logger = logging.getLogger(__name__)


class DynamoDBCostStore:
    """DynamoDB implementation of CostStore protocol."""

    def __init__(
        self,
        table_name: str = "mantissa-cost-records",
        limits_table_name: str = "mantissa-spending-limits",
        region: Optional[str] = None
    ):
        """Initialize DynamoDB cost store.

        Args:
            table_name: Name of the cost records table
            limits_table_name: Name of the spending limits table
            region: AWS region (uses default if not specified)
        """
        self.dynamodb = boto3.resource("dynamodb", region_name=region)
        self.table = self.dynamodb.Table(table_name)
        self.limits_table = self.dynamodb.Table(limits_table_name)
        self.table_name = table_name
        self.limits_table_name = limits_table_name

    def record_cost(self, record: CostRecord) -> None:
        """Record a cost event to DynamoDB.

        Args:
            record: Cost record to persist
        """
        item = {
            "pk": f"COST#{record.resource_type}",
            "sk": f"{record.timestamp.isoformat()}#{record.record_id}",
            "record_id": record.record_id,
            "timestamp": record.timestamp.isoformat(),
            "amount": record.amount,
            "resource_type": record.resource_type,
            "resource_id": record.resource_id,
            "description": record.description,
            "metadata": record.metadata,
            # GSI for querying by resource_id
            "gsi1pk": f"RESOURCE#{record.resource_id}",
            "gsi1sk": record.timestamp.isoformat(),
            # GSI for date-based queries
            "date": record.timestamp.strftime("%Y-%m-%d"),
            "hour": record.timestamp.strftime("%Y-%m-%d-%H"),
        }

        try:
            self.table.put_item(Item=item)
            logger.debug(f"Recorded cost: {record.record_id} - ${record.amount}")
        except Exception as e:
            logger.error(f"Failed to record cost: {e}")
            raise

    def get_costs(
        self,
        start_time: datetime,
        end_time: datetime,
        resource_type: Optional[str] = None,
        resource_id: Optional[str] = None
    ) -> List[CostRecord]:
        """Get cost records for a time period.

        Args:
            start_time: Period start
            end_time: Period end
            resource_type: Optional filter by resource type
            resource_id: Optional filter by resource ID

        Returns:
            List of cost records
        """
        records = []

        try:
            if resource_id:
                # Query by resource_id using GSI
                response = self.table.query(
                    IndexName="gsi1-index",
                    KeyConditionExpression=Key("gsi1pk").eq(f"RESOURCE#{resource_id}")
                    & Key("gsi1sk").between(
                        start_time.isoformat(),
                        end_time.isoformat()
                    )
                )
                items = response.get("Items", [])
            elif resource_type:
                # Query by resource_type using main table
                response = self.table.query(
                    KeyConditionExpression=Key("pk").eq(f"COST#{resource_type}")
                    & Key("sk").between(
                        start_time.isoformat(),
                        end_time.isoformat() + "Z"  # Ensure end is inclusive
                    )
                )
                items = response.get("Items", [])
            else:
                # Scan with time filter (less efficient, use sparingly)
                response = self.table.scan(
                    FilterExpression=Attr("timestamp").between(
                        start_time.isoformat(),
                        end_time.isoformat()
                    ) & Attr("pk").begins_with("COST#")
                )
                items = response.get("Items", [])

            for item in items:
                records.append(CostRecord(
                    record_id=item["record_id"],
                    timestamp=datetime.fromisoformat(item["timestamp"]),
                    amount=Decimal(str(item["amount"])),
                    resource_type=item["resource_type"],
                    resource_id=item["resource_id"],
                    description=item["description"],
                    metadata=item.get("metadata", {})
                ))

        except Exception as e:
            logger.error(f"Failed to get costs: {e}")
            raise

        return records

    def get_spending_limits(
        self,
        scope: str,
        scope_id: Optional[str] = None
    ) -> List[SpendingLimit]:
        """Get spending limits for a scope.

        Args:
            scope: Limit scope (global, rule, user)
            scope_id: Optional scope identifier

        Returns:
            List of spending limits
        """
        limits = []

        try:
            if scope_id:
                pk = f"LIMIT#{scope}#{scope_id}"
            else:
                pk = f"LIMIT#{scope}"

            response = self.limits_table.query(
                KeyConditionExpression=Key("pk").eq(pk)
            )

            for item in response.get("Items", []):
                thresholds = []
                for t in item.get("thresholds", []):
                    thresholds.append(CostThreshold(
                        amount=Decimal(str(t["amount"])),
                        period=CostPeriod(t["period"]),
                        action=CostAction(t["action"]),
                        resource_type=t.get("resource_type", "all"),
                        enabled=t.get("enabled", True),
                        notification_channels=t.get("notification_channels", [])
                    ))

                limits.append(SpendingLimit(
                    limit_id=item["limit_id"],
                    name=item["name"],
                    thresholds=thresholds,
                    scope=item.get("scope", scope),
                    scope_id=item.get("scope_id"),
                    created_at=datetime.fromisoformat(item["created_at"])
                ))

        except Exception as e:
            logger.error(f"Failed to get spending limits: {e}")
            raise

        return limits

    def save_spending_limit(self, limit: SpendingLimit) -> None:
        """Save a spending limit to DynamoDB.

        Args:
            limit: Spending limit to save
        """
        if limit.scope_id:
            pk = f"LIMIT#{limit.scope}#{limit.scope_id}"
        else:
            pk = f"LIMIT#{limit.scope}"

        thresholds = []
        for t in limit.thresholds:
            thresholds.append({
                "amount": str(t.amount),
                "period": t.period.value,
                "action": t.action.value,
                "resource_type": t.resource_type,
                "enabled": t.enabled,
                "notification_channels": t.notification_channels
            })

        item = {
            "pk": pk,
            "sk": limit.limit_id,
            "limit_id": limit.limit_id,
            "name": limit.name,
            "thresholds": thresholds,
            "scope": limit.scope,
            "scope_id": limit.scope_id,
            "created_at": limit.created_at.isoformat()
        }

        try:
            self.limits_table.put_item(Item=item)
            logger.info(f"Saved spending limit: {limit.limit_id}")
        except Exception as e:
            logger.error(f"Failed to save spending limit: {e}")
            raise

    def get_disabled_rules(self) -> List[str]:
        """Get list of rules disabled due to cost.

        Returns:
            List of disabled rule IDs
        """
        try:
            response = self.limits_table.query(
                KeyConditionExpression=Key("pk").eq("DISABLED_RULES")
            )

            return [item["rule_id"] for item in response.get("Items", [])]

        except Exception as e:
            logger.error(f"Failed to get disabled rules: {e}")
            raise

    def disable_rule(self, rule_id: str, reason: str) -> None:
        """Disable a rule due to cost.

        Args:
            rule_id: Rule to disable
            reason: Reason for disabling
        """
        item = {
            "pk": "DISABLED_RULES",
            "sk": rule_id,
            "rule_id": rule_id,
            "reason": reason,
            "disabled_at": datetime.utcnow().isoformat()
        }

        try:
            self.limits_table.put_item(Item=item)
            logger.warning(f"Disabled rule {rule_id}: {reason}")
        except Exception as e:
            logger.error(f"Failed to disable rule: {e}")
            raise

    def enable_rule(self, rule_id: str) -> None:
        """Re-enable a previously disabled rule.

        Args:
            rule_id: Rule to enable
        """
        try:
            self.limits_table.delete_item(
                Key={"pk": "DISABLED_RULES", "sk": rule_id}
            )
            logger.info(f"Re-enabled rule: {rule_id}")
        except Exception as e:
            logger.error(f"Failed to enable rule: {e}")
            raise

    def get_daily_costs(self, date: str) -> Dict[str, Decimal]:
        """Get aggregated costs for a specific date.

        Args:
            date: Date in YYYY-MM-DD format

        Returns:
            Dictionary of resource_type -> total cost
        """
        try:
            response = self.table.query(
                IndexName="date-index",
                KeyConditionExpression=Key("date").eq(date)
            )

            costs: Dict[str, Decimal] = {}
            for item in response.get("Items", []):
                resource_type = item["resource_type"]
                amount = Decimal(str(item["amount"]))
                costs[resource_type] = costs.get(resource_type, Decimal("0")) + amount

            return costs

        except Exception as e:
            logger.error(f"Failed to get daily costs: {e}")
            raise

    def get_hourly_costs(self, hour: str) -> Dict[str, Decimal]:
        """Get aggregated costs for a specific hour.

        Args:
            hour: Hour in YYYY-MM-DD-HH format

        Returns:
            Dictionary of resource_type -> total cost
        """
        try:
            response = self.table.query(
                IndexName="hour-index",
                KeyConditionExpression=Key("hour").eq(hour)
            )

            costs: Dict[str, Decimal] = {}
            for item in response.get("Items", []):
                resource_type = item["resource_type"]
                amount = Decimal(str(item["amount"]))
                costs[resource_type] = costs.get(resource_type, Decimal("0")) + amount

            return costs

        except Exception as e:
            logger.error(f"Failed to get hourly costs: {e}")
            raise


def create_cost_tables(region: Optional[str] = None) -> None:
    """Create DynamoDB tables for cost tracking.

    Args:
        region: AWS region
    """
    dynamodb = boto3.client("dynamodb", region_name=region)

    # Cost records table
    try:
        dynamodb.create_table(
            TableName="mantissa-cost-records",
            KeySchema=[
                {"AttributeName": "pk", "KeyType": "HASH"},
                {"AttributeName": "sk", "KeyType": "RANGE"}
            ],
            AttributeDefinitions=[
                {"AttributeName": "pk", "AttributeType": "S"},
                {"AttributeName": "sk", "AttributeType": "S"},
                {"AttributeName": "gsi1pk", "AttributeType": "S"},
                {"AttributeName": "gsi1sk", "AttributeType": "S"},
                {"AttributeName": "date", "AttributeType": "S"},
                {"AttributeName": "hour", "AttributeType": "S"}
            ],
            GlobalSecondaryIndexes=[
                {
                    "IndexName": "gsi1-index",
                    "KeySchema": [
                        {"AttributeName": "gsi1pk", "KeyType": "HASH"},
                        {"AttributeName": "gsi1sk", "KeyType": "RANGE"}
                    ],
                    "Projection": {"ProjectionType": "ALL"}
                },
                {
                    "IndexName": "date-index",
                    "KeySchema": [
                        {"AttributeName": "date", "KeyType": "HASH"},
                        {"AttributeName": "sk", "KeyType": "RANGE"}
                    ],
                    "Projection": {"ProjectionType": "ALL"}
                },
                {
                    "IndexName": "hour-index",
                    "KeySchema": [
                        {"AttributeName": "hour", "KeyType": "HASH"},
                        {"AttributeName": "sk", "KeyType": "RANGE"}
                    ],
                    "Projection": {"ProjectionType": "ALL"}
                }
            ],
            BillingMode="PAY_PER_REQUEST",
            Tags=[
                {"Key": "Project", "Value": "mantissa-log"},
                {"Key": "Component", "Value": "cost-tracking"}
            ]
        )
        logger.info("Created cost records table")
    except dynamodb.exceptions.ResourceInUseException:
        logger.info("Cost records table already exists")

    # Spending limits table
    try:
        dynamodb.create_table(
            TableName="mantissa-spending-limits",
            KeySchema=[
                {"AttributeName": "pk", "KeyType": "HASH"},
                {"AttributeName": "sk", "KeyType": "RANGE"}
            ],
            AttributeDefinitions=[
                {"AttributeName": "pk", "AttributeType": "S"},
                {"AttributeName": "sk", "AttributeType": "S"}
            ],
            BillingMode="PAY_PER_REQUEST",
            Tags=[
                {"Key": "Project", "Value": "mantissa-log"},
                {"Key": "Component", "Value": "cost-tracking"}
            ]
        )
        logger.info("Created spending limits table")
    except dynamodb.exceptions.ResourceInUseException:
        logger.info("Spending limits table already exists")
