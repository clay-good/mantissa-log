"""Execution Store for SOAR playbook executions.

This module provides storage backends for playbook execution records,
allowing persistence and retrieval of execution state.
"""

import json
import logging
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from .playbook import ExecutionStatus, PlaybookExecution, StepExecutionResult

logger = logging.getLogger(__name__)


class ExecutionStore(ABC):
    """Abstract base class for execution storage backends."""

    @abstractmethod
    def save(self, execution: PlaybookExecution) -> str:
        """Save an execution record.

        Args:
            execution: PlaybookExecution to save

        Returns:
            Execution ID
        """
        pass

    @abstractmethod
    def get(self, execution_id: str) -> Optional[PlaybookExecution]:
        """Get an execution by ID.

        Args:
            execution_id: ID of execution to retrieve

        Returns:
            PlaybookExecution or None if not found
        """
        pass

    @abstractmethod
    def list(
        self,
        playbook_id: Optional[str] = None,
        status: Optional[ExecutionStatus] = None,
        limit: int = 100,
        offset: int = 0,
    ) -> List[PlaybookExecution]:
        """List executions with optional filters.

        Args:
            playbook_id: Filter by playbook ID
            status: Filter by execution status
            limit: Maximum number of results
            offset: Number of results to skip

        Returns:
            List of PlaybookExecution objects
        """
        pass

    @abstractmethod
    def update_status(
        self,
        execution_id: str,
        status: ExecutionStatus,
        error: Optional[str] = None,
        completed_at: Optional[datetime] = None,
    ) -> bool:
        """Update execution status.

        Args:
            execution_id: ID of execution to update
            status: New status
            error: Optional error message
            completed_at: Optional completion timestamp

        Returns:
            True if updated successfully
        """
        pass

    @abstractmethod
    def add_step_result(
        self, execution_id: str, step_result: StepExecutionResult
    ) -> bool:
        """Add a step result to an execution.

        Args:
            execution_id: ID of execution
            step_result: Step execution result to add

        Returns:
            True if added successfully
        """
        pass

    @abstractmethod
    def set_pending_approval(
        self, execution_id: str, approval_id: str, step_id: str
    ) -> bool:
        """Set pending approval for an execution.

        Args:
            execution_id: ID of execution
            approval_id: ID of approval request
            step_id: ID of step waiting for approval

        Returns:
            True if set successfully
        """
        pass


class InMemoryExecutionStore(ExecutionStore):
    """In-memory execution store for testing and development."""

    def __init__(self):
        self._executions: Dict[str, PlaybookExecution] = {}

    def save(self, execution: PlaybookExecution) -> str:
        self._executions[execution.execution_id] = execution
        return execution.execution_id

    def get(self, execution_id: str) -> Optional[PlaybookExecution]:
        return self._executions.get(execution_id)

    def list(
        self,
        playbook_id: Optional[str] = None,
        status: Optional[ExecutionStatus] = None,
        limit: int = 100,
        offset: int = 0,
    ) -> List[PlaybookExecution]:
        executions = list(self._executions.values())

        # Apply filters
        if playbook_id:
            executions = [e for e in executions if e.playbook_id == playbook_id]
        if status:
            executions = [e for e in executions if e.status == status]

        # Sort by start time descending
        executions.sort(key=lambda e: e.started_at, reverse=True)

        # Apply pagination
        return executions[offset : offset + limit]

    def update_status(
        self,
        execution_id: str,
        status: ExecutionStatus,
        error: Optional[str] = None,
        completed_at: Optional[datetime] = None,
    ) -> bool:
        execution = self._executions.get(execution_id)
        if not execution:
            return False

        execution.status = status
        if error:
            execution.error = error
        if completed_at:
            execution.completed_at = completed_at

        return True

    def add_step_result(
        self, execution_id: str, step_result: StepExecutionResult
    ) -> bool:
        execution = self._executions.get(execution_id)
        if not execution:
            return False

        execution.step_results.append(step_result)
        execution.current_step_id = step_result.next_step_id
        return True

    def set_pending_approval(
        self, execution_id: str, approval_id: str, step_id: str
    ) -> bool:
        execution = self._executions.get(execution_id)
        if not execution:
            return False

        execution.pending_approval_id = approval_id
        execution.current_step_id = step_id
        execution.status = ExecutionStatus.PENDING_APPROVAL
        return True


class DynamoDBExecutionStore(ExecutionStore):
    """DynamoDB-backed execution store for production use."""

    def __init__(
        self,
        table_name: str = "mantissa-soar-executions",
        region: Optional[str] = None,
    ):
        """Initialize DynamoDB execution store.

        Args:
            table_name: DynamoDB table name
            region: AWS region (default: use environment)
        """
        self.table_name = table_name
        self.region = region
        self._client = None
        self._table = None

    @property
    def client(self):
        """Lazy-load DynamoDB client."""
        if self._client is None:
            import boto3
            self._client = boto3.client(
                "dynamodb",
                region_name=self.region,
            )
        return self._client

    @property
    def table(self):
        """Lazy-load DynamoDB table resource."""
        if self._table is None:
            import boto3
            dynamodb = boto3.resource(
                "dynamodb",
                region_name=self.region,
            )
            self._table = dynamodb.Table(self.table_name)
        return self._table

    def save(self, execution: PlaybookExecution) -> str:
        item = execution.to_dict()
        item["pk"] = execution.execution_id
        item["sk"] = "EXECUTION"
        item["gsi1pk"] = execution.playbook_id
        item["gsi1sk"] = execution.started_at.isoformat()
        item["status_index"] = execution.status.value

        self.table.put_item(Item=item)
        logger.info(f"Saved execution: {execution.execution_id}")
        return execution.execution_id

    def get(self, execution_id: str) -> Optional[PlaybookExecution]:
        try:
            response = self.table.get_item(
                Key={"pk": execution_id, "sk": "EXECUTION"}
            )
            item = response.get("Item")
            if not item:
                return None

            # Remove DynamoDB-specific keys
            for key in ["pk", "sk", "gsi1pk", "gsi1sk", "status_index"]:
                item.pop(key, None)

            return PlaybookExecution.from_dict(item)
        except Exception as e:
            logger.error(f"Error getting execution {execution_id}: {e}")
            return None

    def list(
        self,
        playbook_id: Optional[str] = None,
        status: Optional[ExecutionStatus] = None,
        limit: int = 100,
        offset: int = 0,
    ) -> List[PlaybookExecution]:
        try:
            if playbook_id:
                # Query by playbook using GSI
                response = self.table.query(
                    IndexName="gsi1-playbook-index",
                    KeyConditionExpression="gsi1pk = :pk",
                    ExpressionAttributeValues={":pk": playbook_id},
                    ScanIndexForward=False,
                    Limit=limit + offset,
                )
            elif status:
                # Query by status using GSI
                response = self.table.query(
                    IndexName="status-index",
                    KeyConditionExpression="status_index = :status",
                    ExpressionAttributeValues={":status": status.value},
                    ScanIndexForward=False,
                    Limit=limit + offset,
                )
            else:
                # Scan all (not recommended for large tables)
                response = self.table.scan(Limit=limit + offset)

            items = response.get("Items", [])
            executions = []

            for item in items[offset:]:
                for key in ["pk", "sk", "gsi1pk", "gsi1sk", "status_index"]:
                    item.pop(key, None)
                executions.append(PlaybookExecution.from_dict(item))

            return executions
        except Exception as e:
            logger.error(f"Error listing executions: {e}")
            return []

    def update_status(
        self,
        execution_id: str,
        status: ExecutionStatus,
        error: Optional[str] = None,
        completed_at: Optional[datetime] = None,
    ) -> bool:
        try:
            update_expr = "SET #status = :status, status_index = :status_val"
            expr_values = {
                ":status": status.value,
                ":status_val": status.value,
            }
            expr_names = {"#status": "status"}

            if error:
                update_expr += ", #error = :error"
                expr_values[":error"] = error
                expr_names["#error"] = "error"

            if completed_at:
                update_expr += ", completed_at = :completed"
                expr_values[":completed"] = completed_at.isoformat()

            self.table.update_item(
                Key={"pk": execution_id, "sk": "EXECUTION"},
                UpdateExpression=update_expr,
                ExpressionAttributeValues=expr_values,
                ExpressionAttributeNames=expr_names,
            )
            return True
        except Exception as e:
            logger.error(f"Error updating execution status: {e}")
            return False

    def add_step_result(
        self, execution_id: str, step_result: StepExecutionResult
    ) -> bool:
        try:
            self.table.update_item(
                Key={"pk": execution_id, "sk": "EXECUTION"},
                UpdateExpression="SET step_results = list_append(if_not_exists(step_results, :empty), :result), current_step_id = :next",
                ExpressionAttributeValues={
                    ":result": [step_result.to_dict()],
                    ":empty": [],
                    ":next": step_result.next_step_id,
                },
            )
            return True
        except Exception as e:
            logger.error(f"Error adding step result: {e}")
            return False

    def set_pending_approval(
        self, execution_id: str, approval_id: str, step_id: str
    ) -> bool:
        try:
            self.table.update_item(
                Key={"pk": execution_id, "sk": "EXECUTION"},
                UpdateExpression="SET pending_approval_id = :approval, current_step_id = :step, #status = :status, status_index = :status",
                ExpressionAttributeValues={
                    ":approval": approval_id,
                    ":step": step_id,
                    ":status": ExecutionStatus.PENDING_APPROVAL.value,
                },
                ExpressionAttributeNames={"#status": "status"},
            )
            return True
        except Exception as e:
            logger.error(f"Error setting pending approval: {e}")
            return False


def get_execution_store(store_type: Optional[str] = None, **kwargs) -> ExecutionStore:
    """Factory function to get an execution store instance.

    Args:
        store_type: Type of store ("memory" or "dynamodb")
        **kwargs: Store-specific configuration

    Returns:
        ExecutionStore instance
    """
    import os

    if store_type is None:
        store_type = os.environ.get("EXECUTION_STORE_TYPE", "memory")

    if store_type == "dynamodb":
        table_name = kwargs.get(
            "table_name",
            os.environ.get("EXECUTION_TABLE_NAME", "mantissa-soar-executions"),
        )
        region = kwargs.get("region", os.environ.get("AWS_REGION"))
        return DynamoDBExecutionStore(table_name=table_name, region=region)
    else:
        return InMemoryExecutionStore()
