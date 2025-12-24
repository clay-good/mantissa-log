"""Approval Service for SOAR playbook actions.

This module provides the approval workflow functionality for dangerous
security actions that require human review before execution.
"""

import logging
from abc import ABC, abstractmethod
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Protocol

from .playbook import ApprovalRequest, PlaybookStep

logger = logging.getLogger(__name__)


class ApprovalServiceProtocol(Protocol):
    """Protocol defining the approval service interface."""

    def create_approval_request(
        self,
        execution_id: str,
        playbook_id: str,
        step: PlaybookStep,
        context: Dict[str, Any],
        requested_by: str,
        expiry_hours: int,
    ) -> str:
        """Create a new approval request."""
        ...

    def get_approval_request(self, approval_id: str) -> Optional[ApprovalRequest]:
        """Get an approval request by ID."""
        ...

    def approve(
        self, approval_id: str, approver: str, notes: Optional[str]
    ) -> bool:
        """Approve a request."""
        ...

    def deny(
        self, approval_id: str, approver: str, notes: Optional[str]
    ) -> bool:
        """Deny a request."""
        ...

    def list_pending(
        self, approver: Optional[str], limit: int
    ) -> List[ApprovalRequest]:
        """List pending approval requests."""
        ...


class ApprovalStore(ABC):
    """Abstract base class for approval request storage."""

    @abstractmethod
    def save(self, request: ApprovalRequest) -> str:
        """Save an approval request."""
        pass

    @abstractmethod
    def get(self, approval_id: str) -> Optional[ApprovalRequest]:
        """Get an approval request by ID."""
        pass

    @abstractmethod
    def update(self, request: ApprovalRequest) -> bool:
        """Update an approval request."""
        pass

    @abstractmethod
    def list_pending(
        self, approver: Optional[str] = None, limit: int = 100
    ) -> List[ApprovalRequest]:
        """List pending approval requests."""
        pass

    @abstractmethod
    def list_by_execution(self, execution_id: str) -> List[ApprovalRequest]:
        """List approval requests for an execution."""
        pass


class InMemoryApprovalStore(ApprovalStore):
    """In-memory approval store for testing and development."""

    def __init__(self):
        self._requests: Dict[str, ApprovalRequest] = {}

    def save(self, request: ApprovalRequest) -> str:
        self._requests[request.id] = request
        return request.id

    def get(self, approval_id: str) -> Optional[ApprovalRequest]:
        return self._requests.get(approval_id)

    def update(self, request: ApprovalRequest) -> bool:
        if request.id not in self._requests:
            return False
        self._requests[request.id] = request
        return True

    def list_pending(
        self, approver: Optional[str] = None, limit: int = 100
    ) -> List[ApprovalRequest]:
        now = datetime.now(timezone.utc)
        pending = []

        for request in self._requests.values():
            if request.status != "pending":
                continue
            if request.expires_at < now:
                continue
            if approver and approver not in request.approvers:
                continue
            pending.append(request)

        # Sort by requested time
        pending.sort(key=lambda r: r.requested_at, reverse=True)
        return pending[:limit]

    def list_by_execution(self, execution_id: str) -> List[ApprovalRequest]:
        return [
            r for r in self._requests.values()
            if r.execution_id == execution_id
        ]


class DynamoDBApprovalStore(ApprovalStore):
    """DynamoDB-backed approval store for production use."""

    def __init__(
        self,
        table_name: str = "mantissa-soar-approvals",
        region: Optional[str] = None,
    ):
        """Initialize DynamoDB approval store.

        Args:
            table_name: DynamoDB table name
            region: AWS region
        """
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

    def save(self, request: ApprovalRequest) -> str:
        item = request.to_dict()
        item["pk"] = request.id
        item["sk"] = "APPROVAL"
        item["execution_pk"] = request.execution_id
        item["status_pk"] = request.status
        item["expires_ttl"] = int(request.expires_at.timestamp())

        self.table.put_item(Item=item)
        return request.id

    def get(self, approval_id: str) -> Optional[ApprovalRequest]:
        try:
            response = self.table.get_item(
                Key={"pk": approval_id, "sk": "APPROVAL"}
            )
            item = response.get("Item")
            if not item:
                return None

            for key in ["pk", "sk", "execution_pk", "status_pk", "expires_ttl"]:
                item.pop(key, None)

            return ApprovalRequest.from_dict(item)
        except Exception as e:
            logger.error(f"Error getting approval {approval_id}: {e}")
            return None

    def update(self, request: ApprovalRequest) -> bool:
        try:
            item = request.to_dict()
            item["pk"] = request.id
            item["sk"] = "APPROVAL"
            item["execution_pk"] = request.execution_id
            item["status_pk"] = request.status

            self.table.put_item(Item=item)
            return True
        except Exception as e:
            logger.error(f"Error updating approval: {e}")
            return False

    def list_pending(
        self, approver: Optional[str] = None, limit: int = 100
    ) -> List[ApprovalRequest]:
        try:
            response = self.table.query(
                IndexName="status-index",
                KeyConditionExpression="status_pk = :status",
                ExpressionAttributeValues={":status": "pending"},
                Limit=limit,
            )

            requests = []
            for item in response.get("Items", []):
                for key in ["pk", "sk", "execution_pk", "status_pk", "expires_ttl"]:
                    item.pop(key, None)
                request = ApprovalRequest.from_dict(item)

                # Filter by approver if specified
                if approver and approver not in request.approvers:
                    continue

                # Skip expired
                if request.is_expired:
                    continue

                requests.append(request)

            return requests
        except Exception as e:
            logger.error(f"Error listing pending approvals: {e}")
            return []

    def list_by_execution(self, execution_id: str) -> List[ApprovalRequest]:
        try:
            response = self.table.query(
                IndexName="execution-index",
                KeyConditionExpression="execution_pk = :eid",
                ExpressionAttributeValues={":eid": execution_id},
            )

            requests = []
            for item in response.get("Items", []):
                for key in ["pk", "sk", "execution_pk", "status_pk", "expires_ttl"]:
                    item.pop(key, None)
                requests.append(ApprovalRequest.from_dict(item))

            return requests
        except Exception as e:
            logger.error(f"Error listing approvals for execution: {e}")
            return []


class ApprovalService:
    """Service for managing approval requests.

    Handles the approval workflow for dangerous security actions,
    including creating requests, sending notifications, and processing
    approval decisions.
    """

    def __init__(
        self,
        store: Optional[ApprovalStore] = None,
        notification_callback: Optional[callable] = None,
    ):
        """Initialize approval service.

        Args:
            store: Approval store backend
            notification_callback: Optional callback for sending notifications
        """
        self.store = store or InMemoryApprovalStore()
        self.notification_callback = notification_callback

    def create_approval_request(
        self,
        execution_id: str,
        playbook_id: str,
        step: PlaybookStep,
        context: Dict[str, Any],
        requested_by: str = "system",
        expiry_hours: int = 1,
    ) -> str:
        """Create a new approval request.

        Args:
            execution_id: ID of the playbook execution
            playbook_id: ID of the playbook
            step: The step requiring approval
            context: Execution context (alert info, etc.)
            requested_by: Who initiated the request
            expiry_hours: Hours until the request expires

        Returns:
            Approval request ID
        """
        request = ApprovalRequest.create(
            execution_id=execution_id,
            playbook_id=playbook_id,
            step=step,
            context=context,
            requested_by=requested_by,
            expiry_hours=expiry_hours,
        )

        approval_id = self.store.save(request)
        logger.info(
            f"Created approval request {approval_id} for step {step.id} "
            f"in execution {execution_id}"
        )

        # Send notification to approvers
        if self.notification_callback:
            try:
                self.notification_callback(request)
            except Exception as e:
                logger.error(f"Failed to send approval notification: {e}")

        return approval_id

    def get_approval_request(self, approval_id: str) -> Optional[ApprovalRequest]:
        """Get an approval request by ID.

        Args:
            approval_id: ID of the approval request

        Returns:
            ApprovalRequest or None
        """
        request = self.store.get(approval_id)

        # Check for expiration
        if request and request.is_expired and request.status == "pending":
            request.status = "expired"
            self.store.update(request)

        return request

    def approve(
        self,
        approval_id: str,
        approver: str,
        notes: Optional[str] = None,
    ) -> bool:
        """Approve a request.

        Args:
            approval_id: ID of the approval request
            approver: User approving the request
            notes: Optional approval notes

        Returns:
            True if approved successfully
        """
        request = self.store.get(approval_id)
        if not request:
            logger.error(f"Approval request not found: {approval_id}")
            return False

        if request.status != "pending":
            logger.warning(f"Approval {approval_id} is not pending: {request.status}")
            return False

        if request.is_expired:
            logger.warning(f"Approval {approval_id} has expired")
            request.status = "expired"
            self.store.update(request)
            return False

        # Verify approver is authorized
        if approver not in request.approvers and "admin" not in request.approvers:
            logger.warning(f"User {approver} not authorized to approve {approval_id}")
            return False

        request.approve(approver, notes)
        self.store.update(request)

        logger.info(f"Approval {approval_id} approved by {approver}")
        return True

    def deny(
        self,
        approval_id: str,
        approver: str,
        notes: Optional[str] = None,
    ) -> bool:
        """Deny a request.

        Args:
            approval_id: ID of the approval request
            approver: User denying the request
            notes: Optional denial notes

        Returns:
            True if denied successfully
        """
        request = self.store.get(approval_id)
        if not request:
            logger.error(f"Approval request not found: {approval_id}")
            return False

        if request.status != "pending":
            logger.warning(f"Approval {approval_id} is not pending: {request.status}")
            return False

        request.deny(approver, notes)
        self.store.update(request)

        logger.info(f"Approval {approval_id} denied by {approver}")
        return True

    def list_pending(
        self,
        approver: Optional[str] = None,
        limit: int = 100,
    ) -> List[ApprovalRequest]:
        """List pending approval requests.

        Args:
            approver: Filter by approver (returns requests they can approve)
            limit: Maximum number of results

        Returns:
            List of pending ApprovalRequest objects
        """
        return self.store.list_pending(approver=approver, limit=limit)

    def expire_old_requests(self) -> int:
        """Expire old pending requests.

        Called periodically to mark expired requests.

        Returns:
            Number of requests expired
        """
        pending = self.store.list_pending(limit=1000)
        expired_count = 0

        for request in pending:
            if request.is_expired:
                request.status = "expired"
                self.store.update(request)
                expired_count += 1
                logger.info(f"Expired approval request: {request.id}")

        return expired_count

    def get_requests_for_execution(self, execution_id: str) -> List[ApprovalRequest]:
        """Get all approval requests for an execution.

        Args:
            execution_id: ID of the execution

        Returns:
            List of ApprovalRequest objects
        """
        return self.store.list_by_execution(execution_id)


def get_approval_service(store_type: Optional[str] = None, **kwargs) -> ApprovalService:
    """Factory function to get an approval service instance.

    Args:
        store_type: Type of store ("memory" or "dynamodb")
        **kwargs: Store-specific configuration

    Returns:
        ApprovalService instance
    """
    import os

    if store_type is None:
        store_type = os.environ.get("APPROVAL_STORE_TYPE", "memory")

    if store_type == "dynamodb":
        table_name = kwargs.get(
            "table_name",
            os.environ.get("APPROVAL_TABLE_NAME", "mantissa-soar-approvals"),
        )
        region = kwargs.get("region", os.environ.get("AWS_REGION"))
        store = DynamoDBApprovalStore(table_name=table_name, region=region)
    else:
        store = InMemoryApprovalStore()

    return ApprovalService(
        store=store,
        notification_callback=kwargs.get("notification_callback"),
    )
