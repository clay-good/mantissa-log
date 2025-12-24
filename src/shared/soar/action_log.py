"""Action Log for SOAR audit trail.

This module provides audit logging for all security actions executed
by playbooks. Every action is recorded for compliance, forensics,
and operational visibility.
"""

import json
import logging
import uuid
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List, Optional, Protocol

from .playbook import ActionType

logger = logging.getLogger(__name__)


@dataclass
class ActionLogEntry:
    """A single action log entry for audit purposes.

    Attributes:
        id: Unique log entry ID
        timestamp: When the action occurred
        execution_id: Playbook execution ID
        playbook_id: Playbook ID
        step_id: Step ID within the playbook
        action_type: Type of action executed
        action_parameters: Parameters used for the action
        provider: Provider used (okta, azure, etc.)
        target: Target of the action (user ID, IP, hostname)
        result: Action result (success/failure)
        output: Action output data
        error: Error message if failed
        dry_run: Whether this was a dry run
        user_id: User who triggered the action (for manual triggers)
        context: Additional context (alert info, etc.)
    """
    id: str
    timestamp: datetime
    execution_id: str
    playbook_id: str
    step_id: str
    action_type: ActionType
    action_parameters: Dict[str, Any]
    provider: Optional[str]
    target: Optional[str]
    result: str  # success, failure, skipped
    output: Dict[str, Any] = field(default_factory=dict)
    error: Optional[str] = None
    dry_run: bool = False
    user_id: Optional[str] = None
    context: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        if isinstance(self.action_type, str):
            self.action_type = ActionType(self.action_type)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for serialization."""
        return {
            "id": self.id,
            "timestamp": self.timestamp.isoformat(),
            "execution_id": self.execution_id,
            "playbook_id": self.playbook_id,
            "step_id": self.step_id,
            "action_type": self.action_type.value,
            "action_parameters": self.action_parameters,
            "provider": self.provider,
            "target": self.target,
            "result": self.result,
            "output": self.output,
            "error": self.error,
            "dry_run": self.dry_run,
            "user_id": self.user_id,
            "context": self.context,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ActionLogEntry":
        """Create from dictionary."""
        timestamp = data.get("timestamp")
        if isinstance(timestamp, str):
            timestamp = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))

        action_type = data.get("action_type", "custom")
        if isinstance(action_type, str):
            action_type = ActionType(action_type)

        return cls(
            id=data.get("id", str(uuid.uuid4())),
            timestamp=timestamp or datetime.now(timezone.utc),
            execution_id=data.get("execution_id", ""),
            playbook_id=data.get("playbook_id", ""),
            step_id=data.get("step_id", ""),
            action_type=action_type,
            action_parameters=data.get("action_parameters", {}),
            provider=data.get("provider"),
            target=data.get("target"),
            result=data.get("result", "unknown"),
            output=data.get("output", {}),
            error=data.get("error"),
            dry_run=data.get("dry_run", False),
            user_id=data.get("user_id"),
            context=data.get("context", {}),
        )


class ActionLogProtocol(Protocol):
    """Protocol defining the action log interface."""

    def log_action(
        self,
        execution_id: str,
        playbook_id: str,
        step_id: str,
        action_type: ActionType,
        action_parameters: Dict[str, Any],
        result: str,
        **kwargs,
    ) -> str:
        """Log an action."""
        ...

    def get_actions(
        self, execution_id: str, limit: int
    ) -> List[ActionLogEntry]:
        """Get actions for an execution."""
        ...

    def get_recent_actions(
        self,
        target: Optional[str],
        action_type: Optional[ActionType],
        since: datetime,
        limit: int,
    ) -> List[ActionLogEntry]:
        """Get recent actions for cooldown checks."""
        ...


class ActionLogStore(ABC):
    """Abstract base class for action log storage."""

    @abstractmethod
    def save(self, entry: ActionLogEntry) -> str:
        """Save a log entry."""
        pass

    @abstractmethod
    def get_by_execution(
        self, execution_id: str, limit: int = 100
    ) -> List[ActionLogEntry]:
        """Get log entries for an execution."""
        pass

    @abstractmethod
    def get_recent(
        self,
        target: Optional[str] = None,
        action_type: Optional[ActionType] = None,
        since: Optional[datetime] = None,
        limit: int = 100,
    ) -> List[ActionLogEntry]:
        """Get recent log entries with filters."""
        pass


class InMemoryActionLogStore(ActionLogStore):
    """In-memory action log store for testing and development."""

    def __init__(self):
        self._entries: Dict[str, ActionLogEntry] = {}

    def save(self, entry: ActionLogEntry) -> str:
        self._entries[entry.id] = entry
        return entry.id

    def get_by_execution(
        self, execution_id: str, limit: int = 100
    ) -> List[ActionLogEntry]:
        entries = [
            e for e in self._entries.values()
            if e.execution_id == execution_id
        ]
        entries.sort(key=lambda e: e.timestamp, reverse=True)
        return entries[:limit]

    def get_recent(
        self,
        target: Optional[str] = None,
        action_type: Optional[ActionType] = None,
        since: Optional[datetime] = None,
        limit: int = 100,
    ) -> List[ActionLogEntry]:
        entries = list(self._entries.values())

        if target:
            entries = [e for e in entries if e.target == target]
        if action_type:
            entries = [e for e in entries if e.action_type == action_type]
        if since:
            entries = [e for e in entries if e.timestamp >= since]

        entries.sort(key=lambda e: e.timestamp, reverse=True)
        return entries[:limit]


class DynamoDBActionLogStore(ActionLogStore):
    """DynamoDB-backed action log store for production use."""

    def __init__(
        self,
        table_name: str = "mantissa-soar-action-log",
        region: Optional[str] = None,
    ):
        """Initialize DynamoDB action log store.

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

    def save(self, entry: ActionLogEntry) -> str:
        item = entry.to_dict()
        item["pk"] = entry.id
        item["sk"] = entry.timestamp.isoformat()
        item["execution_pk"] = entry.execution_id
        item["target_pk"] = entry.target or "none"
        item["action_type_pk"] = entry.action_type.value

        # TTL for log retention (90 days default)
        ttl_days = 90
        item["ttl"] = int((entry.timestamp + timedelta(days=ttl_days)).timestamp())

        self.table.put_item(Item=item)
        return entry.id

    def get_by_execution(
        self, execution_id: str, limit: int = 100
    ) -> List[ActionLogEntry]:
        try:
            response = self.table.query(
                IndexName="execution-index",
                KeyConditionExpression="execution_pk = :eid",
                ExpressionAttributeValues={":eid": execution_id},
                ScanIndexForward=False,
                Limit=limit,
            )

            entries = []
            for item in response.get("Items", []):
                for key in ["pk", "sk", "execution_pk", "target_pk", "action_type_pk", "ttl"]:
                    item.pop(key, None)
                entries.append(ActionLogEntry.from_dict(item))

            return entries
        except Exception as e:
            logger.error(f"Error getting actions for execution: {e}")
            return []

    def get_recent(
        self,
        target: Optional[str] = None,
        action_type: Optional[ActionType] = None,
        since: Optional[datetime] = None,
        limit: int = 100,
    ) -> List[ActionLogEntry]:
        try:
            # Use target index if target specified
            if target:
                response = self.table.query(
                    IndexName="target-index",
                    KeyConditionExpression="target_pk = :target",
                    ExpressionAttributeValues={":target": target},
                    ScanIndexForward=False,
                    Limit=limit,
                )
            else:
                # Fall back to scan (not ideal for large tables)
                response = self.table.scan(Limit=limit)

            entries = []
            for item in response.get("Items", []):
                for key in ["pk", "sk", "execution_pk", "target_pk", "action_type_pk", "ttl"]:
                    item.pop(key, None)
                entry = ActionLogEntry.from_dict(item)

                # Apply filters
                if action_type and entry.action_type != action_type:
                    continue
                if since and entry.timestamp < since:
                    continue

                entries.append(entry)

            entries.sort(key=lambda e: e.timestamp, reverse=True)
            return entries[:limit]
        except Exception as e:
            logger.error(f"Error getting recent actions: {e}")
            return []


class ActionLog:
    """Service for logging security actions.

    Provides audit logging for all actions executed by playbooks.
    Supports cooldown checks to prevent action spam.
    """

    def __init__(self, store: Optional[ActionLogStore] = None):
        """Initialize action log.

        Args:
            store: Action log store backend
        """
        self.store = store or InMemoryActionLogStore()

    def log_action(
        self,
        execution_id: str,
        playbook_id: str,
        step_id: str,
        action_type: ActionType,
        action_parameters: Dict[str, Any],
        result: str,
        provider: Optional[str] = None,
        target: Optional[str] = None,
        output: Optional[Dict[str, Any]] = None,
        error: Optional[str] = None,
        dry_run: bool = False,
        user_id: Optional[str] = None,
        context: Optional[Dict[str, Any]] = None,
    ) -> str:
        """Log an action execution.

        Args:
            execution_id: Playbook execution ID
            playbook_id: Playbook ID
            step_id: Step ID
            action_type: Type of action
            action_parameters: Parameters used
            result: Result (success, failure, skipped)
            provider: Provider used
            target: Target of action
            output: Action output
            error: Error message if failed
            dry_run: Whether this was a dry run
            user_id: User who triggered
            context: Additional context

        Returns:
            Log entry ID
        """
        entry = ActionLogEntry(
            id=str(uuid.uuid4()),
            timestamp=datetime.now(timezone.utc),
            execution_id=execution_id,
            playbook_id=playbook_id,
            step_id=step_id,
            action_type=action_type,
            action_parameters=action_parameters,
            provider=provider,
            target=target,
            result=result,
            output=output or {},
            error=error,
            dry_run=dry_run,
            user_id=user_id,
            context=context or {},
        )

        entry_id = self.store.save(entry)
        logger.info(
            f"Logged action: {action_type.value} for {target}, "
            f"result: {result}, execution: {execution_id}"
        )
        return entry_id

    def get_actions(
        self, execution_id: str, limit: int = 100
    ) -> List[ActionLogEntry]:
        """Get actions for an execution.

        Args:
            execution_id: Execution ID
            limit: Maximum results

        Returns:
            List of ActionLogEntry objects
        """
        return self.store.get_by_execution(execution_id, limit)

    def get_recent_actions(
        self,
        target: Optional[str] = None,
        action_type: Optional[ActionType] = None,
        since: Optional[datetime] = None,
        limit: int = 100,
    ) -> List[ActionLogEntry]:
        """Get recent actions for cooldown checks.

        Args:
            target: Filter by target
            action_type: Filter by action type
            since: Filter by time (entries after this time)
            limit: Maximum results

        Returns:
            List of ActionLogEntry objects
        """
        if since is None:
            since = datetime.now(timezone.utc) - timedelta(hours=24)

        return self.store.get_recent(
            target=target,
            action_type=action_type,
            since=since,
            limit=limit,
        )

    def check_cooldown(
        self,
        target: str,
        action_type: ActionType,
        cooldown_minutes: int = 60,
    ) -> tuple[bool, Optional[ActionLogEntry]]:
        """Check if an action is on cooldown.

        Prevents executing the same action on the same target
        within the cooldown period.

        Args:
            target: Target of the action
            action_type: Type of action
            cooldown_minutes: Cooldown period in minutes

        Returns:
            Tuple of (is_allowed, recent_action if blocked)
        """
        since = datetime.now(timezone.utc) - timedelta(minutes=cooldown_minutes)
        recent = self.get_recent_actions(
            target=target,
            action_type=action_type,
            since=since,
            limit=1,
        )

        if recent:
            return False, recent[0]
        return True, None


def get_action_log(store_type: Optional[str] = None, **kwargs) -> ActionLog:
    """Factory function to get an action log instance.

    Args:
        store_type: Type of store ("memory" or "dynamodb")
        **kwargs: Store-specific configuration

    Returns:
        ActionLog instance
    """
    import os

    if store_type is None:
        store_type = os.environ.get("ACTION_LOG_STORE_TYPE", "memory")

    if store_type == "dynamodb":
        table_name = kwargs.get(
            "table_name",
            os.environ.get("ACTION_LOG_TABLE_NAME", "mantissa-soar-action-log"),
        )
        region = kwargs.get("region", os.environ.get("AWS_REGION"))
        store = DynamoDBActionLogStore(table_name=table_name, region=region)
    else:
        store = InMemoryActionLogStore()

    return ActionLog(store=store)
