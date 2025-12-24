"""SOAR Playbook Data Models.

This module provides data models for Security Orchestration, Automation, and Response
(SOAR) playbooks, actions, and execution records.

Playbooks define automated response workflows that can be triggered by alerts,
manual invocation, schedules, or webhooks. Each playbook contains a series of
steps that execute actions like disabling accounts, blocking IPs, creating tickets,
or calling external webhooks.

Key concepts:
- Playbook: A reusable workflow definition with steps and triggers
- PlaybookStep: An individual action within a playbook
- PlaybookExecution: A runtime instance of a playbook being executed
- ApprovalRequest: A request for human approval before executing a dangerous action
"""

import fnmatch
import json
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Protocol, Set

import yaml


class ActionType(Enum):
    """Types of actions that can be executed in a playbook step.

    These actions map to specific integrations with identity providers,
    security tools, and external services.
    """
    # Notification actions
    NOTIFY = "notify"  # Send notification (Slack, email, PagerDuty)
    SEND_NOTIFICATION = "send_notification"  # Alias for notify (backwards compatibility)

    # Ticketing actions
    CREATE_TICKET = "create_ticket"  # Create Jira/ServiceNow ticket

    # Identity/user actions
    TERMINATE_SESSIONS = "terminate_sessions"  # End user sessions
    REVOKE_SESSIONS = "revoke_sessions"  # Alias for terminate_sessions
    DISABLE_ACCOUNT = "disable_account"  # Disable user account
    DISABLE_USER = "disable_user"  # Alias for disable_account (backwards compatibility)
    ENABLE_ACCOUNT = "enable_account"  # Re-enable user account
    ENABLE_USER = "enable_user"  # Alias for enable_account (backwards compatibility)
    FORCE_PASSWORD_RESET = "force_password_reset"  # Require password change
    FORCE_MFA = "force_mfa"  # Force MFA enrollment/verification
    REVOKE_TOKENS = "revoke_tokens"  # Revoke OAuth/API tokens

    # Network/IP actions
    BLOCK_IP = "block_ip"  # Block IP address
    UNBLOCK_IP = "unblock_ip"  # Remove IP block

    # Host/endpoint actions
    ISOLATE_HOST = "isolate_host"  # Network isolation
    UNISOLATE_HOST = "unisolate_host"  # Remove isolation

    # Investigation actions
    RUN_QUERY = "run_query"  # Execute investigation query
    RUN_SCRIPT = "run_script"  # Execute a script or command

    # Integration actions
    WEBHOOK = "webhook"  # Call external webhook
    CUSTOM = "custom"  # Custom Lambda code

    @classmethod
    def dangerous_actions(cls) -> Set["ActionType"]:
        """Return set of actions that typically require approval."""
        return {
            cls.DISABLE_ACCOUNT,
            cls.DISABLE_USER,
            cls.TERMINATE_SESSIONS,
            cls.REVOKE_SESSIONS,
            cls.FORCE_PASSWORD_RESET,
            cls.FORCE_MFA,
            cls.REVOKE_TOKENS,
            cls.BLOCK_IP,
            cls.ISOLATE_HOST,
        }


class PlaybookTriggerType(Enum):
    """Types of triggers that can start a playbook execution."""
    ALERT = "alert"  # Triggered by detection alert
    MANUAL = "manual"  # Triggered by user
    SCHEDULED = "scheduled"  # Triggered by schedule
    WEBHOOK = "webhook"  # Triggered by external webhook


class ExecutionStatus(Enum):
    """Status of a playbook or step execution."""
    PENDING = "pending"  # Waiting to start
    RUNNING = "running"  # In progress
    PENDING_APPROVAL = "pending_approval"  # Waiting for approval
    APPROVED = "approved"  # Approval granted, continuing
    DENIED = "denied"  # Approval denied, stopped
    COMPLETED = "completed"  # Finished successfully
    FAILED = "failed"  # Finished with error
    CANCELLED = "cancelled"  # Cancelled by user
    TIMED_OUT = "timed_out"  # Exceeded timeout

    @classmethod
    def terminal_statuses(cls) -> Set["ExecutionStatus"]:
        """Return set of statuses that indicate execution is complete."""
        return {
            cls.COMPLETED,
            cls.FAILED,
            cls.DENIED,
            cls.CANCELLED,
            cls.TIMED_OUT,
        }


class AlertProtocol(Protocol):
    """Protocol defining the interface for alerts that can trigger playbooks."""
    severity: str
    rule_name: str
    rule_id: str
    tags: List[str]

    def to_dict(self) -> Dict[str, Any]:
        ...


@dataclass
class PlaybookStep:
    """Represents a single step/action within a playbook.

    Each step executes one action and can specify conditional logic,
    success/failure paths, retry behavior, and approval requirements.

    Attributes:
        id: Unique step identifier within the playbook (also accepts step_id)
        name: Human-readable name for the step
        action_type: Type of action to execute
        provider: Target provider (okta, crowdstrike, jira, etc.) or "auto"
        parameters: Action parameters, may contain Jinja2 templates
        condition: Jinja2 condition, step runs only if True
        on_success: Next step ID on success (None for end)
        on_failure: Next step ID on failure (None for end)
        requires_approval: Whether this step needs human approval
        approval_roles: Roles that can approve this step
        approval_timeout_seconds: Timeout for approval requests
        timeout_seconds: Maximum time for step execution
        retry_count: Number of retries on failure (0 = no retry)
        retry_delay_seconds: Delay between retries
    """
    name: str
    action_type: ActionType
    id: str = ""
    step_id: str = ""  # Alias for id (backwards compatibility)
    provider: Optional[str] = None
    parameters: Dict[str, Any] = field(default_factory=dict)
    condition: Optional[str] = None
    on_success: Optional[str] = None
    on_failure: Optional[str] = None
    depends_on: Optional[List[str]] = None  # Step IDs this step depends on
    requires_approval: Any = False  # Can be bool or ApprovalRequirement enum
    approval_roles: List[str] = field(default_factory=list)
    approval_timeout_seconds: int = 3600  # 1 hour default for approval requests
    timeout_seconds: int = 300
    retry_count: int = 0
    retry_delay_seconds: int = 60

    def __post_init__(self):
        """Validate and normalize fields after initialization."""
        # Handle step_id alias for id
        if self.step_id and not self.id:
            self.id = self.step_id
        elif self.id and not self.step_id:
            self.step_id = self.id

        # Convert action_type from string if needed
        if isinstance(self.action_type, str):
            self.action_type = ActionType(self.action_type)

        # Auto-detect if approval is needed for dangerous actions
        if not self.requires_approval and self.action_type in ActionType.dangerous_actions():
            # Don't auto-set, but could log a warning
            pass

    def to_dict(self) -> Dict[str, Any]:
        """Convert step to dictionary for serialization."""
        result = {
            "id": self.id,
            "name": self.name,
            "action_type": self.action_type.value,
            "parameters": self.parameters,
            "timeout_seconds": self.timeout_seconds,
            "retry_count": self.retry_count,
            "retry_delay_seconds": self.retry_delay_seconds,
        }

        if self.provider:
            result["provider"] = self.provider
        if self.condition:
            result["condition"] = self.condition
        if self.on_success:
            result["on_success"] = self.on_success
        if self.on_failure:
            result["on_failure"] = self.on_failure
        if self.requires_approval:
            result["requires_approval"] = self.requires_approval
            result["approval_roles"] = self.approval_roles

        return result

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "PlaybookStep":
        """Create PlaybookStep from dictionary."""
        action_type = data.get("action_type", "webhook")
        if isinstance(action_type, str):
            action_type = ActionType(action_type)

        return cls(
            id=data.get("id", str(uuid.uuid4())),
            name=data.get("name", "Unnamed Step"),
            action_type=action_type,
            provider=data.get("provider"),
            parameters=data.get("parameters", {}),
            condition=data.get("condition"),
            on_success=data.get("on_success"),
            on_failure=data.get("on_failure"),
            requires_approval=data.get("requires_approval", False),
            approval_roles=data.get("approval_roles", []),
            timeout_seconds=data.get("timeout_seconds", 300),
            retry_count=data.get("retry_count", 0),
            retry_delay_seconds=data.get("retry_delay_seconds", 60),
        )


@dataclass
class PlaybookTrigger:
    """Defines when and how a playbook should be triggered.

    Attributes:
        trigger_type: Type of trigger (alert, manual, scheduled, webhook)
        conditions: Trigger-specific conditions
            For ALERT type:
                - severity: List of severities that trigger (e.g., ["high", "critical"])
                - rule_patterns: Rule name patterns with wildcards (e.g., ["*brute_force*"])
                - tags: Alert tags to match
            For SCHEDULED type:
                - schedule: Cron or rate expression (e.g., "rate(1 hour)")
            For WEBHOOK type:
                - secret: Webhook secret for validation
    """
    trigger_type: PlaybookTriggerType
    conditions: Dict[str, Any] = field(default_factory=dict)

    def __post_init__(self):
        """Normalize trigger type."""
        if isinstance(self.trigger_type, str):
            self.trigger_type = PlaybookTriggerType(self.trigger_type)

    def matches_alert(self, alert: AlertProtocol) -> bool:
        """Check if an alert matches this trigger's conditions.

        Args:
            alert: Alert to check

        Returns:
            True if alert matches trigger conditions
        """
        if self.trigger_type != PlaybookTriggerType.ALERT:
            return False

        # Check severity
        severity_list = self.conditions.get("severity", [])
        if severity_list:
            if alert.severity.lower() not in [s.lower() for s in severity_list]:
                return False

        # Check rule patterns
        rule_patterns = self.conditions.get("rule_patterns", [])
        if rule_patterns:
            rule_name = getattr(alert, "rule_name", "") or ""
            rule_id = getattr(alert, "rule_id", "") or ""
            matched = False
            for pattern in rule_patterns:
                if fnmatch.fnmatch(rule_name.lower(), pattern.lower()):
                    matched = True
                    break
                if fnmatch.fnmatch(rule_id.lower(), pattern.lower()):
                    matched = True
                    break
            if not matched:
                return False

        # Check tags
        required_tags = self.conditions.get("tags", [])
        if required_tags:
            alert_tags = [t.lower() for t in (alert.tags or [])]
            if not any(t.lower() in alert_tags for t in required_tags):
                return False

        return True

    def to_dict(self) -> Dict[str, Any]:
        """Convert trigger to dictionary."""
        return {
            "trigger_type": self.trigger_type.value,
            "conditions": self.conditions,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "PlaybookTrigger":
        """Create PlaybookTrigger from dictionary."""
        trigger_type = data.get("trigger_type", "manual")
        if isinstance(trigger_type, str):
            trigger_type = PlaybookTriggerType(trigger_type)

        return cls(
            trigger_type=trigger_type,
            conditions=data.get("conditions", {}),
        )


@dataclass
class Playbook:
    """A complete playbook definition with steps and triggers.

    Playbooks are reusable workflow definitions that automate security response
    actions. They can be triggered by alerts, manual invocation, schedules,
    or webhooks.

    Attributes:
        id: Unique playbook identifier (UUID), also accepts playbook_id
        name: Human-readable playbook name
        description: Detailed description of what the playbook does
        version: Semantic version (e.g., "1.0.0")
        author: Author name or email
        created: When the playbook was created
        modified: When the playbook was last modified
        enabled: Whether the playbook is active
        trigger: Trigger configuration
        steps: List of playbook steps
        tags: Tags for categorization
        requires_approval: Whether any step requires approval
        dangerous_actions: List of dangerous action types in the playbook
        lambda_arn: ARN of generated Lambda (if deployed)
        lambda_code: Generated Python code for Lambda
    """
    name: str
    description: str
    version: str
    steps: List[PlaybookStep]
    trigger: Optional[PlaybookTrigger] = None
    id: str = ""
    playbook_id: str = ""  # Alias for id (backwards compatibility)
    status: Optional[str] = None  # PlaybookStatus enum value (draft, active, etc.)
    author: str = ""
    created_by: str = ""  # Alias for author
    created: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    modified: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    enabled: bool = True
    tags: List[str] = field(default_factory=list)
    requires_approval: bool = False
    dangerous_actions: List[str] = field(default_factory=list)
    lambda_arn: Optional[str] = None
    lambda_code: Optional[str] = None
    priority: int = 100  # Lower number = higher priority

    def __post_init__(self):
        """Calculate derived fields after initialization."""
        # Handle playbook_id alias for id
        if self.playbook_id and not self.id:
            self.id = self.playbook_id
        elif self.id and not self.playbook_id:
            self.playbook_id = self.id

        # Handle created_by alias for author
        if self.created_by and not self.author:
            self.author = self.created_by
        elif self.author and not self.created_by:
            self.created_by = self.author

        # Normalize status to string if it's an enum
        if self.status is not None and hasattr(self.status, 'value'):
            self.status = self.status.value

        # Calculate requires_approval from steps
        self.requires_approval = any(step.requires_approval for step in self.steps)

        # Calculate dangerous_actions from steps
        self.dangerous_actions = list(set(
            step.action_type.value
            for step in self.steps
            if step.action_type in ActionType.dangerous_actions()
        ))

    def validate(self) -> tuple[bool, List[str]]:
        """Validate playbook structure.

        Checks:
        - All step IDs are unique
        - on_success/on_failure reference valid step IDs or None
        - No circular references
        - At least one step exists

        Returns:
            Tuple of (is_valid, list_of_errors)
        """
        errors = []

        # Check at least one step
        if not self.steps:
            errors.append("Playbook must have at least one step")
            return False, errors

        # Check unique step IDs
        step_ids = [step.id for step in self.steps]
        if len(step_ids) != len(set(step_ids)):
            errors.append("Step IDs must be unique")

        step_id_set = set(step_ids)

        # Check step references
        for step in self.steps:
            if step.on_success and step.on_success not in step_id_set:
                errors.append(f"Step '{step.id}' references unknown on_success step '{step.on_success}'")
            if step.on_failure and step.on_failure not in step_id_set:
                errors.append(f"Step '{step.id}' references unknown on_failure step '{step.on_failure}'")

        # Check for circular references
        if not errors:
            visited: Set[str] = set()
            path: Set[str] = set()

            def has_cycle(step_id: str) -> bool:
                if step_id in path:
                    return True
                if step_id in visited:
                    return False

                visited.add(step_id)
                path.add(step_id)

                step = next((s for s in self.steps if s.id == step_id), None)
                if step:
                    if step.on_success and has_cycle(step.on_success):
                        return True
                    if step.on_failure and has_cycle(step.on_failure):
                        return True

                path.remove(step_id)
                return False

            for step in self.steps:
                if has_cycle(step.id):
                    errors.append(f"Circular reference detected starting from step '{step.id}'")
                    break

        return len(errors) == 0, errors

    def get_first_step(self) -> Optional[PlaybookStep]:
        """Get the first step to execute."""
        return self.steps[0] if self.steps else None

    def get_step(self, step_id: str) -> Optional[PlaybookStep]:
        """Get a step by ID."""
        return next((s for s in self.steps if s.id == step_id), None)

    def to_dict(self) -> Dict[str, Any]:
        """Convert playbook to dictionary."""
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "version": self.version,
            "author": self.author,
            "created": self.created.isoformat(),
            "modified": self.modified.isoformat(),
            "enabled": self.enabled,
            "trigger": self.trigger.to_dict(),
            "steps": [step.to_dict() for step in self.steps],
            "tags": self.tags,
            "requires_approval": self.requires_approval,
            "dangerous_actions": self.dangerous_actions,
            "lambda_arn": self.lambda_arn,
            "lambda_code": self.lambda_code,
        }

    def to_json(self) -> str:
        """Convert playbook to JSON string."""
        return json.dumps(self.to_dict(), indent=2)

    def to_yaml(self) -> str:
        """Convert playbook to YAML string."""
        # Create a clean dict without None values and internal fields
        data = {
            "id": self.id,
            "name": self.name,
            "description": self.description,
            "version": self.version,
            "author": self.author,
            "created": self.created.isoformat(),
            "modified": self.modified.isoformat(),
            "enabled": self.enabled,
            "trigger": self.trigger.to_dict(),
            "steps": [step.to_dict() for step in self.steps],
            "tags": self.tags,
        }
        return yaml.dump(data, default_flow_style=False, sort_keys=False)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Playbook":
        """Create Playbook from dictionary."""
        # Parse timestamps
        created = data.get("created")
        if isinstance(created, str):
            created = datetime.fromisoformat(created.replace("Z", "+00:00"))
        elif created is None:
            created = datetime.utcnow()

        modified = data.get("modified")
        if isinstance(modified, str):
            modified = datetime.fromisoformat(modified.replace("Z", "+00:00"))
        elif modified is None:
            modified = datetime.utcnow()

        # Parse trigger
        trigger_data = data.get("trigger", {"trigger_type": "manual"})
        trigger = PlaybookTrigger.from_dict(trigger_data)

        # Parse steps
        steps_data = data.get("steps", [])
        steps = [PlaybookStep.from_dict(s) for s in steps_data]

        return cls(
            id=data.get("id", str(uuid.uuid4())),
            name=data.get("name", "Unnamed Playbook"),
            description=data.get("description", ""),
            version=data.get("version", "1.0.0"),
            author=data.get("author", "Unknown"),
            created=created,
            modified=modified,
            enabled=data.get("enabled", True),
            trigger=trigger,
            steps=steps,
            tags=data.get("tags", []),
            lambda_arn=data.get("lambda_arn"),
            lambda_code=data.get("lambda_code"),
        )

    @classmethod
    def from_yaml(cls, yaml_content: str) -> "Playbook":
        """Create Playbook from YAML string."""
        data = yaml.safe_load(yaml_content)
        return cls.from_dict(data)


@dataclass
class StepExecutionResult:
    """Result of executing a single playbook step.

    Attributes:
        step_id: ID of the executed step
        step_name: Name of the executed step
        status: Execution status
        started_at: When execution started
        completed_at: When execution completed (if finished)
        duration_ms: Execution duration in milliseconds
        output: Output data from the step
        error: Error message if failed
        next_step_id: ID of the next step to execute
    """
    step_id: str
    step_name: str = ""
    status: ExecutionStatus = ExecutionStatus.PENDING
    started_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    completed_at: Optional[datetime] = None
    duration_ms: Optional[int] = None
    output: Dict[str, Any] = field(default_factory=dict)
    error: Optional[str] = None
    next_step_id: Optional[str] = None
    # Test compatibility fields
    success: bool = False
    executed: bool = False

    def __post_init__(self):
        """Calculate duration and success flag if both timestamps present."""
        if isinstance(self.status, str):
            self.status = ExecutionStatus(self.status)

        if self.completed_at and self.started_at and self.duration_ms is None:
            delta = self.completed_at - self.started_at
            self.duration_ms = int(delta.total_seconds() * 1000)

        # Calculate success from status if not explicitly set
        if self.status == ExecutionStatus.COMPLETED:
            self.success = True
            self.executed = True
        elif self.status in (ExecutionStatus.FAILED, ExecutionStatus.TIMED_OUT):
            self.success = False
            self.executed = True

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        result = {
            "step_id": self.step_id,
            "step_name": self.step_name,
            "status": self.status.value,
            "started_at": self.started_at.isoformat(),
            "output": self.output,
        }

        if self.completed_at:
            result["completed_at"] = self.completed_at.isoformat()
        if self.duration_ms is not None:
            result["duration_ms"] = self.duration_ms
        if self.error:
            result["error"] = self.error
        if self.next_step_id:
            result["next_step_id"] = self.next_step_id

        return result

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "StepExecutionResult":
        """Create from dictionary."""
        started_at = data.get("started_at")
        if isinstance(started_at, str):
            started_at = datetime.fromisoformat(started_at.replace("Z", "+00:00"))

        completed_at = data.get("completed_at")
        if isinstance(completed_at, str):
            completed_at = datetime.fromisoformat(completed_at.replace("Z", "+00:00"))

        status = data.get("status", "pending")
        if isinstance(status, str):
            status = ExecutionStatus(status)

        return cls(
            step_id=data.get("step_id", ""),
            step_name=data.get("step_name", ""),
            status=status,
            started_at=started_at or datetime.utcnow(),
            completed_at=completed_at,
            duration_ms=data.get("duration_ms"),
            output=data.get("output", {}),
            error=data.get("error"),
            next_step_id=data.get("next_step_id"),
        )


@dataclass
class PlaybookExecution:
    """Runtime execution instance of a playbook.

    Tracks the state and progress of a playbook being executed.

    Attributes:
        execution_id: Unique execution identifier
        playbook_id: ID of the playbook being executed
        playbook_version: Version of the playbook
        trigger_type: How the execution was triggered
        trigger_context: Context data from trigger (alert data, etc.)
        status: Current execution status
        started_at: When execution started
        completed_at: When execution completed (if finished)
        current_step_id: ID of currently executing step
        step_results: Results from completed steps
        pending_approval_id: ID of pending approval request
        error: Error message if failed
        dry_run: Whether this is a dry run (no actual actions)
    """
    execution_id: str
    playbook_id: str
    playbook_version: str = "1.0.0"
    trigger_type: PlaybookTriggerType = PlaybookTriggerType.MANUAL
    trigger_context: Dict[str, Any] = field(default_factory=dict)
    status: ExecutionStatus = ExecutionStatus.PENDING
    started_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    completed_at: Optional[datetime] = None
    current_step_id: Optional[str] = None
    current_step: Optional[str] = None  # Alias for current_step_id
    step_results: List[StepExecutionResult] = field(default_factory=list)
    pending_approval_id: Optional[str] = None
    error: Optional[str] = None
    dry_run: bool = False

    def __post_init__(self):
        """Normalize enum fields and handle aliases."""
        if isinstance(self.trigger_type, str):
            self.trigger_type = PlaybookTriggerType(self.trigger_type)
        if isinstance(self.status, str):
            self.status = ExecutionStatus(self.status)

        # Handle current_step alias
        if self.current_step and not self.current_step_id:
            self.current_step_id = self.current_step
        elif self.current_step_id and not self.current_step:
            self.current_step = self.current_step_id

    @property
    def duration_ms(self) -> Optional[int]:
        """Calculate total execution duration in milliseconds."""
        if not self.completed_at:
            return None
        delta = self.completed_at - self.started_at
        return int(delta.total_seconds() * 1000)

    @property
    def is_complete(self) -> bool:
        """Check if execution is in a terminal state."""
        return self.status in ExecutionStatus.terminal_statuses()

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        result = {
            "execution_id": self.execution_id,
            "playbook_id": self.playbook_id,
            "playbook_version": self.playbook_version,
            "trigger_type": self.trigger_type.value,
            "trigger_context": self.trigger_context,
            "status": self.status.value,
            "started_at": self.started_at.isoformat(),
            "step_results": [r.to_dict() for r in self.step_results],
            "dry_run": self.dry_run,
        }

        if self.completed_at:
            result["completed_at"] = self.completed_at.isoformat()
        if self.duration_ms is not None:
            result["duration_ms"] = self.duration_ms
        if self.current_step_id:
            result["current_step_id"] = self.current_step_id
        if self.pending_approval_id:
            result["pending_approval_id"] = self.pending_approval_id
        if self.error:
            result["error"] = self.error

        return result

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "PlaybookExecution":
        """Create from dictionary."""
        started_at = data.get("started_at")
        if isinstance(started_at, str):
            started_at = datetime.fromisoformat(started_at.replace("Z", "+00:00"))

        completed_at = data.get("completed_at")
        if isinstance(completed_at, str):
            completed_at = datetime.fromisoformat(completed_at.replace("Z", "+00:00"))

        trigger_type = data.get("trigger_type", "manual")
        if isinstance(trigger_type, str):
            trigger_type = PlaybookTriggerType(trigger_type)

        status = data.get("status", "pending")
        if isinstance(status, str):
            status = ExecutionStatus(status)

        step_results = [
            StepExecutionResult.from_dict(r)
            for r in data.get("step_results", [])
        ]

        return cls(
            execution_id=data.get("execution_id", str(uuid.uuid4())),
            playbook_id=data.get("playbook_id", ""),
            playbook_version=data.get("playbook_version", "1.0.0"),
            trigger_type=trigger_type,
            trigger_context=data.get("trigger_context", {}),
            status=status,
            started_at=started_at or datetime.utcnow(),
            completed_at=completed_at,
            current_step_id=data.get("current_step_id"),
            step_results=step_results,
            pending_approval_id=data.get("pending_approval_id"),
            error=data.get("error"),
            dry_run=data.get("dry_run", False),
        )


@dataclass
class ApprovalRequest:
    """Request for human approval before executing a dangerous action.

    When a playbook step requires approval, an ApprovalRequest is created
    and the execution pauses until the request is approved or denied.

    Attributes:
        id: Unique approval request identifier
        execution_id: ID of the playbook execution
        playbook_id: ID of the playbook
        step_id: ID of the step requiring approval
        step_name: Name of the step
        action_type: Type of action being approved
        action_parameters: Parameters for the action
        context: Context information (alert info, user info)
        requested_at: When approval was requested
        requested_by: Who initiated the request (system or user)
        approvers: List of users/roles who can approve
        status: Current status (pending, approved, denied, expired)
        decided_at: When a decision was made
        decided_by: Who made the decision
        decision_notes: Notes from the approver
        expires_at: When the request expires
    """
    id: str
    execution_id: str
    step_id: str
    playbook_id: str
    # Optional fields with defaults for test compatibility
    step_name: str = ""
    action_type: Optional[ActionType] = None
    action_parameters: Dict[str, Any] = field(default_factory=dict)
    context: Dict[str, Any] = field(default_factory=dict)
    requested_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    requested_by: str = "system"
    approvers: List[str] = field(default_factory=list)
    status: Any = "pending"  # Can be str or ApprovalStatus enum
    expires_at: Optional[datetime] = None
    decided_at: Optional[datetime] = None
    decided_by: Optional[str] = None
    decision_notes: Optional[str] = None
    # Test compatibility aliases
    approved_by: Optional[str] = None  # Alias for decided_by when status is approved
    denied_by: Optional[str] = None  # Alias for decided_by when status is denied
    denial_reason: Optional[str] = None  # Alias for decision_notes when denied

    def __post_init__(self):
        """Normalize action type and handle aliases."""
        if isinstance(self.action_type, str):
            self.action_type = ActionType(self.action_type)

        # Handle status enum
        if hasattr(self.status, 'value'):
            # Convert ApprovalStatus enum to string for comparison
            self.status = self.status.value

        # Set expires_at default if not provided
        if self.expires_at is None:
            self.expires_at = self.requested_at + timedelta(hours=1)

        # Handle approved_by alias
        if self.approved_by and not self.decided_by:
            self.decided_by = self.approved_by
        elif self.decided_by and not self.approved_by and self.status == "approved":
            self.approved_by = self.decided_by

        # Handle denied_by alias
        if self.denied_by and not self.decided_by:
            self.decided_by = self.denied_by
        elif self.decided_by and not self.denied_by and self.status == "denied":
            self.denied_by = self.decided_by

        # Handle denial_reason alias
        if self.denial_reason and not self.decision_notes:
            self.decision_notes = self.denial_reason
        elif self.decision_notes and not self.denial_reason and self.status == "denied":
            self.denial_reason = self.decision_notes

    @property
    def is_expired(self) -> bool:
        """Check if the approval request has expired."""
        if self.expires_at is None:
            return False
        status_check = self.status.value if hasattr(self.status, 'value') else self.status
        return datetime.utcnow() > self.expires_at and status_check == "pending"

    @property
    def is_pending(self) -> bool:
        """Check if the request is still pending."""
        status_check = self.status.value if hasattr(self.status, 'value') else self.status
        return status_check == "pending" and not self.is_expired

    def approve(self, approver: str, notes: Optional[str] = None) -> None:
        """Approve the request."""
        self.status = "approved"
        self.decided_at = datetime.utcnow()
        self.decided_by = approver
        self.decision_notes = notes

    def deny(self, approver: str, notes: Optional[str] = None) -> None:
        """Deny the request."""
        self.status = "denied"
        self.decided_at = datetime.utcnow()
        self.decided_by = approver
        self.decision_notes = notes

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        result = {
            "id": self.id,
            "execution_id": self.execution_id,
            "playbook_id": self.playbook_id,
            "step_id": self.step_id,
            "step_name": self.step_name,
            "action_type": self.action_type.value,
            "action_parameters": self.action_parameters,
            "context": self.context,
            "requested_at": self.requested_at.isoformat(),
            "requested_by": self.requested_by,
            "approvers": self.approvers,
            "status": self.status,
            "expires_at": self.expires_at.isoformat(),
        }

        if self.decided_at:
            result["decided_at"] = self.decided_at.isoformat()
        if self.decided_by:
            result["decided_by"] = self.decided_by
        if self.decision_notes:
            result["decision_notes"] = self.decision_notes

        return result

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "ApprovalRequest":
        """Create from dictionary."""
        requested_at = data.get("requested_at")
        if isinstance(requested_at, str):
            requested_at = datetime.fromisoformat(requested_at.replace("Z", "+00:00"))

        expires_at = data.get("expires_at")
        if isinstance(expires_at, str):
            expires_at = datetime.fromisoformat(expires_at.replace("Z", "+00:00"))
        elif expires_at is None:
            expires_at = (requested_at or datetime.utcnow()) + timedelta(hours=1)

        decided_at = data.get("decided_at")
        if isinstance(decided_at, str):
            decided_at = datetime.fromisoformat(decided_at.replace("Z", "+00:00"))

        action_type = data.get("action_type", "custom")
        if isinstance(action_type, str):
            action_type = ActionType(action_type)

        return cls(
            id=data.get("id", str(uuid.uuid4())),
            execution_id=data.get("execution_id", ""),
            playbook_id=data.get("playbook_id", ""),
            step_id=data.get("step_id", ""),
            step_name=data.get("step_name", ""),
            action_type=action_type,
            action_parameters=data.get("action_parameters", {}),
            context=data.get("context", {}),
            requested_at=requested_at or datetime.utcnow(),
            requested_by=data.get("requested_by", "system"),
            approvers=data.get("approvers", []),
            status=data.get("status", "pending"),
            expires_at=expires_at,
            decided_at=decided_at,
            decided_by=data.get("decided_by"),
            decision_notes=data.get("decision_notes"),
        )

    @classmethod
    def create(
        cls,
        execution_id: str,
        playbook_id: str,
        step: PlaybookStep,
        context: Dict[str, Any],
        requested_by: str = "system",
        expiry_hours: int = 1,
    ) -> "ApprovalRequest":
        """Create a new approval request for a step.

        Args:
            execution_id: ID of the playbook execution
            playbook_id: ID of the playbook
            step: The step requiring approval
            context: Context information
            requested_by: Who initiated the request
            expiry_hours: Hours until expiration

        Returns:
            New ApprovalRequest instance
        """
        now = datetime.utcnow()
        return cls(
            id=str(uuid.uuid4()),
            execution_id=execution_id,
            playbook_id=playbook_id,
            step_id=step.id,
            step_name=step.name,
            action_type=step.action_type,
            action_parameters=step.parameters,
            context=context,
            requested_at=now,
            requested_by=requested_by,
            approvers=step.approval_roles,
            status="pending",
            expires_at=now + timedelta(hours=expiry_hours),
        )
