"""SOAR (Security Orchestration, Automation, and Response) module.

This module provides automated security response capabilities through
playbooks that can be triggered by alerts, manual invocation, schedules,
or webhooks.

Key Components:
- Playbook: Workflow definition with steps and triggers
- PlaybookStep: Individual action within a playbook
- PlaybookExecution: Runtime instance of a playbook
- ApprovalRequest: Human approval for dangerous actions
- ActionType: Types of actions (disable account, block IP, etc.)
- ExecutionStatus: Execution lifecycle states
- PlaybookStore: Abstract storage interface
- FilePlaybookStore: File-based YAML storage
- DynamoDBPlaybookStore: AWS DynamoDB storage
- S3PlaybookStore: AWS S3 storage
- IRPlanParser: Parse IR plans (markdown/text) into playbooks
- PlaybookCodeGenerator: Generate Lambda code from playbooks
- PlaybookExecutionEngine: Execute playbooks with approval workflow
- ApprovalService: Handle approval requests for dangerous actions
- ActionLog: Audit logging for all security actions
"""

from .playbook import (
    ActionType,
    ApprovalRequest,
    ExecutionStatus,
    Playbook,
    PlaybookExecution,
    PlaybookStep,
    PlaybookTrigger,
    PlaybookTriggerType,
    StepExecutionResult,
)

from .playbook_store import (
    PlaybookStore,
    FilePlaybookStore,
    DynamoDBPlaybookStore,
    S3PlaybookStore,
    get_playbook_store,
)

from .ir_plan_parser import (
    IRPlanParser,
    parse_ir_plan,
)

from .playbook_generator import (
    PlaybookCodeGenerator,
    generate_playbook_code,
    validate_playbook_code,
)

from .execution_engine import (
    ExecutionContext,
    PlaybookExecutionEngine,
    get_execution_engine,
)

from .execution_store import (
    ExecutionStore,
    InMemoryExecutionStore,
    DynamoDBExecutionStore,
    get_execution_store,
)

from .approval_service import (
    ApprovalService,
    ApprovalStore,
    InMemoryApprovalStore,
    DynamoDBApprovalStore,
    get_approval_service,
)

from .action_log import (
    ActionLog,
    ActionLogEntry,
    ActionLogStore,
    InMemoryActionLogStore,
    DynamoDBActionLogStore,
    get_action_log,
)

__all__ = [
    # Playbook models
    "ActionType",
    "ApprovalRequest",
    "ExecutionStatus",
    "Playbook",
    "PlaybookExecution",
    "PlaybookStep",
    "PlaybookTrigger",
    "PlaybookTriggerType",
    "StepExecutionResult",
    # Storage
    "PlaybookStore",
    "FilePlaybookStore",
    "DynamoDBPlaybookStore",
    "S3PlaybookStore",
    "get_playbook_store",
    # IR Plan Parser
    "IRPlanParser",
    "parse_ir_plan",
    # Code Generator
    "PlaybookCodeGenerator",
    "generate_playbook_code",
    "validate_playbook_code",
    # Execution Engine
    "ExecutionContext",
    "PlaybookExecutionEngine",
    "get_execution_engine",
    # Execution Store
    "ExecutionStore",
    "InMemoryExecutionStore",
    "DynamoDBExecutionStore",
    "get_execution_store",
    # Approval Service
    "ApprovalService",
    "ApprovalStore",
    "InMemoryApprovalStore",
    "DynamoDBApprovalStore",
    "get_approval_service",
    # Action Log
    "ActionLog",
    "ActionLogEntry",
    "ActionLogStore",
    "InMemoryActionLogStore",
    "DynamoDBActionLogStore",
    "get_action_log",
]
