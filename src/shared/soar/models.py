"""SOAR models - re-export for package compatibility.

This module provides convenient imports for all SOAR data models.
"""

from enum import Enum
from .playbook import (
    ActionType,
    PlaybookTriggerType,
    ExecutionStatus,
    PlaybookStep,
    PlaybookTrigger,
    Playbook,
    StepExecutionResult,
    PlaybookExecution,
    ApprovalRequest,
)


class ApprovalStatus(Enum):
    """Approval request status."""
    PENDING = "pending"
    APPROVED = "approved"
    DENIED = "denied"
    EXPIRED = "expired"


class ApprovalRequirement(Enum):
    """Whether a playbook step requires approval before execution."""
    REQUIRED = "required"  # Always requires approval
    NOT_REQUIRED = "not_required"  # No approval needed
    CONDITIONAL = "conditional"  # Depends on conditions (e.g., risk score)
    OPTIONAL = "optional"  # Approval is optional


class PlaybookStatus(Enum):
    """Playbook lifecycle status (distinct from execution status)."""
    DRAFT = "draft"  # Playbook is being edited
    ACTIVE = "active"  # Playbook is deployed and ready to run
    INACTIVE = "inactive"  # Playbook is disabled
    DEPRECATED = "deprecated"  # Playbook is being phased out
    ARCHIVED = "archived"  # Playbook is archived (read-only)


# Aliases for compatibility with different naming conventions
Execution = PlaybookExecution
StepResult = StepExecutionResult

__all__ = [
    "ActionType",
    "PlaybookTriggerType",
    "ExecutionStatus",
    "PlaybookStatus",
    "PlaybookStep",
    "PlaybookTrigger",
    "Playbook",
    "StepExecutionResult",
    "StepResult",
    "PlaybookExecution",
    "Execution",
    "ApprovalRequest",
    "ApprovalRequirement",
    "ApprovalStatus",
]
