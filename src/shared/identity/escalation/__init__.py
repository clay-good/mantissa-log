"""Severity escalation for identity alerts.

This package provides rules and logic for automatically escalating
alert severity based on context such as:
- Target user privilege level
- Attack success indicators
- Kill chain progression
- Multiple anomaly combinations
"""

from .escalation_config import (
    EscalationConfig,
    EscalationRule,
    PRIVILEGED_ROLES,
    EXECUTIVE_TITLES,
)
from .severity_rules import (
    SeverityLevel,
    EscalationResult,
    SeverityEscalator,
)

__all__ = [
    "EscalationConfig",
    "EscalationRule",
    "PRIVILEGED_ROLES",
    "EXECUTIVE_TITLES",
    "SeverityLevel",
    "EscalationResult",
    "SeverityEscalator",
]
