"""Response action definitions for identity alerts.

Defines the available automated response actions and their configurations.
"""

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional


class ResponseAction(Enum):
    """Available automated response actions for identity alerts."""

    # Passive actions
    MONITOR_ONLY = "monitor_only"
    NOTIFY_USER = "notify_user"
    NOTIFY_MANAGER = "notify_manager"
    CREATE_TICKET = "create_ticket"

    # Active session actions
    REQUIRE_MFA_REAUTHENTICATION = "require_mfa_reauthentication"
    TERMINATE_SESSIONS = "terminate_sessions"
    REVOKE_TOKENS = "revoke_tokens"

    # Account actions
    DISABLE_ACCOUNT = "disable_account"
    FORCE_PASSWORD_RESET = "force_password_reset"
    LOCK_ACCOUNT = "lock_account"

    # Network actions
    BLOCK_SOURCE_IP = "block_source_ip"
    ISOLATE_DEVICE = "isolate_device"

    @classmethod
    def get_severity_appropriate_actions(cls, severity: str) -> List["ResponseAction"]:
        """Get actions appropriate for a severity level.

        Args:
            severity: Alert severity

        Returns:
            List of appropriate actions
        """
        if severity == "critical":
            return [
                cls.TERMINATE_SESSIONS,
                cls.DISABLE_ACCOUNT,
                cls.REVOKE_TOKENS,
                cls.BLOCK_SOURCE_IP,
                cls.NOTIFY_USER,
                cls.NOTIFY_MANAGER,
                cls.CREATE_TICKET,
            ]
        elif severity == "high":
            return [
                cls.REQUIRE_MFA_REAUTHENTICATION,
                cls.TERMINATE_SESSIONS,
                cls.NOTIFY_USER,
                cls.NOTIFY_MANAGER,
                cls.CREATE_TICKET,
            ]
        elif severity == "medium":
            return [
                cls.REQUIRE_MFA_REAUTHENTICATION,
                cls.NOTIFY_USER,
                cls.CREATE_TICKET,
            ]
        else:
            return [
                cls.MONITOR_ONLY,
                cls.NOTIFY_USER,
            ]

    def is_reversible(self) -> bool:
        """Check if this action can be reversed.

        Returns:
            True if action can be undone
        """
        reversible_actions = {
            ResponseAction.DISABLE_ACCOUNT,
            ResponseAction.LOCK_ACCOUNT,
            ResponseAction.BLOCK_SOURCE_IP,
            ResponseAction.ISOLATE_DEVICE,
        }
        return self in reversible_actions

    def get_revert_action(self) -> Optional[str]:
        """Get the action to revert this action.

        Returns:
            Revert action name or None
        """
        revert_map = {
            ResponseAction.DISABLE_ACCOUNT: "enable_account",
            ResponseAction.LOCK_ACCOUNT: "unlock_account",
            ResponseAction.BLOCK_SOURCE_IP: "unblock_source_ip",
            ResponseAction.ISOLATE_DEVICE: "unisolate_device",
        }
        return revert_map.get(self)

    def requires_provider_integration(self) -> bool:
        """Check if action requires identity provider API.

        Returns:
            True if provider integration needed
        """
        provider_actions = {
            ResponseAction.REQUIRE_MFA_REAUTHENTICATION,
            ResponseAction.TERMINATE_SESSIONS,
            ResponseAction.REVOKE_TOKENS,
            ResponseAction.DISABLE_ACCOUNT,
            ResponseAction.FORCE_PASSWORD_RESET,
            ResponseAction.LOCK_ACCOUNT,
        }
        return self in provider_actions


@dataclass
class ResponseActionConfig:
    """Configuration for a response action.

    Attributes:
        action: The response action
        enabled: Whether this action is enabled
        auto_execute: Execute automatically vs require approval
        severity_threshold: Minimum severity to trigger this action
        cooldown_minutes: Don't repeat action within this window
        requires_approval_from: Roles that must approve before execution
        max_retries: Maximum retry attempts for failed actions
        notification_channels: Channels to notify when action is taken
        applicable_alert_types: Alert types this action applies to (None = all)
    """

    action: ResponseAction
    enabled: bool = True
    auto_execute: bool = False
    severity_threshold: str = "high"
    cooldown_minutes: int = 60
    requires_approval_from: Optional[List[str]] = None
    max_retries: int = 3
    notification_channels: List[str] = field(default_factory=list)
    applicable_alert_types: Optional[List[str]] = None

    def __post_init__(self):
        """Initialize defaults."""
        if self.notification_channels is None:
            self.notification_channels = []

    def applies_to_alert_type(self, alert_type: str) -> bool:
        """Check if this action applies to an alert type.

        Args:
            alert_type: Type of alert

        Returns:
            True if action applies
        """
        if self.applicable_alert_types is None:
            return True
        return alert_type in self.applicable_alert_types

    def meets_severity_threshold(self, severity: str) -> bool:
        """Check if severity meets the threshold.

        Args:
            severity: Alert severity

        Returns:
            True if threshold met
        """
        severity_order = {
            "info": 0,
            "low": 1,
            "medium": 2,
            "high": 3,
            "critical": 4,
        }
        alert_level = severity_order.get(severity.lower(), 0)
        threshold_level = severity_order.get(self.severity_threshold.lower(), 3)
        return alert_level >= threshold_level

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary.

        Returns:
            Dictionary representation
        """
        return {
            "action": self.action.value,
            "enabled": self.enabled,
            "auto_execute": self.auto_execute,
            "severity_threshold": self.severity_threshold,
            "cooldown_minutes": self.cooldown_minutes,
            "requires_approval_from": self.requires_approval_from,
            "max_retries": self.max_retries,
            "notification_channels": self.notification_channels,
            "applicable_alert_types": self.applicable_alert_types,
        }


@dataclass
class ResponseActionResult:
    """Result of executing a response action.

    Attributes:
        action: The action that was executed
        success: Whether the action succeeded
        executed_at: When the action was executed
        details: Additional details about execution
        can_be_reverted: Whether this action can be undone
        revert_action: Name of revert action if applicable
        error_message: Error message if failed
        retry_count: Number of retries attempted
        approval_id: ID of approval request if pending
        affected_resources: Resources affected by the action
    """

    action: ResponseAction
    success: bool
    executed_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    details: Dict[str, Any] = field(default_factory=dict)
    can_be_reverted: bool = False
    revert_action: Optional[str] = None
    error_message: Optional[str] = None
    retry_count: int = 0
    approval_id: Optional[str] = None
    affected_resources: List[str] = field(default_factory=list)

    def __post_init__(self):
        """Set derived fields."""
        if self.can_be_reverted is None:
            self.can_be_reverted = self.action.is_reversible()
        if self.revert_action is None:
            self.revert_action = self.action.get_revert_action()

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary.

        Returns:
            Dictionary representation
        """
        return {
            "action": self.action.value,
            "success": self.success,
            "executed_at": self.executed_at.isoformat(),
            "details": self.details,
            "can_be_reverted": self.can_be_reverted,
            "revert_action": self.revert_action,
            "error_message": self.error_message,
            "retry_count": self.retry_count,
            "approval_id": self.approval_id,
            "affected_resources": self.affected_resources,
        }


# Default response configurations for common scenarios
DEFAULT_RESPONSE_CONFIGS: Dict[str, List[ResponseActionConfig]] = {
    "brute_force": [
        ResponseActionConfig(
            action=ResponseAction.BLOCK_SOURCE_IP,
            enabled=True,
            auto_execute=True,
            severity_threshold="high",
            cooldown_minutes=60,
        ),
        ResponseActionConfig(
            action=ResponseAction.NOTIFY_USER,
            enabled=True,
            auto_execute=True,
            severity_threshold="medium",
        ),
        ResponseActionConfig(
            action=ResponseAction.CREATE_TICKET,
            enabled=True,
            auto_execute=True,
            severity_threshold="high",
        ),
    ],
    "credential_stuffing": [
        ResponseActionConfig(
            action=ResponseAction.BLOCK_SOURCE_IP,
            enabled=True,
            auto_execute=True,
            severity_threshold="high",
        ),
        ResponseActionConfig(
            action=ResponseAction.FORCE_PASSWORD_RESET,
            enabled=True,
            auto_execute=False,  # Requires approval for success cases
            severity_threshold="high",
            requires_approval_from=["security_analyst"],
        ),
    ],
    "password_spray": [
        ResponseActionConfig(
            action=ResponseAction.BLOCK_SOURCE_IP,
            enabled=True,
            auto_execute=True,
            severity_threshold="high",
        ),
        ResponseActionConfig(
            action=ResponseAction.LOCK_ACCOUNT,
            enabled=True,
            auto_execute=False,
            severity_threshold="critical",
            requires_approval_from=["security_analyst"],
            cooldown_minutes=30,
        ),
    ],
    "mfa_fatigue": [
        ResponseActionConfig(
            action=ResponseAction.TERMINATE_SESSIONS,
            enabled=True,
            auto_execute=True,
            severity_threshold="critical",
        ),
        ResponseActionConfig(
            action=ResponseAction.NOTIFY_USER,
            enabled=True,
            auto_execute=True,
            severity_threshold="high",
        ),
        ResponseActionConfig(
            action=ResponseAction.NOTIFY_MANAGER,
            enabled=True,
            auto_execute=True,
            severity_threshold="critical",
        ),
    ],
    "impossible_travel": [
        ResponseActionConfig(
            action=ResponseAction.REQUIRE_MFA_REAUTHENTICATION,
            enabled=True,
            auto_execute=True,
            severity_threshold="high",
        ),
        ResponseActionConfig(
            action=ResponseAction.NOTIFY_USER,
            enabled=True,
            auto_execute=True,
            severity_threshold="medium",
        ),
    ],
    "session_hijack": [
        ResponseActionConfig(
            action=ResponseAction.TERMINATE_SESSIONS,
            enabled=True,
            auto_execute=True,
            severity_threshold="high",
        ),
        ResponseActionConfig(
            action=ResponseAction.REVOKE_TOKENS,
            enabled=True,
            auto_execute=True,
            severity_threshold="high",
        ),
        ResponseActionConfig(
            action=ResponseAction.REQUIRE_MFA_REAUTHENTICATION,
            enabled=True,
            auto_execute=True,
            severity_threshold="high",
        ),
    ],
    "privilege_escalation": [
        ResponseActionConfig(
            action=ResponseAction.DISABLE_ACCOUNT,
            enabled=True,
            auto_execute=False,  # Always requires approval
            severity_threshold="critical",
            requires_approval_from=["security_manager", "it_admin"],
        ),
        ResponseActionConfig(
            action=ResponseAction.NOTIFY_MANAGER,
            enabled=True,
            auto_execute=True,
            severity_threshold="high",
        ),
        ResponseActionConfig(
            action=ResponseAction.CREATE_TICKET,
            enabled=True,
            auto_execute=True,
            severity_threshold="medium",
        ),
    ],
    "account_takeover": [
        ResponseActionConfig(
            action=ResponseAction.DISABLE_ACCOUNT,
            enabled=True,
            auto_execute=True,  # Auto for critical account takeover
            severity_threshold="critical",
        ),
        ResponseActionConfig(
            action=ResponseAction.TERMINATE_SESSIONS,
            enabled=True,
            auto_execute=True,
            severity_threshold="critical",
        ),
        ResponseActionConfig(
            action=ResponseAction.REVOKE_TOKENS,
            enabled=True,
            auto_execute=True,
            severity_threshold="critical",
        ),
        ResponseActionConfig(
            action=ResponseAction.NOTIFY_USER,
            enabled=True,
            auto_execute=True,
            severity_threshold="critical",
        ),
        ResponseActionConfig(
            action=ResponseAction.NOTIFY_MANAGER,
            enabled=True,
            auto_execute=True,
            severity_threshold="critical",
        ),
    ],
    "token_theft": [
        ResponseActionConfig(
            action=ResponseAction.REVOKE_TOKENS,
            enabled=True,
            auto_execute=True,
            severity_threshold="high",
        ),
        ResponseActionConfig(
            action=ResponseAction.REQUIRE_MFA_REAUTHENTICATION,
            enabled=True,
            auto_execute=True,
            severity_threshold="high",
        ),
    ],
    "dormant_account": [
        ResponseActionConfig(
            action=ResponseAction.DISABLE_ACCOUNT,
            enabled=True,
            auto_execute=False,
            severity_threshold="high",
            requires_approval_from=["hr", "security_analyst"],
        ),
        ResponseActionConfig(
            action=ResponseAction.NOTIFY_MANAGER,
            enabled=True,
            auto_execute=True,
            severity_threshold="medium",
        ),
    ],
}
