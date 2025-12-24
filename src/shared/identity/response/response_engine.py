"""Response engine for executing automated actions.

Orchestrates the evaluation and execution of response actions
based on alert type, severity, and configuration.
"""

import logging
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Optional, Protocol

from .response_actions import (
    ResponseAction,
    ResponseActionConfig,
    ResponseActionResult,
    DEFAULT_RESPONSE_CONFIGS,
)
from .provider_actions import IdentityProviderActions, ProviderActionResult

logger = logging.getLogger(__name__)


class AlertProtocol(Protocol):
    """Protocol for Alert objects."""

    id: str
    rule_name: str
    severity: str
    timestamp: datetime
    results: List[Dict[str, Any]]
    metadata: Dict[str, Any]


class ActionLogProtocol(Protocol):
    """Protocol for action logging."""

    def log_action(
        self,
        action: str,
        alert_id: str,
        user_id: str,
        result: Dict[str, Any],
    ) -> None:
        """Log an executed action."""
        ...

    def get_recent_actions(
        self,
        user_id: str,
        action: str,
        since: datetime,
    ) -> List[Dict[str, Any]]:
        """Get recent actions for cooldown check."""
        ...


class ApprovalServiceProtocol(Protocol):
    """Protocol for approval workflow service."""

    def create_approval_request(
        self,
        action: str,
        alert_id: str,
        user_id: str,
        approvers: List[str],
        context: Dict[str, Any],
    ) -> str:
        """Create approval request, return request ID."""
        ...

    def get_approval_status(self, request_id: str) -> Dict[str, Any]:
        """Get status of an approval request."""
        ...


class NotificationServiceProtocol(Protocol):
    """Protocol for notification service."""

    def send_notification(
        self,
        channel: str,
        message: str,
        context: Dict[str, Any],
    ) -> bool:
        """Send a notification."""
        ...


class TicketServiceProtocol(Protocol):
    """Protocol for ticket/case creation service."""

    def create_ticket(
        self,
        title: str,
        description: str,
        severity: str,
        metadata: Dict[str, Any],
    ) -> str:
        """Create a ticket, return ticket ID."""
        ...


@dataclass
class ResponseEngineConfig:
    """Configuration for the response engine.

    Attributes:
        enabled: Whether response engine is enabled
        dry_run: Execute in dry run mode (log but don't execute)
        default_cooldown_minutes: Default cooldown between repeated actions
        max_actions_per_alert: Maximum actions to execute per alert
        require_approval_for_destructive: Require approval for destructive actions
        action_configs: Configuration for each alert type
    """

    enabled: bool = True
    dry_run: bool = True  # Safe default
    default_cooldown_minutes: int = 60
    max_actions_per_alert: int = 5
    require_approval_for_destructive: bool = True
    action_configs: Dict[str, List[ResponseActionConfig]] = field(
        default_factory=lambda: DEFAULT_RESPONSE_CONFIGS.copy()
    )


@dataclass
class ApprovalRequest:
    """Pending approval request for an action.

    Attributes:
        request_id: Unique request ID
        action: Action awaiting approval
        alert_id: Associated alert ID
        user_id: Target user ID
        approvers: Users who can approve
        requested_at: When approval was requested
        context: Additional context
    """

    request_id: str
    action: ResponseAction
    alert_id: str
    user_id: str
    approvers: List[str]
    requested_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    context: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "request_id": self.request_id,
            "action": self.action.value,
            "alert_id": self.alert_id,
            "user_id": self.user_id,
            "approvers": self.approvers,
            "requested_at": self.requested_at.isoformat(),
            "context": self.context,
        }


class ResponseEngine:
    """Engine for evaluating and executing response actions.

    Orchestrates automated responses to identity alerts based on
    configurable rules and severity thresholds.
    """

    def __init__(
        self,
        config: Optional[ResponseEngineConfig] = None,
        provider_clients: Optional[Dict[str, IdentityProviderActions]] = None,
        action_log: Optional[ActionLogProtocol] = None,
        approval_service: Optional[ApprovalServiceProtocol] = None,
        notification_service: Optional[NotificationServiceProtocol] = None,
        ticket_service: Optional[TicketServiceProtocol] = None,
    ):
        """Initialize response engine.

        Args:
            config: Engine configuration
            provider_clients: Dictionary of provider name to action client
            action_log: Service for logging actions
            approval_service: Service for approval workflows
            notification_service: Service for notifications
            ticket_service: Service for ticket creation
        """
        self.config = config or ResponseEngineConfig()
        self.provider_clients = provider_clients or {}
        self.action_log = action_log
        self.approval_service = approval_service
        self.notification_service = notification_service
        self.ticket_service = ticket_service

        # Track pending approvals
        self._pending_approvals: Dict[str, ApprovalRequest] = {}

        # Track action cooldowns (in-memory, for production use external store)
        self._action_cooldowns: Dict[str, datetime] = {}

    def evaluate_response(
        self,
        alert: AlertProtocol,
    ) -> List[ResponseAction]:
        """Determine appropriate response actions for an alert.

        Args:
            alert: Alert to evaluate

        Returns:
            List of recommended response actions
        """
        if not self.config.enabled:
            return []

        # Determine alert type
        alert_type = self._get_alert_type(alert)

        # Get configured actions for this alert type
        action_configs = self.config.action_configs.get(alert_type, [])

        if not action_configs:
            # Fall back to severity-based defaults
            return ResponseAction.get_severity_appropriate_actions(alert.severity)

        # Filter by severity threshold and enabled status
        applicable_actions = []
        for config in action_configs:
            if not config.enabled:
                continue

            if not config.meets_severity_threshold(alert.severity):
                continue

            applicable_actions.append(config.action)

        return applicable_actions[:self.config.max_actions_per_alert]

    def execute_response(
        self,
        action: ResponseAction,
        alert: AlertProtocol,
        force: bool = False,
    ) -> ResponseActionResult:
        """Execute a response action for an alert.

        Args:
            action: Action to execute
            alert: Associated alert
            force: Force execution even if in cooldown

        Returns:
            ResponseActionResult with execution details
        """
        user_id = self._extract_user_id(alert)
        alert_type = self._get_alert_type(alert)

        # Check if action is in cooldown
        if not force and self._is_in_cooldown(action, user_id, alert_type):
            return ResponseActionResult(
                action=action,
                success=False,
                error_message="Action is in cooldown period",
                details={"cooldown": True},
            )

        # Get action config
        config = self._get_action_config(action, alert_type)

        # Check if approval is required
        if config and config.requires_approval_from and not force:
            return self._request_approval(action, alert, user_id, config)

        # Execute the action
        result = self._execute_action(action, alert, user_id)

        # Log the action
        self._log_action(action, alert.id, user_id, result)

        # Update cooldown
        if result.success:
            self._set_cooldown(action, user_id, alert_type, config)

        # Send notifications if configured
        if result.success and config and config.notification_channels:
            self._send_notifications(action, alert, user_id, config.notification_channels)

        return result

    def execute_with_approval(
        self,
        action: ResponseAction,
        alert: AlertProtocol,
        approvers: List[str],
    ) -> str:
        """Create an approval request for an action.

        Args:
            action: Action to execute after approval
            alert: Associated alert
            approvers: List of users who can approve

        Returns:
            Approval request ID
        """
        user_id = self._extract_user_id(alert)
        request_id = str(uuid.uuid4())

        request = ApprovalRequest(
            request_id=request_id,
            action=action,
            alert_id=alert.id,
            user_id=user_id,
            approvers=approvers,
            context={
                "alert_type": self._get_alert_type(alert),
                "severity": alert.severity,
                "rule_name": alert.rule_name,
            },
        )

        self._pending_approvals[request_id] = request

        # If approval service is available, create external request
        if self.approval_service:
            try:
                external_id = self.approval_service.create_approval_request(
                    action=action.value,
                    alert_id=alert.id,
                    user_id=user_id,
                    approvers=approvers,
                    context=request.context,
                )
                request.context["external_approval_id"] = external_id
            except Exception as e:
                logger.error(f"Error creating approval request: {e}")

        logger.info(
            f"Created approval request {request_id} for action {action.value} "
            f"on user {user_id}, approvers: {approvers}"
        )

        return request_id

    def process_approval(
        self,
        request_id: str,
        approved: bool,
        approver: str,
    ) -> Optional[ResponseActionResult]:
        """Process an approval decision.

        Args:
            request_id: Approval request ID
            approved: Whether the request was approved
            approver: Who approved/denied

        Returns:
            ResponseActionResult if approved and executed, None otherwise
        """
        request = self._pending_approvals.pop(request_id, None)

        if not request:
            logger.warning(f"Approval request {request_id} not found")
            return None

        if not approved:
            logger.info(
                f"Approval request {request_id} denied by {approver} "
                f"for action {request.action.value}"
            )
            return ResponseActionResult(
                action=request.action,
                success=False,
                error_message=f"Request denied by {approver}",
                approval_id=request_id,
            )

        logger.info(
            f"Approval request {request_id} approved by {approver} "
            f"for action {request.action.value}"
        )

        # Execute the action
        result = self._execute_action(
            request.action,
            None,  # Alert not available, use stored context
            request.user_id,
        )

        result.approval_id = request_id
        result.details["approved_by"] = approver

        # Log the action
        self._log_action(request.action, request.alert_id, request.user_id, result)

        return result

    def revert_action(
        self,
        action_result: ResponseActionResult,
    ) -> ResponseActionResult:
        """Revert a previously executed action.

        Args:
            action_result: Result of the action to revert

        Returns:
            ResponseActionResult of the revert operation
        """
        if not action_result.can_be_reverted:
            return ResponseActionResult(
                action=action_result.action,
                success=False,
                error_message="Action cannot be reverted",
            )

        revert_action_name = action_result.revert_action
        if not revert_action_name:
            return ResponseActionResult(
                action=action_result.action,
                success=False,
                error_message="No revert action defined",
            )

        # Get affected user
        user_id = (
            action_result.affected_resources[0]
            if action_result.affected_resources
            else action_result.details.get("user_id", "")
        )

        if not user_id:
            return ResponseActionResult(
                action=action_result.action,
                success=False,
                error_message="Cannot determine user to revert",
            )

        # Determine provider
        provider = action_result.details.get("provider", "")
        provider_client = self.provider_clients.get(provider)

        if not provider_client:
            return ResponseActionResult(
                action=action_result.action,
                success=False,
                error_message=f"Provider {provider} not configured",
            )

        # Execute revert
        try:
            if revert_action_name == "enable_account":
                result = provider_client.enable_user_account(user_id)
            elif revert_action_name == "unlock_account":
                result = provider_client.unlock_account(user_id)
            elif revert_action_name == "unblock_source_ip":
                # IP blocking revert would require firewall integration
                logger.info(f"Would unblock IP for user {user_id}")
                result = ProviderActionResult(
                    success=True,
                    provider=provider,
                    action=revert_action_name,
                    user_id=user_id,
                    details={"message": "IP unblock requires firewall integration"},
                    dry_run=True,
                )
            else:
                return ResponseActionResult(
                    action=action_result.action,
                    success=False,
                    error_message=f"Unknown revert action: {revert_action_name}",
                )

            return ResponseActionResult(
                action=action_result.action,
                success=result.success,
                details={
                    "revert_action": revert_action_name,
                    "provider": provider,
                    "provider_result": result.to_dict(),
                },
                error_message=result.error,
            )

        except Exception as e:
            logger.error(f"Error reverting action: {e}")
            return ResponseActionResult(
                action=action_result.action,
                success=False,
                error_message=str(e),
            )

    def _execute_action(
        self,
        action: ResponseAction,
        alert: Optional[AlertProtocol],
        user_id: str,
    ) -> ResponseActionResult:
        """Execute a single response action.

        Args:
            action: Action to execute
            alert: Associated alert (may be None for approval flows)
            user_id: Target user ID

        Returns:
            ResponseActionResult
        """
        # Handle non-provider actions
        if action == ResponseAction.MONITOR_ONLY:
            return ResponseActionResult(
                action=action,
                success=True,
                details={"message": "Alert marked for monitoring only"},
            )

        if action == ResponseAction.NOTIFY_USER:
            return self._notify_user(user_id, alert)

        if action == ResponseAction.NOTIFY_MANAGER:
            return self._notify_manager(user_id, alert)

        if action == ResponseAction.CREATE_TICKET:
            return self._create_ticket(alert)

        if action == ResponseAction.BLOCK_SOURCE_IP:
            return self._block_source_ip(alert)

        if action == ResponseAction.ISOLATE_DEVICE:
            return self._isolate_device(alert)

        # Provider-based actions
        if not action.requires_provider_integration():
            return ResponseActionResult(
                action=action,
                success=False,
                error_message=f"Unhandled action: {action.value}",
            )

        # Determine provider
        provider = self._get_provider(alert)
        provider_client = self.provider_clients.get(provider)

        if not provider_client:
            logger.warning(f"No provider client for {provider}")
            return ResponseActionResult(
                action=action,
                success=False,
                error_message=f"Provider {provider} not configured",
                details={"provider": provider},
            )

        # Execute provider action
        try:
            if action == ResponseAction.TERMINATE_SESSIONS:
                result = provider_client.terminate_user_sessions(user_id)
            elif action == ResponseAction.DISABLE_ACCOUNT:
                result = provider_client.disable_user_account(user_id)
            elif action == ResponseAction.REQUIRE_MFA_REAUTHENTICATION:
                result = provider_client.require_mfa(user_id)
            elif action == ResponseAction.REVOKE_TOKENS:
                result = provider_client.revoke_tokens(user_id)
            elif action == ResponseAction.FORCE_PASSWORD_RESET:
                result = provider_client.force_password_reset(user_id)
            elif action == ResponseAction.LOCK_ACCOUNT:
                result = provider_client.lock_account(user_id)
            else:
                return ResponseActionResult(
                    action=action,
                    success=False,
                    error_message=f"Unhandled provider action: {action.value}",
                )

            return ResponseActionResult(
                action=action,
                success=result.success,
                details={
                    "provider": provider,
                    "provider_result": result.to_dict(),
                    "dry_run": result.dry_run,
                },
                error_message=result.error,
                can_be_reverted=action.is_reversible(),
                revert_action=action.get_revert_action(),
                affected_resources=[user_id],
            )

        except Exception as e:
            logger.error(f"Error executing {action.value}: {e}")
            return ResponseActionResult(
                action=action,
                success=False,
                error_message=str(e),
                details={"provider": provider},
            )

    def _notify_user(
        self,
        user_id: str,
        alert: Optional[AlertProtocol],
    ) -> ResponseActionResult:
        """Send notification to the affected user."""
        if not self.notification_service:
            logger.info(f"Would notify user {user_id} (no notification service)")
            return ResponseActionResult(
                action=ResponseAction.NOTIFY_USER,
                success=True,
                details={"message": "Notification service not configured"},
            )

        try:
            message = self._build_user_notification(alert)
            success = self.notification_service.send_notification(
                channel="email",
                message=message,
                context={"user_id": user_id, "alert_id": alert.id if alert else ""},
            )

            return ResponseActionResult(
                action=ResponseAction.NOTIFY_USER,
                success=success,
                details={"notified_user": user_id},
            )
        except Exception as e:
            return ResponseActionResult(
                action=ResponseAction.NOTIFY_USER,
                success=False,
                error_message=str(e),
            )

    def _notify_manager(
        self,
        user_id: str,
        alert: Optional[AlertProtocol],
    ) -> ResponseActionResult:
        """Send notification to the user's manager."""
        if not self.notification_service:
            logger.info(f"Would notify manager for user {user_id} (no notification service)")
            return ResponseActionResult(
                action=ResponseAction.NOTIFY_MANAGER,
                success=True,
                details={"message": "Notification service not configured"},
            )

        try:
            message = self._build_manager_notification(user_id, alert)
            success = self.notification_service.send_notification(
                channel="email",
                message=message,
                context={"user_id": user_id, "alert_id": alert.id if alert else ""},
            )

            return ResponseActionResult(
                action=ResponseAction.NOTIFY_MANAGER,
                success=success,
                details={"notified_for_user": user_id},
            )
        except Exception as e:
            return ResponseActionResult(
                action=ResponseAction.NOTIFY_MANAGER,
                success=False,
                error_message=str(e),
            )

    def _create_ticket(
        self,
        alert: Optional[AlertProtocol],
    ) -> ResponseActionResult:
        """Create a ticket/case for investigation."""
        if not self.ticket_service:
            logger.info(f"Would create ticket for alert (no ticket service)")
            return ResponseActionResult(
                action=ResponseAction.CREATE_TICKET,
                success=True,
                details={"message": "Ticket service not configured"},
            )

        try:
            title = f"Security Alert: {alert.rule_name}" if alert else "Security Alert"
            description = self._build_ticket_description(alert)
            severity = alert.severity if alert else "medium"

            ticket_id = self.ticket_service.create_ticket(
                title=title,
                description=description,
                severity=severity,
                metadata={"alert_id": alert.id if alert else ""},
            )

            return ResponseActionResult(
                action=ResponseAction.CREATE_TICKET,
                success=True,
                details={"ticket_id": ticket_id},
            )
        except Exception as e:
            return ResponseActionResult(
                action=ResponseAction.CREATE_TICKET,
                success=False,
                error_message=str(e),
            )

    def _block_source_ip(
        self,
        alert: Optional[AlertProtocol],
    ) -> ResponseActionResult:
        """Block the source IP address."""
        source_ip = self._extract_source_ip(alert) if alert else None

        if not source_ip:
            return ResponseActionResult(
                action=ResponseAction.BLOCK_SOURCE_IP,
                success=False,
                error_message="No source IP found in alert",
            )

        # IP blocking requires firewall/network integration
        # This is a placeholder that logs the action
        logger.info(f"Would block source IP: {source_ip}")

        return ResponseActionResult(
            action=ResponseAction.BLOCK_SOURCE_IP,
            success=True,
            details={
                "source_ip": source_ip,
                "message": "IP blocking requires firewall integration",
            },
            can_be_reverted=True,
            revert_action="unblock_source_ip",
            affected_resources=[source_ip],
        )

    def _isolate_device(
        self,
        alert: Optional[AlertProtocol],
    ) -> ResponseActionResult:
        """Isolate a device from the network."""
        device_id = self._extract_device_id(alert) if alert else None

        if not device_id:
            return ResponseActionResult(
                action=ResponseAction.ISOLATE_DEVICE,
                success=False,
                error_message="No device ID found in alert",
            )

        # Device isolation requires EDR/MDM integration
        logger.info(f"Would isolate device: {device_id}")

        return ResponseActionResult(
            action=ResponseAction.ISOLATE_DEVICE,
            success=True,
            details={
                "device_id": device_id,
                "message": "Device isolation requires EDR integration",
            },
            can_be_reverted=True,
            revert_action="unisolate_device",
            affected_resources=[device_id],
        )

    def _request_approval(
        self,
        action: ResponseAction,
        alert: AlertProtocol,
        user_id: str,
        config: ResponseActionConfig,
    ) -> ResponseActionResult:
        """Create an approval request instead of executing."""
        approvers = config.requires_approval_from or []

        request_id = self.execute_with_approval(action, alert, approvers)

        return ResponseActionResult(
            action=action,
            success=True,
            approval_id=request_id,
            details={
                "status": "pending_approval",
                "approvers": approvers,
            },
        )

    def _get_alert_type(self, alert: AlertProtocol) -> str:
        """Extract alert type from alert."""
        if alert.metadata:
            if "alert_type" in alert.metadata:
                return alert.metadata["alert_type"]
            if "identity_alert_type" in alert.metadata:
                return alert.metadata["identity_alert_type"]

        # Infer from rule name
        rule_lower = alert.rule_name.lower()

        type_keywords = {
            "brute_force": ["brute", "bruteforce"],
            "credential_stuffing": ["credential", "stuffing"],
            "password_spray": ["spray"],
            "mfa_fatigue": ["fatigue", "mfa bomb"],
            "impossible_travel": ["impossible", "travel"],
            "session_hijack": ["hijack"],
            "privilege_escalation": ["privilege", "escalat"],
            "account_takeover": ["takeover", "compromise"],
            "token_theft": ["token"],
            "dormant_account": ["dormant"],
        }

        for alert_type, keywords in type_keywords.items():
            for keyword in keywords:
                if keyword in rule_lower:
                    return alert_type

        return "unknown"

    def _get_provider(self, alert: Optional[AlertProtocol]) -> str:
        """Extract identity provider from alert."""
        if not alert:
            return "unknown"

        if alert.metadata:
            if "provider" in alert.metadata:
                return alert.metadata["provider"]

        if alert.results:
            for result in alert.results:
                if "provider" in result:
                    return result["provider"]

        return "unknown"

    def _extract_user_id(self, alert: AlertProtocol) -> str:
        """Extract user ID/email from alert."""
        if alert.metadata:
            for key in ["user_email", "user_id", "email"]:
                if key in alert.metadata:
                    return alert.metadata[key]

        if alert.results:
            for result in alert.results:
                for key in ["user_email", "user_id", "email", "user", "principal"]:
                    if key in result:
                        return result[key]

        return "unknown"

    def _extract_source_ip(self, alert: AlertProtocol) -> Optional[str]:
        """Extract source IP from alert."""
        if alert.metadata:
            if "source_ip" in alert.metadata:
                return alert.metadata["source_ip"]

        if alert.results:
            for result in alert.results:
                for key in ["source_ip", "sourceipaddress", "ip", "client_ip"]:
                    if key in result:
                        return result[key]

        return None

    def _extract_device_id(self, alert: AlertProtocol) -> Optional[str]:
        """Extract device ID from alert."""
        if alert.metadata:
            if "device_id" in alert.metadata:
                return alert.metadata["device_id"]

        if alert.results:
            for result in alert.results:
                for key in ["device_id", "device", "machine_id"]:
                    if key in result:
                        return result[key]

        return None

    def _get_action_config(
        self,
        action: ResponseAction,
        alert_type: str,
    ) -> Optional[ResponseActionConfig]:
        """Get configuration for an action."""
        configs = self.config.action_configs.get(alert_type, [])

        for config in configs:
            if config.action == action:
                return config

        return None

    def _is_in_cooldown(
        self,
        action: ResponseAction,
        user_id: str,
        alert_type: str,
    ) -> bool:
        """Check if action is in cooldown for user."""
        cooldown_key = f"{action.value}:{user_id}:{alert_type}"
        cooldown_until = self._action_cooldowns.get(cooldown_key)

        if cooldown_until and datetime.now(timezone.utc) < cooldown_until:
            return True

        # Check external log if available
        if self.action_log:
            config = self._get_action_config(action, alert_type)
            cooldown_minutes = (
                config.cooldown_minutes if config
                else self.config.default_cooldown_minutes
            )
            since = datetime.now(timezone.utc) - timedelta(minutes=cooldown_minutes)

            try:
                recent = self.action_log.get_recent_actions(
                    user_id, action.value, since
                )
                if recent:
                    return True
            except Exception as e:
                logger.debug(f"Error checking action log: {e}")

        return False

    def _set_cooldown(
        self,
        action: ResponseAction,
        user_id: str,
        alert_type: str,
        config: Optional[ResponseActionConfig],
    ) -> None:
        """Set cooldown for an action."""
        cooldown_minutes = (
            config.cooldown_minutes if config
            else self.config.default_cooldown_minutes
        )
        cooldown_key = f"{action.value}:{user_id}:{alert_type}"
        self._action_cooldowns[cooldown_key] = (
            datetime.now(timezone.utc) + timedelta(minutes=cooldown_minutes)
        )

    def _log_action(
        self,
        action: ResponseAction,
        alert_id: str,
        user_id: str,
        result: ResponseActionResult,
    ) -> None:
        """Log an executed action."""
        logger.info(
            f"Action executed: {action.value} for user {user_id} "
            f"(alert {alert_id}): success={result.success}"
        )

        if self.action_log:
            try:
                self.action_log.log_action(
                    action=action.value,
                    alert_id=alert_id,
                    user_id=user_id,
                    result=result.to_dict(),
                )
            except Exception as e:
                logger.error(f"Error logging action: {e}")

    def _send_notifications(
        self,
        action: ResponseAction,
        alert: AlertProtocol,
        user_id: str,
        channels: List[str],
    ) -> None:
        """Send notifications about action execution."""
        if not self.notification_service:
            return

        message = f"Action {action.value} executed for user {user_id}"

        for channel in channels:
            try:
                self.notification_service.send_notification(
                    channel=channel,
                    message=message,
                    context={
                        "action": action.value,
                        "user_id": user_id,
                        "alert_id": alert.id,
                    },
                )
            except Exception as e:
                logger.error(f"Error sending notification to {channel}: {e}")

    def _build_user_notification(self, alert: Optional[AlertProtocol]) -> str:
        """Build notification message for affected user."""
        if not alert:
            return "A security alert has been triggered on your account."

        return (
            f"Security Alert: {alert.rule_name}\n\n"
            f"A security alert has been triggered on your account. "
            f"If you did not perform this activity, please contact IT Security immediately."
        )

    def _build_manager_notification(
        self,
        user_id: str,
        alert: Optional[AlertProtocol],
    ) -> str:
        """Build notification message for user's manager."""
        if not alert:
            return f"A security alert has been triggered for user {user_id}."

        return (
            f"Security Alert: {alert.rule_name}\n\n"
            f"A security alert has been triggered for {user_id}. "
            f"Severity: {alert.severity.upper()}\n"
            f"Please review and take appropriate action."
        )

    def _build_ticket_description(self, alert: Optional[AlertProtocol]) -> str:
        """Build ticket description from alert."""
        if not alert:
            return "Security alert requiring investigation."

        return (
            f"Alert: {alert.rule_name}\n"
            f"Severity: {alert.severity}\n"
            f"Time: {alert.timestamp.isoformat()}\n"
            f"Alert ID: {alert.id}\n\n"
            f"This ticket was automatically created for investigation."
        )
