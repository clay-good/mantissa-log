"""Identity provider action implementations.

Provides abstract and concrete implementations for executing
response actions against identity providers (Okta, Azure AD, etc.).

Note: These are placeholder implementations that log actions but don't
actually execute them. Full implementations require API credentials
and should be enabled carefully in production.
"""

import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


@dataclass
class ProviderActionResult:
    """Result of a provider action execution.

    Attributes:
        success: Whether the action succeeded
        provider: Identity provider name
        action: Action that was executed
        user_id: Target user ID
        details: Additional details
        error: Error message if failed
        dry_run: Whether this was a dry run (not actually executed)
    """

    success: bool
    provider: str
    action: str
    user_id: str
    details: Dict[str, Any]
    error: Optional[str] = None
    dry_run: bool = True
    executed_at: datetime = None

    def __post_init__(self):
        if self.executed_at is None:
            self.executed_at = datetime.now(timezone.utc)

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "success": self.success,
            "provider": self.provider,
            "action": self.action,
            "user_id": self.user_id,
            "details": self.details,
            "error": self.error,
            "dry_run": self.dry_run,
            "executed_at": self.executed_at.isoformat(),
        }


class IdentityProviderActions(ABC):
    """Abstract base class for identity provider actions.

    Defines the interface for executing response actions against
    identity providers. Implementations should handle provider-specific
    API calls.
    """

    def __init__(
        self,
        api_credentials: Optional[Dict[str, str]] = None,
        dry_run: bool = True,
    ):
        """Initialize provider actions.

        Args:
            api_credentials: API credentials for the provider
            dry_run: If True, log actions but don't execute
        """
        self.api_credentials = api_credentials or {}
        self.dry_run = dry_run

    @property
    @abstractmethod
    def provider_name(self) -> str:
        """Get the provider name."""
        pass

    @abstractmethod
    def terminate_user_sessions(self, user_id: str) -> ProviderActionResult:
        """Terminate all active sessions for a user.

        Args:
            user_id: User identifier

        Returns:
            ProviderActionResult
        """
        pass

    @abstractmethod
    def disable_user_account(self, user_id: str) -> ProviderActionResult:
        """Disable a user account.

        Args:
            user_id: User identifier

        Returns:
            ProviderActionResult
        """
        pass

    @abstractmethod
    def enable_user_account(self, user_id: str) -> ProviderActionResult:
        """Enable a previously disabled user account.

        Args:
            user_id: User identifier

        Returns:
            ProviderActionResult
        """
        pass

    @abstractmethod
    def require_mfa(self, user_id: str) -> ProviderActionResult:
        """Force user to re-authenticate with MFA.

        Args:
            user_id: User identifier

        Returns:
            ProviderActionResult
        """
        pass

    @abstractmethod
    def revoke_tokens(self, user_id: str) -> ProviderActionResult:
        """Revoke all tokens for a user.

        Args:
            user_id: User identifier

        Returns:
            ProviderActionResult
        """
        pass

    @abstractmethod
    def force_password_reset(self, user_id: str) -> ProviderActionResult:
        """Force user to reset password on next login.

        Args:
            user_id: User identifier

        Returns:
            ProviderActionResult
        """
        pass

    def lock_account(self, user_id: str) -> ProviderActionResult:
        """Lock a user account (may differ from disable).

        Args:
            user_id: User identifier

        Returns:
            ProviderActionResult
        """
        # Default implementation uses disable
        return self.disable_user_account(user_id)

    def unlock_account(self, user_id: str) -> ProviderActionResult:
        """Unlock a locked user account.

        Args:
            user_id: User identifier

        Returns:
            ProviderActionResult
        """
        # Default implementation uses enable
        return self.enable_user_account(user_id)


class OktaActions(IdentityProviderActions):
    """Okta-specific action implementations.

    Placeholder implementation that logs actions.
    Full implementation requires Okta API credentials.
    """

    @property
    def provider_name(self) -> str:
        return "okta"

    def __init__(
        self,
        api_credentials: Optional[Dict[str, str]] = None,
        dry_run: bool = True,
        org_url: str = "",
    ):
        """Initialize Okta actions.

        Args:
            api_credentials: Should contain 'api_token'
            dry_run: If True, log actions but don't execute
            org_url: Okta organization URL
        """
        super().__init__(api_credentials, dry_run)
        self.org_url = org_url

    def terminate_user_sessions(self, user_id: str) -> ProviderActionResult:
        """Terminate Okta sessions using DELETE /api/v1/users/{userId}/sessions."""
        action = "terminate_sessions"

        if self.dry_run:
            logger.info(f"[DRY RUN] Okta: Would terminate sessions for user {user_id}")
            return ProviderActionResult(
                success=True,
                provider=self.provider_name,
                action=action,
                user_id=user_id,
                details={"message": "Dry run - no action taken"},
                dry_run=True,
            )

        # Full implementation would call Okta API
        # DELETE https://{org_url}/api/v1/users/{userId}/sessions
        logger.warning(
            f"Okta terminate_sessions not implemented for production. "
            f"User: {user_id}"
        )
        return ProviderActionResult(
            success=False,
            provider=self.provider_name,
            action=action,
            user_id=user_id,
            details={},
            error="Production implementation not configured",
            dry_run=False,
        )

    def disable_user_account(self, user_id: str) -> ProviderActionResult:
        """Disable Okta user using POST /api/v1/users/{userId}/lifecycle/suspend."""
        action = "disable_account"

        if self.dry_run:
            logger.info(f"[DRY RUN] Okta: Would disable account for user {user_id}")
            return ProviderActionResult(
                success=True,
                provider=self.provider_name,
                action=action,
                user_id=user_id,
                details={"message": "Dry run - no action taken"},
                dry_run=True,
            )

        logger.warning(
            f"Okta disable_account not implemented for production. "
            f"User: {user_id}"
        )
        return ProviderActionResult(
            success=False,
            provider=self.provider_name,
            action=action,
            user_id=user_id,
            details={},
            error="Production implementation not configured",
            dry_run=False,
        )

    def enable_user_account(self, user_id: str) -> ProviderActionResult:
        """Enable Okta user using POST /api/v1/users/{userId}/lifecycle/unsuspend."""
        action = "enable_account"

        if self.dry_run:
            logger.info(f"[DRY RUN] Okta: Would enable account for user {user_id}")
            return ProviderActionResult(
                success=True,
                provider=self.provider_name,
                action=action,
                user_id=user_id,
                details={"message": "Dry run - no action taken"},
                dry_run=True,
            )

        logger.warning(
            f"Okta enable_account not implemented for production. "
            f"User: {user_id}"
        )
        return ProviderActionResult(
            success=False,
            provider=self.provider_name,
            action=action,
            user_id=user_id,
            details={},
            error="Production implementation not configured",
            dry_run=False,
        )

    def require_mfa(self, user_id: str) -> ProviderActionResult:
        """Expire Okta session to force MFA re-authentication."""
        action = "require_mfa"

        if self.dry_run:
            logger.info(f"[DRY RUN] Okta: Would require MFA for user {user_id}")
            return ProviderActionResult(
                success=True,
                provider=self.provider_name,
                action=action,
                user_id=user_id,
                details={"message": "Dry run - no action taken"},
                dry_run=True,
            )

        logger.warning(
            f"Okta require_mfa not implemented for production. "
            f"User: {user_id}"
        )
        return ProviderActionResult(
            success=False,
            provider=self.provider_name,
            action=action,
            user_id=user_id,
            details={},
            error="Production implementation not configured",
            dry_run=False,
        )

    def revoke_tokens(self, user_id: str) -> ProviderActionResult:
        """Revoke Okta tokens using DELETE /api/v1/users/{userId}/sessions."""
        action = "revoke_tokens"

        if self.dry_run:
            logger.info(f"[DRY RUN] Okta: Would revoke tokens for user {user_id}")
            return ProviderActionResult(
                success=True,
                provider=self.provider_name,
                action=action,
                user_id=user_id,
                details={"message": "Dry run - no action taken"},
                dry_run=True,
            )

        logger.warning(
            f"Okta revoke_tokens not implemented for production. "
            f"User: {user_id}"
        )
        return ProviderActionResult(
            success=False,
            provider=self.provider_name,
            action=action,
            user_id=user_id,
            details={},
            error="Production implementation not configured",
            dry_run=False,
        )

    def force_password_reset(self, user_id: str) -> ProviderActionResult:
        """Force password reset using POST /api/v1/users/{userId}/lifecycle/expire_password."""
        action = "force_password_reset"

        if self.dry_run:
            logger.info(f"[DRY RUN] Okta: Would force password reset for user {user_id}")
            return ProviderActionResult(
                success=True,
                provider=self.provider_name,
                action=action,
                user_id=user_id,
                details={"message": "Dry run - no action taken"},
                dry_run=True,
            )

        logger.warning(
            f"Okta force_password_reset not implemented for production. "
            f"User: {user_id}"
        )
        return ProviderActionResult(
            success=False,
            provider=self.provider_name,
            action=action,
            user_id=user_id,
            details={},
            error="Production implementation not configured",
            dry_run=False,
        )


class AzureActions(IdentityProviderActions):
    """Azure AD/Entra ID-specific action implementations.

    Placeholder implementation that logs actions.
    Full implementation requires Microsoft Graph API credentials.
    """

    @property
    def provider_name(self) -> str:
        return "azure"

    def __init__(
        self,
        api_credentials: Optional[Dict[str, str]] = None,
        dry_run: bool = True,
        tenant_id: str = "",
    ):
        """Initialize Azure actions.

        Args:
            api_credentials: Should contain 'client_id', 'client_secret'
            dry_run: If True, log actions but don't execute
            tenant_id: Azure tenant ID
        """
        super().__init__(api_credentials, dry_run)
        self.tenant_id = tenant_id

    def terminate_user_sessions(self, user_id: str) -> ProviderActionResult:
        """Revoke Azure AD sign-in sessions using Graph API."""
        action = "terminate_sessions"

        if self.dry_run:
            logger.info(f"[DRY RUN] Azure: Would terminate sessions for user {user_id}")
            return ProviderActionResult(
                success=True,
                provider=self.provider_name,
                action=action,
                user_id=user_id,
                details={"message": "Dry run - no action taken"},
                dry_run=True,
            )

        # Full implementation would call:
        # POST https://graph.microsoft.com/v1.0/users/{userId}/revokeSignInSessions
        logger.warning(
            f"Azure terminate_sessions not implemented for production. "
            f"User: {user_id}"
        )
        return ProviderActionResult(
            success=False,
            provider=self.provider_name,
            action=action,
            user_id=user_id,
            details={},
            error="Production implementation not configured",
            dry_run=False,
        )

    def disable_user_account(self, user_id: str) -> ProviderActionResult:
        """Disable Azure AD user using PATCH /users/{userId}."""
        action = "disable_account"

        if self.dry_run:
            logger.info(f"[DRY RUN] Azure: Would disable account for user {user_id}")
            return ProviderActionResult(
                success=True,
                provider=self.provider_name,
                action=action,
                user_id=user_id,
                details={"message": "Dry run - no action taken"},
                dry_run=True,
            )

        # Full implementation would call:
        # PATCH https://graph.microsoft.com/v1.0/users/{userId}
        # Body: {"accountEnabled": false}
        logger.warning(
            f"Azure disable_account not implemented for production. "
            f"User: {user_id}"
        )
        return ProviderActionResult(
            success=False,
            provider=self.provider_name,
            action=action,
            user_id=user_id,
            details={},
            error="Production implementation not configured",
            dry_run=False,
        )

    def enable_user_account(self, user_id: str) -> ProviderActionResult:
        """Enable Azure AD user using PATCH /users/{userId}."""
        action = "enable_account"

        if self.dry_run:
            logger.info(f"[DRY RUN] Azure: Would enable account for user {user_id}")
            return ProviderActionResult(
                success=True,
                provider=self.provider_name,
                action=action,
                user_id=user_id,
                details={"message": "Dry run - no action taken"},
                dry_run=True,
            )

        logger.warning(
            f"Azure enable_account not implemented for production. "
            f"User: {user_id}"
        )
        return ProviderActionResult(
            success=False,
            provider=self.provider_name,
            action=action,
            user_id=user_id,
            details={},
            error="Production implementation not configured",
            dry_run=False,
        )

    def require_mfa(self, user_id: str) -> ProviderActionResult:
        """Revoke sessions to force MFA re-authentication."""
        action = "require_mfa"

        if self.dry_run:
            logger.info(f"[DRY RUN] Azure: Would require MFA for user {user_id}")
            return ProviderActionResult(
                success=True,
                provider=self.provider_name,
                action=action,
                user_id=user_id,
                details={"message": "Dry run - no action taken"},
                dry_run=True,
            )

        logger.warning(
            f"Azure require_mfa not implemented for production. "
            f"User: {user_id}"
        )
        return ProviderActionResult(
            success=False,
            provider=self.provider_name,
            action=action,
            user_id=user_id,
            details={},
            error="Production implementation not configured",
            dry_run=False,
        )

    def revoke_tokens(self, user_id: str) -> ProviderActionResult:
        """Revoke Azure AD refresh tokens."""
        action = "revoke_tokens"

        if self.dry_run:
            logger.info(f"[DRY RUN] Azure: Would revoke tokens for user {user_id}")
            return ProviderActionResult(
                success=True,
                provider=self.provider_name,
                action=action,
                user_id=user_id,
                details={"message": "Dry run - no action taken"},
                dry_run=True,
            )

        logger.warning(
            f"Azure revoke_tokens not implemented for production. "
            f"User: {user_id}"
        )
        return ProviderActionResult(
            success=False,
            provider=self.provider_name,
            action=action,
            user_id=user_id,
            details={},
            error="Production implementation not configured",
            dry_run=False,
        )

    def force_password_reset(self, user_id: str) -> ProviderActionResult:
        """Force password change on next sign-in."""
        action = "force_password_reset"

        if self.dry_run:
            logger.info(f"[DRY RUN] Azure: Would force password reset for user {user_id}")
            return ProviderActionResult(
                success=True,
                provider=self.provider_name,
                action=action,
                user_id=user_id,
                details={"message": "Dry run - no action taken"},
                dry_run=True,
            )

        # PATCH /users/{userId}
        # Body: {"passwordProfile": {"forceChangePasswordNextSignIn": true}}
        logger.warning(
            f"Azure force_password_reset not implemented for production. "
            f"User: {user_id}"
        )
        return ProviderActionResult(
            success=False,
            provider=self.provider_name,
            action=action,
            user_id=user_id,
            details={},
            error="Production implementation not configured",
            dry_run=False,
        )


class GoogleWorkspaceActions(IdentityProviderActions):
    """Google Workspace-specific action implementations.

    Placeholder implementation that logs actions.
    Full implementation requires Google Admin SDK credentials.
    """

    @property
    def provider_name(self) -> str:
        return "google_workspace"

    def __init__(
        self,
        api_credentials: Optional[Dict[str, str]] = None,
        dry_run: bool = True,
        customer_id: str = "",
    ):
        """Initialize Google Workspace actions.

        Args:
            api_credentials: Service account credentials
            dry_run: If True, log actions but don't execute
            customer_id: Google Workspace customer ID
        """
        super().__init__(api_credentials, dry_run)
        self.customer_id = customer_id

    def terminate_user_sessions(self, user_id: str) -> ProviderActionResult:
        """Sign out user from all devices."""
        action = "terminate_sessions"

        if self.dry_run:
            logger.info(f"[DRY RUN] Google: Would terminate sessions for user {user_id}")
            return ProviderActionResult(
                success=True,
                provider=self.provider_name,
                action=action,
                user_id=user_id,
                details={"message": "Dry run - no action taken"},
                dry_run=True,
            )

        logger.warning(
            f"Google terminate_sessions not implemented for production. "
            f"User: {user_id}"
        )
        return ProviderActionResult(
            success=False,
            provider=self.provider_name,
            action=action,
            user_id=user_id,
            details={},
            error="Production implementation not configured",
            dry_run=False,
        )

    def disable_user_account(self, user_id: str) -> ProviderActionResult:
        """Suspend Google Workspace user."""
        action = "disable_account"

        if self.dry_run:
            logger.info(f"[DRY RUN] Google: Would disable account for user {user_id}")
            return ProviderActionResult(
                success=True,
                provider=self.provider_name,
                action=action,
                user_id=user_id,
                details={"message": "Dry run - no action taken"},
                dry_run=True,
            )

        # PUT https://admin.googleapis.com/admin/directory/v1/users/{userKey}
        # Body: {"suspended": true}
        logger.warning(
            f"Google disable_account not implemented for production. "
            f"User: {user_id}"
        )
        return ProviderActionResult(
            success=False,
            provider=self.provider_name,
            action=action,
            user_id=user_id,
            details={},
            error="Production implementation not configured",
            dry_run=False,
        )

    def enable_user_account(self, user_id: str) -> ProviderActionResult:
        """Unsuspend Google Workspace user."""
        action = "enable_account"

        if self.dry_run:
            logger.info(f"[DRY RUN] Google: Would enable account for user {user_id}")
            return ProviderActionResult(
                success=True,
                provider=self.provider_name,
                action=action,
                user_id=user_id,
                details={"message": "Dry run - no action taken"},
                dry_run=True,
            )

        logger.warning(
            f"Google enable_account not implemented for production. "
            f"User: {user_id}"
        )
        return ProviderActionResult(
            success=False,
            provider=self.provider_name,
            action=action,
            user_id=user_id,
            details={},
            error="Production implementation not configured",
            dry_run=False,
        )

    def require_mfa(self, user_id: str) -> ProviderActionResult:
        """Force re-authentication by signing out user."""
        action = "require_mfa"

        if self.dry_run:
            logger.info(f"[DRY RUN] Google: Would require MFA for user {user_id}")
            return ProviderActionResult(
                success=True,
                provider=self.provider_name,
                action=action,
                user_id=user_id,
                details={"message": "Dry run - no action taken"},
                dry_run=True,
            )

        logger.warning(
            f"Google require_mfa not implemented for production. "
            f"User: {user_id}"
        )
        return ProviderActionResult(
            success=False,
            provider=self.provider_name,
            action=action,
            user_id=user_id,
            details={},
            error="Production implementation not configured",
            dry_run=False,
        )

    def revoke_tokens(self, user_id: str) -> ProviderActionResult:
        """Revoke OAuth tokens for user."""
        action = "revoke_tokens"

        if self.dry_run:
            logger.info(f"[DRY RUN] Google: Would revoke tokens for user {user_id}")
            return ProviderActionResult(
                success=True,
                provider=self.provider_name,
                action=action,
                user_id=user_id,
                details={"message": "Dry run - no action taken"},
                dry_run=True,
            )

        logger.warning(
            f"Google revoke_tokens not implemented for production. "
            f"User: {user_id}"
        )
        return ProviderActionResult(
            success=False,
            provider=self.provider_name,
            action=action,
            user_id=user_id,
            details={},
            error="Production implementation not configured",
            dry_run=False,
        )

    def force_password_reset(self, user_id: str) -> ProviderActionResult:
        """Force password change on next login."""
        action = "force_password_reset"

        if self.dry_run:
            logger.info(f"[DRY RUN] Google: Would force password reset for user {user_id}")
            return ProviderActionResult(
                success=True,
                provider=self.provider_name,
                action=action,
                user_id=user_id,
                details={"message": "Dry run - no action taken"},
                dry_run=True,
            )

        # PUT with changePasswordAtNextLogin: true
        logger.warning(
            f"Google force_password_reset not implemented for production. "
            f"User: {user_id}"
        )
        return ProviderActionResult(
            success=False,
            provider=self.provider_name,
            action=action,
            user_id=user_id,
            details={},
            error="Production implementation not configured",
            dry_run=False,
        )


class DuoActions(IdentityProviderActions):
    """Duo Security-specific action implementations.

    Placeholder implementation that logs actions.
    Full implementation requires Duo Admin API credentials.
    """

    @property
    def provider_name(self) -> str:
        return "duo"

    def __init__(
        self,
        api_credentials: Optional[Dict[str, str]] = None,
        dry_run: bool = True,
        api_host: str = "",
    ):
        """Initialize Duo actions.

        Args:
            api_credentials: Should contain 'integration_key', 'secret_key'
            dry_run: If True, log actions but don't execute
            api_host: Duo API hostname
        """
        super().__init__(api_credentials, dry_run)
        self.api_host = api_host

    def terminate_user_sessions(self, user_id: str) -> ProviderActionResult:
        """Invalidate Duo bypass codes and trusted sessions."""
        action = "terminate_sessions"

        if self.dry_run:
            logger.info(f"[DRY RUN] Duo: Would terminate sessions for user {user_id}")
            return ProviderActionResult(
                success=True,
                provider=self.provider_name,
                action=action,
                user_id=user_id,
                details={"message": "Dry run - no action taken"},
                dry_run=True,
            )

        logger.warning(
            f"Duo terminate_sessions not implemented for production. "
            f"User: {user_id}"
        )
        return ProviderActionResult(
            success=False,
            provider=self.provider_name,
            action=action,
            user_id=user_id,
            details={},
            error="Production implementation not configured",
            dry_run=False,
        )

    def disable_user_account(self, user_id: str) -> ProviderActionResult:
        """Set Duo user status to disabled."""
        action = "disable_account"

        if self.dry_run:
            logger.info(f"[DRY RUN] Duo: Would disable account for user {user_id}")
            return ProviderActionResult(
                success=True,
                provider=self.provider_name,
                action=action,
                user_id=user_id,
                details={"message": "Dry run - no action taken"},
                dry_run=True,
            )

        # POST /admin/v1/users/{user_id} with status=disabled
        logger.warning(
            f"Duo disable_account not implemented for production. "
            f"User: {user_id}"
        )
        return ProviderActionResult(
            success=False,
            provider=self.provider_name,
            action=action,
            user_id=user_id,
            details={},
            error="Production implementation not configured",
            dry_run=False,
        )

    def enable_user_account(self, user_id: str) -> ProviderActionResult:
        """Set Duo user status to active."""
        action = "enable_account"

        if self.dry_run:
            logger.info(f"[DRY RUN] Duo: Would enable account for user {user_id}")
            return ProviderActionResult(
                success=True,
                provider=self.provider_name,
                action=action,
                user_id=user_id,
                details={"message": "Dry run - no action taken"},
                dry_run=True,
            )

        logger.warning(
            f"Duo enable_account not implemented for production. "
            f"User: {user_id}"
        )
        return ProviderActionResult(
            success=False,
            provider=self.provider_name,
            action=action,
            user_id=user_id,
            details={},
            error="Production implementation not configured",
            dry_run=False,
        )

    def require_mfa(self, user_id: str) -> ProviderActionResult:
        """Duo doesn't have a direct 'require MFA' - handled by auth policy."""
        action = "require_mfa"

        if self.dry_run:
            logger.info(f"[DRY RUN] Duo: Would require MFA for user {user_id}")
            return ProviderActionResult(
                success=True,
                provider=self.provider_name,
                action=action,
                user_id=user_id,
                details={"message": "Dry run - no action taken (Duo MFA policy based)"},
                dry_run=True,
            )

        logger.info(
            f"Duo require_mfa: MFA is controlled by Duo policies, not per-user. "
            f"User: {user_id}"
        )
        return ProviderActionResult(
            success=True,
            provider=self.provider_name,
            action=action,
            user_id=user_id,
            details={"message": "Duo MFA is policy-based, not per-user action"},
            dry_run=False,
        )

    def revoke_tokens(self, user_id: str) -> ProviderActionResult:
        """Delete Duo bypass codes and remembered device sessions."""
        action = "revoke_tokens"

        if self.dry_run:
            logger.info(f"[DRY RUN] Duo: Would revoke tokens for user {user_id}")
            return ProviderActionResult(
                success=True,
                provider=self.provider_name,
                action=action,
                user_id=user_id,
                details={"message": "Dry run - no action taken"},
                dry_run=True,
            )

        logger.warning(
            f"Duo revoke_tokens not implemented for production. "
            f"User: {user_id}"
        )
        return ProviderActionResult(
            success=False,
            provider=self.provider_name,
            action=action,
            user_id=user_id,
            details={},
            error="Production implementation not configured",
            dry_run=False,
        )

    def force_password_reset(self, user_id: str) -> ProviderActionResult:
        """Duo doesn't manage passwords - delegate to primary IdP."""
        action = "force_password_reset"

        logger.info(
            f"Duo force_password_reset: Duo doesn't manage passwords. "
            f"Use primary IdP (Okta/Azure/Google) instead. User: {user_id}"
        )
        return ProviderActionResult(
            success=False,
            provider=self.provider_name,
            action=action,
            user_id=user_id,
            details={"message": "Duo does not manage passwords"},
            error="Password management not available in Duo",
            dry_run=self.dry_run,
        )
