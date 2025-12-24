"""Microsoft 365 Management Activity identity event mapper."""

from datetime import datetime
from typing import Any, Dict, List, Optional

from ..identity_event import IdentityEvent, IdentityEventType, GeoLocation, PrivilegeChange
from .base_mapper import BaseIdentityMapper


class Microsoft365IdentityMapper(BaseIdentityMapper):
    """Maps Microsoft 365 Management Activity API events to IdentityEvent format.

    Supports:
    - Azure AD events (user sign-ins, audit logs)
    - Exchange Online events
    - SharePoint Online events
    - Microsoft Teams events
    """

    # Record type to workload mapping
    RECORD_TYPE_MAP = {
        8: "AzureActiveDirectory",
        9: "AzureActiveDirectoryAccountLogon",
        15: "AzureActiveDirectoryStsLogon",
        1: "ExchangeAdmin",
        2: "ExchangeItem",
        4: "SharePoint",
        6: "SharePointFileOperation",
        25: "MicrosoftTeams",
        64: "MicrosoftTeamsAdmin",
    }

    # Operation to event type mapping
    OPERATION_MAP = {
        # Azure AD sign-in operations
        "UserLoggedIn": IdentityEventType.AUTH_SUCCESS,
        "UserLoginFailed": IdentityEventType.AUTH_FAILURE,

        # User management
        "Add user.": IdentityEventType.ACCOUNT_CREATED,
        "Delete user.": IdentityEventType.ACCOUNT_DELETED,
        "Update user.": IdentityEventType.UNKNOWN,
        "Disable account.": IdentityEventType.ACCOUNT_DISABLED,
        "Enable account.": IdentityEventType.ACCOUNT_UNLOCKED,
        "Set force change user password.": IdentityEventType.PASSWORD_RESET,
        "Change user password.": IdentityEventType.PASSWORD_CHANGE,
        "Reset user password.": IdentityEventType.PASSWORD_RESET,
        "User registered security info.": IdentityEventType.MFA_ENROLLED,
        "User deleted security info.": IdentityEventType.MFA_REMOVED,

        # Role/group management
        "Add member to role.": IdentityEventType.PRIVILEGE_GRANT,
        "Remove member from role.": IdentityEventType.PRIVILEGE_REVOKE,
        "Add member to group.": IdentityEventType.PRIVILEGE_GRANT,
        "Remove member from group.": IdentityEventType.PRIVILEGE_REVOKE,

        # Exchange operations
        "Add-MailboxPermission": IdentityEventType.PRIVILEGE_GRANT,
        "Remove-MailboxPermission": IdentityEventType.PRIVILEGE_REVOKE,
        "Set-Mailbox": IdentityEventType.UNKNOWN,
        "New-InboxRule": IdentityEventType.UNKNOWN,

        # OAuth/consent
        "Consent to application.": IdentityEventType.OAUTH_CONSENT_GRANTED,
        "Add OAuth2PermissionGrant.": IdentityEventType.OAUTH_CONSENT_GRANTED,
        "Remove OAuth2PermissionGrant.": IdentityEventType.OAUTH_CONSENT_REVOKED,
    }

    # Result status mapping
    RESULT_STATUS_MAP = {
        "Success": "success",
        "Succeeded": "success",
        "success": "success",
        "true": "success",
        "PartiallyProcessed": "partial",
        "Failed": "failure",
        "Failure": "failure",
        "failure": "failure",
        "false": "failure",
    }

    @property
    def provider_name(self) -> str:
        return "microsoft365"

    def map(self, raw_event: Dict[str, Any]) -> IdentityEvent:
        """Map Microsoft 365 event to IdentityEvent.

        Automatically detects event type based on RecordType and routes
        to appropriate mapper.
        """
        record_type = raw_event.get("RecordType", 0)
        workload = raw_event.get("Workload", "")

        # Azure AD events
        if record_type in (8, 9, 15) or workload == "AzureActiveDirectory":
            return self._map_azure_ad_event(raw_event)
        # Exchange events
        elif record_type in (1, 2, 3, 4) or workload == "Exchange":
            return self._map_exchange_event(raw_event)
        # SharePoint events
        elif record_type in (4, 6, 14) or workload == "SharePoint":
            return self._map_sharepoint_event(raw_event)
        else:
            return self._map_generic_event(raw_event)

    def map_event_type(self, raw_event: Dict[str, Any]) -> IdentityEventType:
        """Map Microsoft 365 event to IdentityEventType."""
        operation = raw_event.get("Operation", "")
        return self._get_event_type(operation, raw_event)

    def _get_event_type(self, operation: str, raw_event: Dict[str, Any]) -> IdentityEventType:
        """Determine event type from operation."""
        # Direct mapping
        if operation in self.OPERATION_MAP:
            return self.OPERATION_MAP[operation]

        # Pattern-based mapping
        operation_lower = operation.lower()

        # Login events
        if "login" in operation_lower or "logon" in operation_lower or "signin" in operation_lower:
            result_status = raw_event.get("ResultStatus", "")
            if self._is_success(result_status):
                return IdentityEventType.AUTH_SUCCESS
            return IdentityEventType.AUTH_FAILURE

        if "logout" in operation_lower or "signout" in operation_lower:
            return IdentityEventType.SESSION_END

        # User management
        if "user" in operation_lower:
            if "add" in operation_lower or "create" in operation_lower or "new" in operation_lower:
                return IdentityEventType.ACCOUNT_CREATED
            if "delete" in operation_lower or "remove" in operation_lower:
                return IdentityEventType.ACCOUNT_DELETED
            if "disable" in operation_lower:
                return IdentityEventType.ACCOUNT_DISABLED
            if "enable" in operation_lower:
                return IdentityEventType.ACCOUNT_UNLOCKED

        # Password management
        if "password" in operation_lower:
            if "reset" in operation_lower or "force" in operation_lower:
                return IdentityEventType.PASSWORD_RESET
            if "change" in operation_lower:
                return IdentityEventType.PASSWORD_CHANGE

        # Role/group management
        if "role" in operation_lower or "member" in operation_lower or "group" in operation_lower:
            if "add" in operation_lower:
                return IdentityEventType.PRIVILEGE_GRANT
            if "remove" in operation_lower:
                return IdentityEventType.PRIVILEGE_REVOKE

        # Permission management
        if "permission" in operation_lower:
            if "add" in operation_lower or "grant" in operation_lower:
                return IdentityEventType.PRIVILEGE_GRANT
            if "remove" in operation_lower or "revoke" in operation_lower:
                return IdentityEventType.PRIVILEGE_REVOKE

        # MFA/security info
        if "security" in operation_lower and "info" in operation_lower:
            if "register" in operation_lower or "add" in operation_lower:
                return IdentityEventType.MFA_ENROLLED
            if "delete" in operation_lower or "remove" in operation_lower:
                return IdentityEventType.MFA_REMOVED

        # OAuth/consent
        if "consent" in operation_lower or "oauth" in operation_lower or "permissiongrant" in operation_lower:
            if "add" in operation_lower or "grant" in operation_lower:
                return IdentityEventType.OAUTH_CONSENT_GRANTED
            if "remove" in operation_lower or "revoke" in operation_lower:
                return IdentityEventType.OAUTH_CONSENT_REVOKED

        return IdentityEventType.UNKNOWN

    def _is_success(self, result_status: str) -> bool:
        """Check if result status indicates success."""
        if not result_status:
            return True  # Assume success if not specified
        status_lower = str(result_status).lower()
        return status_lower in ("success", "succeeded", "true", "partiallyprocessed")

    def _map_azure_ad_event(self, raw_event: Dict[str, Any]) -> IdentityEvent:
        """Map Azure AD event from Microsoft 365."""
        operation = raw_event.get("Operation", "")
        event_type = self._get_event_type(operation, raw_event)

        # Extract user info
        user_id = raw_event.get("UserId", "")
        user_key = raw_event.get("UserKey", "")

        # Extract client IP
        client_ip = raw_event.get("ClientIP", "")

        # Extract result info
        result_status = raw_event.get("ResultStatus", "")
        failure_reason = None
        if not self._is_success(result_status):
            failure_reason = self.normalize_failure_reason(result_status)

        # Extract extended properties
        extended_props = self._extract_extended_properties(raw_event)

        # Extract target user from modified properties
        target_user_id, target_user_email = self._extract_target_user(raw_event)

        # Extract privilege changes
        privilege_changes = self._extract_privilege_changes(raw_event, event_type)

        # Extract application info
        app_id = raw_event.get("AppId", raw_event.get("ApplicationId", ""))
        app_name = extended_props.get("applicationName", extended_props.get("AppDisplayName", ""))

        return IdentityEvent(
            event_id=raw_event.get("Id", self.generate_event_id(raw_event)),
            event_type=event_type,
            timestamp=self.parse_timestamp(raw_event.get("CreationTime")),
            provider=self.provider_name,
            user_id=user_key if user_key else None,
            user_email=self.normalize_email(user_id),
            user_display_name=user_id.split("@")[0] if "@" in user_id else user_id,
            source_ip=client_ip if client_ip else None,
            target_user_id=target_user_id,
            target_user_email=target_user_email,
            privilege_changes=privilege_changes,
            application_id=app_id if app_id else None,
            application_name=app_name if app_name else None,
            failure_reason=failure_reason,
            raw_event=raw_event,
            provider_event_type=operation,
            correlation_id=raw_event.get("CorrelationId"),
        )

    def _map_exchange_event(self, raw_event: Dict[str, Any]) -> IdentityEvent:
        """Map Exchange Online event from Microsoft 365."""
        operation = raw_event.get("Operation", "")
        event_type = self._get_event_type(operation, raw_event)

        # Extract user info
        user_id = raw_event.get("UserId", "")
        user_key = raw_event.get("UserKey", "")

        # Extract client IP
        client_ip = raw_event.get("ClientIP", "")

        # Extract target mailbox
        target_mailbox = raw_event.get("MailboxOwnerUPN", "")

        # Extract privilege changes for permission operations
        privilege_changes = self._extract_exchange_privilege_changes(raw_event, event_type)

        return IdentityEvent(
            event_id=raw_event.get("Id", self.generate_event_id(raw_event)),
            event_type=event_type,
            timestamp=self.parse_timestamp(raw_event.get("CreationTime")),
            provider=self.provider_name,
            user_id=user_key if user_key else None,
            user_email=self.normalize_email(user_id),
            user_display_name=user_id.split("@")[0] if "@" in user_id else user_id,
            source_ip=client_ip if client_ip else None,
            target_user_email=self.normalize_email(target_mailbox) if target_mailbox else None,
            privilege_changes=privilege_changes,
            raw_event=raw_event,
            provider_event_type=operation,
            correlation_id=raw_event.get("CorrelationId"),
        )

    def _map_sharepoint_event(self, raw_event: Dict[str, Any]) -> IdentityEvent:
        """Map SharePoint Online event from Microsoft 365."""
        operation = raw_event.get("Operation", "")
        event_type = self._get_event_type(operation, raw_event)

        # Extract user info
        user_id = raw_event.get("UserId", "")
        user_key = raw_event.get("UserKey", "")

        # Extract client IP
        client_ip = raw_event.get("ClientIP", "")

        # Extract target user for sharing operations
        target_user_email = raw_event.get("TargetUserOrGroupName", "")

        return IdentityEvent(
            event_id=raw_event.get("Id", self.generate_event_id(raw_event)),
            event_type=event_type,
            timestamp=self.parse_timestamp(raw_event.get("CreationTime")),
            provider=self.provider_name,
            user_id=user_key if user_key else None,
            user_email=self.normalize_email(user_id),
            user_display_name=user_id.split("@")[0] if "@" in user_id else user_id,
            source_ip=client_ip if client_ip else None,
            target_user_email=self.normalize_email(target_user_email) if target_user_email and "@" in target_user_email else None,
            raw_event=raw_event,
            provider_event_type=operation,
            correlation_id=raw_event.get("CorrelationId"),
        )

    def _map_generic_event(self, raw_event: Dict[str, Any]) -> IdentityEvent:
        """Map generic/unknown Microsoft 365 event."""
        operation = raw_event.get("Operation", "")
        user_id = raw_event.get("UserId", "")

        return IdentityEvent(
            event_id=raw_event.get("Id", self.generate_event_id(raw_event)),
            event_type=IdentityEventType.UNKNOWN,
            timestamp=self.parse_timestamp(raw_event.get("CreationTime")),
            provider=self.provider_name,
            user_email=self.normalize_email(user_id) if user_id else None,
            source_ip=raw_event.get("ClientIP"),
            raw_event=raw_event,
            provider_event_type=operation,
        )

    def _extract_extended_properties(self, raw_event: Dict[str, Any]) -> Dict[str, Any]:
        """Extract extended properties into a dictionary."""
        props = {}
        extended_properties = raw_event.get("ExtendedProperties", [])

        for prop in extended_properties:
            name = prop.get("Name", "")
            value = prop.get("Value", "")
            if name:
                props[name] = value

        return props

    def _extract_target_user(self, raw_event: Dict[str, Any]) -> tuple:
        """Extract target user from modified properties."""
        modified_properties = raw_event.get("ModifiedProperties", [])

        for prop in modified_properties:
            name = prop.get("Name", "").lower()
            if name in ("userprincipalname", "targetuserprincipalname"):
                new_value = prop.get("NewValue", "")
                if new_value:
                    return (None, self.normalize_email(new_value))

        # Check for ObjectId in certain operations
        object_id = raw_event.get("ObjectId", "")
        if object_id and "@" in object_id:
            return (None, self.normalize_email(object_id))

        return (None, None)

    def _extract_privilege_changes(
        self, raw_event: Dict[str, Any], event_type: IdentityEventType
    ) -> Optional[List[PrivilegeChange]]:
        """Extract privilege changes from Azure AD event."""
        if event_type not in (IdentityEventType.PRIVILEGE_GRANT, IdentityEventType.PRIVILEGE_REVOKE):
            return None

        changes = []
        action = "grant" if event_type == IdentityEventType.PRIVILEGE_GRANT else "revoke"

        # Extract from modified properties
        modified_properties = raw_event.get("ModifiedProperties", [])
        for prop in modified_properties:
            name = prop.get("Name", "").lower()
            if "role" in name or "group" in name:
                new_value = prop.get("NewValue", "")
                if new_value:
                    changes.append(PrivilegeChange(
                        action=action,
                        role_name=new_value,
                        granted_by=raw_event.get("UserId"),
                        timestamp=self.parse_timestamp(raw_event.get("CreationTime")),
                    ))

        # Extract from extended properties
        extended_props = self._extract_extended_properties(raw_event)
        role_name = extended_props.get("Role.DisplayName", extended_props.get("RoleName", ""))
        if role_name and not changes:
            changes.append(PrivilegeChange(
                action=action,
                role_name=role_name,
                granted_by=raw_event.get("UserId"),
                timestamp=self.parse_timestamp(raw_event.get("CreationTime")),
            ))

        return changes if changes else None

    def _extract_exchange_privilege_changes(
        self, raw_event: Dict[str, Any], event_type: IdentityEventType
    ) -> Optional[List[PrivilegeChange]]:
        """Extract privilege changes from Exchange event."""
        if event_type not in (IdentityEventType.PRIVILEGE_GRANT, IdentityEventType.PRIVILEGE_REVOKE):
            return None

        changes = []
        action = "grant" if event_type == IdentityEventType.PRIVILEGE_GRANT else "revoke"

        # Extract parameters
        parameters = raw_event.get("Parameters", [])
        access_rights = None

        for param in parameters:
            name = param.get("Name", "")
            value = param.get("Value", "")
            if name.lower() == "accessrights":
                access_rights = value

        if access_rights:
            changes.append(PrivilegeChange(
                action=action,
                role_name=access_rights,
                granted_by=raw_event.get("UserId"),
                timestamp=self.parse_timestamp(raw_event.get("CreationTime")),
            ))

        return changes if changes else None
