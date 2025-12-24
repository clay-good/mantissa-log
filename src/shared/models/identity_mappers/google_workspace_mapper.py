"""Google Workspace identity event mapper."""

from datetime import datetime
from typing import Any, Dict, List, Optional

from ..identity_event import IdentityEvent, IdentityEventType, GeoLocation, PrivilegeChange
from .base_mapper import BaseIdentityMapper


class GoogleWorkspaceIdentityMapper(BaseIdentityMapper):
    """Maps Google Workspace Reports API events to IdentityEvent format.

    Supports:
    - Login events (login application)
    - Admin events (admin application)
    - Token events (token application)
    - Groups events (groups application)
    """

    # Event name to IdentityEventType mapping
    EVENT_NAME_MAP = {
        # Login events
        "login_success": IdentityEventType.AUTH_SUCCESS,
        "login_failure": IdentityEventType.AUTH_FAILURE,
        "login_verification": IdentityEventType.MFA_CHALLENGE,
        "login_challenge": IdentityEventType.MFA_CHALLENGE,
        "logout": IdentityEventType.SESSION_END,
        "account_disabled_generic": IdentityEventType.ACCOUNT_DISABLED,
        "account_disabled_spamming": IdentityEventType.ACCOUNT_DISABLED,
        "account_disabled_hijacked": IdentityEventType.ACCOUNT_DISABLED,
        "account_disabled_password_leak": IdentityEventType.ACCOUNT_DISABLED,
        "suspicious_login": IdentityEventType.AUTH_FAILURE,
        "suspicious_login_less_secure_app": IdentityEventType.AUTH_FAILURE,
        "suspicious_programmatic_login": IdentityEventType.AUTH_FAILURE,
        "gov_attack_warning": IdentityEventType.AUTH_FAILURE,

        # Admin user events
        "CREATE_USER": IdentityEventType.ACCOUNT_CREATED,
        "DELETE_USER": IdentityEventType.ACCOUNT_DELETED,
        "SUSPEND_USER": IdentityEventType.ACCOUNT_DISABLED,
        "UNSUSPEND_USER": IdentityEventType.ACCOUNT_UNLOCKED,
        "CHANGE_PASSWORD": IdentityEventType.PASSWORD_CHANGE,
        "RESET_PASSWORD": IdentityEventType.PASSWORD_RESET,
        "GRANT_ADMIN_PRIVILEGE": IdentityEventType.PRIVILEGE_GRANT,
        "REVOKE_ADMIN_PRIVILEGE": IdentityEventType.PRIVILEGE_REVOKE,

        # Group events
        "ADD_GROUP_MEMBER": IdentityEventType.PRIVILEGE_GRANT,
        "REMOVE_GROUP_MEMBER": IdentityEventType.PRIVILEGE_REVOKE,
        "CREATE_GROUP": IdentityEventType.UNKNOWN,
        "DELETE_GROUP": IdentityEventType.UNKNOWN,

        # Token events
        "authorize": IdentityEventType.OAUTH_CONSENT_GRANTED,
        "revoke": IdentityEventType.OAUTH_CONSENT_REVOKED,

        # MFA/2SV events
        "2sv_enroll": IdentityEventType.MFA_ENROLLED,
        "2sv_disable": IdentityEventType.MFA_REMOVED,
        "change_2sv": IdentityEventType.MFA_METHOD_CHANGED,
    }

    # Login failure type mapping
    LOGIN_FAILURE_MAP = {
        "login_failure_invalid_password": "invalid_credentials",
        "login_failure_unknown_username": "user_not_found",
        "login_failure_account_disabled": "account_disabled",
        "login_failure_too_many_attempts": "account_locked",
    }

    @property
    def provider_name(self) -> str:
        return "google_workspace"

    def map(self, raw_event: Dict[str, Any]) -> IdentityEvent:
        """Map Google Workspace event to IdentityEvent.

        Automatically detects application type and routes to appropriate mapper.
        """
        event_id = raw_event.get("id", {})
        application_name = event_id.get("applicationName", "")

        if application_name == "login":
            return self._map_login_event(raw_event)
        elif application_name == "admin":
            return self._map_admin_event(raw_event)
        elif application_name == "token":
            return self._map_token_event(raw_event)
        elif application_name == "groups":
            return self._map_groups_event(raw_event)
        else:
            return self._map_generic_event(raw_event)

    def map_event_type(self, raw_event: Dict[str, Any]) -> IdentityEventType:
        """Map Google Workspace event to IdentityEventType."""
        events = raw_event.get("events", [])
        if not events:
            return IdentityEventType.UNKNOWN

        event_name = events[0].get("name", "")
        return self._get_event_type(event_name, events[0])

    def _get_event_type(self, event_name: str, event: Dict[str, Any]) -> IdentityEventType:
        """Determine event type from event name."""
        # Direct mapping
        if event_name in self.EVENT_NAME_MAP:
            return self.EVENT_NAME_MAP[event_name]

        # Pattern-based mapping
        event_name_lower = event_name.lower()

        if "login" in event_name_lower:
            if "success" in event_name_lower:
                return IdentityEventType.AUTH_SUCCESS
            if "failure" in event_name_lower or "failed" in event_name_lower:
                return IdentityEventType.AUTH_FAILURE
            if "challenge" in event_name_lower or "verification" in event_name_lower:
                return IdentityEventType.MFA_CHALLENGE

        if "logout" in event_name_lower:
            return IdentityEventType.SESSION_END

        if "password" in event_name_lower:
            if "reset" in event_name_lower:
                return IdentityEventType.PASSWORD_RESET
            return IdentityEventType.PASSWORD_CHANGE

        if "user" in event_name_lower:
            if "create" in event_name_lower or "add" in event_name_lower:
                return IdentityEventType.ACCOUNT_CREATED
            if "delete" in event_name_lower:
                return IdentityEventType.ACCOUNT_DELETED
            if "suspend" in event_name_lower:
                return IdentityEventType.ACCOUNT_DISABLED

        if "privilege" in event_name_lower or "role" in event_name_lower:
            if "grant" in event_name_lower or "add" in event_name_lower:
                return IdentityEventType.PRIVILEGE_GRANT
            if "revoke" in event_name_lower or "remove" in event_name_lower:
                return IdentityEventType.PRIVILEGE_REVOKE

        if "member" in event_name_lower:
            if "add" in event_name_lower:
                return IdentityEventType.PRIVILEGE_GRANT
            if "remove" in event_name_lower:
                return IdentityEventType.PRIVILEGE_REVOKE

        if "2sv" in event_name_lower or "2fa" in event_name_lower or "mfa" in event_name_lower:
            if "enroll" in event_name_lower or "enable" in event_name_lower:
                return IdentityEventType.MFA_ENROLLED
            if "disable" in event_name_lower or "remove" in event_name_lower:
                return IdentityEventType.MFA_REMOVED

        if "authorize" in event_name_lower or "consent" in event_name_lower:
            return IdentityEventType.OAUTH_CONSENT_GRANTED

        if "revoke" in event_name_lower:
            return IdentityEventType.OAUTH_CONSENT_REVOKED

        return IdentityEventType.UNKNOWN

    def _map_login_event(self, raw_event: Dict[str, Any]) -> IdentityEvent:
        """Map Google Workspace login event."""
        events = raw_event.get("events", [])
        event = events[0] if events else {}
        event_name = event.get("name", "")

        # Extract parameters
        parameters = self._extract_parameters(events)

        # Determine event type
        event_type = self._get_event_type(event_name, event)

        # Extract actor info
        actor = raw_event.get("actor", {})
        actor_email = actor.get("email", "")
        actor_profile_id = actor.get("profileId", "")

        # Extract IP and geo
        ip_address = raw_event.get("ipAddress", "")

        # Extract login details
        login_type = parameters.get("login_type", "")
        login_failure_type = parameters.get("login_failure_type", "")
        is_suspicious = parameters.get("is_suspicious", False)

        # Determine failure reason
        failure_reason = None
        if event_type == IdentityEventType.AUTH_FAILURE:
            if login_failure_type:
                failure_reason = self.normalize_failure_reason(
                    self.LOGIN_FAILURE_MAP.get(login_failure_type, login_failure_type)
                )
            elif is_suspicious:
                failure_reason = "suspicious_activity"

        # Extract 2SV/MFA info
        mfa_method = self._extract_mfa_method(parameters)

        # Check for challenge status
        if parameters.get("login_challenge_status") == "Challenge Passed":
            event_type = IdentityEventType.MFA_SUCCESS
        elif parameters.get("login_challenge_status") == "Challenge Failed":
            event_type = IdentityEventType.MFA_FAILURE
            failure_reason = "mfa_challenge_failed"

        # Extract event ID
        event_id_obj = raw_event.get("id", {})

        return IdentityEvent(
            event_id=event_id_obj.get("uniqueQualifier", self.generate_event_id(raw_event)),
            event_type=event_type,
            timestamp=self.parse_timestamp(event_id_obj.get("time")),
            provider=self.provider_name,
            user_id=actor_profile_id,
            user_email=self.normalize_email(actor_email),
            user_display_name=actor_email.split("@")[0] if "@" in actor_email else actor_email,
            source_ip=ip_address,
            mfa_method=mfa_method,
            auth_protocol=login_type if login_type else None,
            failure_reason=failure_reason,
            raw_event=raw_event,
            provider_event_type=event_name,
        )

    def _map_admin_event(self, raw_event: Dict[str, Any]) -> IdentityEvent:
        """Map Google Workspace admin event."""
        events = raw_event.get("events", [])
        event = events[0] if events else {}
        event_name = event.get("name", "")

        # Extract parameters
        parameters = self._extract_parameters(events)

        # Determine event type
        event_type = self._get_event_type(event_name, event)

        # Extract actor info
        actor = raw_event.get("actor", {})
        actor_email = actor.get("email", "")
        actor_profile_id = actor.get("profileId", "")

        # Extract IP
        ip_address = raw_event.get("ipAddress", "")

        # Extract target user
        target_user_email = parameters.get("USER_EMAIL", "")
        target_user_id = parameters.get("USER_ID", "")

        # Extract privilege changes
        privilege_changes = self._extract_privilege_changes(event_name, parameters, raw_event)

        # Extract event ID
        event_id_obj = raw_event.get("id", {})

        return IdentityEvent(
            event_id=event_id_obj.get("uniqueQualifier", self.generate_event_id(raw_event)),
            event_type=event_type,
            timestamp=self.parse_timestamp(event_id_obj.get("time")),
            provider=self.provider_name,
            user_id=actor_profile_id,
            user_email=self.normalize_email(actor_email),
            user_display_name=actor_email.split("@")[0] if "@" in actor_email else actor_email,
            source_ip=ip_address,
            target_user_id=target_user_id if target_user_id else None,
            target_user_email=self.normalize_email(target_user_email) if target_user_email else None,
            privilege_changes=privilege_changes,
            raw_event=raw_event,
            provider_event_type=event_name,
        )

    def _map_token_event(self, raw_event: Dict[str, Any]) -> IdentityEvent:
        """Map Google Workspace token/OAuth event."""
        events = raw_event.get("events", [])
        event = events[0] if events else {}
        event_name = event.get("name", "")

        # Extract parameters
        parameters = self._extract_parameters(events)

        # Determine event type
        event_type = self._get_event_type(event_name, event)

        # Extract actor info
        actor = raw_event.get("actor", {})
        actor_email = actor.get("email", "")
        actor_profile_id = actor.get("profileId", "")

        # Extract IP
        ip_address = raw_event.get("ipAddress", "")

        # Extract application info
        app_name = parameters.get("app_name", parameters.get("client_id", ""))

        # Extract event ID
        event_id_obj = raw_event.get("id", {})

        return IdentityEvent(
            event_id=event_id_obj.get("uniqueQualifier", self.generate_event_id(raw_event)),
            event_type=event_type,
            timestamp=self.parse_timestamp(event_id_obj.get("time")),
            provider=self.provider_name,
            user_id=actor_profile_id,
            user_email=self.normalize_email(actor_email),
            user_display_name=actor_email.split("@")[0] if "@" in actor_email else actor_email,
            source_ip=ip_address,
            application_name=app_name if app_name else None,
            raw_event=raw_event,
            provider_event_type=event_name,
        )

    def _map_groups_event(self, raw_event: Dict[str, Any]) -> IdentityEvent:
        """Map Google Workspace groups event."""
        events = raw_event.get("events", [])
        event = events[0] if events else {}
        event_name = event.get("name", "")

        # Extract parameters
        parameters = self._extract_parameters(events)

        # Determine event type
        event_type = self._get_event_type(event_name, event)

        # Extract actor info
        actor = raw_event.get("actor", {})
        actor_email = actor.get("email", "")
        actor_profile_id = actor.get("profileId", "")

        # Extract IP
        ip_address = raw_event.get("ipAddress", "")

        # Extract target user (member being added/removed)
        target_user_email = parameters.get("USER_EMAIL", parameters.get("MEMBER_ID", ""))
        group_email = parameters.get("GROUP_EMAIL", "")

        # Extract privilege changes
        privilege_changes = self._extract_privilege_changes(event_name, parameters, raw_event)

        # Extract event ID
        event_id_obj = raw_event.get("id", {})

        return IdentityEvent(
            event_id=event_id_obj.get("uniqueQualifier", self.generate_event_id(raw_event)),
            event_type=event_type,
            timestamp=self.parse_timestamp(event_id_obj.get("time")),
            provider=self.provider_name,
            user_id=actor_profile_id,
            user_email=self.normalize_email(actor_email),
            user_display_name=actor_email.split("@")[0] if "@" in actor_email else actor_email,
            source_ip=ip_address,
            target_user_email=self.normalize_email(target_user_email) if target_user_email else None,
            privilege_changes=privilege_changes,
            raw_event=raw_event,
            provider_event_type=event_name,
        )

    def _map_generic_event(self, raw_event: Dict[str, Any]) -> IdentityEvent:
        """Map generic/unknown Google Workspace event."""
        event_id_obj = raw_event.get("id", {})
        actor = raw_event.get("actor", {})

        return IdentityEvent(
            event_id=event_id_obj.get("uniqueQualifier", self.generate_event_id(raw_event)),
            event_type=IdentityEventType.UNKNOWN,
            timestamp=self.parse_timestamp(event_id_obj.get("time")),
            provider=self.provider_name,
            user_email=self.normalize_email(actor.get("email", "")),
            source_ip=raw_event.get("ipAddress"),
            raw_event=raw_event,
        )

    def _extract_parameters(self, events: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Extract and flatten parameters from all events."""
        all_params = {}

        for event in events:
            params = event.get("parameters", [])
            for param in params:
                name = param.get("name", "")
                # Use first non-None value
                value = (
                    param.get("value")
                    or param.get("multiValue")
                    or param.get("intValue")
                    or param.get("boolValue")
                )
                if value is not None:
                    all_params[name] = value

        return all_params

    def _extract_mfa_method(self, parameters: Dict[str, Any]) -> Optional[str]:
        """Extract MFA method from login parameters."""
        login_challenge_method = parameters.get("login_challenge_method", "")
        if login_challenge_method:
            return login_challenge_method.lower()

        # Check for 2SV method
        if parameters.get("is_second_factor"):
            return "second_factor"

        return None

    def _extract_privilege_changes(
        self, event_name: str, parameters: Dict[str, Any], raw_event: Dict[str, Any]
    ) -> Optional[List[PrivilegeChange]]:
        """Extract privilege changes from admin/groups event."""
        event_type = self._get_event_type(event_name, {})

        if event_type not in (IdentityEventType.PRIVILEGE_GRANT, IdentityEventType.PRIVILEGE_REVOKE):
            return None

        changes = []
        action = "grant" if event_type == IdentityEventType.PRIVILEGE_GRANT else "revoke"

        # Extract role/group info
        role_name = parameters.get("ROLE_NAME", parameters.get("GROUP_EMAIL", ""))
        role_id = parameters.get("ROLE_ID", "")

        actor = raw_event.get("actor", {})
        event_id_obj = raw_event.get("id", {})

        if role_name or role_id:
            changes.append(PrivilegeChange(
                action=action,
                role_name=role_name,
                role_id=role_id if role_id else None,
                granted_by=actor.get("email"),
                timestamp=self.parse_timestamp(event_id_obj.get("time")),
            ))

        return changes if changes else None
