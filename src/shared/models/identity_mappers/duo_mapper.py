"""Duo Security identity event mapper."""

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from ..identity_event import IdentityEvent, IdentityEventType, GeoLocation, PrivilegeChange
from .base_mapper import BaseIdentityMapper


class DuoIdentityMapper(BaseIdentityMapper):
    """Maps Duo Security logs to IdentityEvent format.

    Supports:
    - Authentication logs (MFA attempts)
    - Administrator activity logs
    - Trust monitor events
    """

    # Duo result to event type mapping
    RESULT_MAP = {
        "SUCCESS": IdentityEventType.MFA_SUCCESS,
        "FAILURE": IdentityEventType.MFA_FAILURE,
        "FRAUD": IdentityEventType.MFA_FAILURE,
        "DENIED": IdentityEventType.MFA_FAILURE,
    }

    # Duo factor mapping
    FACTOR_MAP = {
        "duo_push": "push",
        "phone_call": "phone",
        "sms_passcode": "sms",
        "hardware_token": "hardware_token",
        "yubikey_passcode": "yubikey",
        "bypass_code": "bypass_code",
        "passcode": "totp",
        "mobile_otp": "totp",
        "remembered_device": "remembered_device",
        "trusted_network": "trusted_network",
        "webauthn_credential": "webauthn",
        "u2f_token": "u2f",
    }

    # Duo admin action to event type mapping
    ADMIN_ACTION_MAP = {
        # User management
        "user_create": IdentityEventType.ACCOUNT_CREATED,
        "user_delete": IdentityEventType.ACCOUNT_DELETED,
        "user_update": IdentityEventType.UNKNOWN,
        "user_pending_delete": IdentityEventType.ACCOUNT_DISABLED,
        "user_restore": IdentityEventType.ACCOUNT_UNLOCKED,

        # Bypass code management
        "bypass_create": IdentityEventType.MFA_BYPASS_USED,
        "bypass_delete": IdentityEventType.UNKNOWN,

        # Admin management
        "admin_create": IdentityEventType.ACCOUNT_CREATED,
        "admin_delete": IdentityEventType.ACCOUNT_DELETED,
        "admin_update": IdentityEventType.UNKNOWN,
        "admin_login": IdentityEventType.AUTH_SUCCESS,
        "admin_login_failure": IdentityEventType.AUTH_FAILURE,

        # Role management
        "admin_role_assign": IdentityEventType.PRIVILEGE_GRANT,
        "admin_role_unassign": IdentityEventType.PRIVILEGE_REVOKE,
        "group_create": IdentityEventType.UNKNOWN,
        "group_delete": IdentityEventType.UNKNOWN,
        "group_update": IdentityEventType.UNKNOWN,

        # Phone/device management
        "phone_create": IdentityEventType.MFA_ENROLLED,
        "phone_delete": IdentityEventType.MFA_REMOVED,
        "phone_update": IdentityEventType.MFA_METHOD_CHANGED,
    }

    # Failure reason mapping
    FAILURE_REASON_MAP = {
        "user_marked_fraud": "fraud_reported",
        "user_denied": "user_denied",
        "user_disabled": "user_disabled",
        "no_response": "no_response",
        "timeout": "timeout",
        "invalid_passcode": "invalid_code",
        "locked_out": "account_locked",
        "user_not_enrolled": "not_enrolled",
        "allow_unenrolled_user_disabled": "enrollment_required",
        "bypass_user": "bypass_used",
        "anomalous_push": "anomalous_activity",
        "invalid_device": "invalid_device",
        "software_restriction": "software_restriction",
        "location_restricted": "location_restricted",
        "platform_restricted": "platform_restricted",
        "version_restricted": "version_restricted",
        "rooted_device": "rooted_device",
        "no_screen_lock": "no_screen_lock",
        "touch_id_disabled": "biometric_disabled",
        "no_disk_encryption": "no_disk_encryption",
        "anonymous_ip": "anonymous_ip",
        "out_of_date": "out_of_date",
        "denied_by_policy": "policy_denied",
        "user_mistake": "user_mistake",
    }

    @property
    def provider_name(self) -> str:
        return "duo"

    def map(self, raw_event: Dict[str, Any]) -> IdentityEvent:
        """Map Duo event to IdentityEvent.

        Automatically detects event type (auth vs admin) and routes
        to appropriate mapper.
        """
        # Detect event type
        if "txid" in raw_event and ("factor" in raw_event or "result" in raw_event):
            return self._map_auth_event(raw_event)
        elif "action" in raw_event and "object" in raw_event:
            return self._map_admin_event(raw_event)
        else:
            return self._map_generic_event(raw_event)

    def map_event_type(self, raw_event: Dict[str, Any]) -> IdentityEventType:
        """Map Duo event to IdentityEventType."""
        if "txid" in raw_event and ("factor" in raw_event or "result" in raw_event):
            return self._get_auth_event_type(raw_event)
        elif "action" in raw_event:
            return self._get_admin_event_type(raw_event)
        return IdentityEventType.UNKNOWN

    def _get_auth_event_type(self, raw_event: Dict[str, Any]) -> IdentityEventType:
        """Determine event type for authentication events."""
        result = raw_event.get("result", "")
        reason = raw_event.get("reason", "")

        # Check for fraud
        if result == "FRAUD" or reason == "user_marked_fraud":
            return IdentityEventType.MFA_FAILURE

        # Check result
        if result in self.RESULT_MAP:
            return self.RESULT_MAP[result]

        # Check for bypass
        factor = raw_event.get("factor", "").lower()
        if "bypass" in factor:
            return IdentityEventType.MFA_BYPASS_USED

        return IdentityEventType.UNKNOWN

    def _get_admin_event_type(self, raw_event: Dict[str, Any]) -> IdentityEventType:
        """Determine event type for admin events."""
        action = raw_event.get("action", "").lower()

        # Direct mapping
        if action in self.ADMIN_ACTION_MAP:
            return self.ADMIN_ACTION_MAP[action]

        # Pattern-based mapping
        if "user" in action:
            if "create" in action or "add" in action:
                return IdentityEventType.ACCOUNT_CREATED
            if "delete" in action:
                return IdentityEventType.ACCOUNT_DELETED
            if "disable" in action or "pending_delete" in action:
                return IdentityEventType.ACCOUNT_DISABLED

        if "admin" in action:
            if "login" in action:
                if "failure" in action or "fail" in action:
                    return IdentityEventType.AUTH_FAILURE
                return IdentityEventType.AUTH_SUCCESS
            if "create" in action:
                return IdentityEventType.ACCOUNT_CREATED

        if "role" in action or "group" in action:
            if "assign" in action or "add" in action:
                return IdentityEventType.PRIVILEGE_GRANT
            if "unassign" in action or "remove" in action:
                return IdentityEventType.PRIVILEGE_REVOKE

        if "phone" in action or "device" in action or "token" in action:
            if "create" in action or "add" in action:
                return IdentityEventType.MFA_ENROLLED
            if "delete" in action or "remove" in action:
                return IdentityEventType.MFA_REMOVED
            if "update" in action:
                return IdentityEventType.MFA_METHOD_CHANGED

        if "bypass" in action:
            if "create" in action:
                return IdentityEventType.MFA_BYPASS_USED

        return IdentityEventType.UNKNOWN

    def _map_auth_event(self, raw_event: Dict[str, Any]) -> IdentityEvent:
        """Map Duo authentication event."""
        event_type = self._get_auth_event_type(raw_event)

        # Extract user info
        user_info = raw_event.get("user", {})
        username = user_info.get("name", "")
        user_key = user_info.get("key", "")
        user_email = user_info.get("email", "")

        # Extract access device info (where the auth request came from)
        access_device = raw_event.get("access_device", {})
        access_ip = access_device.get("ip", "")
        access_location = access_device.get("location", {})
        access_browser = access_device.get("browser", "")
        access_os = access_device.get("os", "")

        # Extract auth device info (the 2FA device)
        auth_device = raw_event.get("auth_device", {})
        device_name = auth_device.get("name", "")

        # Extract application info
        application = raw_event.get("application", {})
        app_name = application.get("name", "")
        app_key = application.get("key", "")

        # Extract MFA method
        factor = raw_event.get("factor", "")
        mfa_method = self.FACTOR_MAP.get(factor.lower(), factor.lower()) if factor else None

        # Extract failure reason
        failure_reason = None
        result = raw_event.get("result", "")
        reason = raw_event.get("reason", "")
        if result != "SUCCESS":
            failure_reason = self.normalize_failure_reason(
                self.FAILURE_REASON_MAP.get(reason, reason),
                reason
            )

        # Extract geo
        source_geo = self._extract_duo_geo(access_location)

        # Parse timestamp
        timestamp = raw_event.get("timestamp", 0)

        return IdentityEvent(
            event_id=raw_event.get("txid", self.generate_event_id(raw_event)),
            event_type=event_type,
            timestamp=self._parse_unix_timestamp(timestamp),
            provider=self.provider_name,
            user_id=user_key,
            user_email=self.normalize_email(user_email) if user_email else self.normalize_email(username),
            user_display_name=username,
            source_ip=access_ip if access_ip else None,
            source_geo=source_geo,
            device_type=access_os if access_os else None,
            user_agent=access_browser if access_browser else None,
            mfa_method=mfa_method,
            application_name=app_name if app_name else None,
            application_id=app_key if app_key else None,
            failure_reason=failure_reason,
            raw_event=raw_event,
            provider_event_type=f"auth_{factor.lower()}" if factor else "auth",
        )

    def _map_admin_event(self, raw_event: Dict[str, Any]) -> IdentityEvent:
        """Map Duo administrator event."""
        event_type = self._get_admin_event_type(raw_event)
        action = raw_event.get("action", "")
        obj = raw_event.get("object", "")
        username = raw_event.get("username", "")
        description = raw_event.get("description", {})

        # Extract target user from description
        target_user_id = None
        target_user_email = None
        if isinstance(description, dict):
            target_user_email = description.get("email", description.get("user_email", ""))
            target_user_id = description.get("user_key", description.get("user_id", ""))

        # Extract privilege changes
        privilege_changes = self._extract_admin_privilege_changes(action, description, raw_event)

        # Parse timestamp
        timestamp = raw_event.get("timestamp", 0)

        return IdentityEvent(
            event_id=self.generate_event_id(raw_event),
            event_type=event_type,
            timestamp=self._parse_unix_timestamp(timestamp),
            provider=self.provider_name,
            user_email=self.normalize_email(username) if username else None,
            user_display_name=username,
            target_user_id=target_user_id if target_user_id else None,
            target_user_email=self.normalize_email(target_user_email) if target_user_email else None,
            privilege_changes=privilege_changes,
            raw_event=raw_event,
            provider_event_type=action,
        )

    def _map_generic_event(self, raw_event: Dict[str, Any]) -> IdentityEvent:
        """Map generic/unknown Duo event."""
        timestamp = raw_event.get("timestamp", 0)

        return IdentityEvent(
            event_id=self.generate_event_id(raw_event),
            event_type=IdentityEventType.UNKNOWN,
            timestamp=self._parse_unix_timestamp(timestamp),
            provider=self.provider_name,
            raw_event=raw_event,
        )

    def _extract_duo_geo(self, location: Dict[str, Any]) -> Optional[GeoLocation]:
        """Extract geolocation from Duo location data."""
        if not location:
            return None

        country = location.get("country", "")
        city = location.get("city", "")
        state = location.get("state", "")

        if not (country or city or state):
            return None

        return GeoLocation(
            country=country if country else None,
            city=city if city else None,
            region=state if state else None,
        )

    def _parse_unix_timestamp(self, timestamp: int) -> datetime:
        """Convert Unix timestamp to datetime."""
        if not timestamp:
            return datetime.now(timezone.utc)

        try:
            return datetime.fromtimestamp(timestamp, tz=timezone.utc)
        except (ValueError, OSError):
            return datetime.now(timezone.utc)

    def _extract_admin_privilege_changes(
        self, action: str, description: Dict[str, Any], raw_event: Dict[str, Any]
    ) -> Optional[List[PrivilegeChange]]:
        """Extract privilege changes from admin event."""
        event_type = self._get_admin_event_type(raw_event)

        if event_type not in (IdentityEventType.PRIVILEGE_GRANT, IdentityEventType.PRIVILEGE_REVOKE):
            return None

        changes = []
        action_type = "grant" if event_type == IdentityEventType.PRIVILEGE_GRANT else "revoke"

        # Extract role info from description
        role_name = ""
        if isinstance(description, dict):
            role_name = description.get("role_name", description.get("group_name", ""))

        username = raw_event.get("username", "")
        timestamp = raw_event.get("timestamp", 0)

        if role_name:
            changes.append(PrivilegeChange(
                action=action_type,
                role_name=role_name,
                granted_by=username,
                timestamp=self._parse_unix_timestamp(timestamp),
            ))

        return changes if changes else None
