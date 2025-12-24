"""Azure/Entra identity event mapper."""

from datetime import datetime
from typing import Any, Dict, List, Optional

from ..identity_event import IdentityEvent, IdentityEventType, GeoLocation, PrivilegeChange
from .base_mapper import BaseIdentityMapper


class AzureIdentityMapper(BaseIdentityMapper):
    """Maps Azure AD/Entra sign-in and audit logs to IdentityEvent format.

    Supports:
    - Azure AD Sign-in Logs
    - Azure AD Audit Logs
    - Azure AD Identity Protection events
    """

    # Azure AD sign-in error codes
    ERROR_CODE_MAP = {
        "0": "success",
        "50126": "invalid_credentials",
        "50053": "account_locked",
        "50055": "password_expired",
        "50057": "account_disabled",
        "50058": "silent_signin_failed",
        "50072": "mfa_required",
        "50074": "strong_auth_required",
        "50076": "mfa_required_other_device",
        "50079": "mfa_registration_required",
        "50105": "missing_required_claim",
        "50131": "device_not_compliant",
        "53003": "conditional_access_blocked",
        "530032": "security_policy_blocked",
        "700016": "application_not_found",
    }

    # Azure AD audit activity mapping
    AUDIT_ACTIVITY_MAP = {
        # User management
        "Add user": IdentityEventType.ACCOUNT_CREATED,
        "Delete user": IdentityEventType.ACCOUNT_DELETED,
        "Update user": IdentityEventType.UNKNOWN,
        "Disable account": IdentityEventType.ACCOUNT_DISABLED,
        "Enable account": IdentityEventType.ACCOUNT_UNLOCKED,

        # Password management
        "Reset password": IdentityEventType.PASSWORD_RESET,
        "Change password": IdentityEventType.PASSWORD_CHANGE,
        "Reset user password": IdentityEventType.PASSWORD_RESET,
        "Self-service password reset": IdentityEventType.PASSWORD_RESET,

        # Role/group management
        "Add member to role": IdentityEventType.PRIVILEGE_GRANT,
        "Remove member from role": IdentityEventType.PRIVILEGE_REVOKE,
        "Add member to group": IdentityEventType.PRIVILEGE_GRANT,
        "Remove member from group": IdentityEventType.PRIVILEGE_REVOKE,
        "Add group member": IdentityEventType.PRIVILEGE_GRANT,
        "Remove group member": IdentityEventType.PRIVILEGE_REVOKE,

        # MFA management
        "User registered security info": IdentityEventType.MFA_ENROLLED,
        "User deleted security info": IdentityEventType.MFA_REMOVED,
        "Admin registered security info": IdentityEventType.MFA_ENROLLED,
        "Admin deleted security info": IdentityEventType.MFA_REMOVED,
        "Update user authentication method": IdentityEventType.MFA_METHOD_CHANGED,

        # OAuth/consent
        "Consent to application": IdentityEventType.OAUTH_CONSENT_GRANTED,
        "Remove OAuth2PermissionGrant": IdentityEventType.OAUTH_CONSENT_REVOKED,
        "Add OAuth2PermissionGrant": IdentityEventType.OAUTH_CONSENT_GRANTED,
    }

    # Risk level mapping
    RISK_LEVEL_MAP = {
        "none": None,
        "low": "low",
        "medium": "medium",
        "high": "high",
        "hidden": "medium",
    }

    @property
    def provider_name(self) -> str:
        return "azure"

    def map(self, raw_event: Dict[str, Any]) -> IdentityEvent:
        """Map Azure event to IdentityEvent.

        Automatically detects event type (sign-in vs audit) and routes
        to appropriate mapper.
        """
        # Detect event type
        if self._is_signin_event(raw_event):
            return self._map_signin_event(raw_event)
        elif self._is_audit_event(raw_event):
            return self._map_audit_event(raw_event)
        else:
            return self._map_generic_event(raw_event)

    def map_event_type(self, raw_event: Dict[str, Any]) -> IdentityEventType:
        """Map Azure event to IdentityEventType."""
        if self._is_signin_event(raw_event):
            return self._get_signin_event_type(raw_event)
        elif self._is_audit_event(raw_event):
            return self._get_audit_event_type(raw_event)
        return IdentityEventType.UNKNOWN

    def _is_signin_event(self, raw_event: Dict[str, Any]) -> bool:
        """Check if event is a sign-in event."""
        return (
            "userPrincipalName" in raw_event and "status" in raw_event
        ) or (
            raw_event.get("category") == "SignInLogs"
        )

    def _is_audit_event(self, raw_event: Dict[str, Any]) -> bool:
        """Check if event is an audit event."""
        return (
            "activityDisplayName" in raw_event
        ) or (
            raw_event.get("category") == "AuditLogs"
        )

    def _get_signin_event_type(self, raw_event: Dict[str, Any]) -> IdentityEventType:
        """Determine event type for sign-in events."""
        status = raw_event.get("status", {})
        error_code = str(status.get("errorCode", "0"))

        # Check for MFA events
        auth_details = raw_event.get("authenticationDetails", [])
        for detail in auth_details:
            method = detail.get("authenticationMethod", "").lower()
            if "mfa" in method or "multifactor" in method:
                if detail.get("succeeded"):
                    return IdentityEventType.MFA_SUCCESS
                else:
                    return IdentityEventType.MFA_FAILURE

        # Check error code
        if error_code == "0":
            return IdentityEventType.AUTH_SUCCESS
        elif error_code in ("50072", "50074", "50076", "50079"):
            return IdentityEventType.MFA_CHALLENGE
        elif error_code == "50053":
            return IdentityEventType.ACCOUNT_LOCKED
        elif error_code == "50057":
            return IdentityEventType.ACCOUNT_DISABLED
        else:
            return IdentityEventType.AUTH_FAILURE

    def _get_audit_event_type(self, raw_event: Dict[str, Any]) -> IdentityEventType:
        """Determine event type for audit events."""
        activity = raw_event.get("activityDisplayName", "")

        # Direct mapping
        if activity in self.AUDIT_ACTIVITY_MAP:
            return self.AUDIT_ACTIVITY_MAP[activity]

        # Pattern-based mapping
        activity_lower = activity.lower()

        if "password" in activity_lower:
            if "reset" in activity_lower:
                return IdentityEventType.PASSWORD_RESET
            return IdentityEventType.PASSWORD_CHANGE

        if "role" in activity_lower or "member" in activity_lower:
            if "add" in activity_lower:
                return IdentityEventType.PRIVILEGE_GRANT
            if "remove" in activity_lower:
                return IdentityEventType.PRIVILEGE_REVOKE

        if "user" in activity_lower:
            if "add" in activity_lower or "create" in activity_lower:
                return IdentityEventType.ACCOUNT_CREATED
            if "delete" in activity_lower:
                return IdentityEventType.ACCOUNT_DELETED
            if "disable" in activity_lower:
                return IdentityEventType.ACCOUNT_DISABLED

        if "mfa" in activity_lower or "authentication" in activity_lower:
            if "register" in activity_lower:
                return IdentityEventType.MFA_ENROLLED
            if "delete" in activity_lower or "remove" in activity_lower:
                return IdentityEventType.MFA_REMOVED

        return IdentityEventType.UNKNOWN

    def _map_signin_event(self, raw_event: Dict[str, Any]) -> IdentityEvent:
        """Map Azure AD sign-in event."""
        event_type = self._get_signin_event_type(raw_event)

        # Extract user info
        user_principal_name = raw_event.get("userPrincipalName", "")
        user_display_name = raw_event.get("userDisplayName", "")
        user_id = raw_event.get("userId", raw_event.get("id", ""))

        # Extract status and failure reason
        status = raw_event.get("status", {})
        error_code = str(status.get("errorCode", "0"))
        failure_reason = None
        if error_code != "0":
            reason_text = status.get("failureReason", "")
            failure_reason = self.normalize_failure_reason(
                reason_text or self.ERROR_CODE_MAP.get(error_code, "unknown_error"),
                error_code
            )

        # Extract IP and location
        ip_address = raw_event.get("ipAddress", "")
        location = raw_event.get("location", {})
        source_geo = self._extract_azure_geo(location)

        # Extract device info
        device_detail = raw_event.get("deviceDetail", {})
        device_id = device_detail.get("deviceId", "")
        device_os = device_detail.get("operatingSystem", "")
        browser = device_detail.get("browser", "")

        # Extract app info
        app_display_name = raw_event.get("appDisplayName", "")
        app_id = raw_event.get("appId", "")

        # Extract MFA info
        mfa_method = self._extract_mfa_method(raw_event)

        # Extract risk info
        risk_level = self._extract_risk_level(raw_event)
        risk_reasons = self._extract_risk_reasons(raw_event)

        return IdentityEvent(
            event_id=raw_event.get("id", self.generate_event_id(raw_event)),
            event_type=event_type,
            timestamp=self.parse_timestamp(
                raw_event.get("createdDateTime", raw_event.get("time"))
            ),
            provider=self.provider_name,
            user_id=user_id,
            user_email=self.normalize_email(user_principal_name),
            user_display_name=user_display_name,
            source_ip=ip_address,
            source_geo=source_geo,
            device_id=device_id if device_id else None,
            device_type=device_os,
            user_agent=browser,
            session_id=raw_event.get("correlationId"),
            mfa_method=mfa_method,
            auth_protocol=raw_event.get("clientAppUsed"),
            application_id=app_id,
            application_name=app_display_name,
            failure_reason=failure_reason,
            risk_level=risk_level,
            risk_reasons=risk_reasons,
            raw_event=raw_event,
            provider_event_type="SignIn",
            correlation_id=raw_event.get("correlationId"),
        )

    def _map_audit_event(self, raw_event: Dict[str, Any]) -> IdentityEvent:
        """Map Azure AD audit event."""
        event_type = self._get_audit_event_type(raw_event)
        activity = raw_event.get("activityDisplayName", "")

        # Extract initiator (who performed the action)
        initiated_by = raw_event.get("initiatedBy", {})
        user_info = initiated_by.get("user", {})
        app_info = initiated_by.get("app", {})

        initiator_upn = user_info.get("userPrincipalName", "")
        initiator_display_name = user_info.get("displayName", app_info.get("displayName", ""))
        initiator_id = user_info.get("id", app_info.get("appId", ""))
        initiator_ip = user_info.get("ipAddress", "")

        # Extract target user
        target_user_id, target_user_email = self._extract_audit_target(raw_event)

        # Extract privilege changes
        privilege_changes = self._extract_audit_privilege_changes(raw_event, event_type)

        # Determine result
        result = raw_event.get("result", "success")
        failure_reason = None
        if result.lower() != "success":
            failure_reason = raw_event.get("resultReason", "")

        return IdentityEvent(
            event_id=raw_event.get("id", self.generate_event_id(raw_event)),
            event_type=event_type,
            timestamp=self.parse_timestamp(
                raw_event.get("activityDateTime", raw_event.get("time"))
            ),
            provider=self.provider_name,
            user_id=initiator_id,
            user_email=self.normalize_email(initiator_upn),
            user_display_name=initiator_display_name,
            source_ip=initiator_ip if initiator_ip else None,
            target_user_id=target_user_id,
            target_user_email=target_user_email,
            privilege_changes=privilege_changes,
            failure_reason=failure_reason,
            raw_event=raw_event,
            provider_event_type=activity,
            correlation_id=raw_event.get("correlationId"),
        )

    def _map_generic_event(self, raw_event: Dict[str, Any]) -> IdentityEvent:
        """Map generic/unknown Azure event."""
        return IdentityEvent(
            event_id=self.generate_event_id(raw_event),
            event_type=IdentityEventType.UNKNOWN,
            timestamp=self.parse_timestamp(
                raw_event.get("time", raw_event.get("timeGenerated"))
            ),
            provider=self.provider_name,
            raw_event=raw_event,
        )

    def _extract_azure_geo(self, location: Dict[str, Any]) -> Optional[GeoLocation]:
        """Extract geolocation from Azure location data."""
        if not location:
            return None

        geo_coords = location.get("geoCoordinates", {})

        return GeoLocation(
            country=location.get("countryOrRegion"),
            city=location.get("city"),
            region=location.get("state"),
            lat=geo_coords.get("latitude"),
            lon=geo_coords.get("longitude"),
        )

    def _extract_mfa_method(self, raw_event: Dict[str, Any]) -> Optional[str]:
        """Extract MFA method from sign-in event."""
        mfa_detail = raw_event.get("mfaDetail", {})
        if mfa_detail:
            method = mfa_detail.get("authMethod", "")
            if method:
                return method.lower()

        auth_details = raw_event.get("authenticationDetails", [])
        for detail in auth_details:
            method = detail.get("authenticationMethod", "")
            if method and "mfa" in method.lower():
                return method.lower()

        return None

    def _extract_risk_level(self, raw_event: Dict[str, Any]) -> Optional[str]:
        """Extract risk level from sign-in event."""
        risk_level = raw_event.get("riskLevelAggregated", raw_event.get("riskLevel", "none"))
        return self.RISK_LEVEL_MAP.get(risk_level.lower(), None)

    def _extract_risk_reasons(self, raw_event: Dict[str, Any]) -> Optional[List[str]]:
        """Extract risk reasons from sign-in event."""
        risk_event_types = raw_event.get("riskEventTypes", [])
        if risk_event_types:
            return risk_event_types

        risk_detail = raw_event.get("riskDetail", "")
        if risk_detail and risk_detail != "none":
            return [risk_detail]

        return None

    def _extract_audit_target(self, raw_event: Dict[str, Any]) -> tuple:
        """Extract target user from audit event."""
        target_resources = raw_event.get("targetResources", [])

        for target in target_resources:
            target_type = target.get("type", "").lower()
            if target_type == "user":
                return (
                    target.get("id", ""),
                    self.normalize_email(target.get("userPrincipalName", ""))
                )

        return None, None

    def _extract_audit_privilege_changes(
        self, raw_event: Dict[str, Any], event_type: IdentityEventType
    ) -> Optional[List[PrivilegeChange]]:
        """Extract privilege changes from audit event."""
        if event_type not in (IdentityEventType.PRIVILEGE_GRANT, IdentityEventType.PRIVILEGE_REVOKE):
            return None

        changes = []
        action = "grant" if event_type == IdentityEventType.PRIVILEGE_GRANT else "revoke"
        initiated_by = raw_event.get("initiatedBy", {})
        user_info = initiated_by.get("user", {})

        target_resources = raw_event.get("targetResources", [])
        for target in target_resources:
            target_type = target.get("type", "").lower()
            if target_type in ("role", "group"):
                changes.append(PrivilegeChange(
                    action=action,
                    role_name=target.get("displayName", ""),
                    role_id=target.get("id"),
                    granted_by=user_info.get("userPrincipalName"),
                    timestamp=self.parse_timestamp(
                        raw_event.get("activityDateTime", raw_event.get("time"))
                    ),
                ))

        return changes if changes else None
