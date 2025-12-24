"""Okta identity event mapper."""

from datetime import datetime
from typing import Any, Dict, List, Optional

from ..identity_event import IdentityEvent, IdentityEventType, GeoLocation, PrivilegeChange
from .base_mapper import BaseIdentityMapper


class OktaIdentityMapper(BaseIdentityMapper):
    """Maps Okta System Log events to IdentityEvent format.

    Okta event types reference:
    https://developer.okta.com/docs/reference/api/event-types/
    """

    # Mapping of Okta event types to IdentityEventType
    EVENT_TYPE_MAP = {
        # Authentication events
        "user.session.start": IdentityEventType.SESSION_START,
        "user.session.end": IdentityEventType.SESSION_END,
        "user.authentication.auth_via_mfa": IdentityEventType.MFA_SUCCESS,
        "user.authentication.sso": IdentityEventType.AUTH_SUCCESS,
        "user.authentication.verify": IdentityEventType.AUTH_SUCCESS,
        "user.authentication.auth_via_IDP": IdentityEventType.AUTH_SUCCESS,
        "user.authentication.auth_via_inbound_SAML": IdentityEventType.AUTH_SUCCESS,
        "user.authentication.auth_via_radius": IdentityEventType.AUTH_SUCCESS,
        "user.authentication.auth_via_social": IdentityEventType.AUTH_SUCCESS,

        # MFA events
        "user.mfa.factor.activate": IdentityEventType.MFA_ENROLLED,
        "user.mfa.factor.deactivate": IdentityEventType.MFA_REMOVED,
        "user.mfa.factor.update": IdentityEventType.MFA_METHOD_CHANGED,
        "user.mfa.factor.reset_all": IdentityEventType.MFA_REMOVED,
        "system.mfa.factor.deactivate": IdentityEventType.MFA_REMOVED,
        "user.mfa.attempt_bypass": IdentityEventType.MFA_CHALLENGE,
        "user.mfa.okta_verify.deny_push": IdentityEventType.MFA_FAILURE,

        # Account lifecycle events
        "user.lifecycle.create": IdentityEventType.ACCOUNT_CREATED,
        "user.lifecycle.activate": IdentityEventType.ACCOUNT_CREATED,
        "user.lifecycle.deactivate": IdentityEventType.ACCOUNT_DISABLED,
        "user.lifecycle.suspend": IdentityEventType.ACCOUNT_DISABLED,
        "user.lifecycle.unsuspend": IdentityEventType.ACCOUNT_UNLOCKED,
        "user.lifecycle.delete": IdentityEventType.ACCOUNT_DELETED,

        # Credential events
        "user.credential.password.update": IdentityEventType.PASSWORD_CHANGE,
        "user.credential.password.reset": IdentityEventType.PASSWORD_RESET,
        "user.account.lock": IdentityEventType.ACCOUNT_LOCKED,
        "user.account.unlock": IdentityEventType.ACCOUNT_UNLOCKED,
        "user.account.unlock_token": IdentityEventType.ACCOUNT_UNLOCKED,

        # API token events
        "system.api_token.create": IdentityEventType.API_KEY_CREATED,
        "system.api_token.revoke": IdentityEventType.API_KEY_REVOKED,

        # Role/privilege events
        "user.account.privilege.grant": IdentityEventType.PRIVILEGE_GRANT,
        "user.account.privilege.revoke": IdentityEventType.PRIVILEGE_REVOKE,
        "group.user_membership.add": IdentityEventType.PRIVILEGE_GRANT,
        "group.user_membership.remove": IdentityEventType.PRIVILEGE_REVOKE,
        "application.user_membership.add": IdentityEventType.PRIVILEGE_GRANT,
        "application.user_membership.remove": IdentityEventType.PRIVILEGE_REVOKE,

        # OAuth events
        "app.oauth2.token.grant": IdentityEventType.TOKEN_ISSUED,
        "app.oauth2.token.revoke": IdentityEventType.TOKEN_REVOKED,
        "app.oauth2.consent.grant": IdentityEventType.OAUTH_CONSENT_GRANTED,
        "app.oauth2.consent.revoke": IdentityEventType.OAUTH_CONSENT_REVOKED,
    }

    # MFA factor types
    MFA_FACTOR_MAP = {
        "okta_verify": "push",
        "push": "push",
        "sms": "sms",
        "call": "phone_call",
        "email": "email",
        "token:software:totp": "totp",
        "token:hardware": "hardware_key",
        "token:hotp": "hotp",
        "u2f": "u2f",
        "webauthn": "webauthn",
        "security_question": "security_question",
    }

    @property
    def provider_name(self) -> str:
        return "okta"

    def map(self, raw_event: Dict[str, Any]) -> IdentityEvent:
        """Map Okta System Log event to IdentityEvent."""
        # Extract event type and determine outcome
        event_type = self.map_event_type(raw_event)
        outcome = raw_event.get("outcome", {})
        result = outcome.get("result", "")

        # Adjust event type based on outcome
        if event_type == IdentityEventType.SESSION_START:
            if result == "FAILURE" or result == "DENY":
                event_type = IdentityEventType.AUTH_FAILURE

        # Extract actor (user) information
        actor = raw_event.get("actor", {})
        user_email = self.normalize_email(actor.get("alternateId", ""))
        user_id = actor.get("id", "")
        user_display_name = actor.get("displayName", "")

        # Extract client information
        client = raw_event.get("client", {})
        source_ip = client.get("ipAddress", "")
        user_agent = client.get("userAgent", {}).get("rawUserAgent", "")
        device_type = client.get("device", "")

        # Extract geolocation
        geo_data = client.get("geographicalContext", {})
        source_geo = self._extract_okta_geo(geo_data)

        # Extract session ID
        auth_context = raw_event.get("authenticationContext", {})
        session_id = auth_context.get("externalSessionId", "")

        # Extract MFA method
        mfa_method = self._extract_mfa_method(raw_event)

        # Extract auth protocol
        auth_protocol = auth_context.get("credentialType", "")

        # Extract target application
        app_id, app_name = self._extract_application(raw_event)

        # Extract failure reason
        failure_reason = None
        if result in ("FAILURE", "DENY"):
            failure_reason = self.normalize_failure_reason(
                outcome.get("reason"), None
            )

        # Extract target user (for admin actions)
        target_user_id, target_user_email = self._extract_target_user(raw_event)

        # Extract privilege changes
        privilege_changes = self._extract_privilege_changes(raw_event, event_type)

        # Extract risk information
        security_context = raw_event.get("securityContext", {})
        risk_level = self._map_risk_level(security_context)

        return IdentityEvent(
            event_id=raw_event.get("uuid", self.generate_event_id(raw_event)),
            event_type=event_type,
            timestamp=self.parse_timestamp(raw_event.get("published")),
            provider=self.provider_name,
            user_id=user_id,
            user_email=user_email,
            user_display_name=user_display_name,
            source_ip=source_ip,
            source_geo=source_geo,
            device_id=client.get("id"),
            device_type=device_type,
            user_agent=user_agent,
            session_id=session_id,
            mfa_method=mfa_method,
            auth_protocol=auth_protocol,
            application_id=app_id,
            application_name=app_name,
            failure_reason=failure_reason,
            risk_level=risk_level,
            privilege_changes=privilege_changes,
            target_user_id=target_user_id,
            target_user_email=target_user_email,
            raw_event=raw_event,
            provider_event_type=raw_event.get("eventType"),
            correlation_id=raw_event.get("transaction", {}).get("id"),
        )

    def map_event_type(self, raw_event: Dict[str, Any]) -> IdentityEventType:
        """Map Okta event type to IdentityEventType."""
        okta_event_type = raw_event.get("eventType", "")

        # Direct mapping
        if okta_event_type in self.EVENT_TYPE_MAP:
            return self.EVENT_TYPE_MAP[okta_event_type]

        # Pattern-based mapping
        lower_event = okta_event_type.lower()

        if "authentication" in lower_event or "session.start" in lower_event:
            outcome = raw_event.get("outcome", {}).get("result", "")
            if outcome in ("FAILURE", "DENY"):
                return IdentityEventType.AUTH_FAILURE
            return IdentityEventType.AUTH_SUCCESS

        if "mfa" in lower_event or "factor" in lower_event:
            outcome = raw_event.get("outcome", {}).get("result", "")
            if "verify" in lower_event or "challenge" in lower_event:
                if outcome == "FAILURE":
                    return IdentityEventType.MFA_FAILURE
                elif outcome == "SUCCESS":
                    return IdentityEventType.MFA_SUCCESS
                return IdentityEventType.MFA_CHALLENGE
            if "activate" in lower_event:
                return IdentityEventType.MFA_ENROLLED
            if "deactivate" in lower_event:
                return IdentityEventType.MFA_REMOVED

        if "password" in lower_event:
            if "reset" in lower_event:
                return IdentityEventType.PASSWORD_RESET
            return IdentityEventType.PASSWORD_CHANGE

        if "privilege" in lower_event or "role" in lower_event:
            if "grant" in lower_event or "add" in lower_event:
                return IdentityEventType.PRIVILEGE_GRANT
            if "revoke" in lower_event or "remove" in lower_event:
                return IdentityEventType.PRIVILEGE_REVOKE

        if "user.lifecycle" in lower_event:
            if "create" in lower_event or "activate" in lower_event:
                return IdentityEventType.ACCOUNT_CREATED
            if "deactivate" in lower_event or "suspend" in lower_event:
                return IdentityEventType.ACCOUNT_DISABLED
            if "delete" in lower_event:
                return IdentityEventType.ACCOUNT_DELETED

        if "token" in lower_event:
            if "grant" in lower_event or "create" in lower_event:
                return IdentityEventType.TOKEN_ISSUED
            if "revoke" in lower_event:
                return IdentityEventType.TOKEN_REVOKED

        return IdentityEventType.UNKNOWN

    def _extract_okta_geo(self, geo_data: Dict[str, Any]) -> Optional[GeoLocation]:
        """Extract geolocation from Okta geographicalContext."""
        if not geo_data:
            return None

        geolocation = geo_data.get("geolocation", {})

        return GeoLocation(
            country=geo_data.get("country"),
            city=geo_data.get("city"),
            region=geo_data.get("state"),
            lat=geolocation.get("lat"),
            lon=geolocation.get("lon"),
            asn=geo_data.get("asn"),
            isp=geo_data.get("isp"),
        )

    def _extract_mfa_method(self, raw_event: Dict[str, Any]) -> Optional[str]:
        """Extract MFA method from event."""
        # Check authentication context
        auth_context = raw_event.get("authenticationContext", {})
        credential_type = auth_context.get("credentialType", "").lower()

        if credential_type in self.MFA_FACTOR_MAP:
            return self.MFA_FACTOR_MAP[credential_type]

        # Check debug context for factor type
        debug_context = raw_event.get("debugContext", {})
        debug_data = debug_context.get("debugData", {})
        factor = debug_data.get("factor", "").lower()

        if factor in self.MFA_FACTOR_MAP:
            return self.MFA_FACTOR_MAP[factor]

        # Check event type for MFA info
        event_type = raw_event.get("eventType", "").lower()
        if "okta_verify" in event_type:
            return "push"
        if "sms" in event_type:
            return "sms"
        if "totp" in event_type:
            return "totp"

        return None

    def _extract_application(self, raw_event: Dict[str, Any]) -> tuple:
        """Extract target application information."""
        targets = raw_event.get("target", [])

        for target in targets:
            target_type = target.get("type", "").lower()
            if target_type == "appinstance" or target_type == "app":
                return target.get("id", ""), target.get("displayName", "")

        # Check debug context
        debug_context = raw_event.get("debugContext", {})
        debug_data = debug_context.get("debugData", {})

        return debug_data.get("appId", ""), debug_data.get("appName", "")

    def _extract_target_user(self, raw_event: Dict[str, Any]) -> tuple:
        """Extract target user for admin/privilege actions."""
        targets = raw_event.get("target", [])

        for target in targets:
            target_type = target.get("type", "").lower()
            if target_type == "user":
                return (
                    target.get("id", ""),
                    self.normalize_email(target.get("alternateId", ""))
                )

        return None, None

    def _extract_privilege_changes(
        self, raw_event: Dict[str, Any], event_type: IdentityEventType
    ) -> Optional[List[PrivilegeChange]]:
        """Extract privilege changes from event."""
        if event_type not in (IdentityEventType.PRIVILEGE_GRANT, IdentityEventType.PRIVILEGE_REVOKE):
            return None

        changes = []
        action = "grant" if event_type == IdentityEventType.PRIVILEGE_GRANT else "revoke"
        actor = raw_event.get("actor", {})
        targets = raw_event.get("target", [])

        for target in targets:
            target_type = target.get("type", "").lower()
            if target_type in ("role", "group", "permission", "usergroup", "appgroup"):
                changes.append(PrivilegeChange(
                    action=action,
                    role_name=target.get("displayName", ""),
                    role_id=target.get("id"),
                    granted_by=actor.get("alternateId"),
                    timestamp=self.parse_timestamp(raw_event.get("published")),
                ))

        return changes if changes else None

    def _map_risk_level(self, security_context: Dict[str, Any]) -> Optional[str]:
        """Map Okta security context to risk level."""
        if not security_context:
            return None

        # Check for threat suspected flag
        if security_context.get("isThreatSuspected"):
            return "high"

        # Check for proxy detection
        if security_context.get("isProxy"):
            return "medium"

        return None
