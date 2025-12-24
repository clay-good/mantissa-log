"""
Unified Identity Event Schema for ITDR Module

This module provides a normalized identity event schema that unifies authentication
and identity events across all supported identity providers:
- Okta
- Azure/Entra
- Google Workspace
- Duo Security
- Microsoft 365

The schema enables cross-provider detection, correlation, and behavioral analysis.
"""

from dataclasses import dataclass, field, asdict
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional
import json
import uuid


class IdentityEventType(Enum):
    """Enumeration of all identity event types across providers.

    These event types are normalized from provider-specific event types
    to enable cross-provider detection and correlation.
    """
    # Authentication events
    AUTH_SUCCESS = "auth_success"
    AUTH_FAILURE = "auth_failure"

    # MFA events
    MFA_CHALLENGE = "mfa_challenge"
    MFA_SUCCESS = "mfa_success"
    MFA_FAILURE = "mfa_failure"

    # Session events
    SESSION_START = "session_start"
    SESSION_END = "session_end"
    LOGOUT = "session_end"  # Alias for SESSION_END

    # Privilege/role events
    PRIVILEGE_GRANT = "privilege_grant"
    PRIVILEGE_REVOKE = "privilege_revoke"

    # Account lifecycle events
    ACCOUNT_CREATED = "account_created"
    ACCOUNT_DISABLED = "account_disabled"
    ACCOUNT_LOCKED = "account_locked"
    ACCOUNT_UNLOCKED = "account_unlocked"
    ACCOUNT_DELETED = "account_deleted"

    # Credential events
    PASSWORD_CHANGE = "password_change"
    PASSWORD_RESET = "password_reset"

    # Token/API key events
    API_KEY_CREATED = "api_key_created"
    API_KEY_REVOKED = "api_key_revoked"
    TOKEN_ISSUED = "token_issued"
    TOKEN_REVOKED = "token_revoked"
    TOKEN_REFRESH = "token_refresh"

    # OAuth/consent events
    OAUTH_CONSENT_GRANTED = "oauth_consent_granted"
    OAUTH_CONSENT_REVOKED = "oauth_consent_revoked"

    # MFA configuration events
    MFA_ENROLLED = "mfa_enrolled"
    MFA_REMOVED = "mfa_removed"
    MFA_METHOD_CHANGED = "mfa_method_changed"
    MFA_BYPASS_USED = "mfa_bypass_used"

    # Unknown/other
    UNKNOWN = "unknown"


@dataclass
class GeoLocation:
    """Geographic location information for identity events.

    Attributes:
        country: Country name or ISO code
        city: City name
        region: State/region/province name
        lat: Latitude coordinate (alias: latitude)
        lon: Longitude coordinate (alias: longitude)
        asn: Autonomous System Number (for IP-based detection)
        isp: Internet Service Provider name
    """
    country: Optional[str] = None
    city: Optional[str] = None
    region: Optional[str] = None
    lat: Optional[float] = None
    lon: Optional[float] = None
    asn: Optional[str] = None
    isp: Optional[str] = None

    def __init__(
        self,
        country: Optional[str] = None,
        city: Optional[str] = None,
        region: Optional[str] = None,
        lat: Optional[float] = None,
        lon: Optional[float] = None,
        asn: Optional[str] = None,
        isp: Optional[str] = None,
        # Aliases for compatibility
        latitude: Optional[float] = None,
        longitude: Optional[float] = None,
    ):
        self.country = country
        self.city = city
        self.region = region
        # Support both lat/lon and latitude/longitude
        self.lat = lat if lat is not None else latitude
        self.lon = lon if lon is not None else longitude
        self.asn = asn
        self.isp = isp

    # Property aliases for convenience
    @property
    def latitude(self) -> Optional[float]:
        """Alias for lat."""
        return self.lat

    @property
    def longitude(self) -> Optional[float]:
        """Alias for lon."""
        return self.lon

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary, excluding None values."""
        result = {
            "country": self.country,
            "city": self.city,
            "region": self.region,
            "lat": self.lat,
            "lon": self.lon,
            "asn": self.asn,
            "isp": self.isp,
        }
        return {k: v for k, v in result.items() if v is not None}

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "GeoLocation":
        """Create GeoLocation from dictionary."""
        if not data:
            return cls()
        return cls(
            country=data.get("country"),
            city=data.get("city"),
            region=data.get("region"),
            lat=data.get("lat") or data.get("latitude"),
            lon=data.get("lon") or data.get("longitude"),
            asn=data.get("asn"),
            isp=data.get("isp"),
        )

    def is_populated(self) -> bool:
        """Check if any location data is present."""
        return any([self.country, self.city, self.lat, self.lon])


@dataclass
class PrivilegeChange:
    """Represents a privilege/role change event.

    Attributes:
        action: 'grant' or 'revoke'
        role_name: Name of the role/privilege
        role_id: Provider-specific role ID
        granted_by: Email/ID of user who performed the grant
        timestamp: When the change occurred
        scope: Scope of the privilege (e.g., 'organization', 'application')
    """
    action: str  # 'grant' or 'revoke'
    role_name: str
    role_id: Optional[str] = None
    granted_by: Optional[str] = None
    timestamp: Optional[datetime] = None
    scope: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        result = {
            "action": self.action,
            "role_name": self.role_name,
        }
        if self.role_id:
            result["role_id"] = self.role_id
        if self.granted_by:
            result["granted_by"] = self.granted_by
        if self.timestamp:
            result["timestamp"] = self.timestamp.isoformat()
        if self.scope:
            result["scope"] = self.scope
        return result

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "PrivilegeChange":
        """Create PrivilegeChange from dictionary."""
        timestamp = data.get("timestamp")
        if isinstance(timestamp, str):
            timestamp = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
        return cls(
            action=data.get("action", "unknown"),
            role_name=data.get("role_name", "unknown"),
            role_id=data.get("role_id"),
            granted_by=data.get("granted_by"),
            timestamp=timestamp,
            scope=data.get("scope"),
        )


@dataclass
class IdentityEvent:
    """Unified identity event schema for ITDR.

    This dataclass normalizes identity events from all supported providers
    into a common format for cross-provider detection and correlation.

    Attributes:
        event_id: Unique identifier for this event
        event_type: Normalized event type from IdentityEventType enum
        timestamp: When the event occurred
        provider: Source identity provider (okta, azure, google_workspace, duo, microsoft365)
        user_id: Provider-specific user ID
        user_email: Normalized user email address
        user_display_name: User's display name
        source_ip: Source IP address of the request
        source_geo: Geographic location of the source IP
        device_id: Device identifier if available
        device_type: Type of device (desktop, mobile, etc.)
        user_agent: Browser/client user agent string
        session_id: Session identifier if available
        mfa_method: MFA method used (push, sms, totp, hardware_key, etc.)
        auth_protocol: Authentication protocol (SAML, OIDC, OAuth, LDAP)
        application_id: Target application ID
        application_name: Target application name
        failure_reason: Normalized failure reason for failed events
        risk_level: Risk level (none, low, medium, high, critical)
        risk_reasons: List of risk indicators/reasons
        privilege_changes: List of privilege changes in this event
        raw_event: Original provider-specific event data
        provider_event_type: Original provider-specific event type
        correlation_id: Provider's correlation/transaction ID
    """
    # Required fields
    event_id: str
    event_type: IdentityEventType
    timestamp: datetime
    provider: str

    # User identification
    user_id: str = ""
    user_email: str = ""
    user_display_name: Optional[str] = None

    # Source/client information
    source_ip: Optional[str] = None
    source_geo: Optional[GeoLocation] = None
    device_id: Optional[str] = None
    device_type: Optional[str] = None
    user_agent: Optional[str] = None

    # Session information
    session_id: Optional[str] = None

    # Authentication details
    mfa_method: Optional[str] = None
    auth_protocol: Optional[str] = None

    # Target application
    application_id: Optional[str] = None
    application_name: Optional[str] = None

    # Failure/risk information
    failure_reason: Optional[str] = None
    risk_level: Optional[str] = None
    risk_reasons: Optional[List[str]] = None

    # Privilege changes
    privilege_changes: Optional[List[PrivilegeChange]] = None

    # Target user (for admin actions)
    target_user_id: Optional[str] = None
    target_user_email: Optional[str] = None

    # Raw event and provider-specific data
    raw_event: Dict[str, Any] = field(default_factory=dict)
    provider_event_type: Optional[str] = None
    correlation_id: Optional[str] = None

    def __post_init__(self):
        """Validate and normalize fields after initialization."""
        # Ensure event_id is set
        if not self.event_id:
            self.event_id = str(uuid.uuid4())

        # Normalize provider name
        self.provider = self.provider.lower().replace("-", "_").replace(" ", "_")

        # Normalize email to lowercase
        if self.user_email:
            self.user_email = self.user_email.lower()
        if self.target_user_email:
            self.target_user_email = self.target_user_email.lower()

        # Normalize risk level
        if self.risk_level:
            self.risk_level = self.risk_level.lower()

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for storage/serialization."""
        result = {
            "event_id": self.event_id,
            "event_type": self.event_type.value,
            "timestamp": self.timestamp.isoformat(),
            "provider": self.provider,
            "user_id": self.user_id,
            "user_email": self.user_email,
        }

        # Add optional fields if present
        if self.user_display_name:
            result["user_display_name"] = self.user_display_name
        if self.source_ip:
            result["source_ip"] = self.source_ip
        if self.source_geo and self.source_geo.is_populated():
            result["source_geo"] = self.source_geo.to_dict()
        if self.device_id:
            result["device_id"] = self.device_id
        if self.device_type:
            result["device_type"] = self.device_type
        if self.user_agent:
            result["user_agent"] = self.user_agent
        if self.session_id:
            result["session_id"] = self.session_id
        if self.mfa_method:
            result["mfa_method"] = self.mfa_method
        if self.auth_protocol:
            result["auth_protocol"] = self.auth_protocol
        if self.application_id:
            result["application_id"] = self.application_id
        if self.application_name:
            result["application_name"] = self.application_name
        if self.failure_reason:
            result["failure_reason"] = self.failure_reason
        if self.risk_level:
            result["risk_level"] = self.risk_level
        if self.risk_reasons:
            result["risk_reasons"] = self.risk_reasons
        if self.privilege_changes:
            result["privilege_changes"] = [p.to_dict() for p in self.privilege_changes]
        if self.target_user_id:
            result["target_user_id"] = self.target_user_id
        if self.target_user_email:
            result["target_user_email"] = self.target_user_email
        if self.provider_event_type:
            result["provider_event_type"] = self.provider_event_type
        if self.correlation_id:
            result["correlation_id"] = self.correlation_id

        # Include raw event
        result["raw_event"] = self.raw_event

        return result

    def to_json(self) -> str:
        """Convert to JSON string."""
        return json.dumps(self.to_dict(), default=str)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "IdentityEvent":
        """Create IdentityEvent from dictionary."""
        # Parse timestamp
        timestamp = data.get("timestamp")
        if isinstance(timestamp, str):
            timestamp = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
        elif timestamp is None:
            timestamp = datetime.utcnow()

        # Parse event type
        event_type_str = data.get("event_type", "unknown")
        try:
            event_type = IdentityEventType(event_type_str)
        except ValueError:
            event_type = IdentityEventType.UNKNOWN

        # Parse geo location
        source_geo = None
        if "source_geo" in data and data["source_geo"]:
            source_geo = GeoLocation.from_dict(data["source_geo"])

        # Parse privilege changes
        privilege_changes = None
        if "privilege_changes" in data and data["privilege_changes"]:
            privilege_changes = [
                PrivilegeChange.from_dict(p) for p in data["privilege_changes"]
            ]

        return cls(
            event_id=data.get("event_id", str(uuid.uuid4())),
            event_type=event_type,
            timestamp=timestamp,
            provider=data.get("provider", "unknown"),
            user_id=data.get("user_id", ""),
            user_email=data.get("user_email", ""),
            user_display_name=data.get("user_display_name"),
            source_ip=data.get("source_ip"),
            source_geo=source_geo,
            device_id=data.get("device_id"),
            device_type=data.get("device_type"),
            user_agent=data.get("user_agent"),
            session_id=data.get("session_id"),
            mfa_method=data.get("mfa_method"),
            auth_protocol=data.get("auth_protocol"),
            application_id=data.get("application_id"),
            application_name=data.get("application_name"),
            failure_reason=data.get("failure_reason"),
            risk_level=data.get("risk_level"),
            risk_reasons=data.get("risk_reasons"),
            privilege_changes=privilege_changes,
            target_user_id=data.get("target_user_id"),
            target_user_email=data.get("target_user_email"),
            raw_event=data.get("raw_event", {}),
            provider_event_type=data.get("provider_event_type"),
            correlation_id=data.get("correlation_id"),
        )

    def is_authentication_event(self) -> bool:
        """Check if this is an authentication-related event."""
        return self.event_type in (
            IdentityEventType.AUTH_SUCCESS,
            IdentityEventType.AUTH_FAILURE,
            IdentityEventType.SESSION_START,
            IdentityEventType.SESSION_END,
        )

    def is_mfa_event(self) -> bool:
        """Check if this is an MFA-related event."""
        return self.event_type in (
            IdentityEventType.MFA_CHALLENGE,
            IdentityEventType.MFA_SUCCESS,
            IdentityEventType.MFA_FAILURE,
            IdentityEventType.MFA_ENROLLED,
            IdentityEventType.MFA_REMOVED,
            IdentityEventType.MFA_METHOD_CHANGED,
        )

    def is_privilege_event(self) -> bool:
        """Check if this is a privilege/role change event."""
        return self.event_type in (
            IdentityEventType.PRIVILEGE_GRANT,
            IdentityEventType.PRIVILEGE_REVOKE,
        )

    def is_account_lifecycle_event(self) -> bool:
        """Check if this is an account lifecycle event."""
        return self.event_type in (
            IdentityEventType.ACCOUNT_CREATED,
            IdentityEventType.ACCOUNT_DISABLED,
            IdentityEventType.ACCOUNT_LOCKED,
            IdentityEventType.ACCOUNT_UNLOCKED,
            IdentityEventType.ACCOUNT_DELETED,
        )

    def is_failure_event(self) -> bool:
        """Check if this event represents a failure."""
        return self.event_type in (
            IdentityEventType.AUTH_FAILURE,
            IdentityEventType.MFA_FAILURE,
        )

    def is_success_event(self) -> bool:
        """Check if this event represents a success."""
        return self.event_type in (
            IdentityEventType.AUTH_SUCCESS,
            IdentityEventType.MFA_SUCCESS,
            IdentityEventType.SESSION_START,
        )

    def has_geolocation(self) -> bool:
        """Check if geolocation data is available."""
        return self.source_geo is not None and self.source_geo.is_populated()


class IdentityEventNormalizer:
    """Normalizes raw provider events to IdentityEvent objects.

    This class serves as a facade for the provider-specific mappers,
    automatically detecting the provider and delegating to the appropriate mapper.
    """

    def __init__(self):
        """Initialize the normalizer with provider mappers."""
        # Import mappers here to avoid circular imports
        from .identity_mappers import (
            OktaIdentityMapper,
            AzureIdentityMapper,
            GoogleWorkspaceIdentityMapper,
            DuoIdentityMapper,
            Microsoft365IdentityMapper,
        )

        self._mappers = {
            "okta": OktaIdentityMapper(),
            "azure": AzureIdentityMapper(),
            "azure_monitor": AzureIdentityMapper(),
            "google_workspace": GoogleWorkspaceIdentityMapper(),
            "duo": DuoIdentityMapper(),
            "microsoft365": Microsoft365IdentityMapper(),
        }

    def normalize(self, raw_event: Dict[str, Any], provider: str) -> IdentityEvent:
        """Normalize a raw event from a specific provider.

        Args:
            raw_event: Raw event dictionary from the provider
            provider: Provider name (okta, azure, google_workspace, duo, microsoft365)

        Returns:
            Normalized IdentityEvent

        Raises:
            ValueError: If provider is not supported
        """
        provider_lower = provider.lower().replace("-", "_").replace(" ", "_")

        if provider_lower not in self._mappers:
            raise ValueError(f"Unsupported provider: {provider}")

        mapper = self._mappers[provider_lower]
        return mapper.map(raw_event)

    def normalize_batch(
        self, events: List[Dict[str, Any]], provider: str
    ) -> List[IdentityEvent]:
        """Normalize a batch of events from a specific provider.

        Args:
            events: List of raw event dictionaries
            provider: Provider name

        Returns:
            List of normalized IdentityEvents
        """
        return [self.normalize(event, provider) for event in events]

    def detect_provider(self, raw_event: Dict[str, Any]) -> Optional[str]:
        """Attempt to detect the provider from event structure.

        Args:
            raw_event: Raw event dictionary

        Returns:
            Detected provider name or None if unable to detect
        """
        # Okta detection
        if "eventType" in raw_event and "actor" in raw_event and "outcome" in raw_event:
            return "okta"

        # Azure/Entra detection
        if "userPrincipalName" in raw_event and "status" in raw_event:
            return "azure"
        if "operationName" in raw_event and "resourceId" in raw_event:
            return "azure"

        # Google Workspace detection
        if "id" in raw_event and isinstance(raw_event.get("id"), dict):
            if "applicationName" in raw_event.get("id", {}):
                return "google_workspace"

        # Duo detection
        if "txid" in raw_event and "factor" in raw_event:
            return "duo"

        # Microsoft 365 detection
        if "RecordType" in raw_event and "Workload" in raw_event:
            return "microsoft365"

        return None

    def normalize_auto(self, raw_event: Dict[str, Any]) -> Optional[IdentityEvent]:
        """Normalize an event by auto-detecting the provider.

        Args:
            raw_event: Raw event dictionary

        Returns:
            Normalized IdentityEvent or None if provider cannot be detected
        """
        provider = self.detect_provider(raw_event)
        if provider is None:
            return None
        return self.normalize(raw_event, provider)
