"""User Context Enrichment Service.

Provides user context from Google Workspace, Azure Entra ID, and Okta.
"""

import logging
import os
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


@dataclass
class UserContext:
    """User context information from identity provider."""

    user_id: str
    email: Optional[str] = None
    display_name: Optional[str] = None
    first_name: Optional[str] = None
    last_name: Optional[str] = None

    # Organizational info
    department: Optional[str] = None
    job_title: Optional[str] = None
    manager: Optional[str] = None
    manager_email: Optional[str] = None
    cost_center: Optional[str] = None
    office_location: Optional[str] = None

    # Account status
    status: str = "unknown"  # active, suspended, deprovisioned, etc.
    account_enabled: bool = True
    is_admin: bool = False
    is_service_account: bool = False

    # Security info
    mfa_enabled: bool = False
    last_login: Optional[str] = None
    last_password_change: Optional[str] = None
    risk_level: Optional[str] = None  # low, medium, high

    # Groups and roles
    groups: List[str] = field(default_factory=list)
    roles: List[str] = field(default_factory=list)

    # Provider info
    source: str = "unknown"  # google_workspace, azure_entra, okta
    cached: bool = False
    error: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            "user_id": self.user_id,
            "email": self.email,
            "display_name": self.display_name,
            "first_name": self.first_name,
            "last_name": self.last_name,
            "department": self.department,
            "job_title": self.job_title,
            "manager": self.manager,
            "manager_email": self.manager_email,
            "cost_center": self.cost_center,
            "office_location": self.office_location,
            "status": self.status,
            "account_enabled": self.account_enabled,
            "is_admin": self.is_admin,
            "is_service_account": self.is_service_account,
            "mfa_enabled": self.mfa_enabled,
            "last_login": self.last_login,
            "last_password_change": self.last_password_change,
            "risk_level": self.risk_level,
            "groups": self.groups,
            "roles": self.roles,
            "source": self.source,
            "cached": self.cached,
            "error": self.error,
        }


class UserContextCache:
    """In-memory cache for user context."""

    def __init__(self, ttl_hours: int = 1, max_size: int = 5000):
        """Initialize cache.

        Args:
            ttl_hours: Time-to-live in hours
            max_size: Maximum cache entries
        """
        self.ttl = timedelta(hours=ttl_hours)
        self.max_size = max_size
        self._cache: Dict[str, tuple] = {}

    def _make_key(self, user_id: str, source: str) -> str:
        """Generate cache key."""
        return f"{source}:{user_id.lower()}"

    def get(self, user_id: str, source: str) -> Optional[UserContext]:
        """Get cached user context."""
        key = self._make_key(user_id, source)
        if key in self._cache:
            result, timestamp = self._cache[key]
            if datetime.utcnow() - timestamp < self.ttl:
                result.cached = True
                return result
            else:
                del self._cache[key]
        return None

    def put(self, user_context: UserContext) -> None:
        """Cache user context."""
        if len(self._cache) >= self.max_size:
            oldest_key = min(self._cache, key=lambda k: self._cache[k][1])
            del self._cache[oldest_key]

        key = self._make_key(user_context.user_id, user_context.source)
        self._cache[key] = (user_context, datetime.utcnow())

    def clear(self) -> None:
        """Clear cache."""
        self._cache.clear()


class UserContextService:
    """User context service supporting multiple identity providers."""

    def __init__(
        self,
        # Google Workspace
        google_credentials_path: Optional[str] = None,
        google_admin_email: Optional[str] = None,
        # Azure Entra ID
        azure_tenant_id: Optional[str] = None,
        azure_client_id: Optional[str] = None,
        azure_client_secret: Optional[str] = None,
        # Okta
        okta_domain: Optional[str] = None,
        okta_api_token: Optional[str] = None,
        # Cache
        cache_ttl_hours: int = 1,
    ):
        """Initialize user context service.

        Args:
            google_credentials_path: Path to Google service account JSON
            google_admin_email: Admin email for domain-wide delegation
            azure_tenant_id: Azure AD tenant ID
            azure_client_id: Azure AD application client ID
            azure_client_secret: Azure AD client secret
            okta_domain: Okta domain (e.g., yourcompany.okta.com)
            okta_api_token: Okta API token
            cache_ttl_hours: Cache TTL in hours
        """
        # Google Workspace
        self.google_credentials_path = google_credentials_path or os.environ.get("GOOGLE_CREDENTIALS_PATH")
        self.google_admin_email = google_admin_email or os.environ.get("GOOGLE_ADMIN_EMAIL")

        # Azure Entra ID
        self.azure_tenant_id = azure_tenant_id or os.environ.get("AZURE_TENANT_ID")
        self.azure_client_id = azure_client_id or os.environ.get("AZURE_CLIENT_ID")
        self.azure_client_secret = azure_client_secret or os.environ.get("AZURE_CLIENT_SECRET")

        # Okta
        self.okta_domain = okta_domain or os.environ.get("OKTA_DOMAIN")
        self.okta_api_token = okta_api_token or os.environ.get("OKTA_API_TOKEN")

        self.cache = UserContextCache(ttl_hours=cache_ttl_hours)

    def get_user(self, user_id: str, provider: Optional[str] = None) -> UserContext:
        """Get user context from configured provider.

        Args:
            user_id: User ID or email
            provider: Provider to use (google_workspace, azure_entra, okta)
                     If None, will try all configured providers

        Returns:
            UserContext
        """
        # Try specified provider
        if provider:
            return self._get_user_from_provider(user_id, provider)

        # Try all configured providers
        if self.okta_domain and self.okta_api_token:
            result = self._get_user_from_okta(user_id)
            if not result.error:
                return result

        if self.azure_tenant_id and self.azure_client_id:
            result = self._get_user_from_azure(user_id)
            if not result.error:
                return result

        if self.google_credentials_path and self.google_admin_email:
            result = self._get_user_from_google(user_id)
            if not result.error:
                return result

        return UserContext(
            user_id=user_id,
            error="No identity provider configured or all lookups failed",
        )

    def _get_user_from_provider(self, user_id: str, provider: str) -> UserContext:
        """Get user from specific provider."""
        if provider == "google_workspace":
            return self._get_user_from_google(user_id)
        elif provider == "azure_entra":
            return self._get_user_from_azure(user_id)
        elif provider == "okta":
            return self._get_user_from_okta(user_id)
        else:
            return UserContext(user_id=user_id, error=f"Unknown provider: {provider}")

    def _get_user_from_google(self, user_id: str) -> UserContext:
        """Get user from Google Workspace Admin SDK."""
        # Check cache
        cached = self.cache.get(user_id, "google_workspace")
        if cached:
            return cached

        result = UserContext(user_id=user_id, source="google_workspace")

        try:
            from google.oauth2 import service_account
            from googleapiclient.discovery import build

            # Build credentials with domain-wide delegation
            credentials = service_account.Credentials.from_service_account_file(
                self.google_credentials_path,
                scopes=[
                    "https://www.googleapis.com/auth/admin.directory.user.readonly",
                    "https://www.googleapis.com/auth/admin.directory.group.readonly",
                ],
            )
            delegated_credentials = credentials.with_subject(self.google_admin_email)

            # Build Admin SDK service
            service = build("admin", "directory_v1", credentials=delegated_credentials)

            # Get user
            user = service.users().get(userKey=user_id).execute()

            result.email = user.get("primaryEmail")
            result.display_name = user.get("name", {}).get("fullName")
            result.first_name = user.get("name", {}).get("givenName")
            result.last_name = user.get("name", {}).get("familyName")

            # Organizational info from custom schemas or org unit
            result.department = user.get("organizations", [{}])[0].get("department") if user.get("organizations") else None
            result.job_title = user.get("organizations", [{}])[0].get("title") if user.get("organizations") else None
            result.office_location = user.get("locations", [{}])[0].get("buildingId") if user.get("locations") else None

            # Status
            result.status = "active" if not user.get("suspended") else "suspended"
            result.account_enabled = not user.get("suspended", False)
            result.is_admin = user.get("isAdmin", False)

            # Security
            result.mfa_enabled = user.get("isEnrolledIn2Sv", False)
            result.last_login = user.get("lastLoginTime")

            # Get groups
            try:
                groups_response = service.groups().list(userKey=user_id).execute()
                result.groups = [g.get("name") for g in groups_response.get("groups", [])]
            except Exception:
                pass

            self.cache.put(result)
            return result

        except ImportError:
            result.error = "google-auth and google-api-python-client packages required"
            return result
        except Exception as e:
            logger.debug(f"Google Workspace lookup failed for {user_id}: {e}")
            result.error = str(e)
            return result

    def _get_user_from_azure(self, user_id: str) -> UserContext:
        """Get user from Azure Entra ID (Microsoft Graph API)."""
        # Check cache
        cached = self.cache.get(user_id, "azure_entra")
        if cached:
            return cached

        result = UserContext(user_id=user_id, source="azure_entra")

        try:
            import requests

            # Get access token
            token_url = f"https://login.microsoftonline.com/{self.azure_tenant_id}/oauth2/v2.0/token"
            token_response = requests.post(
                token_url,
                data={
                    "client_id": self.azure_client_id,
                    "client_secret": self.azure_client_secret,
                    "scope": "https://graph.microsoft.com/.default",
                    "grant_type": "client_credentials",
                },
                timeout=10,
            )
            token_response.raise_for_status()
            access_token = token_response.json().get("access_token")

            # Query user (try by userPrincipalName or id)
            graph_url = f"https://graph.microsoft.com/v1.0/users/{user_id}"
            headers = {"Authorization": f"Bearer {access_token}"}
            params = {"$select": "id,displayName,givenName,surname,mail,userPrincipalName,department,jobTitle,officeLocation,accountEnabled,lastSignInDateTime,manager"}

            response = requests.get(graph_url, headers=headers, params=params, timeout=10)
            response.raise_for_status()
            user = response.json()

            result.email = user.get("mail") or user.get("userPrincipalName")
            result.display_name = user.get("displayName")
            result.first_name = user.get("givenName")
            result.last_name = user.get("surname")
            result.department = user.get("department")
            result.job_title = user.get("jobTitle")
            result.office_location = user.get("officeLocation")
            result.status = "active" if user.get("accountEnabled") else "disabled"
            result.account_enabled = user.get("accountEnabled", False)
            result.last_login = user.get("lastSignInDateTime")

            # Get manager
            try:
                manager_response = requests.get(
                    f"{graph_url}/manager",
                    headers=headers,
                    timeout=10,
                )
                if manager_response.status_code == 200:
                    manager = manager_response.json()
                    result.manager = manager.get("displayName")
                    result.manager_email = manager.get("mail") or manager.get("userPrincipalName")
            except Exception:
                pass

            # Get group memberships
            try:
                groups_response = requests.get(
                    f"{graph_url}/memberOf",
                    headers=headers,
                    params={"$select": "displayName"},
                    timeout=10,
                )
                if groups_response.status_code == 200:
                    result.groups = [
                        g.get("displayName") for g in groups_response.json().get("value", [])
                        if g.get("@odata.type") == "#microsoft.graph.group"
                    ]
                    result.roles = [
                        r.get("displayName") for r in groups_response.json().get("value", [])
                        if r.get("@odata.type") == "#microsoft.graph.directoryRole"
                    ]
            except Exception:
                pass

            # Check if admin
            result.is_admin = any("admin" in r.lower() for r in result.roles)

            self.cache.put(result)
            return result

        except Exception as e:
            logger.debug(f"Azure Entra lookup failed for {user_id}: {e}")
            result.error = str(e)
            return result

    def _get_user_from_okta(self, user_id: str) -> UserContext:
        """Get user from Okta Users API."""
        # Check cache
        cached = self.cache.get(user_id, "okta")
        if cached:
            return cached

        result = UserContext(user_id=user_id, source="okta")

        try:
            import requests

            headers = {
                "Authorization": f"SSWS {self.okta_api_token}",
                "Accept": "application/json",
            }

            # Get user (try by login/email or id)
            user_url = f"https://{self.okta_domain}/api/v1/users/{user_id}"
            response = requests.get(user_url, headers=headers, timeout=10)
            response.raise_for_status()
            user = response.json()

            profile = user.get("profile", {})

            result.email = profile.get("email") or profile.get("login")
            result.display_name = f"{profile.get('firstName', '')} {profile.get('lastName', '')}".strip()
            result.first_name = profile.get("firstName")
            result.last_name = profile.get("lastName")
            result.department = profile.get("department")
            result.job_title = profile.get("title")
            result.manager = profile.get("manager")
            result.manager_email = profile.get("managerId")
            result.cost_center = profile.get("costCenter")
            result.office_location = profile.get("city")

            # Status
            okta_status = user.get("status", "").upper()
            status_map = {
                "ACTIVE": "active",
                "PROVISIONED": "provisioned",
                "STAGED": "staged",
                "SUSPENDED": "suspended",
                "DEPROVISIONED": "deprovisioned",
                "LOCKED_OUT": "locked",
                "PASSWORD_EXPIRED": "password_expired",
                "RECOVERY": "recovery",
            }
            result.status = status_map.get(okta_status, okta_status.lower())
            result.account_enabled = okta_status == "ACTIVE"

            # Last login
            result.last_login = user.get("lastLogin")
            result.last_password_change = user.get("passwordChanged")

            # Get groups
            try:
                groups_url = f"https://{self.okta_domain}/api/v1/users/{user.get('id')}/groups"
                groups_response = requests.get(groups_url, headers=headers, timeout=10)
                if groups_response.status_code == 200:
                    result.groups = [g.get("profile", {}).get("name") for g in groups_response.json()]
            except Exception:
                pass

            # Check if admin (Okta-specific)
            result.is_admin = any("admin" in g.lower() for g in result.groups)

            self.cache.put(result)
            return result

        except Exception as e:
            logger.debug(f"Okta lookup failed for {user_id}: {e}")
            result.error = str(e)
            return result


def get_user_context(user_id: str, provider: Optional[str] = None, **kwargs) -> UserContext:
    """Convenience function to get user context.

    Args:
        user_id: User ID or email
        provider: Optional provider to use
        **kwargs: Arguments passed to UserContextService

    Returns:
        UserContext
    """
    service = UserContextService(**kwargs)
    return service.get_user(user_id, provider=provider)
