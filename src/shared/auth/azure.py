"""Azure AD Authentication utilities for Azure Functions.

This module provides Azure AD token verification and authentication helpers
for Azure Functions, following the same patterns as the AWS auth modules.
"""

import json
import logging
import os
from typing import Any, Dict, Optional, Tuple

import jwt
from jwt import PyJWKClient

logger = logging.getLogger(__name__)


class AuthenticationError(Exception):
    """Exception raised when authentication fails."""

    def __init__(self, message: str, status_code: int = 401):
        self.message = message
        self.status_code = status_code
        super().__init__(message)


# Azure AD configuration from environment
AZURE_TENANT_ID = os.environ.get('AZURE_TENANT_ID', '')
AZURE_CLIENT_ID = os.environ.get('AZURE_CLIENT_ID', '')
AZURE_AD_ISSUER = os.environ.get(
    'AZURE_AD_ISSUER',
    f'https://login.microsoftonline.com/{AZURE_TENANT_ID}/v2.0' if AZURE_TENANT_ID else ''
)
AZURE_AD_JWKS_URI = os.environ.get(
    'AZURE_AD_JWKS_URI',
    f'https://login.microsoftonline.com/{AZURE_TENANT_ID}/discovery/v2.0/keys' if AZURE_TENANT_ID else ''
)

# Cache for JWKS client
_jwks_client: Optional[PyJWKClient] = None


def _get_jwks_client() -> PyJWKClient:
    """Get cached JWKS client for Azure AD."""
    global _jwks_client
    if _jwks_client is None:
        if not AZURE_AD_JWKS_URI:
            raise AuthenticationError("Azure AD JWKS URI not configured")
        _jwks_client = PyJWKClient(AZURE_AD_JWKS_URI)
    return _jwks_client


def _extract_token_from_header(auth_header: Optional[str]) -> str:
    """Extract JWT token from Authorization header.

    Args:
        auth_header: Authorization header value (e.g., "Bearer <token>")

    Returns:
        JWT token string

    Raises:
        AuthenticationError: If header is missing or malformed
    """
    if not auth_header:
        raise AuthenticationError("Authorization header missing")

    parts = auth_header.split()

    if len(parts) != 2:
        raise AuthenticationError("Invalid Authorization header format")

    if parts[0].lower() != 'bearer':
        raise AuthenticationError("Authorization must use Bearer scheme")

    return parts[1]


def verify_azure_ad_token(request: Any) -> str:
    """Verify Azure AD token from Azure Function request.

    Args:
        request: Azure Functions HttpRequest object

    Returns:
        User ID (email or object ID) from the token

    Raises:
        AuthenticationError: If token is invalid or verification fails
    """
    # Skip auth if disabled (for development/testing)
    if os.environ.get('DISABLE_AUTH', '').lower() == 'true':
        logger.warning("Authentication is disabled - returning anonymous user")
        return 'anonymous'

    # Get Authorization header
    auth_header = request.headers.get('Authorization')
    token = _extract_token_from_header(auth_header)

    try:
        # Get signing key from JWKS
        jwks_client = _get_jwks_client()
        signing_key = jwks_client.get_signing_key_from_jwt(token)

        # Verify and decode token
        payload = jwt.decode(
            token,
            signing_key.key,
            algorithms=['RS256'],
            audience=AZURE_CLIENT_ID,
            issuer=AZURE_AD_ISSUER,
            options={
                'verify_exp': True,
                'verify_iat': True,
                'verify_aud': bool(AZURE_CLIENT_ID),
                'verify_iss': bool(AZURE_AD_ISSUER),
            }
        )

        # Extract user identifier
        # Azure AD tokens typically have 'preferred_username', 'email', or 'oid'
        user_id = (
            payload.get('preferred_username') or
            payload.get('email') or
            payload.get('upn') or
            payload.get('oid') or
            payload.get('sub')
        )

        if not user_id:
            raise AuthenticationError("No user identifier found in token")

        logger.debug(f"Authenticated user: {user_id}")
        return user_id

    except jwt.ExpiredSignatureError:
        raise AuthenticationError("Token has expired")
    except jwt.InvalidAudienceError:
        raise AuthenticationError("Token has invalid audience")
    except jwt.InvalidIssuerError:
        raise AuthenticationError("Token has invalid issuer")
    except jwt.DecodeError as e:
        raise AuthenticationError(f"Failed to decode token: {str(e)}")
    except jwt.PyJWKClientError as e:
        raise AuthenticationError(f"Failed to get signing key: {str(e)}")
    except Exception as e:
        logger.error(f"Token verification failed: {e}", exc_info=True)
        raise AuthenticationError(f"Authentication failed: {str(e)}")


def get_token_claims(request: Any) -> Dict[str, Any]:
    """Get all claims from the Azure AD token.

    Args:
        request: Azure Functions HttpRequest object

    Returns:
        Dictionary of token claims

    Raises:
        AuthenticationError: If token is invalid
    """
    auth_header = request.headers.get('Authorization')
    token = _extract_token_from_header(auth_header)

    try:
        # Decode without verification to get claims
        # (use verify_azure_ad_token first for secure verification)
        return jwt.decode(token, options={"verify_signature": False})
    except jwt.DecodeError as e:
        raise AuthenticationError(f"Failed to decode token: {str(e)}")


def get_user_roles(request: Any) -> list:
    """Extract roles from Azure AD token.

    Args:
        request: Azure Functions HttpRequest object

    Returns:
        List of role names assigned to the user
    """
    try:
        claims = get_token_claims(request)
        return claims.get('roles', [])
    except AuthenticationError:
        return []


def require_role(request: Any, required_role: str) -> str:
    """Verify token and require a specific role.

    Args:
        request: Azure Functions HttpRequest object
        required_role: Role name that must be present

    Returns:
        User ID if authorized

    Raises:
        AuthenticationError: If not authorized
    """
    user_id = verify_azure_ad_token(request)
    roles = get_user_roles(request)

    if required_role not in roles:
        raise AuthenticationError(
            f"Required role '{required_role}' not found",
            status_code=403
        )

    return user_id


def get_cors_headers(request: Any) -> Dict[str, str]:
    """Get CORS headers for Azure Functions.

    This is a convenience wrapper that adapts the Azure Functions request
    format for CORS header generation.

    Args:
        request: Azure Functions HttpRequest object

    Returns:
        Dictionary of CORS headers
    """
    from . import cors

    # Get allowed origins from environment
    allowed_origins = cors.get_allowed_origins()

    # Get request origin
    request_origin = request.headers.get('Origin', '')

    # Determine allowed origin
    if '*' in allowed_origins:
        cors_origin = '*'
    elif request_origin in allowed_origins:
        cors_origin = request_origin
    elif allowed_origins:
        cors_origin = allowed_origins[0]
    else:
        # Default to allowing all for development
        cors_origin = request_origin or '*'

    return {
        'Access-Control-Allow-Origin': cors_origin,
        'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type, Authorization, X-Requested-With',
        'Vary': 'Origin',
    }


def cors_preflight_response(request: Any) -> Tuple[str, int, Dict[str, str]]:
    """Generate CORS preflight response for Azure Functions.

    Args:
        request: Azure Functions HttpRequest object

    Returns:
        Tuple of (body, status_code, headers)
    """
    headers = get_cors_headers(request)
    headers['Access-Control-Max-Age'] = '86400'

    return ('', 204, headers)


def optional_auth(request: Any) -> Optional[str]:
    """Attempt authentication but don't fail if not present.

    Useful for endpoints that behave differently for authenticated
    vs anonymous users.

    Args:
        request: Azure Functions HttpRequest object

    Returns:
        User ID if authenticated, None otherwise
    """
    try:
        return verify_azure_ad_token(request)
    except AuthenticationError:
        return None


# Aliases for backwards compatibility
get_authenticated_user_id = verify_azure_ad_token
