"""CORS configuration utilities for secure cross-origin requests.

This module provides secure CORS header generation that:
- Uses environment-configured allowed origins instead of '*'
- Supports multiple allowed origins
- Validates Origin header against whitelist
- Provides secure defaults for production
"""

import os
import logging
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


def get_allowed_origins() -> List[str]:
    """Get list of allowed CORS origins from environment.

    Environment variables:
        CORS_ALLOWED_ORIGINS: Comma-separated list of allowed origins
        CORS_ALLOWED_ORIGIN: Single allowed origin (fallback)

    Returns:
        List of allowed origin URLs
    """
    # Try comma-separated list first
    origins_str = os.environ.get('CORS_ALLOWED_ORIGINS', '')
    if origins_str:
        return [origin.strip() for origin in origins_str.split(',') if origin.strip()]

    # Fall back to single origin
    single_origin = os.environ.get('CORS_ALLOWED_ORIGIN', '')
    if single_origin:
        return [single_origin]

    # Default to empty list (no CORS allowed) in production
    # Use '*' only if explicitly enabled for development
    if os.environ.get('CORS_ALLOW_ALL', '').lower() == 'true':
        logger.warning("CORS_ALLOW_ALL is enabled - this should not be used in production")
        return ['*']

    return []


def get_cors_origin(request_origin: Optional[str] = None) -> str:
    """Get the appropriate CORS origin header value.

    If the request origin is in the allowed list, return it.
    Otherwise return empty string (no CORS header).

    Args:
        request_origin: The Origin header from the request

    Returns:
        Origin to use in Access-Control-Allow-Origin header
    """
    allowed_origins = get_allowed_origins()

    # If '*' is in allowed origins, return '*'
    if '*' in allowed_origins:
        return '*'

    # If no origins configured, don't allow CORS
    if not allowed_origins:
        return ''

    # If request origin is in allowed list, return it
    if request_origin and request_origin in allowed_origins:
        return request_origin

    # Return first allowed origin as default (for preflight requests without Origin)
    return allowed_origins[0] if allowed_origins else ''


def get_cors_headers(
    event: Optional[Dict[str, Any]] = None,
    allow_credentials: bool = False
) -> Dict[str, str]:
    """Get CORS headers for response.

    Args:
        event: API Gateway event (to extract Origin header)
        allow_credentials: Whether to allow credentials (cookies, auth headers)

    Returns:
        Dictionary of CORS headers
    """
    # Extract Origin from request
    request_origin = None
    if event:
        headers = event.get('headers', {}) or {}
        # Headers may be case-insensitive
        request_origin = headers.get('Origin') or headers.get('origin')

    cors_origin = get_cors_origin(request_origin)

    if not cors_origin:
        # No CORS headers if origin not allowed
        return {}

    cors_headers = {
        'Access-Control-Allow-Origin': cors_origin,
        'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
        'Access-Control-Allow-Headers': 'Content-Type, Authorization, X-Requested-With',
    }

    # Only set credentials header if origin is not '*'
    if allow_credentials and cors_origin != '*':
        cors_headers['Access-Control-Allow-Credentials'] = 'true'

    # Add Vary header for caching
    cors_headers['Vary'] = 'Origin'

    return cors_headers


def cors_preflight_response(event: Dict[str, Any]) -> Dict[str, Any]:
    """Generate a CORS preflight (OPTIONS) response.

    Args:
        event: API Gateway event

    Returns:
        API Gateway response for OPTIONS request
    """
    cors_headers = get_cors_headers(event)

    if not cors_headers:
        return {
            'statusCode': 403,
            'body': 'CORS not allowed'
        }

    return {
        'statusCode': 200,
        'headers': {
            **cors_headers,
            'Access-Control-Max-Age': '86400',  # Cache preflight for 24 hours
            'Content-Type': 'text/plain',
        },
        'body': ''
    }


def add_cors_headers(
    response: Dict[str, Any],
    event: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """Add CORS headers to an existing response.

    Args:
        response: API Gateway response dict
        event: API Gateway event (to extract Origin header)

    Returns:
        Response with CORS headers added
    """
    cors_headers = get_cors_headers(event)

    if cors_headers:
        existing_headers = response.get('headers', {}) or {}
        response['headers'] = {**existing_headers, **cors_headers}

    return response
