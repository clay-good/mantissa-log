"""Authentication, authorization, CORS, and rate limiting utilities for Mantissa Log."""

from .middleware import (
    AuthenticationError,
    AuthorizationError,
    get_authenticated_user_id,
    validate_user_access,
    require_authentication,
    get_safe_user_id_from_request,
)

from .cors import (
    get_allowed_origins,
    get_cors_origin,
    get_cors_headers,
    cors_preflight_response,
    add_cors_headers,
)

from .rate_limiter import (
    RateLimitExceeded,
    RateLimitConfig,
    RateLimiter,
    get_rate_limiter,
    rate_limit_response,
)

__all__ = [
    # Authentication
    "AuthenticationError",
    "AuthorizationError",
    "get_authenticated_user_id",
    "validate_user_access",
    "require_authentication",
    "get_safe_user_id_from_request",
    # CORS
    "get_allowed_origins",
    "get_cors_origin",
    "get_cors_headers",
    "cors_preflight_response",
    "add_cors_headers",
    # Rate Limiting
    "RateLimitExceeded",
    "RateLimitConfig",
    "RateLimiter",
    "get_rate_limiter",
    "rate_limit_response",
]
