"""Authentication middleware for AWS Lambda handlers.

This module provides secure authentication utilities that extract
user identity from Cognito JWT claims and enforce authorization.

Security Features:
- Extracts user ID from verified Cognito JWT claims only
- Never trusts client-provided user IDs
- Enforces user can only access their own resources
- Provides decorator for easy authentication enforcement
"""

import functools
import json
import logging
import os
from typing import Any, Callable, Dict, Optional, TypeVar, cast

logger = logging.getLogger(__name__)

# Type variable for decorated functions
F = TypeVar('F', bound=Callable[..., Any])


class AuthenticationError(Exception):
    """Raised when authentication fails."""
    pass


class AuthorizationError(Exception):
    """Raised when authorization fails."""
    pass


def get_authenticated_user_id(event: Dict[str, Any]) -> str:
    """Extract authenticated user ID from Cognito claims in API Gateway event.

    This function extracts the user ID from the verified JWT claims
    that are populated by API Gateway after Cognito authorizer validates
    the token. It NEVER trusts client-provided user IDs.

    Args:
        event: API Gateway Lambda proxy event

    Returns:
        Authenticated user ID from Cognito 'sub' claim

    Raises:
        AuthenticationError: If no valid authentication found
    """
    request_context = event.get('requestContext', {})
    authorizer = request_context.get('authorizer', {})

    # Try different authorizer formats
    # Lambda authorizer format
    claims = authorizer.get('claims', {})

    # JWT authorizer format (API Gateway HTTP APIs)
    if not claims:
        jwt_claims = authorizer.get('jwt', {}).get('claims', {})
        claims = jwt_claims

    # Get user ID from Cognito 'sub' claim (unique user identifier)
    user_id = claims.get('sub')

    if not user_id:
        # Try cognito:username as fallback
        user_id = claims.get('cognito:username')

    if not user_id:
        # Check if running in development/test mode
        if os.environ.get('MANTISSA_DEV_MODE') == 'true':
            # Allow test user in development mode only
            logger.warning("Using development mode authentication")
            return 'dev-test-user'

        logger.error("No authenticated user found in request context")
        raise AuthenticationError("Authentication required")

    return user_id


def validate_user_access(
    event: Dict[str, Any],
    requested_user_id: Optional[str] = None
) -> str:
    """Validate that the authenticated user can access the requested resource.

    This function ensures that users can only access their own resources
    by comparing the authenticated user ID with the requested resource owner.

    Args:
        event: API Gateway Lambda proxy event
        requested_user_id: Optional user_id from request (query param or body).
                          If provided, must match authenticated user.

    Returns:
        The authenticated user ID (safe to use for database queries)

    Raises:
        AuthenticationError: If no valid authentication found
        AuthorizationError: If user tries to access another user's resources
    """
    authenticated_user_id = get_authenticated_user_id(event)

    # If a specific user_id was requested, verify it matches the authenticated user
    if requested_user_id and requested_user_id != authenticated_user_id:
        logger.warning(
            f"Authorization failed: user {authenticated_user_id} "
            f"attempted to access resources of user {requested_user_id}"
        )
        raise AuthorizationError("Access denied: cannot access other user's resources")

    return authenticated_user_id


def require_authentication(func: F) -> F:
    """Decorator that enforces authentication on Lambda handlers.

    Use this decorator on Lambda handlers to automatically:
    1. Extract the authenticated user ID from Cognito claims
    2. Reject unauthenticated requests with 401 response
    3. Make user_id available in the event under 'authenticated_user_id'

    Example:
        @require_authentication
        def lambda_handler(event, context):
            user_id = event['authenticated_user_id']
            # Safe to use user_id for database queries
            ...
    """
    @functools.wraps(func)
    def wrapper(event: Dict[str, Any], context: Any) -> Dict[str, Any]:
        try:
            # Extract and validate authentication
            user_id = get_authenticated_user_id(event)

            # Add authenticated user ID to event for handler use
            event['authenticated_user_id'] = user_id

            return func(event, context)

        except AuthenticationError as e:
            logger.warning(f"Authentication failed: {e}")
            return {
                'statusCode': 401,
                'headers': {
                    'Content-Type': 'application/json',
                    'Access-Control-Allow-Origin': os.environ.get(
                        'CORS_ALLOWED_ORIGIN', '*'
                    ),
                },
                'body': json.dumps({
                    'error': 'Unauthorized',
                    'message': 'Authentication required'
                })
            }

        except AuthorizationError as e:
            logger.warning(f"Authorization failed: {e}")
            return {
                'statusCode': 403,
                'headers': {
                    'Content-Type': 'application/json',
                    'Access-Control-Allow-Origin': os.environ.get(
                        'CORS_ALLOWED_ORIGIN', '*'
                    ),
                },
                'body': json.dumps({
                    'error': 'Forbidden',
                    'message': 'Access denied'
                })
            }

    return cast(F, wrapper)


def get_safe_user_id_from_request(
    event: Dict[str, Any],
    allow_query_param: bool = False
) -> str:
    """Get user ID safely, preferring authenticated ID over request parameters.

    This is a migration helper for handlers that currently accept user_id
    from query parameters. It validates that any provided user_id matches
    the authenticated user.

    Args:
        event: API Gateway Lambda proxy event
        allow_query_param: If True, allows user_id in query params but validates it

    Returns:
        The validated user ID

    Raises:
        AuthenticationError: If no valid authentication found
        AuthorizationError: If query param user_id doesn't match authenticated user
    """
    authenticated_user_id = get_authenticated_user_id(event)

    if allow_query_param:
        # Extract user_id from query params if present
        query_params = event.get('queryStringParameters') or {}
        requested_user_id = query_params.get('user_id')

        if requested_user_id and requested_user_id != authenticated_user_id:
            raise AuthorizationError(
                "Query parameter user_id must match authenticated user"
            )

    return authenticated_user_id
