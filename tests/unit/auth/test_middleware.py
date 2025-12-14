"""Unit tests for authentication middleware.

Tests cover:
- JWT token extraction from Cognito claims
- Development mode fallback
- Authorization verification for resource access
- Decorator functionality
"""

import json
import os
from unittest.mock import patch, MagicMock

import pytest

from src.shared.auth.middleware import (
    AuthenticationError,
    AuthorizationError,
    get_authenticated_user_id,
    validate_user_access,
    require_authentication,
    get_safe_user_id_from_request,
)


class TestGetAuthenticatedUserId:
    """Tests for get_authenticated_user_id function."""

    def test_extracts_user_from_cognito_sub_claim(self):
        """Should extract user ID from Cognito 'sub' claim."""
        event = {
            'requestContext': {
                'authorizer': {
                    'claims': {
                        'sub': 'user-abc-123',
                        'cognito:username': 'testuser@example.com'
                    }
                }
            }
        }

        user_id = get_authenticated_user_id(event)

        assert user_id == 'user-abc-123'

    def test_falls_back_to_cognito_username(self):
        """Should fall back to cognito:username if sub is not present."""
        event = {
            'requestContext': {
                'authorizer': {
                    'claims': {
                        'cognito:username': 'testuser@example.com'
                    }
                }
            }
        }

        user_id = get_authenticated_user_id(event)

        assert user_id == 'testuser@example.com'

    def test_extracts_from_jwt_authorizer_format(self):
        """Should extract user ID from JWT authorizer format (HTTP APIs)."""
        event = {
            'requestContext': {
                'authorizer': {
                    'jwt': {
                        'claims': {
                            'sub': 'jwt-user-456'
                        }
                    }
                }
            }
        }

        user_id = get_authenticated_user_id(event)

        assert user_id == 'jwt-user-456'

    def test_raises_error_when_no_claims(self):
        """Should raise AuthenticationError when no claims present."""
        event = {
            'requestContext': {
                'authorizer': {}
            }
        }

        with pytest.raises(AuthenticationError) as exc_info:
            get_authenticated_user_id(event)

        assert 'Authentication required' in str(exc_info.value)

    def test_raises_error_when_no_authorizer(self):
        """Should raise AuthenticationError when no authorizer context."""
        event = {
            'requestContext': {}
        }

        with pytest.raises(AuthenticationError):
            get_authenticated_user_id(event)

    def test_raises_error_when_empty_event(self):
        """Should raise AuthenticationError for empty event."""
        event = {}

        with pytest.raises(AuthenticationError):
            get_authenticated_user_id(event)

    @patch.dict(os.environ, {'MANTISSA_DEV_MODE': 'true'})
    def test_dev_mode_returns_test_user(self):
        """Should return dev-test-user when MANTISSA_DEV_MODE is true."""
        event = {
            'requestContext': {
                'authorizer': {}
            }
        }

        user_id = get_authenticated_user_id(event)

        assert user_id == 'dev-test-user'

    @patch.dict(os.environ, {'MANTISSA_DEV_MODE': 'false'})
    def test_dev_mode_disabled_raises_error(self):
        """Should raise error when dev mode is explicitly disabled."""
        event = {
            'requestContext': {
                'authorizer': {}
            }
        }

        with pytest.raises(AuthenticationError):
            get_authenticated_user_id(event)


class TestValidateUserAccess:
    """Tests for validate_user_access function."""

    def test_returns_authenticated_user_when_no_requested_id(self):
        """Should return authenticated user ID when no specific ID requested."""
        event = {
            'requestContext': {
                'authorizer': {
                    'claims': {'sub': 'user-123'}
                }
            }
        }

        user_id = validate_user_access(event)

        assert user_id == 'user-123'

    def test_allows_access_when_ids_match(self):
        """Should allow access when requested ID matches authenticated user."""
        event = {
            'requestContext': {
                'authorizer': {
                    'claims': {'sub': 'user-123'}
                }
            }
        }

        user_id = validate_user_access(event, requested_user_id='user-123')

        assert user_id == 'user-123'

    def test_raises_authorization_error_when_ids_mismatch(self):
        """Should raise AuthorizationError when trying to access another user's resources."""
        event = {
            'requestContext': {
                'authorizer': {
                    'claims': {'sub': 'user-123'}
                }
            }
        }

        with pytest.raises(AuthorizationError) as exc_info:
            validate_user_access(event, requested_user_id='user-456')

        assert 'cannot access other user' in str(exc_info.value)

    def test_raises_authentication_error_for_unauthenticated(self):
        """Should raise AuthenticationError if not authenticated."""
        event = {}

        with pytest.raises(AuthenticationError):
            validate_user_access(event, requested_user_id='user-123')


class TestRequireAuthenticationDecorator:
    """Tests for require_authentication decorator."""

    def test_passes_user_id_to_handler(self):
        """Should add authenticated_user_id to event and call handler."""
        @require_authentication
        def handler(event, context):
            return {
                'statusCode': 200,
                'body': json.dumps({'user_id': event['authenticated_user_id']})
            }

        event = {
            'requestContext': {
                'authorizer': {
                    'claims': {'sub': 'decorator-user'}
                }
            }
        }

        response = handler(event, {})

        assert response['statusCode'] == 200
        body = json.loads(response['body'])
        assert body['user_id'] == 'decorator-user'

    def test_returns_401_for_unauthenticated(self):
        """Should return 401 when authentication fails."""
        @require_authentication
        def handler(event, context):
            return {'statusCode': 200}

        event = {}

        response = handler(event, {})

        assert response['statusCode'] == 401
        body = json.loads(response['body'])
        assert body['error'] == 'Unauthorized'

    def test_returns_403_for_authorization_failure(self):
        """Should return 403 when authorization fails."""
        @require_authentication
        def handler(event, context):
            # This would need to raise AuthorizationError internally
            from src.shared.auth.middleware import AuthorizationError
            raise AuthorizationError("Access denied")

        event = {
            'requestContext': {
                'authorizer': {
                    'claims': {'sub': 'user-123'}
                }
            }
        }

        response = handler(event, {})

        assert response['statusCode'] == 403
        body = json.loads(response['body'])
        assert body['error'] == 'Forbidden'


class TestGetSafeUserIdFromRequest:
    """Tests for get_safe_user_id_from_request function."""

    def test_returns_authenticated_user_id_without_query_param(self):
        """Should return authenticated user ID when query params not allowed."""
        event = {
            'requestContext': {
                'authorizer': {
                    'claims': {'sub': 'safe-user-123'}
                }
            }
        }

        user_id = get_safe_user_id_from_request(event, allow_query_param=False)

        assert user_id == 'safe-user-123'

    def test_allows_matching_query_param(self):
        """Should allow query param user_id when it matches authenticated user."""
        event = {
            'requestContext': {
                'authorizer': {
                    'claims': {'sub': 'safe-user-123'}
                }
            },
            'queryStringParameters': {
                'user_id': 'safe-user-123'
            }
        }

        user_id = get_safe_user_id_from_request(event, allow_query_param=True)

        assert user_id == 'safe-user-123'

    def test_rejects_mismatched_query_param(self):
        """Should reject query param user_id that doesn't match authenticated user."""
        event = {
            'requestContext': {
                'authorizer': {
                    'claims': {'sub': 'safe-user-123'}
                }
            },
            'queryStringParameters': {
                'user_id': 'attacker-user-456'
            }
        }

        with pytest.raises(AuthorizationError) as exc_info:
            get_safe_user_id_from_request(event, allow_query_param=True)

        assert 'must match authenticated user' in str(exc_info.value)

    def test_ignores_query_param_when_not_allowed(self):
        """Should ignore query param when allow_query_param is False."""
        event = {
            'requestContext': {
                'authorizer': {
                    'claims': {'sub': 'safe-user-123'}
                }
            },
            'queryStringParameters': {
                'user_id': 'different-user'
            }
        }

        # Should not raise, just return authenticated user
        user_id = get_safe_user_id_from_request(event, allow_query_param=False)

        assert user_id == 'safe-user-123'

    def test_handles_none_query_params(self):
        """Should handle None queryStringParameters gracefully."""
        event = {
            'requestContext': {
                'authorizer': {
                    'claims': {'sub': 'safe-user-123'}
                }
            },
            'queryStringParameters': None
        }

        user_id = get_safe_user_id_from_request(event, allow_query_param=True)

        assert user_id == 'safe-user-123'


class TestSecurityScenarios:
    """Security-focused test scenarios."""

    def test_prevents_horizontal_privilege_escalation(self):
        """Should prevent user from accessing another user's resources via request body."""
        event = {
            'requestContext': {
                'authorizer': {
                    'claims': {'sub': 'honest-user'}
                }
            },
            'body': json.dumps({'user_id': 'victim-user'})
        }

        # The middleware should extract from claims, not body
        user_id = get_authenticated_user_id(event)
        assert user_id == 'honest-user'

        # And validation should fail if attacker tries to specify victim's ID
        with pytest.raises(AuthorizationError):
            validate_user_access(event, requested_user_id='victim-user')

    def test_prevents_spoofed_claims_in_body(self):
        """Should not accept claims from request body."""
        # Attacker tries to inject fake claims in body
        event = {
            'requestContext': {
                'authorizer': {}
            },
            'body': json.dumps({
                'claims': {'sub': 'fake-admin-user'}
            })
        }

        # Should fail because actual authorizer has no claims
        with pytest.raises(AuthenticationError):
            get_authenticated_user_id(event)

    def test_empty_string_user_id_rejected(self):
        """Should reject empty string as user ID."""
        event = {
            'requestContext': {
                'authorizer': {
                    'claims': {'sub': ''}
                }
            }
        }

        with pytest.raises(AuthenticationError):
            get_authenticated_user_id(event)
