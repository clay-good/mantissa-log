"""Unit tests for CORS utilities.

Tests cover:
- Origin whitelist configuration
- CORS header generation
- Preflight request handling
- Security scenarios (origin validation)
"""

import os
from unittest.mock import patch

import pytest

from src.shared.auth.cors import (
    get_allowed_origins,
    get_cors_origin,
    get_cors_headers,
    cors_preflight_response,
    add_cors_headers,
)


class TestGetAllowedOrigins:
    """Tests for get_allowed_origins function."""

    @patch.dict(os.environ, {}, clear=True)
    def test_returns_empty_list_by_default(self):
        """Should return empty list when no origins configured."""
        origins = get_allowed_origins()
        assert origins == []

    @patch.dict(os.environ, {'CORS_ALLOWED_ORIGINS': 'https://app.example.com,https://admin.example.com'})
    def test_parses_comma_separated_origins(self):
        """Should parse comma-separated CORS_ALLOWED_ORIGINS."""
        origins = get_allowed_origins()

        assert len(origins) == 2
        assert 'https://app.example.com' in origins
        assert 'https://admin.example.com' in origins

    @patch.dict(os.environ, {'CORS_ALLOWED_ORIGINS': ' https://app.example.com , https://admin.example.com '})
    def test_strips_whitespace_from_origins(self):
        """Should strip whitespace from origin values."""
        origins = get_allowed_origins()

        assert 'https://app.example.com' in origins
        assert 'https://admin.example.com' in origins

    @patch.dict(os.environ, {'CORS_ALLOWED_ORIGIN': 'https://single.example.com'}, clear=True)
    def test_falls_back_to_single_origin(self):
        """Should use CORS_ALLOWED_ORIGIN as fallback."""
        origins = get_allowed_origins()

        assert origins == ['https://single.example.com']

    @patch.dict(os.environ, {'CORS_ALLOW_ALL': 'true'}, clear=True)
    def test_allows_all_when_explicitly_enabled(self):
        """Should return ['*'] when CORS_ALLOW_ALL is true."""
        origins = get_allowed_origins()

        assert origins == ['*']

    @patch.dict(os.environ, {'CORS_ALLOW_ALL': 'false'}, clear=True)
    def test_does_not_allow_all_when_disabled(self):
        """Should not return '*' when CORS_ALLOW_ALL is false."""
        origins = get_allowed_origins()

        assert origins == []

    @patch.dict(os.environ, {
        'CORS_ALLOWED_ORIGINS': 'https://preferred.com',
        'CORS_ALLOWED_ORIGIN': 'https://fallback.com'
    })
    def test_prefers_cors_allowed_origins_over_single(self):
        """Should prefer CORS_ALLOWED_ORIGINS over CORS_ALLOWED_ORIGIN."""
        origins = get_allowed_origins()

        assert origins == ['https://preferred.com']


class TestGetCorsOrigin:
    """Tests for get_cors_origin function."""

    @patch.dict(os.environ, {'CORS_ALLOWED_ORIGINS': 'https://app.example.com,https://admin.example.com'})
    def test_returns_matching_origin(self):
        """Should return request origin if it's in allowed list."""
        origin = get_cors_origin('https://app.example.com')

        assert origin == 'https://app.example.com'

    @patch.dict(os.environ, {'CORS_ALLOWED_ORIGINS': 'https://app.example.com'})
    def test_rejects_non_matching_origin(self):
        """Should not return origin that's not in allowed list."""
        origin = get_cors_origin('https://evil.attacker.com')

        # Should return the default allowed origin, not the attacker's
        assert origin == 'https://app.example.com'

    @patch.dict(os.environ, {'CORS_ALLOW_ALL': 'true'}, clear=True)
    def test_returns_wildcard_when_all_allowed(self):
        """Should return '*' when CORS_ALLOW_ALL is enabled."""
        origin = get_cors_origin('https://any.origin.com')

        assert origin == '*'

    @patch.dict(os.environ, {}, clear=True)
    def test_returns_empty_when_no_origins_configured(self):
        """Should return empty string when no origins are configured."""
        origin = get_cors_origin('https://any.origin.com')

        assert origin == ''

    @patch.dict(os.environ, {'CORS_ALLOWED_ORIGINS': 'https://app.example.com'})
    def test_handles_none_request_origin(self):
        """Should handle None request origin gracefully."""
        origin = get_cors_origin(None)

        # Should return first allowed origin
        assert origin == 'https://app.example.com'


class TestGetCorsHeaders:
    """Tests for get_cors_headers function."""

    @patch.dict(os.environ, {'CORS_ALLOWED_ORIGINS': 'https://app.example.com'})
    def test_returns_cors_headers_for_valid_origin(self):
        """Should return CORS headers when origin is valid."""
        event = {
            'headers': {
                'Origin': 'https://app.example.com'
            }
        }

        headers = get_cors_headers(event)

        assert headers['Access-Control-Allow-Origin'] == 'https://app.example.com'
        assert 'GET' in headers['Access-Control-Allow-Methods']
        assert 'POST' in headers['Access-Control-Allow-Methods']
        assert 'Authorization' in headers['Access-Control-Allow-Headers']
        assert headers['Vary'] == 'Origin'

    @patch.dict(os.environ, {}, clear=True)
    def test_returns_empty_dict_when_origin_not_allowed(self):
        """Should return empty dict when origin is not allowed."""
        event = {
            'headers': {
                'Origin': 'https://evil.com'
            }
        }

        headers = get_cors_headers(event)

        assert headers == {}

    @patch.dict(os.environ, {'CORS_ALLOWED_ORIGINS': 'https://app.example.com'})
    def test_handles_lowercase_origin_header(self):
        """Should handle lowercase 'origin' header."""
        event = {
            'headers': {
                'origin': 'https://app.example.com'
            }
        }

        headers = get_cors_headers(event)

        assert headers['Access-Control-Allow-Origin'] == 'https://app.example.com'

    @patch.dict(os.environ, {'CORS_ALLOWED_ORIGINS': 'https://app.example.com'})
    def test_handles_none_headers(self):
        """Should handle None headers in event."""
        event = {
            'headers': None
        }

        headers = get_cors_headers(event)

        # Should still return headers using first allowed origin
        assert 'Access-Control-Allow-Origin' in headers

    @patch.dict(os.environ, {'CORS_ALLOWED_ORIGINS': 'https://app.example.com'})
    def test_handles_none_event(self):
        """Should handle None event gracefully."""
        headers = get_cors_headers(None)

        # Should return headers using first allowed origin
        assert 'Access-Control-Allow-Origin' in headers

    @patch.dict(os.environ, {'CORS_ALLOWED_ORIGINS': 'https://app.example.com'})
    def test_credentials_not_set_by_default(self):
        """Should not include credentials header by default."""
        event = {'headers': {'Origin': 'https://app.example.com'}}

        headers = get_cors_headers(event)

        assert 'Access-Control-Allow-Credentials' not in headers

    @patch.dict(os.environ, {'CORS_ALLOWED_ORIGINS': 'https://app.example.com'})
    def test_credentials_set_when_requested(self):
        """Should include credentials header when allow_credentials=True."""
        event = {'headers': {'Origin': 'https://app.example.com'}}

        headers = get_cors_headers(event, allow_credentials=True)

        assert headers['Access-Control-Allow-Credentials'] == 'true'

    @patch.dict(os.environ, {'CORS_ALLOW_ALL': 'true'}, clear=True)
    def test_credentials_not_set_with_wildcard(self):
        """Should not include credentials when origin is '*'."""
        event = {'headers': {'Origin': 'https://app.example.com'}}

        headers = get_cors_headers(event, allow_credentials=True)

        # Credentials cannot be used with wildcard origin
        assert 'Access-Control-Allow-Credentials' not in headers


class TestCorsPreflightResponse:
    """Tests for cors_preflight_response function."""

    @patch.dict(os.environ, {'CORS_ALLOWED_ORIGINS': 'https://app.example.com'})
    def test_returns_200_for_valid_preflight(self):
        """Should return 200 for valid preflight request."""
        event = {'headers': {'Origin': 'https://app.example.com'}}

        response = cors_preflight_response(event)

        assert response['statusCode'] == 200
        assert 'Access-Control-Allow-Origin' in response['headers']
        assert response['headers']['Access-Control-Max-Age'] == '86400'

    @patch.dict(os.environ, {}, clear=True)
    def test_returns_403_for_invalid_origin(self):
        """Should return 403 when CORS not allowed."""
        event = {'headers': {'Origin': 'https://evil.com'}}

        response = cors_preflight_response(event)

        assert response['statusCode'] == 403
        assert response['body'] == 'CORS not allowed'

    @patch.dict(os.environ, {'CORS_ALLOWED_ORIGINS': 'https://app.example.com'})
    def test_includes_max_age_header(self):
        """Should include Access-Control-Max-Age for caching."""
        event = {'headers': {'Origin': 'https://app.example.com'}}

        response = cors_preflight_response(event)

        assert response['headers']['Access-Control-Max-Age'] == '86400'


class TestAddCorsHeaders:
    """Tests for add_cors_headers function."""

    @patch.dict(os.environ, {'CORS_ALLOWED_ORIGINS': 'https://app.example.com'})
    def test_adds_cors_headers_to_response(self):
        """Should add CORS headers to existing response."""
        response = {
            'statusCode': 200,
            'headers': {'Content-Type': 'application/json'},
            'body': '{}'
        }
        event = {'headers': {'Origin': 'https://app.example.com'}}

        updated_response = add_cors_headers(response, event)

        assert updated_response['headers']['Content-Type'] == 'application/json'
        assert updated_response['headers']['Access-Control-Allow-Origin'] == 'https://app.example.com'

    @patch.dict(os.environ, {'CORS_ALLOWED_ORIGINS': 'https://app.example.com'})
    def test_handles_response_without_headers(self):
        """Should handle response without existing headers."""
        response = {
            'statusCode': 200,
            'body': '{}'
        }
        event = {'headers': {'Origin': 'https://app.example.com'}}

        updated_response = add_cors_headers(response, event)

        assert 'Access-Control-Allow-Origin' in updated_response['headers']

    @patch.dict(os.environ, {}, clear=True)
    def test_does_not_add_headers_when_not_allowed(self):
        """Should not add headers when CORS not allowed."""
        response = {
            'statusCode': 200,
            'headers': {'Content-Type': 'application/json'},
            'body': '{}'
        }
        event = {'headers': {'Origin': 'https://evil.com'}}

        updated_response = add_cors_headers(response, event)

        # Should only have original headers
        assert 'Access-Control-Allow-Origin' not in updated_response['headers']


class TestSecurityScenarios:
    """Security-focused test scenarios for CORS."""

    @patch.dict(os.environ, {'CORS_ALLOWED_ORIGINS': 'https://app.example.com'})
    def test_rejects_origin_with_path(self):
        """Should not match origins with paths appended."""
        event = {
            'headers': {
                'Origin': 'https://app.example.com/malicious'
            }
        }

        headers = get_cors_headers(event)

        # The exact origin 'https://app.example.com/malicious' is not in the list
        # It should fall back to the first allowed origin
        assert headers.get('Access-Control-Allow-Origin') == 'https://app.example.com'

    @patch.dict(os.environ, {'CORS_ALLOWED_ORIGINS': 'https://app.example.com'})
    def test_rejects_subdomain_of_allowed_origin(self):
        """Should not automatically allow subdomains."""
        event = {
            'headers': {
                'Origin': 'https://evil.app.example.com'
            }
        }

        headers = get_cors_headers(event)

        # Should not return the attacker's subdomain
        if 'Access-Control-Allow-Origin' in headers:
            assert headers['Access-Control-Allow-Origin'] != 'https://evil.app.example.com'

    @patch.dict(os.environ, {'CORS_ALLOWED_ORIGINS': 'https://example.com'})
    def test_rejects_similar_domain(self):
        """Should not match similar but different domains."""
        event = {
            'headers': {
                'Origin': 'https://exampleecom.attacker.com'
            }
        }

        headers = get_cors_headers(event)

        if 'Access-Control-Allow-Origin' in headers:
            assert headers['Access-Control-Allow-Origin'] != 'https://exampleecom.attacker.com'

    @patch.dict(os.environ, {'CORS_ALLOWED_ORIGINS': 'https://app.example.com'})
    def test_case_sensitive_origin_matching(self):
        """Should use case-sensitive origin matching."""
        event = {
            'headers': {
                'Origin': 'https://APP.EXAMPLE.COM'
            }
        }

        headers = get_cors_headers(event)

        # Origins are case-sensitive per spec
        if 'Access-Control-Allow-Origin' in headers:
            assert headers['Access-Control-Allow-Origin'] == 'https://app.example.com'

    @patch.dict(os.environ, {'CORS_ALLOWED_ORIGINS': 'https://app.example.com'})
    def test_null_origin_rejected(self):
        """Should not allow 'null' origin."""
        event = {
            'headers': {
                'Origin': 'null'
            }
        }

        headers = get_cors_headers(event)

        if 'Access-Control-Allow-Origin' in headers:
            assert headers['Access-Control-Allow-Origin'] != 'null'
