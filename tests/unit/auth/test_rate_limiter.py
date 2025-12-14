"""Unit tests for rate limiting utilities.

Tests cover:
- Rate limit configuration
- In-memory rate limiting (for testing)
- Multi-tier rate limits (minute/hour/day)
- Rate limit exceeded responses
"""

import os
import time
from unittest.mock import patch, MagicMock

import pytest

from src.shared.auth.rate_limiter import (
    RateLimitExceeded,
    RateLimitConfig,
    RateLimiter,
    InMemoryRateLimitBackend,
    get_rate_limiter,
    rate_limit_response,
)


class TestRateLimitConfig:
    """Tests for RateLimitConfig dataclass."""

    def test_default_values(self):
        """Should have sensible default values."""
        config = RateLimitConfig()

        assert config.requests_per_minute == 60
        assert config.requests_per_hour == 1000
        assert config.requests_per_day == 10000
        assert config.burst_limit == 10

    def test_strict_config(self):
        """Should provide stricter limits for expensive operations."""
        config = RateLimitConfig.strict()

        assert config.requests_per_minute == 10
        assert config.requests_per_hour == 100
        assert config.requests_per_day == 1000
        assert config.burst_limit == 5

    def test_relaxed_config(self):
        """Should provide relaxed limits for lightweight operations."""
        config = RateLimitConfig.relaxed()

        assert config.requests_per_minute == 120
        assert config.requests_per_hour == 5000
        assert config.requests_per_day == 50000
        assert config.burst_limit == 20

    @patch.dict(os.environ, {
        'RATE_LIMIT_PER_MINUTE': '30',
        'RATE_LIMIT_PER_HOUR': '500',
        'RATE_LIMIT_PER_DAY': '5000',
        'RATE_LIMIT_BURST': '15'
    })
    def test_from_environment(self):
        """Should load config from environment variables."""
        config = RateLimitConfig.from_environment()

        assert config.requests_per_minute == 30
        assert config.requests_per_hour == 500
        assert config.requests_per_day == 5000
        assert config.burst_limit == 15


class TestRateLimitExceeded:
    """Tests for RateLimitExceeded exception."""

    def test_default_retry_after(self):
        """Should have default retry_after of 60 seconds."""
        exc = RateLimitExceeded()

        assert exc.retry_after == 60

    def test_custom_retry_after(self):
        """Should accept custom retry_after value."""
        exc = RateLimitExceeded(retry_after=120)

        assert exc.retry_after == 120

    def test_exception_message(self):
        """Should include retry_after in message."""
        exc = RateLimitExceeded(retry_after=30)

        assert '30 seconds' in str(exc)


class TestInMemoryRateLimitBackend:
    """Tests for InMemoryRateLimitBackend."""

    def test_allows_first_request(self):
        """Should allow first request."""
        backend = InMemoryRateLimitBackend()

        allowed, count, retry_after = backend.check_and_increment(
            key='user:test',
            window_seconds=60,
            max_requests=10
        )

        assert allowed is True
        assert count == 1
        assert retry_after == 0

    def test_tracks_request_count(self):
        """Should track request count accurately."""
        backend = InMemoryRateLimitBackend()

        for i in range(5):
            allowed, count, _ = backend.check_and_increment(
                key='user:count',
                window_seconds=60,
                max_requests=10
            )
            assert allowed is True
            assert count == i + 1

    def test_blocks_when_limit_exceeded(self):
        """Should block requests when limit is exceeded."""
        backend = InMemoryRateLimitBackend()

        # Use up all requests
        for _ in range(3):
            backend.check_and_increment(
                key='user:limit',
                window_seconds=60,
                max_requests=3
            )

        # Next request should be blocked
        allowed, count, retry_after = backend.check_and_increment(
            key='user:limit',
            window_seconds=60,
            max_requests=3
        )

        assert allowed is False
        assert count == 3
        assert retry_after > 0

    def test_get_remaining(self):
        """Should return remaining requests correctly."""
        backend = InMemoryRateLimitBackend()

        # Make 3 requests
        for _ in range(3):
            backend.check_and_increment(
                key='user:remaining',
                window_seconds=60,
                max_requests=10
            )

        remaining = backend.get_remaining(
            key='user:remaining',
            window_seconds=60,
            max_requests=10
        )

        assert remaining == 7

    def test_returns_max_for_unknown_key(self):
        """Should return max requests for unknown key."""
        backend = InMemoryRateLimitBackend()

        remaining = backend.get_remaining(
            key='user:unknown',
            window_seconds=60,
            max_requests=10
        )

        assert remaining == 10

    def test_separate_keys_have_separate_limits(self):
        """Should maintain separate limits per key."""
        backend = InMemoryRateLimitBackend()

        # User A makes requests
        for _ in range(5):
            backend.check_and_increment('user:A', 60, 10)

        # User B makes requests
        for _ in range(3):
            backend.check_and_increment('user:B', 60, 10)

        assert backend.get_remaining('user:A', 60, 10) == 5
        assert backend.get_remaining('user:B', 60, 10) == 7


class TestRateLimiter:
    """Tests for RateLimiter class."""

    def test_check_rate_limit_returns_info(self):
        """Should return rate limit info on success."""
        limiter = RateLimiter(
            backend=InMemoryRateLimitBackend(),
            config=RateLimitConfig(requests_per_minute=10)
        )

        result = limiter.check_rate_limit('user-123', 'test-endpoint')

        assert result['allowed'] is True
        assert 'remaining_minute' in result
        assert 'remaining_hour' in result
        assert 'remaining_day' in result

    def test_raises_exception_when_limit_exceeded(self):
        """Should raise RateLimitExceeded when limit is hit."""
        limiter = RateLimiter(
            backend=InMemoryRateLimitBackend(),
            config=RateLimitConfig(requests_per_minute=2)
        )

        # Use up the limit
        limiter.check_rate_limit('user-limited', 'endpoint')
        limiter.check_rate_limit('user-limited', 'endpoint')

        # Should raise on third request
        with pytest.raises(RateLimitExceeded) as exc_info:
            limiter.check_rate_limit('user-limited', 'endpoint')

        assert exc_info.value.retry_after > 0

    def test_different_endpoints_have_separate_limits(self):
        """Should maintain separate limits per endpoint."""
        limiter = RateLimiter(
            backend=InMemoryRateLimitBackend(),
            config=RateLimitConfig(requests_per_minute=2)
        )

        # Use up limit on endpoint A
        limiter.check_rate_limit('user-123', 'endpoint-A')
        limiter.check_rate_limit('user-123', 'endpoint-A')

        # Should still be allowed on endpoint B
        result = limiter.check_rate_limit('user-123', 'endpoint-B')
        assert result['allowed'] is True

    def test_different_users_have_separate_limits(self):
        """Should maintain separate limits per user."""
        limiter = RateLimiter(
            backend=InMemoryRateLimitBackend(),
            config=RateLimitConfig(requests_per_minute=2)
        )

        # Use up limit for user A
        limiter.check_rate_limit('user-A', 'endpoint')
        limiter.check_rate_limit('user-A', 'endpoint')

        # User B should still be allowed
        result = limiter.check_rate_limit('user-B', 'endpoint')
        assert result['allowed'] is True

    def test_get_headers_returns_rate_limit_headers(self):
        """Should return X-RateLimit-* headers."""
        limiter = RateLimiter(
            backend=InMemoryRateLimitBackend(),
            config=RateLimitConfig(requests_per_minute=60)
        )

        # Make some requests
        limiter.check_rate_limit('user-123', 'endpoint')
        limiter.check_rate_limit('user-123', 'endpoint')

        headers = limiter.get_headers('user-123', 'endpoint')

        assert 'X-RateLimit-Limit' in headers
        assert 'X-RateLimit-Remaining' in headers
        assert 'X-RateLimit-Reset' in headers
        assert headers['X-RateLimit-Limit'] == '60'


class TestGetRateLimiter:
    """Tests for get_rate_limiter factory function."""

    def test_returns_limiter_for_aws(self):
        """Should return a RateLimiter for AWS platform."""
        limiter = get_rate_limiter('aws')

        assert isinstance(limiter, RateLimiter)

    def test_returns_limiter_for_gcp(self):
        """Should return a RateLimiter for GCP platform."""
        limiter = get_rate_limiter('gcp')

        assert isinstance(limiter, RateLimiter)

    def test_returns_limiter_for_azure(self):
        """Should return a RateLimiter for Azure platform."""
        limiter = get_rate_limiter('azure')

        assert isinstance(limiter, RateLimiter)

    def test_returns_memory_backend_for_unknown(self):
        """Should return in-memory limiter for unknown platform."""
        limiter = get_rate_limiter('unknown')

        assert isinstance(limiter, RateLimiter)
        # Should fall back to memory backend
        assert isinstance(limiter.backend, InMemoryRateLimitBackend)

    def test_returns_memory_backend_for_memory(self):
        """Should return in-memory limiter when explicitly requested."""
        limiter = get_rate_limiter('memory')

        assert isinstance(limiter.backend, InMemoryRateLimitBackend)


class TestRateLimitResponse:
    """Tests for rate_limit_response helper function."""

    def test_returns_429_status(self):
        """Should return 429 Too Many Requests status."""
        response = rate_limit_response(retry_after=60)

        assert response['statusCode'] == 429

    def test_includes_retry_after_header(self):
        """Should include Retry-After header."""
        response = rate_limit_response(retry_after=120)

        assert response['headers']['Retry-After'] == '120'

    def test_includes_error_in_body(self):
        """Should include error message in body."""
        import json
        response = rate_limit_response(retry_after=60)

        body = json.loads(response['body'])
        assert body['error'] == 'Too Many Requests'
        assert body['retry_after'] == 60

    def test_merges_additional_headers(self):
        """Should merge additional headers."""
        additional_headers = {
            'Access-Control-Allow-Origin': 'https://example.com',
            'Content-Type': 'application/json'
        }

        response = rate_limit_response(retry_after=60, headers=additional_headers)

        assert response['headers']['Access-Control-Allow-Origin'] == 'https://example.com'
        assert response['headers']['Retry-After'] == '60'


class TestMultiTierRateLimiting:
    """Tests for multi-tier rate limiting (minute/hour/day)."""

    def test_minute_limit_enforced_first(self):
        """Should enforce minute limit before hour/day limits."""
        limiter = RateLimiter(
            backend=InMemoryRateLimitBackend(),
            config=RateLimitConfig(
                requests_per_minute=2,
                requests_per_hour=100,
                requests_per_day=1000
            )
        )

        limiter.check_rate_limit('user-123', 'endpoint')
        limiter.check_rate_limit('user-123', 'endpoint')

        with pytest.raises(RateLimitExceeded):
            limiter.check_rate_limit('user-123', 'endpoint')

    def test_all_tiers_must_pass(self):
        """Should require all tiers to be within limits."""
        backend = InMemoryRateLimitBackend()
        limiter = RateLimiter(
            backend=backend,
            config=RateLimitConfig(
                requests_per_minute=100,
                requests_per_hour=5,
                requests_per_day=1000
            )
        )

        # Use up hour limit
        for _ in range(5):
            limiter.check_rate_limit('user-123', 'endpoint')

        # Should fail even though minute limit not reached
        with pytest.raises(RateLimitExceeded):
            limiter.check_rate_limit('user-123', 'endpoint')


class TestSecurityScenarios:
    """Security-focused test scenarios for rate limiting."""

    def test_prevents_brute_force_attack(self):
        """Should effectively rate limit potential brute force attempts."""
        limiter = RateLimiter(
            backend=InMemoryRateLimitBackend(),
            config=RateLimitConfig.strict()  # 10/min for auth endpoints
        )

        blocked_count = 0
        for i in range(50):  # Simulate 50 rapid requests
            try:
                limiter.check_rate_limit('attacker', 'login')
            except RateLimitExceeded:
                blocked_count += 1

        # Should have blocked majority of requests
        assert blocked_count >= 40

    def test_user_isolation(self):
        """Should ensure one user's rate limiting doesn't affect others."""
        limiter = RateLimiter(
            backend=InMemoryRateLimitBackend(),
            config=RateLimitConfig(requests_per_minute=3)
        )

        # Attacker exhausts their limit
        for _ in range(3):
            limiter.check_rate_limit('attacker', 'api')

        # Legitimate user should not be affected
        result = limiter.check_rate_limit('legitimate-user', 'api')
        assert result['allowed'] is True

    def test_endpoint_isolation(self):
        """Should ensure rate limits are per-endpoint."""
        limiter = RateLimiter(
            backend=InMemoryRateLimitBackend(),
            config=RateLimitConfig(requests_per_minute=2)
        )

        # User exhausts limit on expensive endpoint
        for _ in range(2):
            limiter.check_rate_limit('user', 'llm-query')

        # Should still be able to use other endpoints
        result = limiter.check_rate_limit('user', 'get-settings')
        assert result['allowed'] is True
