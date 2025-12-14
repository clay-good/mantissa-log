"""
Retry Handler with Exponential Backoff

Implements robust retry logic for integration requests with exponential backoff,
jitter, and circuit breaker pattern to prevent overwhelming failing services.
"""

import time
import random
from typing import Callable, Any, Optional, TypeVar, Dict
from dataclasses import dataclass
from enum import Enum
from datetime import datetime, timedelta
import functools
import logging

logger = logging.getLogger(__name__)


T = TypeVar('T')


class RetryableError(Exception):
    """Error that should trigger a retry."""
    pass


class NonRetryableError(Exception):
    """Error that should NOT trigger a retry."""
    pass


class CircuitState(Enum):
    """Circuit breaker states."""
    CLOSED = "closed"  # Normal operation
    OPEN = "open"  # Too many failures, reject requests
    HALF_OPEN = "half_open"  # Testing if service recovered


@dataclass
class RetryConfig:
    """Configuration for retry behavior."""
    max_attempts: int = 3
    initial_delay_ms: float = 1000
    max_delay_ms: float = 30000
    exponential_base: float = 2.0
    jitter: bool = True
    retryable_exceptions: tuple = (RetryableError, ConnectionError, TimeoutError)
    non_retryable_exceptions: tuple = (NonRetryableError, ValueError, TypeError)


@dataclass
class CircuitBreakerConfig:
    """Configuration for circuit breaker."""
    failure_threshold: int = 5  # Failures before opening circuit
    success_threshold: int = 2  # Successes needed to close circuit
    timeout_seconds: int = 60  # Time to wait before trying half-open


class CircuitBreaker:
    """
    Circuit breaker to prevent cascading failures.

    Tracks failures and automatically stops sending requests to failing services,
    giving them time to recover.
    """

    def __init__(self, config: Optional[CircuitBreakerConfig] = None):
        """Initialize circuit breaker."""
        self.config = config or CircuitBreakerConfig()
        self.state = CircuitState.CLOSED
        self.failure_count = 0
        self.success_count = 0
        self.last_failure_time: Optional[datetime] = None
        self.last_state_change: datetime = datetime.utcnow()

    def call(self, func: Callable[[], T]) -> T:
        """
        Execute function through circuit breaker.

        Args:
            func: Function to execute

        Returns:
            Result from function

        Raises:
            Exception if circuit is open or function fails
        """
        # Check if circuit should transition
        self._check_state_transition()

        # Reject if circuit is open
        if self.state == CircuitState.OPEN:
            raise CircuitBreakerOpenError(
                f"Circuit breaker is OPEN. Last failure: {self.last_failure_time}"
            )

        try:
            result = func()
            self._record_success()
            return result
        except Exception as e:
            self._record_failure()
            raise

    def _check_state_transition(self):
        """Check if circuit state should transition."""
        if self.state == CircuitState.OPEN:
            # Check if timeout has elapsed to try half-open
            if self.last_failure_time:
                time_since_failure = (
                    datetime.utcnow() - self.last_failure_time
                ).total_seconds()

                if time_since_failure >= self.config.timeout_seconds:
                    self.state = CircuitState.HALF_OPEN
                    self.success_count = 0
                    self.last_state_change = datetime.utcnow()

    def _record_success(self):
        """Record successful request."""
        if self.state == CircuitState.HALF_OPEN:
            self.success_count += 1

            # Close circuit if enough successes
            if self.success_count >= self.config.success_threshold:
                self.state = CircuitState.CLOSED
                self.failure_count = 0
                self.success_count = 0
                self.last_state_change = datetime.utcnow()
        elif self.state == CircuitState.CLOSED:
            # Reset failure count on success
            self.failure_count = 0

    def _record_failure(self):
        """Record failed request."""
        self.failure_count += 1
        self.last_failure_time = datetime.utcnow()

        # Open circuit if too many failures
        if self.failure_count >= self.config.failure_threshold:
            if self.state != CircuitState.OPEN:
                self.state = CircuitState.OPEN
                self.last_state_change = datetime.utcnow()

    def get_state(self) -> Dict[str, Any]:
        """Get current circuit breaker state."""
        return {
            'state': self.state.value,
            'failure_count': self.failure_count,
            'success_count': self.success_count,
            'last_failure_time': self.last_failure_time.isoformat() if self.last_failure_time else None,
            'last_state_change': self.last_state_change.isoformat()
        }

    def reset(self):
        """Reset circuit breaker to initial state."""
        self.state = CircuitState.CLOSED
        self.failure_count = 0
        self.success_count = 0
        self.last_failure_time = None
        self.last_state_change = datetime.utcnow()


class CircuitBreakerOpenError(Exception):
    """Raised when circuit breaker is open."""
    pass


class RetryHandler:
    """
    Handles retry logic with exponential backoff and jitter.
    """

    def __init__(
        self,
        config: Optional[RetryConfig] = None,
        circuit_breaker: Optional[CircuitBreaker] = None
    ):
        """
        Initialize retry handler.

        Args:
            config: Retry configuration
            circuit_breaker: Optional circuit breaker instance
        """
        self.config = config or RetryConfig()
        self.circuit_breaker = circuit_breaker

    def execute(
        self,
        func: Callable[[], T],
        operation_name: str = "operation"
    ) -> T:
        """
        Execute function with retry logic.

        Args:
            func: Function to execute
            operation_name: Name of operation for logging

        Returns:
            Result from function

        Raises:
            Last exception if all retries exhausted
        """
        last_exception = None

        for attempt in range(1, self.config.max_attempts + 1):
            try:
                # Use circuit breaker if configured
                if self.circuit_breaker:
                    return self.circuit_breaker.call(func)
                else:
                    return func()

            except CircuitBreakerOpenError:
                # Don't retry if circuit is open
                raise

            except self.config.non_retryable_exceptions as e:
                # Don't retry non-retryable errors
                logger.error(f"{operation_name} failed with non-retryable error: {e}")
                raise

            except Exception as e:
                last_exception = e

                # Check if this exception is retryable
                if not isinstance(e, self.config.retryable_exceptions):
                    # Not a known retryable exception, check if it looks retryable
                    if not self._is_retryable_error(e):
                        logger.error(f"{operation_name} failed with non-retryable error: {e}")
                        raise

                # Last attempt failed
                if attempt == self.config.max_attempts:
                    logger.error(f"{operation_name} failed after {attempt} attempts")
                    break

                # Calculate delay with exponential backoff
                delay_ms = self._calculate_delay(attempt)

                logger.warning(
                    f"{operation_name} attempt {attempt}/{self.config.max_attempts} "
                    f"failed: {e}. Retrying in {delay_ms}ms..."
                )

                # Wait before retry
                time.sleep(delay_ms / 1000.0)

        # All retries exhausted
        if last_exception:
            raise last_exception
        else:
            raise RuntimeError(f"{operation_name} failed with unknown error")

    def _calculate_delay(self, attempt: int) -> float:
        """
        Calculate delay for retry with exponential backoff and jitter.

        Args:
            attempt: Current attempt number (1-indexed)

        Returns:
            Delay in milliseconds
        """
        # Exponential backoff: initial_delay * (base ^ (attempt - 1))
        delay = self.config.initial_delay_ms * (
            self.config.exponential_base ** (attempt - 1)
        )

        # Cap at max delay
        delay = min(delay, self.config.max_delay_ms)

        # Add jitter to prevent thundering herd
        if self.config.jitter:
            # Random jitter between 0% and 25% of delay
            jitter_amount = delay * random.uniform(0, 0.25)
            delay += jitter_amount

        return delay

    def _is_retryable_error(self, error: Exception) -> bool:
        """
        Determine if an error is retryable based on its characteristics.

        Args:
            error: Exception to check

        Returns:
            True if error should be retried
        """
        error_str = str(error).lower()

        # Common retryable error patterns
        retryable_patterns = [
            'timeout',
            'connection',
            'network',
            'temporary',
            'unavailable',
            'service error',
            '503',
            '502',
            '504',
            'rate limit',
            'throttle'
        ]

        return any(pattern in error_str for pattern in retryable_patterns)


def with_retry(
    config: Optional[RetryConfig] = None,
    circuit_breaker: Optional[CircuitBreaker] = None,
    operation_name: Optional[str] = None
):
    """
    Decorator to add retry logic to a function.

    Args:
        config: Retry configuration
        circuit_breaker: Optional circuit breaker
        operation_name: Name of operation for logging

    Example:
        @with_retry(config=RetryConfig(max_attempts=5))
        def send_to_slack(payload):
            # ... send logic ...
            pass
    """
    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            handler = RetryHandler(config, circuit_breaker)
            op_name = operation_name or func.__name__

            def execute():
                return func(*args, **kwargs)

            return handler.execute(execute, op_name)

        return wrapper
    return decorator


# Global circuit breakers per integration type
_circuit_breakers: Dict[str, CircuitBreaker] = {}


def get_circuit_breaker(integration_type: str) -> CircuitBreaker:
    """
    Get or create circuit breaker for an integration type.

    Args:
        integration_type: Type of integration (slack, jira, etc.)

    Returns:
        Circuit breaker instance
    """
    if integration_type not in _circuit_breakers:
        _circuit_breakers[integration_type] = CircuitBreaker()

    return _circuit_breakers[integration_type]


def reset_circuit_breaker(integration_type: str):
    """
    Reset circuit breaker for an integration type.

    Args:
        integration_type: Type of integration
    """
    if integration_type in _circuit_breakers:
        _circuit_breakers[integration_type].reset()


def get_all_circuit_states() -> Dict[str, Dict[str, Any]]:
    """
    Get states of all circuit breakers.

    Returns:
        Dictionary mapping integration type to circuit state
    """
    return {
        integration_type: breaker.get_state()
        for integration_type, breaker in _circuit_breakers.items()
    }
