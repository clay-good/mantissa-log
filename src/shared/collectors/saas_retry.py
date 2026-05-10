"""
Retry-with-backoff helpers for SaaS collectors.

Most SaaS APIs (Google Workspace Reports, Microsoft Graph, M365 Management
Activity) signal transient failure with HTTP 429/5xx and a ``Retry-After``
header (seconds, or HTTP-date). The collector needs to honour that and
otherwise fall back to exponential backoff with jitter.

Kept dependency-free so it works in any deployment target.
"""

from __future__ import annotations

import logging
import random
import time
from dataclasses import dataclass, field
from email.utils import parsedate_to_datetime
from datetime import datetime, timezone
from typing import Callable, Optional, TypeVar

logger = logging.getLogger(__name__)

T = TypeVar("T")


class TransientError(Exception):
    """Raise from inside a retried callable to signal a retryable failure.

    Optionally carries a ``retry_after`` (seconds) hint from the upstream API.
    Anything else (auth errors, 4xx that is not 429, programmer errors)
    should NOT be wrapped in TransientError so it surfaces immediately as a
    feed-level failure rather than being silently retried.
    """

    def __init__(self, message: str, retry_after: Optional[float] = None):
        super().__init__(message)
        self.retry_after = retry_after


@dataclass(frozen=True)
class RetryPolicy:
    max_attempts: int = 6
    base_delay_seconds: float = 1.0
    max_delay_seconds: float = 60.0
    jitter: float = 0.25  # +/- fraction of computed delay
    # Retry only on TransientError by default. Collectors classify upstream
    # HTTP errors and re-raise as TransientError when they are genuinely
    # retryable (429, 5xx, network blip). Anything else surfaces immediately
    # as a feed-level failure on the run result. Tests can broaden the tuple
    # to drive specific scenarios.
    retry_on: tuple[type[BaseException], ...] = (TransientError,)


def parse_retry_after(value: Optional[str]) -> Optional[float]:
    """Parse an HTTP ``Retry-After`` value into seconds. None on failure."""
    if not value:
        return None
    value = value.strip()
    try:
        return max(0.0, float(value))
    except ValueError:
        pass
    try:
        when = parsedate_to_datetime(value)
        if when.tzinfo is None:
            when = when.replace(tzinfo=timezone.utc)
        delta = (when - datetime.now(timezone.utc)).total_seconds()
        return max(0.0, delta)
    except (TypeError, ValueError):
        return None


def compute_delay(
    attempt: int,
    policy: RetryPolicy,
    server_hint: Optional[float] = None,
) -> float:
    """Compute next sleep duration. Server hint (Retry-After) wins if larger."""
    base = policy.base_delay_seconds * (2 ** (attempt - 1))
    jitter_span = base * policy.jitter
    delay = base + random.uniform(-jitter_span, jitter_span)
    delay = max(0.0, min(delay, policy.max_delay_seconds))
    if server_hint is not None:
        delay = max(delay, server_hint)
    return delay


def retry_call(
    fn: Callable[[], T],
    policy: RetryPolicy = RetryPolicy(),
    sleep: Callable[[float], None] = time.sleep,
) -> T:
    """Run ``fn`` with retry-with-backoff.

    Retries any exception in ``policy.retry_on``. ``TransientError.retry_after``
    is honoured as a server hint. Re-raises the last exception on exhaustion.
    Exceptions outside ``policy.retry_on`` propagate immediately.
    """
    last_exc: Optional[BaseException] = None
    for attempt in range(1, policy.max_attempts + 1):
        try:
            return fn()
        except policy.retry_on as exc:  # type: ignore[misc]
            last_exc = exc
            if attempt == policy.max_attempts:
                break
            hint = getattr(exc, "retry_after", None)
            delay = compute_delay(attempt, policy, hint if isinstance(hint, (int, float)) else None)
            logger.warning(
                "collector.retry attempt=%d/%d delay=%.2fs error=%s",
                attempt, policy.max_attempts, delay, exc,
            )
            sleep(delay)
    assert last_exc is not None
    raise last_exc
