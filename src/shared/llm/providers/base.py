"""Base LLM provider interface."""

import time
from abc import ABC, abstractmethod
from typing import Optional


class LLMProvider(ABC):
    """Abstract base class for LLM providers."""

    @abstractmethod
    def generate(self, prompt: str, max_tokens: int = 500) -> str:
        """Generate completion from prompt.

        Args:
            prompt: Input prompt
            max_tokens: Maximum tokens to generate

        Returns:
            Generated text
        """
        pass

    def generate_with_retry(
        self, prompt: str, max_tokens: int = 500, max_retries: int = 3
    ) -> str:
        """Generate completion with retry logic.

        Args:
            prompt: Input prompt
            max_tokens: Maximum tokens to generate
            max_retries: Maximum retry attempts

        Returns:
            Generated text

        Raises:
            Exception: If all retries fail
        """
        last_error = None

        for attempt in range(max_retries):
            try:
                return self.generate(prompt, max_tokens)
            except Exception as e:
                last_error = e
                if attempt < max_retries - 1:
                    backoff = 2 ** attempt
                    time.sleep(backoff)
                continue

        raise last_error


class LLMError(Exception):
    """Base exception for LLM provider errors."""

    pass


class LLMRateLimitError(LLMError):
    """Raised when rate limit is exceeded."""

    pass


class LLMAuthenticationError(LLMError):
    """Raised when authentication fails."""

    pass


class LLMServiceError(LLMError):
    """Raised when LLM service has an error."""

    pass
