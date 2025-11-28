"""Anthropic API LLM provider."""

import os
from typing import Optional

from anthropic import Anthropic, APIError, RateLimitError

from .base import (
    LLMAuthenticationError,
    LLMError,
    LLMProvider,
    LLMRateLimitError,
    LLMServiceError,
)


class AnthropicProvider(LLMProvider):
    """Anthropic Claude API provider."""

    def __init__(
        self,
        api_key: Optional[str] = None,
        model: Optional[str] = None,
        **kwargs,
    ):
        """Initialize Anthropic provider.

        Args:
            api_key: Anthropic API key (defaults to ANTHROPIC_API_KEY env var)
            model: Model name (defaults to claude-sonnet-4)
            **kwargs: Additional configuration
        """
        self.api_key = api_key or os.getenv("ANTHROPIC_API_KEY")
        if not self.api_key:
            raise LLMAuthenticationError(
                "Anthropic API key not provided. Set ANTHROPIC_API_KEY environment variable."
            )

        self.model = model or "claude-sonnet-4-20250514"
        self.client = Anthropic(api_key=self.api_key)

    def generate(self, prompt: str, max_tokens: int = 500) -> str:
        """Generate completion from prompt using Anthropic API.

        Args:
            prompt: Input prompt
            max_tokens: Maximum tokens to generate

        Returns:
            Generated text

        Raises:
            LLMError: If generation fails
        """
        try:
            message = self.client.messages.create(
                model=self.model,
                max_tokens=max_tokens,
                temperature=0.0,
                messages=[{"role": "user", "content": prompt}],
            )

            if message.content:
                return message.content[0].text
            else:
                raise LLMError("Empty response from Anthropic")

        except RateLimitError as e:
            raise LLMRateLimitError("Anthropic rate limit exceeded") from e
        except APIError as e:
            if e.status_code == 401:
                raise LLMAuthenticationError(
                    "Invalid Anthropic API key"
                ) from e
            else:
                raise LLMServiceError(
                    f"Anthropic API error: {e.message}"
                ) from e
        except Exception as e:
            raise LLMError(f"Unexpected error: {e}") from e
