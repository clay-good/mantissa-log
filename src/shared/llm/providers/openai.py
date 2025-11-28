"""OpenAI API LLM provider."""

import os
from typing import Optional

import openai
from openai import AuthenticationError, OpenAIError, RateLimitError

from .base import (
    LLMAuthenticationError,
    LLMError,
    LLMProvider,
    LLMRateLimitError,
    LLMServiceError,
)


class OpenAIProvider(LLMProvider):
    """OpenAI API provider."""

    def __init__(
        self,
        api_key: Optional[str] = None,
        model: Optional[str] = None,
        **kwargs,
    ):
        """Initialize OpenAI provider.

        Args:
            api_key: OpenAI API key (defaults to OPENAI_API_KEY env var)
            model: Model name (defaults to gpt-4-turbo)
            **kwargs: Additional configuration
        """
        self.api_key = api_key or os.getenv("OPENAI_API_KEY")
        if not self.api_key:
            raise LLMAuthenticationError(
                "OpenAI API key not provided. Set OPENAI_API_KEY environment variable."
            )

        self.model = model or "gpt-4-turbo"
        openai.api_key = self.api_key

    def generate(self, prompt: str, max_tokens: int = 500) -> str:
        """Generate completion from prompt using OpenAI API.

        Args:
            prompt: Input prompt
            max_tokens: Maximum tokens to generate

        Returns:
            Generated text

        Raises:
            LLMError: If generation fails
        """
        try:
            response = openai.chat.completions.create(
                model=self.model,
                messages=[{"role": "user", "content": prompt}],
                max_tokens=max_tokens,
                temperature=0.0,
            )

            if response.choices and response.choices[0].message.content:
                return response.choices[0].message.content
            else:
                raise LLMError("Empty response from OpenAI")

        except RateLimitError as e:
            raise LLMRateLimitError("OpenAI rate limit exceeded") from e
        except AuthenticationError as e:
            raise LLMAuthenticationError("Invalid OpenAI API key") from e
        except OpenAIError as e:
            raise LLMServiceError(f"OpenAI API error: {e}") from e
        except Exception as e:
            raise LLMError(f"Unexpected error: {e}") from e
