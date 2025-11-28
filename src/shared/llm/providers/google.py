"""Google Gemini API LLM provider."""

import os
from typing import Optional

import google.generativeai as genai

from .base import (
    LLMAuthenticationError,
    LLMError,
    LLMProvider,
    LLMRateLimitError,
    LLMServiceError,
)


class GoogleProvider(LLMProvider):
    """Google Gemini API provider."""

    def __init__(
        self,
        api_key: Optional[str] = None,
        model: Optional[str] = None,
        **kwargs,
    ):
        """Initialize Google Gemini provider.

        Args:
            api_key: Google API key (defaults to GOOGLE_API_KEY env var)
            model: Model name (defaults to gemini-1.5-pro)
            **kwargs: Additional configuration
        """
        self.api_key = api_key or os.getenv("GOOGLE_API_KEY")
        if not self.api_key:
            raise LLMAuthenticationError(
                "Google API key not provided. Set GOOGLE_API_KEY environment variable."
            )

        self.model_name = model or "gemini-1.5-pro"

        # Configure the API
        genai.configure(api_key=self.api_key)

        # Initialize the model
        self.model = genai.GenerativeModel(self.model_name)

    def generate(self, prompt: str, max_tokens: int = 500) -> str:
        """Generate completion from prompt using Google Gemini API.

        Args:
            prompt: Input prompt
            max_tokens: Maximum tokens to generate

        Returns:
            Generated text

        Raises:
            LLMError: If generation fails
        """
        try:
            generation_config = genai.types.GenerationConfig(
                max_output_tokens=max_tokens,
                temperature=0.0,
            )

            response = self.model.generate_content(
                prompt,
                generation_config=generation_config
            )

            if response.text:
                return response.text
            else:
                raise LLMError("Empty response from Google Gemini")

        except Exception as e:
            error_msg = str(e).lower()

            # Check for rate limiting
            if 'quota' in error_msg or 'rate' in error_msg:
                raise LLMRateLimitError("Google Gemini rate limit exceeded") from e

            # Check for authentication errors
            if 'api key' in error_msg or 'authentication' in error_msg or '401' in error_msg:
                raise LLMAuthenticationError("Invalid Google API key") from e

            # Check for service errors
            if '500' in error_msg or 'internal' in error_msg or 'service' in error_msg:
                raise LLMServiceError(f"Google Gemini API error: {e}") from e

            # Generic error
            raise LLMError(f"Unexpected error: {e}") from e
