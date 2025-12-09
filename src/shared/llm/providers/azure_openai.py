"""Azure OpenAI Service LLM provider."""

import os
from typing import Optional

from openai import AzureOpenAI, AuthenticationError, APIError, RateLimitError

from .base import (
    LLMAuthenticationError,
    LLMError,
    LLMProvider,
    LLMRateLimitError,
    LLMServiceError,
)


class AzureOpenAIProvider(LLMProvider):
    """Azure OpenAI Service provider.

    Uses Azure-hosted OpenAI models with Azure AD or API key authentication.
    Requires an Azure OpenAI resource with deployed models.
    """

    def __init__(
        self,
        api_key: Optional[str] = None,
        endpoint: Optional[str] = None,
        deployment_name: Optional[str] = None,
        api_version: Optional[str] = None,
        **kwargs,
    ):
        """Initialize Azure OpenAI provider.

        Args:
            api_key: Azure OpenAI API key (defaults to AZURE_OPENAI_API_KEY env var)
            endpoint: Azure OpenAI endpoint URL (defaults to AZURE_OPENAI_ENDPOINT env var)
            deployment_name: Model deployment name (defaults to AZURE_OPENAI_DEPLOYMENT env var)
            api_version: API version (defaults to 2024-02-15-preview)
            **kwargs: Additional configuration
        """
        self.api_key = api_key or os.getenv("AZURE_OPENAI_API_KEY")
        self.endpoint = endpoint or os.getenv("AZURE_OPENAI_ENDPOINT")
        self.deployment_name = deployment_name or os.getenv(
            "AZURE_OPENAI_DEPLOYMENT", "gpt-4"
        )
        self.api_version = api_version or os.getenv(
            "AZURE_OPENAI_API_VERSION", "2024-02-15-preview"
        )

        if not self.api_key:
            raise LLMAuthenticationError(
                "Azure OpenAI API key not provided. Set AZURE_OPENAI_API_KEY environment variable."
            )

        if not self.endpoint:
            raise LLMAuthenticationError(
                "Azure OpenAI endpoint not provided. Set AZURE_OPENAI_ENDPOINT environment variable."
            )

        # Ensure endpoint has correct format
        self.endpoint = self.endpoint.rstrip("/")

        # Initialize Azure OpenAI client
        self.client = AzureOpenAI(
            api_key=self.api_key,
            api_version=self.api_version,
            azure_endpoint=self.endpoint,
        )

    def generate(self, prompt: str, max_tokens: int = 500) -> str:
        """Generate completion from prompt using Azure OpenAI Service.

        Args:
            prompt: Input prompt
            max_tokens: Maximum tokens to generate

        Returns:
            Generated text

        Raises:
            LLMError: If generation fails
        """
        try:
            response = self.client.chat.completions.create(
                model=self.deployment_name,
                messages=[{"role": "user", "content": prompt}],
                max_tokens=max_tokens,
                temperature=0.0,
            )

            if response.choices and response.choices[0].message.content:
                return response.choices[0].message.content
            else:
                raise LLMError("Empty response from Azure OpenAI")

        except RateLimitError as e:
            raise LLMRateLimitError("Azure OpenAI rate limit exceeded") from e
        except AuthenticationError as e:
            raise LLMAuthenticationError("Invalid Azure OpenAI credentials") from e
        except APIError as e:
            raise LLMServiceError(f"Azure OpenAI API error: {e}") from e
        except Exception as e:
            raise LLMError(f"Unexpected error: {e}") from e

    def validate_config(self) -> bool:
        """Validate Azure OpenAI configuration by testing API connectivity.

        Returns:
            True if configuration is valid and API is accessible
        """
        try:
            # Make a minimal request to validate connectivity
            response = self.client.chat.completions.create(
                model=self.deployment_name,
                messages=[{"role": "user", "content": "test"}],
                max_tokens=1,
            )
            return response.choices is not None
        except Exception:
            return False

    def list_deployments(self) -> list:
        """List available model deployments.

        Note: This requires additional Azure permissions and may not work
        with all API key configurations.

        Returns:
            List of deployment names (empty if listing not available)
        """
        # Azure OpenAI SDK doesn't provide a direct way to list deployments
        # This would require Azure Resource Management SDK
        # For now, return an empty list and document the limitation
        return []

    @property
    def model(self) -> str:
        """Get the current deployment name.

        Returns:
            Deployment name
        """
        return self.deployment_name
