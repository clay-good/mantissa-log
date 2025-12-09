"""Google Cloud Vertex AI LLM provider."""

import os
from typing import Optional

import vertexai
from vertexai.generative_models import GenerativeModel, GenerationConfig

from .base import (
    LLMAuthenticationError,
    LLMError,
    LLMProvider,
    LLMRateLimitError,
    LLMServiceError,
)


class VertexAIProvider(LLMProvider):
    """Google Cloud Vertex AI provider.

    Uses Vertex AI Generative Models (Gemini) with Google Cloud authentication.
    Requires a GCP project with Vertex AI API enabled and appropriate IAM permissions.
    """

    # Supported models
    SUPPORTED_MODELS = [
        "gemini-1.5-pro",
        "gemini-1.5-flash",
        "gemini-1.0-pro",
        "gemini-pro",
    ]

    def __init__(
        self,
        project_id: Optional[str] = None,
        location: Optional[str] = None,
        model: Optional[str] = None,
        **kwargs,
    ):
        """Initialize Vertex AI provider.

        Args:
            project_id: GCP project ID (defaults to GOOGLE_CLOUD_PROJECT env var)
            location: GCP region (defaults to VERTEX_AI_LOCATION or us-central1)
            model: Model name (defaults to gemini-1.5-pro)
            **kwargs: Additional configuration
        """
        self.project_id = project_id or os.getenv("GOOGLE_CLOUD_PROJECT")
        self.location = location or os.getenv("VERTEX_AI_LOCATION", "us-central1")
        self.model_name = model or os.getenv("VERTEX_AI_MODEL", "gemini-1.5-pro")

        if not self.project_id:
            raise LLMAuthenticationError(
                "GCP project ID not provided. Set GOOGLE_CLOUD_PROJECT environment variable."
            )

        # Initialize Vertex AI
        try:
            vertexai.init(project=self.project_id, location=self.location)
        except Exception as e:
            raise LLMAuthenticationError(
                f"Failed to initialize Vertex AI: {e}. "
                "Ensure GOOGLE_APPLICATION_CREDENTIALS is set or running on GCP with appropriate IAM."
            ) from e

        # Initialize the model
        try:
            self.model = GenerativeModel(self.model_name)
        except Exception as e:
            raise LLMError(f"Failed to load model {self.model_name}: {e}") from e

    def generate(self, prompt: str, max_tokens: int = 500) -> str:
        """Generate completion from prompt using Vertex AI.

        Args:
            prompt: Input prompt
            max_tokens: Maximum tokens to generate

        Returns:
            Generated text

        Raises:
            LLMError: If generation fails
        """
        try:
            generation_config = GenerationConfig(
                max_output_tokens=max_tokens,
                temperature=0.0,
            )

            response = self.model.generate_content(
                prompt,
                generation_config=generation_config,
            )

            if response.text:
                return response.text
            else:
                # Check for blocked content
                if hasattr(response, 'candidates') and response.candidates:
                    candidate = response.candidates[0]
                    if hasattr(candidate, 'finish_reason'):
                        raise LLMError(
                            f"Generation stopped: {candidate.finish_reason}"
                        )
                raise LLMError("Empty response from Vertex AI")

        except Exception as e:
            error_msg = str(e).lower()

            # Check for quota/rate limiting
            if 'quota' in error_msg or 'rate' in error_msg or '429' in error_msg:
                raise LLMRateLimitError("Vertex AI rate limit exceeded") from e

            # Check for authentication errors
            if 'permission' in error_msg or 'credentials' in error_msg or '401' in error_msg or '403' in error_msg:
                raise LLMAuthenticationError(
                    "Vertex AI authentication failed. Check IAM permissions."
                ) from e

            # Check for service errors
            if '500' in error_msg or '503' in error_msg or 'internal' in error_msg:
                raise LLMServiceError(f"Vertex AI service error: {e}") from e

            # Generic error
            raise LLMError(f"Vertex AI error: {e}") from e

    def validate_config(self) -> bool:
        """Validate Vertex AI configuration by testing API connectivity.

        Returns:
            True if configuration is valid and API is accessible
        """
        try:
            # Make a minimal request to validate connectivity
            generation_config = GenerationConfig(
                max_output_tokens=1,
                temperature=0.0,
            )
            response = self.model.generate_content(
                "test",
                generation_config=generation_config,
            )
            return response is not None
        except Exception:
            return False

    def list_models(self) -> list:
        """List supported Vertex AI models.

        Returns:
            List of supported model names
        """
        return self.SUPPORTED_MODELS.copy()

    @property
    def current_model(self) -> str:
        """Get the current model name.

        Returns:
            Model name
        """
        return self.model_name
