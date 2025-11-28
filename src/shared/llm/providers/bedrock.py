"""AWS Bedrock LLM provider."""

import json
from typing import Optional

import boto3
from botocore.exceptions import ClientError

from .base import (
    LLMAuthenticationError,
    LLMError,
    LLMProvider,
    LLMRateLimitError,
    LLMServiceError,
)


class BedrockProvider(LLMProvider):
    """AWS Bedrock LLM provider."""

    def __init__(
        self,
        model_id: Optional[str] = None,
        region: str = "us-east-1",
        **kwargs,
    ):
        """Initialize Bedrock provider.

        Args:
            model_id: Model ID (defaults to Claude Sonnet)
            region: AWS region
            **kwargs: Additional configuration
        """
        self.model_id = model_id or "anthropic.claude-sonnet-4-20250514-v1:0"
        self.region = region

        self.bedrock_runtime = boto3.client(
            "bedrock-runtime", region_name=region
        )

    def generate(self, prompt: str, max_tokens: int = 500) -> str:
        """Generate completion from prompt using Bedrock.

        Args:
            prompt: Input prompt
            max_tokens: Maximum tokens to generate

        Returns:
            Generated text

        Raises:
            LLMError: If generation fails
        """
        try:
            if self.model_id.startswith("anthropic.claude"):
                return self._generate_anthropic(prompt, max_tokens)
            else:
                raise LLMError(f"Unsupported model: {self.model_id}")

        except ClientError as e:
            error_code = e.response["Error"]["Code"]

            if error_code == "ThrottlingException":
                raise LLMRateLimitError(
                    "Bedrock rate limit exceeded"
                ) from e
            elif error_code == "AccessDeniedException":
                raise LLMAuthenticationError(
                    "Bedrock access denied. Check IAM permissions."
                ) from e
            elif error_code == "ValidationException":
                raise LLMError(f"Invalid request: {e}") from e
            else:
                raise LLMServiceError(
                    f"Bedrock service error: {error_code}"
                ) from e

    def _generate_anthropic(self, prompt: str, max_tokens: int) -> str:
        """Generate using Anthropic models on Bedrock.

        Args:
            prompt: Input prompt
            max_tokens: Maximum tokens to generate

        Returns:
            Generated text
        """
        body = {
            "anthropic_version": "bedrock-2023-05-31",
            "max_tokens": max_tokens,
            "messages": [{"role": "user", "content": prompt}],
            "temperature": 0.0,
        }

        response = self.bedrock_runtime.invoke_model(
            modelId=self.model_id, body=json.dumps(body)
        )

        response_body = json.loads(response["body"].read())

        if "content" in response_body and response_body["content"]:
            return response_body["content"][0]["text"]
        else:
            raise LLMError("Empty response from Bedrock")
