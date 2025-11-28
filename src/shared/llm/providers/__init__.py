"""LLM provider adapters."""

import os
from typing import Optional

from .base import LLMProvider
from .bedrock import BedrockProvider


def get_provider(
    provider_name: Optional[str] = None, **kwargs
) -> LLMProvider:
    """Get LLM provider instance.

    Args:
        provider_name: Provider name ("anthropic", "openai", "bedrock")
        **kwargs: Provider-specific configuration

    Returns:
        LLMProvider instance
    """
    if provider_name is None:
        provider_name = os.getenv("LLM_PROVIDER", "bedrock")

    provider_name = provider_name.lower()

    if provider_name == "bedrock":
        return BedrockProvider(**kwargs)
    elif provider_name == "anthropic":
        from .anthropic import AnthropicProvider

        return AnthropicProvider(**kwargs)
    elif provider_name == "openai":
        from .openai import OpenAIProvider

        return OpenAIProvider(**kwargs)
    else:
        raise ValueError(f"Unknown LLM provider: {provider_name}")


__all__ = [
    "LLMProvider",
    "BedrockProvider",
    "get_provider",
]
