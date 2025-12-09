"""
LLM Provider Factory

Creates appropriate LLM provider instances based on user configuration.
Handles provider selection, API key retrieval from Secrets Manager, and fallback logic.
"""

import boto3
import json
from typing import Dict, Any, Optional
from .providers.anthropic import AnthropicProvider
from .providers.openai import OpenAIProvider
from .providers.google import GoogleProvider
from .providers.bedrock import BedrockProvider
from .providers.azure_openai import AzureOpenAIProvider
from .providers.vertex_ai import VertexAIProvider
from .providers.base import BaseLLMProvider

dynamodb = boto3.resource('dynamodb')
secrets_manager = boto3.client('secretsmanager')

USER_SETTINGS_TABLE = 'mantissa_user_settings'


class LLMProviderFactory:
    """Factory for creating and managing LLM provider instances"""

    def __init__(self):
        self.settings_table = dynamodb.Table(USER_SETTINGS_TABLE)
        self._provider_cache = {}

    def get_provider_for_use_case(
        self,
        user_id: str,
        use_case: str,
        fallback_to_bedrock: bool = True
    ) -> BaseLLMProvider:
        """
        Get the appropriate LLM provider for a specific use case.

        Args:
            user_id: User ID
            use_case: Use case (query_generation, detection_engineering)
            fallback_to_bedrock: Whether to fall back to Bedrock if user's provider fails

        Returns:
            Configured LLM provider instance

        Raises:
            Exception: If no provider is available
        """
        # Get user's LLM configuration
        config = self._get_user_llm_config(user_id)

        # Get provider and model for this use case
        use_case_config = config.get('useCases', {}).get(use_case, {})
        provider_id = use_case_config.get('provider')
        model_id = use_case_config.get('model')

        # Get provider preferences
        preferences = config.get('preferences', {})
        max_tokens = preferences.get('maxTokens', 2000)
        temperature = preferences.get('temperature', 0.0)

        # Try to create the user's configured provider
        if provider_id and model_id:
            try:
                provider = self._create_provider(
                    user_id=user_id,
                    provider_id=provider_id,
                    model_id=model_id,
                    max_tokens=max_tokens,
                    temperature=temperature,
                    config=config
                )
                return provider
            except Exception as e:
                print(f"Failed to create user's configured provider {provider_id}: {e}")
                if not fallback_to_bedrock:
                    raise

        # Fallback to AWS Bedrock if available and allowed
        if fallback_to_bedrock:
            return self._create_bedrock_provider(max_tokens, temperature)

        raise Exception("No LLM provider available")

    def _get_user_llm_config(self, user_id: str) -> Dict[str, Any]:
        """Retrieve user's LLM configuration from DynamoDB"""
        try:
            response = self.settings_table.get_item(
                Key={'user_id': user_id, 'setting_type': 'llm_config'}
            )
            return response.get('Item', {}).get('config', {})
        except Exception as e:
            print(f"Error getting user LLM config: {e}")
            return {}

    def _create_provider(
        self,
        user_id: str,
        provider_id: str,
        model_id: str,
        max_tokens: int,
        temperature: float,
        config: Dict[str, Any]
    ) -> BaseLLMProvider:
        """Create a specific LLM provider instance"""

        provider_config = config.get('providers', {}).get(provider_id, {})

        if provider_id == 'anthropic':
            api_key = self._get_api_key(user_id, provider_id, provider_config)
            return AnthropicProvider(
                api_key=api_key,
                model=model_id,
                max_tokens=max_tokens,
                temperature=temperature
            )

        elif provider_id == 'openai':
            api_key = self._get_api_key(user_id, provider_id, provider_config)
            return OpenAIProvider(
                api_key=api_key,
                model=model_id,
                max_tokens=max_tokens,
                temperature=temperature
            )

        elif provider_id == 'google':
            api_key = self._get_api_key(user_id, provider_id, provider_config)
            return GoogleProvider(
                api_key=api_key,
                model=model_id,
                max_tokens=max_tokens,
                temperature=temperature
            )

        elif provider_id == 'bedrock':
            region = provider_config.get('region', 'us-east-1')
            return BedrockProvider(
                region=region,
                model=model_id,
                max_tokens=max_tokens,
                temperature=temperature
            )

        elif provider_id in ('azure_openai', 'azure-openai', 'azureopenai'):
            api_key = self._get_api_key(user_id, provider_id, provider_config)
            endpoint = provider_config.get('endpoint')
            deployment_name = provider_config.get('deployment_name', model_id)
            api_version = provider_config.get('api_version', '2024-02-15-preview')
            return AzureOpenAIProvider(
                api_key=api_key,
                endpoint=endpoint,
                deployment_name=deployment_name,
                api_version=api_version
            )

        elif provider_id in ('vertex_ai', 'vertex-ai', 'vertexai'):
            project_id = provider_config.get('project_id')
            location = provider_config.get('location', 'us-central1')
            return VertexAIProvider(
                project_id=project_id,
                location=location,
                model=model_id
            )

        else:
            raise ValueError(f"Unknown provider: {provider_id}")

    def _create_bedrock_provider(
        self,
        max_tokens: int,
        temperature: float
    ) -> BedrockProvider:
        """Create a Bedrock provider as fallback"""
        return BedrockProvider(
            region='us-east-1',
            model='anthropic.claude-3-5-sonnet-20241022-v2:0',
            max_tokens=max_tokens,
            temperature=temperature
        )

    def _get_api_key(
        self,
        user_id: str,
        provider_id: str,
        provider_config: Dict[str, Any]
    ) -> str:
        """
        Retrieve API key from Secrets Manager.

        Args:
            user_id: User ID
            provider_id: Provider ID (anthropic, openai, google)
            provider_config: Provider configuration

        Returns:
            API key string

        Raises:
            Exception: If API key cannot be retrieved
        """
        secret_id = provider_config.get('apiKeySecretId')

        if not secret_id:
            raise Exception(f"No API key configured for {provider_id}")

        try:
            response = secrets_manager.get_secret_value(SecretId=secret_id)
            return response['SecretString']
        except Exception as e:
            raise Exception(f"Failed to retrieve API key from Secrets Manager: {e}")

    def track_usage(
        self,
        user_id: str,
        provider_id: str,
        model_id: str,
        use_case: str,
        input_tokens: int,
        output_tokens: int,
        cost: float
    ):
        """
        Track LLM usage and costs.

        Stores usage data in DynamoDB for analytics and cost monitoring.
        """
        from datetime import datetime

        usage_table = dynamodb.Table('mantissa_llm_usage')

        try:
            usage_table.put_item(
                Item={
                    'user_id': user_id,
                    'timestamp': datetime.utcnow().isoformat(),
                    'provider': provider_id,
                    'model': model_id,
                    'use_case': use_case,
                    'input_tokens': input_tokens,
                    'output_tokens': output_tokens,
                    'cost': cost
                }
            )
        except Exception as e:
            print(f"Error tracking LLM usage: {e}")


# Singleton instance
_factory = None

def get_provider_factory() -> LLMProviderFactory:
    """Get the singleton LLMProviderFactory instance"""
    global _factory
    if _factory is None:
        _factory = LLMProviderFactory()
    return _factory
