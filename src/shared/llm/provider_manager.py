"""
LLM Provider Manager

Manages multiple LLM provider configurations, API key storage,
and provider switching logic for query generation.
"""

import os
import json
from typing import Dict, List, Any, Optional
from dataclasses import dataclass, asdict
from enum import Enum
import boto3
import logging

logger = logging.getLogger(__name__)


class LLMProvider(Enum):
    """Supported LLM providers."""
    ANTHROPIC = "anthropic"
    OPENAI = "openai"
    GOOGLE = "google"
    AWS_BEDROCK = "aws_bedrock"


@dataclass
class ModelPricing:
    """Pricing information for a model."""
    input_per_1m_tokens: float
    output_per_1m_tokens: float
    currency: str = "USD"


@dataclass
class LLMModel:
    """LLM model configuration."""
    provider: LLMProvider
    model_id: str
    display_name: str
    pricing: ModelPricing
    max_tokens: int = 8192
    supports_streaming: bool = True
    best_for: List[str] = None


@dataclass
class ProviderConfig:
    """Configuration for an LLM provider."""
    provider: LLMProvider
    enabled: bool
    api_key_secret_id: Optional[str] = None  # Secrets Manager ID
    region: Optional[str] = None  # For AWS Bedrock
    selected_model: Optional[str] = None
    custom_endpoint: Optional[str] = None


@dataclass
class UserLLMSettings:
    """User's LLM configuration settings."""
    user_id: str
    providers: List[ProviderConfig]
    default_provider: LLMProvider
    query_generation_model: str
    detection_engineering_model: str
    max_tokens_per_request: int = 2000
    temperature: float = 0.0
    created_at: str = None
    updated_at: str = None


class LLMProviderManager:
    """
    Manages LLM provider configurations and API keys.

    Features:
    - Secure API key storage in AWS Secrets Manager
    - Provider preferences in DynamoDB
    - Multi-provider support with fallback
    - Usage tracking
    - Cost estimation
    """

    # Model registry
    AVAILABLE_MODELS = {
        LLMProvider.ANTHROPIC: [
            LLMModel(
                provider=LLMProvider.ANTHROPIC,
                model_id="claude-3-5-sonnet-20241022",
                display_name="Claude 3.5 Sonnet",
                pricing=ModelPricing(input_per_1m_tokens=3.0, output_per_1m_tokens=15.0),
                max_tokens=8192,
                best_for=["query_generation", "detection_engineering", "general"]
            ),
            LLMModel(
                provider=LLMProvider.ANTHROPIC,
                model_id="claude-3-opus-20240229",
                display_name="Claude 3 Opus",
                pricing=ModelPricing(input_per_1m_tokens=15.0, output_per_1m_tokens=75.0),
                max_tokens=4096,
                best_for=["complex_analysis", "detection_engineering"]
            ),
            LLMModel(
                provider=LLMProvider.ANTHROPIC,
                model_id="claude-3-haiku-20240307",
                display_name="Claude 3 Haiku",
                pricing=ModelPricing(input_per_1m_tokens=0.25, output_per_1m_tokens=1.25),
                max_tokens=4096,
                best_for=["budget", "simple_queries"]
            ),
            LLMModel(
                provider=LLMProvider.ANTHROPIC,
                model_id="claude-3-5-haiku-20241022",
                display_name="Claude 3.5 Haiku",
                pricing=ModelPricing(input_per_1m_tokens=0.80, output_per_1m_tokens=4.0),
                max_tokens=8192,
                best_for=["budget", "query_generation"]
            ),
        ],
        LLMProvider.OPENAI: [
            LLMModel(
                provider=LLMProvider.OPENAI,
                model_id="gpt-4-turbo-preview",
                display_name="GPT-4 Turbo",
                pricing=ModelPricing(input_per_1m_tokens=10.0, output_per_1m_tokens=30.0),
                max_tokens=4096,
                best_for=["query_generation", "general"]
            ),
            LLMModel(
                provider=LLMProvider.OPENAI,
                model_id="gpt-4",
                display_name="GPT-4",
                pricing=ModelPricing(input_per_1m_tokens=30.0, output_per_1m_tokens=60.0),
                max_tokens=8192,
                best_for=["detection_engineering", "complex_analysis"]
            ),
            LLMModel(
                provider=LLMProvider.OPENAI,
                model_id="gpt-3.5-turbo",
                display_name="GPT-3.5 Turbo",
                pricing=ModelPricing(input_per_1m_tokens=0.50, output_per_1m_tokens=1.50),
                max_tokens=4096,
                best_for=["budget", "simple_queries"]
            ),
        ],
        LLMProvider.GOOGLE: [
            LLMModel(
                provider=LLMProvider.GOOGLE,
                model_id="gemini-1.5-pro",
                display_name="Gemini 1.5 Pro",
                pricing=ModelPricing(input_per_1m_tokens=3.50, output_per_1m_tokens=10.50),
                max_tokens=8192,
                best_for=["query_generation", "general"]
            ),
            LLMModel(
                provider=LLMProvider.GOOGLE,
                model_id="gemini-1.5-flash",
                display_name="Gemini 1.5 Flash",
                pricing=ModelPricing(input_per_1m_tokens=0.35, output_per_1m_tokens=1.05),
                max_tokens=8192,
                best_for=["budget", "detection_engineering"]
            ),
            LLMModel(
                provider=LLMProvider.GOOGLE,
                model_id="gemini-pro",
                display_name="Gemini Pro",
                pricing=ModelPricing(input_per_1m_tokens=0.50, output_per_1m_tokens=1.50),
                max_tokens=4096,
                best_for=["budget", "simple_queries"]
            ),
        ],
        LLMProvider.AWS_BEDROCK: [
            LLMModel(
                provider=LLMProvider.AWS_BEDROCK,
                model_id="anthropic.claude-3-5-sonnet-20241022-v2:0",
                display_name="Claude 3.5 Sonnet (Bedrock)",
                pricing=ModelPricing(input_per_1m_tokens=3.0, output_per_1m_tokens=15.0),
                max_tokens=8192,
                best_for=["query_generation", "detection_engineering"]
            ),
            LLMModel(
                provider=LLMProvider.AWS_BEDROCK,
                model_id="anthropic.claude-3-opus-20240229-v1:0",
                display_name="Claude 3 Opus (Bedrock)",
                pricing=ModelPricing(input_per_1m_tokens=15.0, output_per_1m_tokens=75.0),
                max_tokens=4096,
                best_for=["complex_analysis"]
            ),
            LLMModel(
                provider=LLMProvider.AWS_BEDROCK,
                model_id="anthropic.claude-3-haiku-20240307-v1:0",
                display_name="Claude 3 Haiku (Bedrock)",
                pricing=ModelPricing(input_per_1m_tokens=0.25, output_per_1m_tokens=1.25),
                max_tokens=4096,
                best_for=["budget"]
            ),
        ],
    }

    def __init__(
        self,
        settings_table: Optional[str] = None,
        secrets_client: Optional[Any] = None
    ):
        """
        Initialize provider manager.

        Args:
            settings_table: DynamoDB table for user settings
            secrets_client: Boto3 Secrets Manager client
        """
        self.settings_table_name = settings_table or os.environ.get(
            'USER_SETTINGS_TABLE',
            'mantissa-log-user-settings'
        )

        self.dynamodb = boto3.resource('dynamodb')
        self.settings_table = self.dynamodb.Table(self.settings_table_name)
        self.secrets_client = secrets_client or boto3.client('secretsmanager')

    def get_user_settings(self, user_id: str) -> Optional[UserLLMSettings]:
        """
        Get user's LLM settings.

        Args:
            user_id: User ID

        Returns:
            UserLLMSettings or None if not configured
        """
        try:
            response = self.settings_table.get_item(
                Key={
                    'pk': f'user#{user_id}',
                    'sk': 'llm_settings'
                }
            )

            if 'Item' not in response:
                return None

            item = response['Item']

            # Convert providers from dict to ProviderConfig
            providers = []
            for p in item.get('providers', []):
                providers.append(ProviderConfig(
                    provider=LLMProvider(p['provider']),
                    enabled=p['enabled'],
                    api_key_secret_id=p.get('api_key_secret_id'),
                    region=p.get('region'),
                    selected_model=p.get('selected_model'),
                    custom_endpoint=p.get('custom_endpoint')
                ))

            settings = UserLLMSettings(
                user_id=user_id,
                providers=providers,
                default_provider=LLMProvider(item['default_provider']),
                query_generation_model=item['query_generation_model'],
                detection_engineering_model=item['detection_engineering_model'],
                max_tokens_per_request=item.get('max_tokens_per_request', 2000),
                temperature=float(item.get('temperature', 0.0)),
                created_at=item.get('created_at'),
                updated_at=item.get('updated_at')
            )

            return settings

        except Exception as e:
            logger.error(f'Error getting user settings: {e}')
            return None

    def save_user_settings(self, settings: UserLLMSettings):
        """
        Save user's LLM settings.

        Args:
            settings: UserLLMSettings to save
        """
        from datetime import datetime

        timestamp = datetime.utcnow().isoformat() + 'Z'

        if not settings.created_at:
            settings.created_at = timestamp
        settings.updated_at = timestamp

        try:
            # Convert to dict for DynamoDB
            item = {
                'pk': f'user#{settings.user_id}',
                'sk': 'llm_settings',
                'user_id': settings.user_id,
                'providers': [
                    {
                        'provider': p.provider.value,
                        'enabled': p.enabled,
                        'api_key_secret_id': p.api_key_secret_id,
                        'region': p.region,
                        'selected_model': p.selected_model,
                        'custom_endpoint': p.custom_endpoint
                    }
                    for p in settings.providers
                ],
                'default_provider': settings.default_provider.value,
                'query_generation_model': settings.query_generation_model,
                'detection_engineering_model': settings.detection_engineering_model,
                'max_tokens_per_request': settings.max_tokens_per_request,
                'temperature': settings.temperature,
                'created_at': settings.created_at,
                'updated_at': settings.updated_at
            }

            self.settings_table.put_item(Item=item)

        except Exception as e:
            logger.error(f'Error saving user settings: {e}')
            raise

    def store_api_key(
        self,
        user_id: str,
        provider: LLMProvider,
        api_key: str
    ) -> str:
        """
        Securely store API key in Secrets Manager.

        Args:
            user_id: User ID
            provider: Provider name
            api_key: API key to store

        Returns:
            Secret ID for later retrieval
        """
        secret_name = f'mantissa-log/{user_id}/{provider.value}-api-key'

        try:
            # Try to update existing secret
            response = self.secrets_client.update_secret(
                SecretId=secret_name,
                SecretString=api_key
            )
            secret_id = response['ARN']

        except self.secrets_client.exceptions.ResourceNotFoundException:
            # Create new secret
            response = self.secrets_client.create_secret(
                Name=secret_name,
                Description=f'{provider.value} API key for user {user_id}',
                SecretString=api_key,
                Tags=[
                    {'Key': 'user_id', 'Value': user_id},
                    {'Key': 'provider', 'Value': provider.value},
                    {'Key': 'managed_by', 'Value': 'mantissa-log'}
                ]
            )
            secret_id = response['ARN']

        return secret_id

    def retrieve_api_key(self, secret_id: str) -> Optional[str]:
        """
        Retrieve API key from Secrets Manager.

        Args:
            secret_id: Secret ID or ARN

        Returns:
            API key or None if not found
        """
        try:
            response = self.secrets_client.get_secret_value(SecretId=secret_id)
            return response['SecretString']

        except Exception as e:
            logger.error(f'Error retrieving API key: {e}')
            return None

    def delete_api_key(self, secret_id: str):
        """
        Delete API key from Secrets Manager.

        Args:
            secret_id: Secret ID or ARN
        """
        try:
            self.secrets_client.delete_secret(
                SecretId=secret_id,
                ForceDeleteWithoutRecovery=True
            )
        except Exception as e:
            logger.error(f'Error deleting API key: {e}')

    def test_provider_connection(
        self,
        provider: LLMProvider,
        api_key: Optional[str] = None,
        model_id: Optional[str] = None,
        region: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Test connection to LLM provider.

        Args:
            provider: Provider to test
            api_key: API key (if required)
            model_id: Model to test
            region: AWS region (for Bedrock)

        Returns:
            Dictionary with test results
        """
        try:
            if provider == LLMProvider.ANTHROPIC:
                return self._test_anthropic(api_key, model_id)
            elif provider == LLMProvider.OPENAI:
                return self._test_openai(api_key, model_id)
            elif provider == LLMProvider.GOOGLE:
                return self._test_google(api_key, model_id)
            elif provider == LLMProvider.AWS_BEDROCK:
                return self._test_bedrock(model_id, region)
            else:
                return {'success': False, 'error': 'Unknown provider'}

        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }

    def _test_anthropic(self, api_key: str, model_id: str) -> Dict[str, Any]:
        """Test Anthropic API connection."""
        import anthropic

        try:
            client = anthropic.Anthropic(api_key=api_key)

            # Simple test message
            message = client.messages.create(
                model=model_id or "claude-3-5-sonnet-20241022",
                max_tokens=10,
                messages=[
                    {"role": "user", "content": "Test"}
                ]
            )

            return {
                'success': True,
                'model': message.model,
                'message': 'Connection successful'
            }

        except Exception as e:
            return {
                'success': False,
                'error': f'Anthropic API test failed: {str(e)}'
            }

    def _test_openai(self, api_key: str, model_id: str) -> Dict[str, Any]:
        """Test OpenAI API connection."""
        import openai

        try:
            client = openai.OpenAI(api_key=api_key)

            # Simple test message
            response = client.chat.completions.create(
                model=model_id or "gpt-4-turbo-preview",
                max_tokens=10,
                messages=[
                    {"role": "user", "content": "Test"}
                ]
            )

            return {
                'success': True,
                'model': response.model,
                'message': 'Connection successful'
            }

        except Exception as e:
            return {
                'success': False,
                'error': f'OpenAI API test failed: {str(e)}'
            }

    def _test_google(self, api_key: str, model_id: str) -> Dict[str, Any]:
        """Test Google Gemini API connection."""
        import google.generativeai as genai

        try:
            genai.configure(api_key=api_key)

            model = genai.GenerativeModel(model_id or 'gemini-1.5-pro')
            response = model.generate_content("Test")

            return {
                'success': True,
                'model': model_id,
                'message': 'Connection successful'
            }

        except Exception as e:
            return {
                'success': False,
                'error': f'Google API test failed: {str(e)}'
            }

    def _test_bedrock(self, model_id: str, region: str) -> Dict[str, Any]:
        """Test AWS Bedrock connection."""
        try:
            bedrock = boto3.client('bedrock-runtime', region_name=region or 'us-east-1')

            # Simple test invocation
            response = bedrock.invoke_model(
                modelId=model_id or "anthropic.claude-3-5-sonnet-20241022-v2:0",
                body=json.dumps({
                    "anthropic_version": "bedrock-2023-05-31",
                    "max_tokens": 10,
                    "messages": [
                        {"role": "user", "content": "Test"}
                    ]
                })
            )

            return {
                'success': True,
                'model': model_id,
                'message': 'Connection successful'
            }

        except Exception as e:
            return {
                'success': False,
                'error': f'Bedrock test failed: {str(e)}'
            }

    def get_available_models(
        self,
        provider: Optional[LLMProvider] = None
    ) -> List[LLMModel]:
        """
        Get available models.

        Args:
            provider: Filter by provider (optional)

        Returns:
            List of available models
        """
        if provider:
            return self.AVAILABLE_MODELS.get(provider, [])
        else:
            # Return all models
            all_models = []
            for models in self.AVAILABLE_MODELS.values():
                all_models.extend(models)
            return all_models

    def get_model_info(self, model_id: str) -> Optional[LLMModel]:
        """
        Get information about a specific model.

        Args:
            model_id: Model ID

        Returns:
            LLMModel or None if not found
        """
        for models in self.AVAILABLE_MODELS.values():
            for model in models:
                if model.model_id == model_id:
                    return model
        return None


def get_user_llm_provider(user_id: str) -> Optional[UserLLMSettings]:
    """
    Convenience function to get user's LLM settings.

    Args:
        user_id: User ID

    Returns:
        UserLLMSettings or None
    """
    manager = LLMProviderManager()
    return manager.get_user_settings(user_id)
