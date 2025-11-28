"""
LLM Provider Integration

Integrates the LLMProviderManager with the query generation system,
allowing queries to use user-configured LLM providers and models.
"""

import os
from typing import Optional, Dict, Any
from .provider_manager import (
    LLMProviderManager,
    LLMProvider,
    UserLLMSettings
)


class ProviderBasedLLMClient:
    """
    LLM client that uses user's configured provider settings.

    This adapter bridges the LLMProviderManager with the existing
    query generation system, allowing queries to use user-specified
    providers and models.
    """

    def __init__(self, user_id: str, task_type: str = 'query_generation'):
        """
        Initialize provider-based LLM client.

        Args:
            user_id: User ID for loading settings
            task_type: Type of task ('query_generation' or 'detection_engineering')
        """
        self.user_id = user_id
        self.task_type = task_type
        self.provider_manager = LLMProviderManager()

        # Load user's settings
        self.settings = self.provider_manager.get_user_settings(user_id)

        # Determine which model to use based on task type
        if self.settings:
            if task_type == 'detection_engineering':
                self.model_id = self.settings.detection_model
            else:
                self.model_id = self.settings.query_model
        else:
            # Default to Claude 3.5 Sonnet if no settings
            self.model_id = 'claude-3-5-sonnet-20241022'

    def generate(
        self,
        prompt: str,
        max_tokens: Optional[int] = None,
        temperature: Optional[float] = None,
        **kwargs
    ) -> str:
        """
        Generate text using the user's configured LLM provider.

        Args:
            prompt: Input prompt
            max_tokens: Maximum tokens to generate (uses user settings if not specified)
            temperature: Temperature for generation (uses user settings if not specified)
            **kwargs: Additional provider-specific parameters

        Returns:
            Generated text

        Raises:
            Exception: If generation fails with all configured providers
        """
        # Use user's preferences if not overridden
        if max_tokens is None and self.settings:
            max_tokens = self.settings.max_tokens
        elif max_tokens is None:
            max_tokens = 2000

        if temperature is None and self.settings:
            temperature = self.settings.temperature
        elif temperature is None:
            temperature = 0.0

        # Try to generate with user's configured providers
        if self.settings and self.settings.providers:
            # Try enabled providers in order
            enabled_providers = [
                (provider, config) for provider, config in self.settings.providers.items()
                if config.enabled
            ]

            for provider, config in enabled_providers:
                try:
                    result = self._generate_with_provider(
                        provider=provider,
                        model_id=config.model_id,
                        prompt=prompt,
                        max_tokens=max_tokens,
                        temperature=temperature,
                        region=config.region,
                        **kwargs
                    )

                    if result:
                        return result

                except Exception as e:
                    print(f'Error generating with {provider.value}: {e}')
                    # Continue to next provider
                    continue

        # Fallback to AWS Bedrock if available
        try:
            return self._generate_with_bedrock(
                prompt=prompt,
                max_tokens=max_tokens,
                temperature=temperature
            )
        except Exception as e:
            raise Exception(
                f'Failed to generate with all configured providers. '
                f'Last error: {str(e)}'
            )

    def _generate_with_provider(
        self,
        provider: LLMProvider,
        model_id: str,
        prompt: str,
        max_tokens: int,
        temperature: float,
        region: Optional[str] = None,
        **kwargs
    ) -> Optional[str]:
        """
        Generate text with a specific provider.

        Args:
            provider: LLM provider to use
            model_id: Model ID
            prompt: Input prompt
            max_tokens: Maximum tokens
            temperature: Temperature
            region: AWS region (for Bedrock)
            **kwargs: Additional parameters

        Returns:
            Generated text or None if failed
        """
        if provider == LLMProvider.ANTHROPIC:
            return self._generate_with_anthropic(
                model_id=model_id,
                prompt=prompt,
                max_tokens=max_tokens,
                temperature=temperature
            )
        elif provider == LLMProvider.OPENAI:
            return self._generate_with_openai(
                model_id=model_id,
                prompt=prompt,
                max_tokens=max_tokens,
                temperature=temperature
            )
        elif provider == LLMProvider.GOOGLE:
            return self._generate_with_google(
                model_id=model_id,
                prompt=prompt,
                max_tokens=max_tokens,
                temperature=temperature
            )
        elif provider == LLMProvider.AWS_BEDROCK:
            return self._generate_with_bedrock(
                model_id=model_id,
                prompt=prompt,
                max_tokens=max_tokens,
                temperature=temperature,
                region=region
            )
        else:
            return None

    def _generate_with_anthropic(
        self,
        model_id: str,
        prompt: str,
        max_tokens: int,
        temperature: float
    ) -> str:
        """Generate with Anthropic API."""
        import anthropic

        # Retrieve API key
        api_key = self.provider_manager.retrieve_api_key(
            user_id=self.user_id,
            provider=LLMProvider.ANTHROPIC
        )

        if not api_key:
            raise Exception('Anthropic API key not found')

        client = anthropic.Anthropic(api_key=api_key)

        response = client.messages.create(
            model=model_id,
            max_tokens=max_tokens,
            temperature=temperature,
            messages=[
                {"role": "user", "content": prompt}
            ]
        )

        return response.content[0].text

    def _generate_with_openai(
        self,
        model_id: str,
        prompt: str,
        max_tokens: int,
        temperature: float
    ) -> str:
        """Generate with OpenAI API."""
        import openai

        # Retrieve API key
        api_key = self.provider_manager.retrieve_api_key(
            user_id=self.user_id,
            provider=LLMProvider.OPENAI
        )

        if not api_key:
            raise Exception('OpenAI API key not found')

        client = openai.OpenAI(api_key=api_key)

        response = client.chat.completions.create(
            model=model_id,
            max_tokens=max_tokens,
            temperature=temperature,
            messages=[
                {"role": "user", "content": prompt}
            ]
        )

        return response.choices[0].message.content

    def _generate_with_google(
        self,
        model_id: str,
        prompt: str,
        max_tokens: int,
        temperature: float
    ) -> str:
        """Generate with Google Gemini API."""
        import google.generativeai as genai

        # Retrieve API key
        api_key = self.provider_manager.retrieve_api_key(
            user_id=self.user_id,
            provider=LLMProvider.GOOGLE
        )

        if not api_key:
            raise Exception('Google API key not found')

        genai.configure(api_key=api_key)

        model = genai.GenerativeModel(model_id)

        generation_config = {
            'max_output_tokens': max_tokens,
            'temperature': temperature
        }

        response = model.generate_content(
            prompt,
            generation_config=generation_config
        )

        return response.text

    def _generate_with_bedrock(
        self,
        prompt: str,
        max_tokens: int,
        temperature: float,
        model_id: Optional[str] = None,
        region: Optional[str] = None
    ) -> str:
        """Generate with AWS Bedrock."""
        import boto3
        import json

        region = region or os.environ.get('AWS_REGION', 'us-east-1')
        model_id = model_id or 'anthropic.claude-3-5-sonnet-20241022-v2:0'

        bedrock_runtime = boto3.client('bedrock-runtime', region_name=region)

        # Format request for Claude models on Bedrock
        body = json.dumps({
            "anthropic_version": "bedrock-2023-05-31",
            "max_tokens": max_tokens,
            "temperature": temperature,
            "messages": [
                {
                    "role": "user",
                    "content": prompt
                }
            ]
        })

        response = bedrock_runtime.invoke_model(
            modelId=model_id,
            body=body
        )

        response_body = json.loads(response['body'].read())

        return response_body['content'][0]['text']

    def get_usage_stats(self) -> Dict[str, Any]:
        """
        Get usage statistics for the user.

        Returns:
            Usage statistics dictionary
        """
        return self.provider_manager.get_usage_stats(self.user_id, days=30)

    def track_usage(
        self,
        provider: LLMProvider,
        model_id: str,
        input_tokens: int,
        output_tokens: int,
        cost_usd: float
    ):
        """
        Track LLM usage.

        Args:
            provider: Provider used
            model_id: Model ID
            input_tokens: Input token count
            output_tokens: Output token count
            cost_usd: Cost in USD
        """
        # This would be implemented to track usage in DynamoDB
        # For now, just log it
        print(f'LLM Usage - Provider: {provider.value}, Model: {model_id}, '
              f'Input: {input_tokens}, Output: {output_tokens}, Cost: ${cost_usd:.6f}')


def generate_sql_from_nlp(
    prompt: str,
    user_id: str,
    session_context=None
) -> Dict[str, Any]:
    """
    Generate SQL from natural language using user's configured LLM provider.

    This function integrates with the conversation API handler and uses
    the user's LLM settings.

    Args:
        prompt: Natural language prompt or context-aware prompt
        user_id: User ID for loading LLM settings
        session_context: Optional conversation session context

    Returns:
        Dictionary with generated SQL and execution metadata
    """
    try:
        # Create provider-based LLM client
        llm_client = ProviderBasedLLMClient(
            user_id=user_id,
            task_type='query_generation'
        )

        # Generate SQL using the configured provider
        response = llm_client.generate(
            prompt=prompt,
            max_tokens=2000,
            temperature=0.0
        )

        # Extract SQL from response
        import re

        # Try to extract SQL from code blocks
        code_block_pattern = r'```(?:sql)?\s*(SELECT.*?)```'
        match = re.search(code_block_pattern, response, re.IGNORECASE | re.DOTALL)

        if match:
            sql = match.group(1).strip()
        else:
            # Try to find SELECT statement directly
            select_pattern = r'(SELECT\s+.*?)(?:\n\n|$)'
            match = re.search(select_pattern, response, re.IGNORECASE | re.DOTALL)

            if match:
                sql = match.group(1).strip()
            else:
                # If response starts with SELECT, use entire response
                if response.strip().upper().startswith('SELECT'):
                    sql = response.strip()
                else:
                    raise Exception('Could not extract SQL from LLM response')

        return {
            'sql': sql,
            'execution_id': f'query-{user_id}-{int(os.times().elapsed * 1000)}',
            'llm_response': response
        }

    except Exception as e:
        print(f'Error generating SQL: {e}')
        raise
