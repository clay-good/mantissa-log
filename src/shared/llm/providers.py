"""
LLM Provider Adapters

Unified interface for multiple LLM providers (Anthropic, OpenAI, Google, AWS Bedrock).
"""

import os
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Dict, Any, List, Optional
import json


@dataclass
class LLMUsage:
    """LLM usage metrics."""
    input_tokens: int
    output_tokens: int
    total_tokens: int
    cost_usd: float
    latency_ms: float
    model: str
    provider: str


@dataclass
class LLMResponse:
    """Standardized LLM response."""
    content: str
    usage: LLMUsage
    model: str
    provider: str
    raw_response: Dict[str, Any]


class LLMProvider(ABC):
    """Base class for LLM providers."""
    
    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key
    
    @abstractmethod
    def generate(
        self,
        prompt: str,
        max_tokens: int = 2000,
        temperature: float = 0.0,
        model: Optional[str] = None
    ) -> LLMResponse:
        """Generate completion from prompt."""
        pass
    
    @abstractmethod
    def get_pricing(self, model: str) -> Dict[str, float]:
        """Get pricing per 1M tokens."""
        pass
    
    @abstractmethod
    def list_models(self) -> List[str]:
        """List available models."""
        pass


class AnthropicProvider(LLMProvider):
    """Anthropic Claude provider."""
    
    PRICING = {
        'claude-3-5-sonnet-20241022': {
            'input': 3.00,   # per 1M tokens
            'output': 15.00
        },
        'claude-3-5-haiku-20241022': {
            'input': 0.80,
            'output': 4.00
        },
        'claude-3-opus-20240229': {
            'input': 15.00,
            'output': 75.00
        }
    }
    
    def __init__(self, api_key: Optional[str] = None):
        super().__init__(api_key)
        import anthropic
        self.client = anthropic.Anthropic(api_key=api_key)
    
    def generate(
        self,
        prompt: str,
        max_tokens: int = 2000,
        temperature: float = 0.0,
        model: Optional[str] = None
    ) -> LLMResponse:
        """Generate completion using Claude."""
        import time
        
        model = model or 'claude-3-5-sonnet-20241022'
        
        start = time.time()
        response = self.client.messages.create(
            model=model,
            max_tokens=max_tokens,
            temperature=temperature,
            messages=[{"role": "user", "content": prompt}]
        )
        latency = (time.time() - start) * 1000
        
        # Calculate usage
        input_tokens = response.usage.input_tokens
        output_tokens = response.usage.output_tokens
        total_tokens = input_tokens + output_tokens
        
        pricing = self.PRICING.get(model, self.PRICING['claude-3-5-sonnet-20241022'])
        cost = (
            (input_tokens / 1_000_000) * pricing['input'] +
            (output_tokens / 1_000_000) * pricing['output']
        )
        
        usage = LLMUsage(
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            total_tokens=total_tokens,
            cost_usd=cost,
            latency_ms=round(latency, 2),
            model=model,
            provider='anthropic'
        )
        
        return LLMResponse(
            content=response.content[0].text,
            usage=usage,
            model=model,
            provider='anthropic',
            raw_response=response.model_dump()
        )
    
    def get_pricing(self, model: str) -> Dict[str, float]:
        """Get pricing per 1M tokens."""
        return self.PRICING.get(model, self.PRICING['claude-3-5-sonnet-20241022'])
    
    def list_models(self) -> List[str]:
        """List available Claude models."""
        return list(self.PRICING.keys())


class OpenAIProvider(LLMProvider):
    """OpenAI GPT provider."""
    
    PRICING = {
        'gpt-4-turbo': {
            'input': 10.00,
            'output': 30.00
        },
        'gpt-4': {
            'input': 30.00,
            'output': 60.00
        },
        'gpt-3.5-turbo': {
            'input': 0.50,
            'output': 1.50
        }
    }
    
    def __init__(self, api_key: Optional[str] = None):
        super().__init__(api_key)
        import openai
        self.client = openai.OpenAI(api_key=api_key)
    
    def generate(
        self,
        prompt: str,
        max_tokens: int = 2000,
        temperature: float = 0.0,
        model: Optional[str] = None
    ) -> LLMResponse:
        """Generate completion using GPT."""
        import time
        
        model = model or 'gpt-4-turbo'
        
        start = time.time()
        response = self.client.chat.completions.create(
            model=model,
            max_tokens=max_tokens,
            temperature=temperature,
            messages=[{"role": "user", "content": prompt}]
        )
        latency = (time.time() - start) * 1000
        
        # Calculate usage
        input_tokens = response.usage.prompt_tokens
        output_tokens = response.usage.completion_tokens
        total_tokens = response.usage.total_tokens
        
        pricing = self.PRICING.get(model, self.PRICING['gpt-4-turbo'])
        cost = (
            (input_tokens / 1_000_000) * pricing['input'] +
            (output_tokens / 1_000_000) * pricing['output']
        )
        
        usage = LLMUsage(
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            total_tokens=total_tokens,
            cost_usd=cost,
            latency_ms=round(latency, 2),
            model=model,
            provider='openai'
        )
        
        return LLMResponse(
            content=response.choices[0].message.content,
            usage=usage,
            model=model,
            provider='openai',
            raw_response=response.model_dump()
        )
    
    def get_pricing(self, model: str) -> Dict[str, float]:
        """Get pricing per 1M tokens."""
        return self.PRICING.get(model, self.PRICING['gpt-4-turbo'])
    
    def list_models(self) -> List[str]:
        """List available GPT models."""
        return list(self.PRICING.keys())


class GoogleProvider(LLMProvider):
    """Google Gemini provider."""
    
    PRICING = {
        'gemini-pro': {
            'input': 0.50,
            'output': 1.50
        },
        'gemini-1.5-pro': {
            'input': 3.50,
            'output': 10.50
        }
    }
    
    def __init__(self, api_key: Optional[str] = None):
        super().__init__(api_key)
        import google.generativeai as genai
        genai.configure(api_key=api_key)
        self.genai = genai
    
    def generate(
        self,
        prompt: str,
        max_tokens: int = 2000,
        temperature: float = 0.0,
        model: Optional[str] = None
    ) -> LLMResponse:
        """Generate completion using Gemini."""
        import time
        
        model_name = model or 'gemini-pro'
        model_obj = self.genai.GenerativeModel(model_name)
        
        start = time.time()
        response = model_obj.generate_content(
            prompt,
            generation_config={
                'max_output_tokens': max_tokens,
                'temperature': temperature
            }
        )
        latency = (time.time() - start) * 1000
        
        # Estimate tokens (Gemini doesn't provide exact counts)
        input_tokens = len(prompt.split()) * 1.3  # Rough estimate
        output_tokens = len(response.text.split()) * 1.3
        total_tokens = int(input_tokens + output_tokens)
        
        pricing = self.PRICING.get(model_name, self.PRICING['gemini-pro'])
        cost = (
            (input_tokens / 1_000_000) * pricing['input'] +
            (output_tokens / 1_000_000) * pricing['output']
        )
        
        usage = LLMUsage(
            input_tokens=int(input_tokens),
            output_tokens=int(output_tokens),
            total_tokens=total_tokens,
            cost_usd=cost,
            latency_ms=round(latency, 2),
            model=model_name,
            provider='google'
        )
        
        return LLMResponse(
            content=response.text,
            usage=usage,
            model=model_name,
            provider='google',
            raw_response={'text': response.text}
        )
    
    def get_pricing(self, model: str) -> Dict[str, float]:
        """Get pricing per 1M tokens."""
        return self.PRICING.get(model, self.PRICING['gemini-pro'])
    
    def list_models(self) -> List[str]:
        """List available Gemini models."""
        return list(self.PRICING.keys())


class BedrockProvider(LLMProvider):
    """AWS Bedrock provider (uses Claude via Bedrock)."""
    
    PRICING = {
        'anthropic.claude-3-5-sonnet-20241022-v2:0': {
            'input': 3.00,
            'output': 15.00
        },
        'anthropic.claude-3-5-haiku-20241022-v1:0': {
            'input': 0.80,
            'output': 4.00
        },
        'anthropic.claude-3-opus-20240229-v1:0': {
            'input': 15.00,
            'output': 75.00
        }
    }
    
    def __init__(self, api_key: Optional[str] = None):
        super().__init__(api_key)
        import boto3
        self.client = boto3.client('bedrock-runtime')
    
    def generate(
        self,
        prompt: str,
        max_tokens: int = 2000,
        temperature: float = 0.0,
        model: Optional[str] = None
    ) -> LLMResponse:
        """Generate completion using Bedrock."""
        import time
        
        model = model or 'anthropic.claude-3-5-sonnet-20241022-v2:0'
        
        request_body = {
            'anthropic_version': 'bedrock-2023-05-31',
            'max_tokens': max_tokens,
            'temperature': temperature,
            'messages': [
                {'role': 'user', 'content': prompt}
            ]
        }
        
        start = time.time()
        response = self.client.invoke_model(
            modelId=model,
            body=json.dumps(request_body)
        )
        latency = (time.time() - start) * 1000
        
        response_body = json.loads(response['body'].read())
        
        # Calculate usage
        input_tokens = response_body['usage']['input_tokens']
        output_tokens = response_body['usage']['output_tokens']
        total_tokens = input_tokens + output_tokens
        
        pricing = self.PRICING.get(model, self.PRICING['anthropic.claude-3-5-sonnet-20241022-v2:0'])
        cost = (
            (input_tokens / 1_000_000) * pricing['input'] +
            (output_tokens / 1_000_000) * pricing['output']
        )
        
        usage = LLMUsage(
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            total_tokens=total_tokens,
            cost_usd=cost,
            latency_ms=round(latency, 2),
            model=model,
            provider='bedrock'
        )
        
        return LLMResponse(
            content=response_body['content'][0]['text'],
            usage=usage,
            model=model,
            provider='bedrock',
            raw_response=response_body
        )
    
    def get_pricing(self, model: str) -> Dict[str, float]:
        """Get pricing per 1M tokens."""
        return self.PRICING.get(model, self.PRICING['anthropic.claude-3-5-sonnet-20241022-v2:0'])
    
    def list_models(self) -> List[str]:
        """List available Bedrock models."""
        return list(self.PRICING.keys())


class LLMProviderFactory:
    """Factory for creating LLM providers."""
    
    @staticmethod
    def create(
        provider: str,
        api_key: Optional[str] = None
    ) -> LLMProvider:
        """Create LLM provider instance."""
        if provider == 'anthropic':
            return AnthropicProvider(api_key)
        elif provider == 'openai':
            return OpenAIProvider(api_key)
        elif provider == 'google':
            return GoogleProvider(api_key)
        elif provider == 'bedrock':
            return BedrockProvider(api_key)
        else:
            raise ValueError(f"Unknown provider: {provider}")
    
    @staticmethod
    def get_all_providers() -> List[str]:
        """Get list of all supported providers."""
        return ['anthropic', 'openai', 'google', 'bedrock']
