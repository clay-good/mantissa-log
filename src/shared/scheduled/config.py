"""
Configuration for Scheduled Intelligence Summaries.
"""

import os
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Any


@dataclass
class ScheduledQueryConfig:
    """Configuration for scheduled query execution."""

    # General settings
    enabled: bool = True
    max_queries_per_user: int = 20
    default_timezone: str = "UTC"

    # Execution settings
    max_execution_time_seconds: int = 300
    max_results_per_query: int = 1000
    max_summary_length: int = 4000  # Slack message limit

    # LLM settings for summarization
    use_llm_for_summary: bool = True
    llm_model: str = "claude-3-5-sonnet-20241022"
    max_tokens_for_summary: int = 1500
    temperature: float = 0.0

    # Slack settings
    slack_webhook_timeout: int = 30
    include_query_details: bool = True
    include_execution_stats: bool = True

    # Retry settings
    max_retries: int = 3
    retry_delay_seconds: int = 60

    # Storage settings
    table_name: str = ""
    history_retention_days: int = 90

    @classmethod
    def from_dict(cls, config_dict: Optional[Dict[str, Any]] = None) -> 'ScheduledQueryConfig':
        """Create config from dictionary."""
        if not config_dict:
            return cls()

        return cls(
            enabled=config_dict.get('enabled', True),
            max_queries_per_user=config_dict.get('max_queries_per_user', 20),
            default_timezone=config_dict.get('default_timezone', 'UTC'),
            max_execution_time_seconds=config_dict.get('max_execution_time_seconds', 300),
            max_results_per_query=config_dict.get('max_results_per_query', 1000),
            max_summary_length=config_dict.get('max_summary_length', 4000),
            use_llm_for_summary=config_dict.get('use_llm_for_summary', True),
            llm_model=config_dict.get('llm_model', 'claude-3-5-sonnet-20241022'),
            max_tokens_for_summary=config_dict.get('max_tokens_for_summary', 1500),
            temperature=config_dict.get('temperature', 0.0),
            slack_webhook_timeout=config_dict.get('slack_webhook_timeout', 30),
            include_query_details=config_dict.get('include_query_details', True),
            include_execution_stats=config_dict.get('include_execution_stats', True),
            max_retries=config_dict.get('max_retries', 3),
            retry_delay_seconds=config_dict.get('retry_delay_seconds', 60),
            table_name=config_dict.get('table_name', ''),
            history_retention_days=config_dict.get('history_retention_days', 90),
        )

    @classmethod
    def from_environment(cls) -> 'ScheduledQueryConfig':
        """Create config from environment variables."""
        return cls(
            enabled=os.environ.get('SCHEDULED_QUERIES_ENABLED', 'true').lower() == 'true',
            max_queries_per_user=int(os.environ.get('SCHEDULED_MAX_QUERIES_PER_USER', '20')),
            default_timezone=os.environ.get('SCHEDULED_DEFAULT_TIMEZONE', 'UTC'),
            max_execution_time_seconds=int(os.environ.get('SCHEDULED_MAX_EXECUTION_TIME', '300')),
            max_results_per_query=int(os.environ.get('SCHEDULED_MAX_RESULTS', '1000')),
            use_llm_for_summary=os.environ.get('SCHEDULED_USE_LLM', 'true').lower() == 'true',
            llm_model=os.environ.get('SCHEDULED_LLM_MODEL', 'claude-3-5-sonnet-20241022'),
            table_name=os.environ.get('SCHEDULED_QUERIES_TABLE', 'mantissa-log-scheduled-queries'),
        )

    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary."""
        return {
            'enabled': self.enabled,
            'max_queries_per_user': self.max_queries_per_user,
            'default_timezone': self.default_timezone,
            'max_execution_time_seconds': self.max_execution_time_seconds,
            'max_results_per_query': self.max_results_per_query,
            'max_summary_length': self.max_summary_length,
            'use_llm_for_summary': self.use_llm_for_summary,
            'llm_model': self.llm_model,
            'max_tokens_for_summary': self.max_tokens_for_summary,
            'temperature': self.temperature,
            'slack_webhook_timeout': self.slack_webhook_timeout,
            'include_query_details': self.include_query_details,
            'include_execution_stats': self.include_execution_stats,
            'max_retries': self.max_retries,
            'retry_delay_seconds': self.retry_delay_seconds,
            'table_name': self.table_name,
            'history_retention_days': self.history_retention_days,
        }
