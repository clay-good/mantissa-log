"""
Scheduled Intelligence Summaries Module

Provides scheduled NL query execution with Slack output for report-like
functionality without dashboards.
"""

from .config import ScheduledQueryConfig
from .manager import ScheduledQueryManager, ScheduledQuery
from .executor import ScheduledQueryExecutor
from .formatters import SlackSummaryFormatter

__all__ = [
    'ScheduledQueryConfig',
    'ScheduledQueryManager',
    'ScheduledQuery',
    'ScheduledQueryExecutor',
    'SlackSummaryFormatter',
]
