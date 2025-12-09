"""
Mantissa Log - Azure Function Apps

This package contains Azure Functions for:
- Data collectors (12 sources in collectors/ subdirectory)
- LLM Query function (llm_query/)
- Detection Engine (detection_engine/)
- Alert Router (alert_router/)

Collector implementations are in separate subdirectories under collectors/.
Each collector is deployed as a separate Azure Function App for isolation.
"""

# Export collector modules for programmatic access
from .collectors.okta import main as okta_collector
from .collectors.github import main as github_collector
from .collectors.slack import main as slack_collector
from .collectors.microsoft365 import main as microsoft365_collector
from .collectors.crowdstrike import main as crowdstrike_collector
from .collectors.duo import main as duo_collector
from .collectors.google_workspace import main as google_workspace_collector
from .collectors.salesforce import main as salesforce_collector
from .collectors.snowflake import main as snowflake_collector
from .collectors.jamf import main as jamf_collector
from .collectors.onepassword import main as onepassword_collector
from .collectors.azure_monitor import main as azure_monitor_collector

__all__ = [
    "okta_collector",
    "github_collector",
    "slack_collector",
    "microsoft365_collector",
    "crowdstrike_collector",
    "duo_collector",
    "google_workspace_collector",
    "salesforce_collector",
    "snowflake_collector",
    "jamf_collector",
    "onepassword_collector",
    "azure_monitor_collector",
]
