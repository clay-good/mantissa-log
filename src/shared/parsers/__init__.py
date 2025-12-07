"""Mantissa Log parser library for normalizing log data from various sources."""

from .base import ParsedEvent, Parser, ParserError
from .registry import ParserRegistry, get_parser, list_parsers, register_parser

# Import parsers for registry auto-registration
from .cloudtrail import CloudTrailParser
from .vpc_flow import VPCFlowLogsParser
from .guardduty import GuardDutyParser
from .okta import OktaParser
from .google_workspace import GoogleWorkspaceParser
from .crowdstrike import CrowdStrikeParser
from .kubernetes import KubernetesParser
from .slack import SlackParser
from .microsoft365 import Microsoft365Parser
from .github import GitHubParser
from .duo import DuoParser
from .docker import DockerParser
from .salesforce import SalesforceParser
from .snowflake import SnowflakeParser
from .jamf import JamfParser
from .onepassword import OnePasswordParser
from .azure_monitor import AzureMonitorParser
from .gcp_logging import GCPLoggingParser

__all__ = [
    "ParsedEvent",
    "Parser",
    "ParserError",
    "ParserRegistry",
    "get_parser",
    "list_parsers",
    "register_parser",
    # Parsers
    "CloudTrailParser",
    "VPCFlowLogsParser",
    "GuardDutyParser",
    "OktaParser",
    "GoogleWorkspaceParser",
    "CrowdStrikeParser",
    "KubernetesParser",
    "SlackParser",
    "Microsoft365Parser",
    "GitHubParser",
    "DuoParser",
    "DockerParser",
    "SalesforceParser",
    "SnowflakeParser",
    "JamfParser",
    "OnePasswordParser",
    "AzureMonitorParser",
    "GCPLoggingParser",
]
