"""Mantissa Log parser library for normalizing log data from various sources."""

from .base import ParsedEvent, Parser, ParserError
from .registry import ParserRegistry, get_parser, list_parsers, register_parser

# Import parsers for registry auto-registration
from .cloudtrail import CloudTrailParser
from .vpc_flow import VPCFlowParser
from .guardduty import GuardDutyParser
from .okta import OktaParser
from .google_workspace import GoogleWorkspaceParser
from .crowdstrike import CrowdStrikeParser
from .kubernetes import KubernetesParser
from .slack import SlackParser
from .microsoft365 import Microsoft365Parser
from .github import GitHubParser
from .duo import DuoParser

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
    "VPCFlowParser",
    "GuardDutyParser",
    "OktaParser",
    "GoogleWorkspaceParser",
    "CrowdStrikeParser",
    "KubernetesParser",
    "SlackParser",
    "Microsoft365Parser",
    "GitHubParser",
    "DuoParser",
]
