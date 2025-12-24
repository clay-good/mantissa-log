"""Auto-response actions for identity alerts (Pre-SOAR).

This package provides automated response capabilities for identity threats,
preparing for future SOAR integration. Actions are designed to be:
- Safe (can be undone)
- Logged for audit
- Configurable with approval workflows
"""

from .response_actions import (
    ResponseAction,
    ResponseActionConfig,
    ResponseActionResult,
    DEFAULT_RESPONSE_CONFIGS,
)
from .response_engine import ResponseEngine
from .provider_actions import (
    IdentityProviderActions,
    OktaActions,
    AzureActions,
    GoogleWorkspaceActions,
    DuoActions,
)

__all__ = [
    "ResponseAction",
    "ResponseActionConfig",
    "ResponseActionResult",
    "DEFAULT_RESPONSE_CONFIGS",
    "ResponseEngine",
    "IdentityProviderActions",
    "OktaActions",
    "AzureActions",
    "GoogleWorkspaceActions",
    "DuoActions",
]
