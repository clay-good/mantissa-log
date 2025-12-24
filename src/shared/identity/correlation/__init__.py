"""Identity-specific correlation and incident management.

This package provides identity-focused alert correlation capabilities
that extend the base AlertCorrelator with identity attack patterns:
- Same target user correlation
- Same attacker IP correlation
- Credential attack chain detection
- Account takeover chain detection
- Lateral movement detection
- Kill chain progression detection
- Cross-provider attack correlation
"""

from .identity_incident import (
    IdentityAttackType,
    IdentityCorrelationType,
    IdentityIncident,
)
from .identity_correlator import IdentityCorrelator
from .identity_kill_chain import (
    IdentityKillChainStage,
    KillChainIncident,
    KillChainDetector,
    KILL_CHAIN_SEQUENCE,
    STAGE_SEVERITY,
    STAGE_RESPONSES,
)
from .cross_provider_correlator import (
    CrossProviderIncident,
    CrossProviderCorrelator,
    SUPPORTED_PROVIDERS,
)

__all__ = [
    "IdentityAttackType",
    "IdentityCorrelationType",
    "IdentityIncident",
    "IdentityCorrelator",
    "IdentityKillChainStage",
    "KillChainIncident",
    "KillChainDetector",
    "KILL_CHAIN_SEQUENCE",
    "STAGE_SEVERITY",
    "STAGE_RESPONSES",
    "CrossProviderIncident",
    "CrossProviderCorrelator",
    "SUPPORTED_PROVIDERS",
]
