"""Kill chain detector - re-export for package compatibility."""

from .identity_kill_chain import (
    IdentityKillChainStage,
    KillChainIncident,
    KillChainDetector,
    KILL_CHAIN_SEQUENCE,
    STAGE_SEVERITY,
    STAGE_RESPONSES,
)

__all__ = [
    "IdentityKillChainStage",
    "KillChainIncident",
    "KillChainDetector",
    "KILL_CHAIN_SEQUENCE",
    "STAGE_SEVERITY",
    "STAGE_RESPONSES",
]
