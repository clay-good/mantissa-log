"""Identity-specific alert enrichment.

This package provides enrichment capabilities for identity alerts,
adding context such as:
- User risk scores and risk factors
- Baseline comparison and deviation analysis
- Session context and concurrent session warnings
- User profile information
- Historical alert context
- Human-readable behavior summaries
- Peer group comparison for outlier detection
"""

from .identity_enricher import IdentityAlertEnricher
from .behavior_summary import (
    BehaviorSummaryGenerator,
    UserBehaviorSummary,
)
from .peer_comparison import (
    PeerGroupAnalyzer,
    PeerComparison,
    PeerDeviation,
    PeerAlertComparison,
)

__all__ = [
    "IdentityAlertEnricher",
    "BehaviorSummaryGenerator",
    "UserBehaviorSummary",
    "PeerGroupAnalyzer",
    "PeerComparison",
    "PeerDeviation",
    "PeerAlertComparison",
]
