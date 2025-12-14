"""Context enrichment for security alerts.

Provides IP geolocation, threat intelligence, user context, asset context,
and behavioral baseline analysis.
"""

from .geolocation import (
    GeoIPService,
    GeoLocation,
    get_geolocation,
)
from .threat_intel import (
    ThreatIntelService,
    ThreatIntelResult,
    lookup_ip_reputation,
    lookup_hash,
    lookup_domain,
)
from .user_context import (
    UserContextService,
    UserContext,
    get_user_context,
)
from .asset_context import (
    AssetContextService,
    AssetContext,
    get_asset_context,
)
from .behavioral import (
    BehavioralAnalyzer,
    BehavioralAnalysisResult,
    BehavioralDeviation,
    UserBaseline,
    AssetBaseline,
    DeviationType,
    RiskLevel,
    BaselineStore,
    InMemoryBaselineStore,
    DynamoDBBaselineStore,
    enrich_with_behavioral_analysis,
)

__all__ = [
    # Geolocation
    "GeoIPService",
    "GeoLocation",
    "get_geolocation",
    # Threat Intelligence
    "ThreatIntelService",
    "ThreatIntelResult",
    "lookup_ip_reputation",
    "lookup_hash",
    "lookup_domain",
    # User Context
    "UserContextService",
    "UserContext",
    "get_user_context",
    # Asset Context
    "AssetContextService",
    "AssetContext",
    "get_asset_context",
    # Behavioral Analysis
    "BehavioralAnalyzer",
    "BehavioralAnalysisResult",
    "BehavioralDeviation",
    "UserBaseline",
    "AssetBaseline",
    "DeviationType",
    "RiskLevel",
    "BaselineStore",
    "InMemoryBaselineStore",
    "DynamoDBBaselineStore",
    "enrich_with_behavioral_analysis",
]
