"""Identity threat detection and response components for Mantissa Log.

This package provides:
- Session tracking and management
- User behavioral baselines
- Session anomaly detection
- Cross-provider correlation
- Anomaly detection algorithms
- Travel analysis
- Risk scoring engine
"""

from .session_store import (
    UserSession,
    ConcurrentSessionAlert,
    SessionAnomaly,
    AnomalyType,
    SessionStore,
    InMemorySessionStore,
)
from .session_tracker import SessionTracker
from .user_baseline import IdentityBaseline
from .baseline_calculator import BaselineCalculator
from .baseline_store import (
    BaselineStore,
    InMemoryBaselineStore,
)
from .anomaly_types import (
    IdentityAnomalyType,
    AnomalySeverity,
    IdentityAnomaly,
    get_recommended_action,
    get_default_severity,
)
from .travel_analyzer import (
    GeoUtils,
    ImpossibleTravelAnalyzer,
    TravelAnalysisResult,
)
from .anomaly_detector import IdentityAnomalyDetector
from .risk_models import (
    RiskFactorType,
    RiskLevel,
    RiskTrend,
    SessionAction,
    RiskFactor,
    UserRiskScore,
    SessionRiskScore,
    EventRiskScore,
    RiskScoringConfig,
)
from .risk_scorer import IdentityRiskScorer
from .correlation import (
    IdentityAttackType,
    IdentityCorrelationType,
    IdentityIncident,
    IdentityCorrelator,
    IdentityKillChainStage,
    KillChainIncident,
    KillChainDetector,
    CrossProviderIncident,
    CrossProviderCorrelator,
)
from .enrichment import (
    IdentityAlertEnricher,
    BehaviorSummaryGenerator,
    UserBehaviorSummary,
    PeerGroupAnalyzer,
    PeerComparison,
    PeerDeviation,
    PeerAlertComparison,
)
from .templates import (
    AlertTemplate,
    RenderedAlert,
    IdentityAlertTemplates,
    SlackTemplateRenderer,
    EmailTemplateRenderer,
)
from .escalation import (
    EscalationConfig,
    EscalationRule,
    SeverityLevel,
    EscalationResult,
    SeverityEscalator,
)
from .response import (
    ResponseAction,
    ResponseActionConfig,
    ResponseActionResult,
    ResponseEngine,
    IdentityProviderActions,
    OktaActions,
    AzureActions,
    GoogleWorkspaceActions,
    DuoActions,
)


# Cloud implementations - imported lazily to avoid requiring cloud SDKs
def get_dynamodb_session_store(*args, **kwargs):
    """Get DynamoDB session store (AWS)."""
    from .session_store_dynamodb import DynamoDBSessionStore
    return DynamoDBSessionStore(*args, **kwargs)


def get_firestore_session_store(*args, **kwargs):
    """Get Firestore session store (GCP)."""
    from .session_store_firestore import FirestoreSessionStore
    return FirestoreSessionStore(*args, **kwargs)


def get_cosmos_session_store(*args, **kwargs):
    """Get Cosmos DB session store (Azure)."""
    from .session_store_cosmos import CosmosSessionStore
    return CosmosSessionStore(*args, **kwargs)


def get_dynamodb_baseline_store(*args, **kwargs):
    """Get DynamoDB baseline store (AWS)."""
    from .baseline_store import DynamoDBBaselineStore
    return DynamoDBBaselineStore(*args, **kwargs)


def get_firestore_baseline_store(*args, **kwargs):
    """Get Firestore baseline store (GCP)."""
    from .baseline_store import FirestoreBaselineStore
    return FirestoreBaselineStore(*args, **kwargs)


def get_cosmos_baseline_store(*args, **kwargs):
    """Get Cosmos DB baseline store (Azure)."""
    from .baseline_store import CosmosBaselineStore
    return CosmosBaselineStore(*args, **kwargs)


__all__ = [
    # Session tracking
    "UserSession",
    "ConcurrentSessionAlert",
    "SessionAnomaly",
    "AnomalyType",
    "SessionStore",
    "InMemorySessionStore",
    "SessionTracker",
    # Baseline management
    "IdentityBaseline",
    "BaselineCalculator",
    "BaselineStore",
    "InMemoryBaselineStore",
    # Anomaly detection
    "IdentityAnomalyType",
    "AnomalySeverity",
    "IdentityAnomaly",
    "get_recommended_action",
    "get_default_severity",
    "GeoUtils",
    "ImpossibleTravelAnalyzer",
    "TravelAnalysisResult",
    "IdentityAnomalyDetector",
    # Risk scoring
    "RiskFactorType",
    "RiskLevel",
    "RiskTrend",
    "SessionAction",
    "RiskFactor",
    "UserRiskScore",
    "SessionRiskScore",
    "EventRiskScore",
    "RiskScoringConfig",
    "IdentityRiskScorer",
    # Cloud store factories
    "get_dynamodb_session_store",
    "get_firestore_session_store",
    "get_cosmos_session_store",
    "get_dynamodb_baseline_store",
    "get_firestore_baseline_store",
    "get_cosmos_baseline_store",
    # Correlation
    "IdentityAttackType",
    "IdentityCorrelationType",
    "IdentityIncident",
    "IdentityCorrelator",
    # Kill chain
    "IdentityKillChainStage",
    "KillChainIncident",
    "KillChainDetector",
    # Cross-provider
    "CrossProviderIncident",
    "CrossProviderCorrelator",
    # Enrichment
    "IdentityAlertEnricher",
    "BehaviorSummaryGenerator",
    "UserBehaviorSummary",
    # Peer comparison
    "PeerGroupAnalyzer",
    "PeerComparison",
    "PeerDeviation",
    "PeerAlertComparison",
    # Alert templates
    "AlertTemplate",
    "RenderedAlert",
    "IdentityAlertTemplates",
    "SlackTemplateRenderer",
    "EmailTemplateRenderer",
    # Severity escalation
    "EscalationConfig",
    "EscalationRule",
    "SeverityLevel",
    "EscalationResult",
    "SeverityEscalator",
    # Response actions
    "ResponseAction",
    "ResponseActionConfig",
    "ResponseActionResult",
    "ResponseEngine",
    "IdentityProviderActions",
    "OktaActions",
    "AzureActions",
    "GoogleWorkspaceActions",
    "DuoActions",
]
