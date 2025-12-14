"""Mantissa Log detection engine for executing detection rules."""

from .engine import DetectionEngine, DetectionResult, QueryExecutor, AthenaQueryExecutor
from .rule import DetectionRule, RuleLoader, SigmaRuleValidator
from .state_manager import StateManager, InMemoryStateManager, DynamoDBStateManager, RedisStateManager
from .alert_generator import Alert, AlertGenerator
from .nl_to_sigma import NLToSigmaConverter, SigmaGenerationResult, create_sigma_from_query
from .sigma_validator import SigmaValidator, ValidationResult, validate_sigma_rule
from .rule_tester import RuleTester, RuleTestResult, test_sigma_rule
from .sigma_to_nl import SigmaToNLConverter, NLDescription, sigma_to_nl
from .metrics import (
    MetricsCalculator,
    MetricsPeriod,
    RuleMetrics,
    PortfolioMetrics,
    calculate_metrics,
    calculate_portfolio,
)
from .false_positive import (
    FalsePositiveTracker,
    FalsePositiveRecord,
    FPReason,
    FPStats,
    SuppressionRecommendation,
    mark_false_positive,
)
from .rule_optimizer import (
    RuleOptimizer,
    Optimization,
    OptimizationType,
    OptimizationStatus,
    RuleVersion,
    RollbackResult,
)
from .zero_alert import (
    ZeroAlertAnalyzer,
    ZeroAlertDiagnostic,
    ZeroAlertReport,
    ZeroAlertReason,
    LogSourceStatus,
    analyze_zero_alert_rules,
)
from .coverage import (
    CoverageAnalyzer,
    CoverageReport,
    CoverageGap,
    RuleCoverage,
    TechniqueMapping,
    Tactic,
    analyze_detection_coverage,
)

__all__ = [
    "DetectionEngine",
    "DetectionResult",
    "QueryExecutor",
    "AthenaQueryExecutor",
    "DetectionRule",
    "RuleLoader",
    "SigmaRuleValidator",
    "StateManager",
    "InMemoryStateManager",
    "DynamoDBStateManager",
    "RedisStateManager",
    "Alert",
    "AlertGenerator",
    # Natural Language to Sigma
    "NLToSigmaConverter",
    "SigmaGenerationResult",
    "create_sigma_from_query",
    # Sigma Validation
    "SigmaValidator",
    "ValidationResult",
    "validate_sigma_rule",
    # Rule Testing
    "RuleTester",
    "RuleTestResult",
    "test_sigma_rule",
    # Sigma to Natural Language
    "SigmaToNLConverter",
    "NLDescription",
    "sigma_to_nl",
    # Detection Metrics
    "MetricsCalculator",
    "MetricsPeriod",
    "RuleMetrics",
    "PortfolioMetrics",
    "calculate_metrics",
    "calculate_portfolio",
    # False Positive Tracking
    "FalsePositiveTracker",
    "FalsePositiveRecord",
    "FPReason",
    "FPStats",
    "SuppressionRecommendation",
    "mark_false_positive",
    # Rule Optimization
    "RuleOptimizer",
    "Optimization",
    "OptimizationType",
    "OptimizationStatus",
    "RuleVersion",
    "RollbackResult",
    # Zero-Alert Detection
    "ZeroAlertAnalyzer",
    "ZeroAlertDiagnostic",
    "ZeroAlertReport",
    "ZeroAlertReason",
    "LogSourceStatus",
    "analyze_zero_alert_rules",
    # MITRE ATT&CK Coverage Analysis
    "CoverageAnalyzer",
    "CoverageReport",
    "CoverageGap",
    "RuleCoverage",
    "TechniqueMapping",
    "Tactic",
    "analyze_detection_coverage",
]
