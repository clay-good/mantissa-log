"""
Enrichment Configuration

Defines configuration schema and defaults for LLM-enriched alerts.
"""

from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any


@dataclass
class EnrichmentConfig:
    """Configuration for alert enrichment."""

    # Master enable/disable
    enabled: bool = True

    # LLM model to use for enrichment
    llm_model: str = "claude-3-5-sonnet-20241022"

    # Which severities to enrich (others get basic enrichment only)
    enrich_severities: List[str] = field(
        default_factory=lambda: ["critical", "high", "medium"]
    )

    # Enrichment components to include
    include_five_w_one_h: bool = True
    include_behavioral_context: bool = True
    include_baseline_deviation: bool = True
    include_detection_explainer: bool = True
    include_recommended_actions: bool = True

    # Cost controls
    max_tokens_per_enrichment: int = 1500
    use_haiku_for_low_severity: bool = True
    haiku_model: str = "claude-3-haiku-20240307"

    # Behavioral baseline settings
    baseline_window_days: int = 30
    cache_behavioral_baselines: bool = True
    baseline_cache_ttl_hours: int = 24

    # Query limits for behavioral analysis
    max_historical_events_per_query: int = 1000

    # Skip enrichment if LLM call fails (use basic enrichment instead)
    fallback_on_error: bool = True

    # Timeout for LLM enrichment calls (seconds)
    enrichment_timeout_seconds: int = 30

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "EnrichmentConfig":
        """Create config from dictionary."""
        return cls(
            enabled=data.get("enabled", True),
            llm_model=data.get("llm_model", "claude-3-5-sonnet-20241022"),
            enrich_severities=data.get("enrich_severities", ["critical", "high", "medium"]),
            include_five_w_one_h=data.get("components", {}).get("five_w_one_h", True),
            include_behavioral_context=data.get("components", {}).get("behavioral_context", True),
            include_baseline_deviation=data.get("components", {}).get("baseline_deviation", True),
            include_detection_explainer=data.get("components", {}).get("detection_explainer", True),
            include_recommended_actions=data.get("components", {}).get("recommended_actions", True),
            max_tokens_per_enrichment=data.get("max_tokens_per_enrichment", 1500),
            use_haiku_for_low_severity=data.get("use_haiku_for_low_severity", True),
            baseline_window_days=data.get("baseline_window_days", 30),
            cache_behavioral_baselines=data.get("cache_behavioral_baselines", True),
            baseline_cache_ttl_hours=data.get("baseline_cache_ttl_hours", 24),
            max_historical_events_per_query=data.get("max_historical_events_per_query", 1000),
            fallback_on_error=data.get("fallback_on_error", True),
            enrichment_timeout_seconds=data.get("enrichment_timeout_seconds", 30),
        )

    def to_dict(self) -> Dict[str, Any]:
        """Convert config to dictionary."""
        return {
            "enabled": self.enabled,
            "llm_model": self.llm_model,
            "enrich_severities": self.enrich_severities,
            "components": {
                "five_w_one_h": self.include_five_w_one_h,
                "behavioral_context": self.include_behavioral_context,
                "baseline_deviation": self.include_baseline_deviation,
                "detection_explainer": self.include_detection_explainer,
                "recommended_actions": self.include_recommended_actions,
            },
            "max_tokens_per_enrichment": self.max_tokens_per_enrichment,
            "use_haiku_for_low_severity": self.use_haiku_for_low_severity,
            "baseline_window_days": self.baseline_window_days,
            "cache_behavioral_baselines": self.cache_behavioral_baselines,
            "baseline_cache_ttl_hours": self.baseline_cache_ttl_hours,
            "max_historical_events_per_query": self.max_historical_events_per_query,
            "fallback_on_error": self.fallback_on_error,
            "enrichment_timeout_seconds": self.enrichment_timeout_seconds,
        }

    def should_enrich_severity(self, severity: str) -> bool:
        """Check if the given severity level should be enriched."""
        return severity.lower() in [s.lower() for s in self.enrich_severities]

    def get_model_for_severity(self, severity: str) -> str:
        """Get the appropriate model based on severity."""
        if self.use_haiku_for_low_severity and severity.lower() in ["low", "info"]:
            return self.haiku_model
        return self.llm_model
