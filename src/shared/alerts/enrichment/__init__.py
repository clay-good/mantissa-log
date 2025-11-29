"""
Alert Enrichment Module

Provides LLM-powered alert enrichment with:
- 5W1H Summary (Who, What, When, Where, Why, How)
- Behavioral Context Analysis
- Baseline Deviation Detection
- Detection Explainer
- Recommended Actions
"""

from .enricher import AlertEnricher, EnrichmentConfig
from .behavioral import BehavioralAnalyzer
from .prompts import EnrichmentPromptBuilder

__all__ = [
    'AlertEnricher',
    'EnrichmentConfig',
    'BehavioralAnalyzer',
    'EnrichmentPromptBuilder',
]
