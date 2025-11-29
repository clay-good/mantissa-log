"""
Self-Learning Detection Engineer

Analyzes detection rule performance and generates tuning recommendations.
Creates Jira tickets for HIGH CONFIDENCE suggestions only.
"""

from .config import TuningConfig
from .analyzer import TuningAnalyzer, AnalysisResult, TuningRecommendation
from .feedback import FeedbackTracker, FeedbackRecord

__all__ = [
    'TuningConfig',
    'TuningAnalyzer',
    'AnalysisResult',
    'TuningRecommendation',
    'FeedbackTracker',
    'FeedbackRecord',
]
