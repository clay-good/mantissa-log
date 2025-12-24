"""APM (Application Performance Monitoring) module.

This module provides service map generation, trace analysis, APM metrics
functionality, and detection for the Observability feature.

Components:
- ServiceMapGenerator: Generate service dependency graphs from trace data
- APMDetector: Detect APM anomalies (latency spikes, error rates, etc.)
- APMRule: APM-specific detection rule
- APMDetectionResult: Result of APM detection evaluation
"""

from .service_map import ServiceMapGenerator
from .apm_detector import APMDetector, APMRule, APMDetectionResult

__all__ = [
    "ServiceMapGenerator",
    "APMDetector",
    "APMRule",
    "APMDetectionResult",
]
