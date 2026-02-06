"""Log source health monitoring for Mantissa Log."""

from .log_source_health import (
    LogSourceHealthConfig,
    LogSourceHealthState,
    LogSourceStatus,
    DEFAULT_HEALTH_CONFIGS,
)
from .health_state_store import (
    HealthStateStore,
    InMemoryHealthStateStore,
    DynamoDBHealthStateStore,
    FirestoreHealthStateStore,
    CosmosHealthStateStore,
)
from .health_check_engine import (
    HealthCheckEngine,
    HealthCheckResult,
)

__all__ = [
    # Data model (Step 1)
    "LogSourceHealthConfig",
    "LogSourceHealthState",
    "LogSourceStatus",
    "DEFAULT_HEALTH_CONFIGS",
    # State storage backends (Step 2)
    "HealthStateStore",
    "InMemoryHealthStateStore",
    "DynamoDBHealthStateStore",
    "FirestoreHealthStateStore",
    "CosmosHealthStateStore",
    # Health check engine (Step 3)
    "HealthCheckEngine",
    "HealthCheckResult",
]
