"""Query executor implementations for multi-cloud support."""

from .base import (
    QueryExecutor,
    QueryResult,
    QueryMetrics,
    QueryExecutionError,
    QueryValidationError,
    QueryTimeoutError
)
from .athena import AthenaQueryExecutor
from .bigquery import BigQueryExecutor
from .synapse import SynapseExecutor
from .config import (
    CloudProvider,
    CloudProviderConfig,
    AWSConfig,
    GCPConfig,
    AzureConfig,
    create_executor_from_config
)

__all__ = [
    # Base classes and exceptions
    "QueryExecutor",
    "QueryResult",
    "QueryMetrics",
    "QueryExecutionError",
    "QueryValidationError",
    "QueryTimeoutError",

    # Executor implementations
    "AthenaQueryExecutor",
    "BigQueryExecutor",
    "SynapseExecutor",

    # Configuration
    "CloudProvider",
    "CloudProviderConfig",
    "AWSConfig",
    "GCPConfig",
    "AzureConfig",
    "create_executor_from_config",
]
