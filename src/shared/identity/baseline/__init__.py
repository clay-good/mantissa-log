"""Baseline calculation and storage subpackage.

This subpackage provides user behavioral baseline functionality:
- UserBaseline: Data model for user behavioral baselines
- BaselineCalculator: Calculate baselines from historical events
- BaselineStore: Abstract storage for baselines
- BaselineBuilder: Build baselines from event streams (alias for compatibility)
"""

# Re-export from parent module for backwards compatibility
from ..user_baseline import IdentityBaseline as UserBaseline
from ..baseline_calculator import BaselineCalculator
from ..baseline_store import (
    BaselineStore,
    InMemoryBaselineStore,
    DynamoDBBaselineStore,
    FirestoreBaselineStore,
    CosmosBaselineStore,
)
from ..baseline_service import BaselineService

# BaselineBuilder is an alias for BaselineCalculator for test compatibility
BaselineBuilder = BaselineCalculator

__all__ = [
    "UserBaseline",
    "BaselineCalculator",
    "BaselineBuilder",
    "BaselineStore",
    "InMemoryBaselineStore",
    "DynamoDBBaselineStore",
    "FirestoreBaselineStore",
    "CosmosBaselineStore",
    "BaselineService",
]
