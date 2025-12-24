"""Anomaly detector - re-export for package compatibility."""

from ..anomaly_detector import IdentityAnomalyDetector
from ..travel_analyzer import ImpossibleTravelAnalyzer

__all__ = ["IdentityAnomalyDetector", "ImpossibleTravelAnalyzer"]
