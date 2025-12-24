"""Travel analyzer - re-export for package compatibility."""

from ..travel_analyzer import (
    GeoUtils,
    ImpossibleTravelAnalyzer,
    TravelAnalysisResult,
)

__all__ = ["GeoUtils", "ImpossibleTravelAnalyzer", "TravelAnalysisResult"]
