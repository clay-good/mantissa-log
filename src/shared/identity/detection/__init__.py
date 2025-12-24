"""Identity detection subpackage - re-exports from detections for compatibility.

This package aliases the 'detections' subpackage to 'detection' for
backwards compatibility with test imports.
"""

from ..detections import (
    BruteForceDetector,
    CredentialStuffingDetector,
    PasswordSprayDetector,
    MFADetector,
    ImpossibleTravelDetector,
    UnusualTimeDetector,
    NewAccessDetector,
    VolumeDetector as VolumeAnomalyDetector,
    PrivilegeDetector as PrivilegeEscalationDetector,
    SessionHijackDetector,
    TokenDetector as TokenTheftDetector,
    DormantAccountDetector,
)
from ..anomaly_detector import IdentityAnomalyDetector
from ..travel_analyzer import ImpossibleTravelAnalyzer

__all__ = [
    "BruteForceDetector",
    "CredentialStuffingDetector",
    "PasswordSprayDetector",
    "MFADetector",
    "ImpossibleTravelDetector",
    "UnusualTimeDetector",
    "NewAccessDetector",
    "VolumeAnomalyDetector",
    "PrivilegeEscalationDetector",
    "SessionHijackDetector",
    "TokenTheftDetector",
    "DormantAccountDetector",
    "IdentityAnomalyDetector",
    "ImpossibleTravelAnalyzer",
]
