"""Identity-specific detection modules for ITDR.

This package provides specialized detection logic for identity threats
that go beyond simple Sigma rules, including:
- Cross-provider correlation
- Behavioral pattern detection
- Attack chain identification
- Privilege escalation detection
- Session hijacking detection
- Token theft and OAuth abuse detection
- Dormant account activation detection
"""

from .brute_force_detector import BruteForceDetector
from .credential_stuffing_detector import CredentialStuffingDetector
from .dormant_detector import DormantAccountDetector
from .impossible_travel_detector import ImpossibleTravelDetector
from .mfa_detector import MFADetector
from .new_access_detector import NewAccessDetector
from .password_spray_detector import PasswordSprayDetector
from .privilege_detector import PrivilegeDetector
from .session_hijack_detector import SessionHijackDetector
from .token_detector import TokenDetector
from .unusual_time_detector import UnusualTimeDetector
from .volume_detector import VolumeDetector

__all__ = [
    "BruteForceDetector",
    "CredentialStuffingDetector",
    "DormantAccountDetector",
    "ImpossibleTravelDetector",
    "MFADetector",
    "NewAccessDetector",
    "PasswordSprayDetector",
    "PrivilegeDetector",
    "SessionHijackDetector",
    "TokenDetector",
    "UnusualTimeDetector",
    "VolumeDetector",
]
