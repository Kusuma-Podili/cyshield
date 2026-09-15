"""CyberShield Enterprise - Deception Technology & Active Honeypot Subsystem.

Provides enterprise-grade deception defenses: canary honeytokens (API keys, honeyfiles,
canary credentials, canary DNS tokens) and decoy traps (decoy SSH, SMB, HTTP admin, Redis/MySQL).
"""

from cybershield.deception.schemas import (
    TrapType,
    CanaryType,
    CanaryToken,
    TripwireAlert,
    DecoyServiceStatus,
)
from cybershield.deception.engine import DeceptionEngine

__all__ = [
    "TrapType",
    "CanaryType",
    "CanaryToken",
    "TripwireAlert",
    "DecoyServiceStatus",
    "DeceptionEngine",
]
