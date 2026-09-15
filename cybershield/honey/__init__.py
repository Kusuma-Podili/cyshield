"""CyberShield Enterprise - Threat Deception Orchestration & Service Emulation Subsystem.
Provides dynamic memory breadcrumbs, canary tokens, and high-interaction service emulators
(Redis, PostgreSQL, Docker API) for deterministic early adversary detection.
"""

from .schemas import (
    HoneytokenType,
    EmulatedServiceType,
    DeceptionLure,
    Honeytoken,
    DeceptionInteractionEvent,
    DeceptionAlert,
)
from .orchestrator import DeceptionOrchestrator

__all__ = [
    "HoneytokenType",
    "EmulatedServiceType",
    "DeceptionLure",
    "Honeytoken",
    "DeceptionInteractionEvent",
    "DeceptionAlert",
    "DeceptionOrchestrator",
]
