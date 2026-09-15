"""
CyberShield Enterprise Threat Hunting Subsystem.
Proactive hypothesis management, LOLBAS/lateral hunting queries, and IOC extraction.
"""

from cybershield.hunting.engine import ThreatHuntingEngine
from cybershield.hunting.queries import BUILTIN_HUNT_TEMPLATES
from cybershield.hunting.routes import hunting_router

__all__ = [
    "ThreatHuntingEngine",
    "BUILTIN_HUNT_TEMPLATES",
    "hunting_router",
]
