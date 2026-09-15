"""Decoy Service Traps for CyberShield Enterprise Deception Subsystem."""

from cybershield.deception.traps.service_traps import (
    SSHTrap,
    SMBShareTrap,
    HTTPAdminTrap,
    DatabaseTrap,
)

__all__ = [
    "SSHTrap",
    "SMBShareTrap",
    "HTTPAdminTrap",
    "DatabaseTrap",
]
