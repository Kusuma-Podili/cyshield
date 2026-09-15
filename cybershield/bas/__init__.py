"""
CyberShield Enterprise Breach and Attack Simulation (BAS) Subsystem.
Automated continuous security validation, Atomic Red Team execution, and MITRE ATT&CK defense gap analysis.
"""

from cybershield.bas.atomic_tests import ATOMIC_TEST_CATALOG, get_atomic_test
from cybershield.bas.runner import AttackSimulationRunner
from cybershield.bas.routes import bas_router

__all__ = [
    "AttackSimulationRunner",
    "ATOMIC_TEST_CATALOG",
    "get_atomic_test",
    "bas_router",
]
