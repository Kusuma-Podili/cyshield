"""CyberShield Security Orchestration, Automation, and Response (SOAR) Module."""

from cybershield.soar.actions import SOARActionRegistry
from cybershield.soar.playbook import soar_engine, SOAREngine, PlaybookDefinition

# Pre-load default playbooks
from cybershield.config import settings
soar_engine.load_playbooks_from_dir(settings.playbooks_dir)

__all__ = [
    "SOARActionRegistry",
    "soar_engine",
    "SOAREngine",
    "PlaybookDefinition",
]
