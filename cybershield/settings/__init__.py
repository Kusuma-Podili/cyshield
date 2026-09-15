"""Platform Settings & Runtime Configuration Subsystem."""

from cybershield.settings.manager import SettingsManager
from cybershield.settings.routes import router as settings_router

__all__ = ["SettingsManager", "settings_router"]
