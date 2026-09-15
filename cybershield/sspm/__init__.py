"""
CyberShield Enterprise - SaaS Security Posture Management (SSPM) Module
"""

from cybershield.sspm.schemas import (
    SaaSPlatform,
    SSPMSeverity,
    OAuthConsentRisk,
    OAuthAppGrant,
    MailboxForwardingRule,
    MFAChallengeEvent,
    SaaSPostureFinding,
    SaaSAccountAudit,
    SSPMPostureReport,
)
from cybershield.sspm.engine import SaaSSecurityPostureEngine
from cybershield.sspm.routes import router

__all__ = [
    "SaaSPlatform",
    "SSPMSeverity",
    "OAuthConsentRisk",
    "OAuthAppGrant",
    "MailboxForwardingRule",
    "MFAChallengeEvent",
    "SaaSPostureFinding",
    "SaaSAccountAudit",
    "SSPMPostureReport",
    "SaaSSecurityPostureEngine",
    "router",
]
