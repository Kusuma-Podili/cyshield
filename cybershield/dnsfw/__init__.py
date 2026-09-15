"""
DNS Firewall & Protective C2 Sinkholing Subsystem.
"""

from cybershield.dnsfw.schemas import (
    DNSAction,
    DNSFirewallRule,
    DNSInspectionRequest,
    DNSInspectionResponse,
    DNSQueryType,
    DNSSinkholeHit,
)
from cybershield.dnsfw.engine import DNSFirewallEngine
from cybershield.dnsfw.routes import dnsfw_router

__all__ = [
    "DNSAction",
    "DNSFirewallRule",
    "DNSInspectionRequest",
    "DNSInspectionResponse",
    "DNSQueryType",
    "DNSSinkholeHit",
    "DNSFirewallEngine",
    "dnsfw_router",
]
