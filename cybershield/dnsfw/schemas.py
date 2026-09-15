"""
DNS Firewall & Protective C2 Sinkholing Schemas.
Models DNS inspection, Response Policy Zone (RPZ) rules, DGA detection, and sinkhole hits.
"""

from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class DNSAction(str, Enum):
    ALLOW = "ALLOW"
    BLOCK_NXDOMAIN = "BLOCK_NXDOMAIN"
    SINKHOLE = "SINKHOLE"
    REWRITE = "REWRITE"


class DNSQueryType(str, Enum):
    A = "A"
    AAAA = "AAAA"
    TXT = "TXT"
    CNAME = "CNAME"
    MX = "MX"
    PTR = "PTR"
    NULL = "NULL"
    ANY = "ANY"


class DNSSinkholeHit(BaseModel):
    """Captured connection attempt from a compromised host directed to the sinkhole."""
    hit_id: str
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    client_ip: str
    sinkhole_ip: str
    requested_domain: str
    protocol: str = "HTTP"
    user_agent: Optional[str] = None
    payload_preview: Optional[str] = None


class DNSFirewallRule(BaseModel):
    """RPZ (Response Policy Zone) filtering rule."""
    rule_id: str
    domain_pattern: str  # e.g., "*.evil-c2.com", "malicious-phish.xyz"
    action: DNSAction = DNSAction.SINKHOLE
    redirect_ip: Optional[str] = "10.254.254.254"
    category: str = "C2_INFRASTRUCTURE"
    description: str
    hit_count: int = 0
    is_active: bool = True
    created_at: datetime = Field(default_factory=datetime.utcnow)


class DNSInspectionRequest(BaseModel):
    """Outbound DNS query requiring inspection."""
    client_ip: str
    domain: str
    query_type: DNSQueryType = DNSQueryType.A


class DNSInspectionResponse(BaseModel):
    """Policy decision returned by DNS Firewall."""
    action: DNSAction
    domain: str
    resolved_ip: Optional[str] = None
    block_reason: Optional[str] = None
    is_dga_detected: bool = False
    is_tunneling_detected: bool = False
    shannon_entropy: float = 0.0
    matched_rule_id: Optional[str] = None
    inspection_time_ms: float = 0.5
