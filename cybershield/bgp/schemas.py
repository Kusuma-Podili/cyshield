"""
BGP Route Hijacking & Autonomous System Peering Monitor Schemas.
Models RPKI Route Origin Validation (ROV), BGP announcements, and route hijack alerts.
"""

import ipaddress
from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class RPKIValidationState(str, Enum):
    VALID = "VALID"
    INVALID_ASN = "INVALID_ASN"
    INVALID_MAX_LENGTH = "INVALID_MAX_LENGTH"
    NOT_FOUND = "NOT_FOUND"


class BGPHijackType(str, Enum):
    ORIGIN_HIJACK = "ORIGIN_HIJACK"
    SUBPREFIX_HIJACK = "SUBPREFIX_HIJACK"
    ROUTE_LEAK = "ROUTE_LEAK"
    BOGON_ANNOUNCEMENT = "BOGON_ANNOUNCEMENT"


class RouteOriginAuthorization(BaseModel):
    """Cryptographically signed RPKI Route Origin Authorization (ROA)."""
    roa_id: str
    prefix: str  # CIDR notation e.g., "198.51.100.0/24"
    origin_asn: int  # e.g., 64500
    max_length: int = 24
    ta_name: str = "ARIN-RPKI"  # Trust Anchor
    is_active: bool = True
    created_at: datetime = Field(default_factory=datetime.utcnow)


class BGPRouteAnnouncement(BaseModel):
    """Inbound BGP UPDATE announcement from border routers / looking glasses."""
    message_id: str
    prefix: str
    origin_asn: int
    as_path: List[int] = Field(default_factory=list)
    next_hop: Optional[str] = "192.0.2.1"
    communities: List[str] = Field(default_factory=list)
    timestamp: datetime = Field(default_factory=datetime.utcnow)


class BGPHijackAlert(BaseModel):
    """Alert triggered upon detection of unauthorized routing changes or prefix hijacking."""
    alert_id: str
    hijacked_prefix: str
    authorized_asn: Optional[int] = None
    rogue_asn: int
    hijack_type: BGPHijackType
    severity: str = "CRITICAL"
    reason: str
    as_path: List[int] = Field(default_factory=list)
    mitigation_recommendation: str
    timestamp: datetime = Field(default_factory=datetime.utcnow)


class BGPRouteEvaluationResult(BaseModel):
    """Outcome of RPKI Route Origin Validation and hijack analysis."""
    message_id: str
    prefix: str
    origin_asn: int
    rpki_status: RPKIValidationState
    is_hijack_detected: bool = False
    alert: Optional[BGPHijackAlert] = None
