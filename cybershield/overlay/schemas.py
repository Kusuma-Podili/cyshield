"""CyberShield Enterprise - Autonomous Zero-Trust Micro-Tunneling & Mesh Overlay Schemas.
Data contracts for Curve25519 peer identity, WireGuard micro-tunnels, ZTNA peer access policies,
and mesh network health.
"""

from enum import Enum
from typing import Dict, List, Optional, Any
from datetime import datetime, timezone
from pydantic import BaseModel, Field


class PeerRole(str, Enum):
    WORKSTATION = "WORKSTATION"
    SERVER_CROWN_JEWEL = "SERVER_CROWN_JEWEL"
    CLOUD_GATEWAY = "CLOUD_GATEWAY"
    IOT_EDGE_NODE = "IOT_EDGE_NODE"


class TunnelStatus(str, Enum):
    CONNECTED_ENCRYPTED = "CONNECTED_ENCRYPTED"
    DEGRADED = "DEGRADED"
    DISCONNECTED = "DISCONNECTED"
    ACCESS_BLOCKED_POLICY = "ACCESS_BLOCKED_POLICY"


class OverlayPeer(BaseModel):
    """Zero-Trust Mesh Overlay node identity."""
    peer_id: str
    hostname: str
    role: PeerRole = PeerRole.WORKSTATION
    overlay_ip: str = Field(..., description="Virtual 10.42.x.x overlay IP")
    public_key_curve25519: str = Field(..., description="Base64 encoded Curve25519 public key")
    listen_port: int = 51820
    is_authorized: bool = True
    device_posture_score: float = Field(default=95.0, ge=0.0, le=100.0)
    last_handshake: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class RegisterPeerRequest(BaseModel):
    """Request to register and onboard an overlay node."""
    hostname: str
    role: PeerRole = PeerRole.WORKSTATION
    device_posture_score: float = Field(default=90.0, ge=0.0, le=100.0)
    listen_port: int = 51820


class EvaluateAccessRequest(BaseModel):
    """Request to evaluate whether source peer is authorized to open micro-tunnel to destination."""
    source_peer_id: str
    dest_peer_id: str
    dest_port: int = Field(..., ge=1, le=65535)
    protocol: str = "TCP"


class AccessPolicyDecision(BaseModel):
    """ZTNA policy decision for micro-tunnel creation."""
    is_allowed: bool
    decision_reason: str
    encryption_suite: str = "ChaCha20-Poly1305-Curve25519"
    enforced_firewall_rule: Optional[str] = None
    evaluated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class MeshHealthReport(BaseModel):
    """Consolidated status of Zero-Trust encrypted mesh overlay."""
    total_active_peers: int
    connected_tunnels_count: int
    average_rtt_latency_ms: float
    blocked_unauthorized_attempts: int
    encryption_algorithm: str = "WireGuard-Compatible ChaCha20-Poly1305"
    mesh_resilience_status: str = "OPTIMAL_HIGH_AVAILABILITY"
