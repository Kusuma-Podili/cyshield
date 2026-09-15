"""CyberShield Enterprise - Autonomous Zero-Trust Micro-Tunneling & Mesh Overlay Routes.
Exposes endpoints for peer node registration, ZTNA access policy evaluation,
active overlay topology inspection, and mesh health telemetry.
"""

from typing import Dict, List, Optional, Any
from fastapi import APIRouter, HTTPException, Query, status

from .schemas import (
    OverlayPeer,
    RegisterPeerRequest,
    EvaluateAccessRequest,
    AccessPolicyDecision,
    MeshHealthReport,
)
from .mesh import ZeroTrustMeshOverlayEngine

router = APIRouter(prefix="/api/v1/overlay", tags=["Zero-Trust Mesh Overlay & Micro-Tunneling"])

# Singleton mesh engine instance
_MESH_ENGINE = ZeroTrustMeshOverlayEngine()


@router.post("/peers/register", response_model=OverlayPeer, status_code=status.HTTP_201_CREATED)
def register_overlay_peer(request: RegisterPeerRequest):
    """Register and onboard a peer node into the encrypted Zero-Trust overlay mesh."""
    return _MESH_ENGINE.register_peer(request)


@router.post("/policy/evaluate", response_model=AccessPolicyDecision, status_code=status.HTTP_200_OK)
def evaluate_micro_tunnel_access(request: EvaluateAccessRequest):
    """Evaluate whether a peer-to-peer micro-tunnel is permitted under ZTNA posture policies."""
    return _MESH_ENGINE.evaluate_access(request)


@router.get("/peers", response_model=List[OverlayPeer])
def list_overlay_peers():
    """Retrieve all active overlay nodes and assigned virtual overlay IPs."""
    return list(_MESH_ENGINE.peers.values())


@router.get("/mesh/status", response_model=MeshHealthReport)
def get_mesh_overlay_health():
    """Query Zero-Trust mesh overlay connectivity, active tunnels, and encryption status."""
    return _MESH_ENGINE.get_mesh_health()
