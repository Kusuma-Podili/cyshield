"""REST API Endpoints for Active Deception Technology & Honeypots."""

from __future__ import annotations

from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field

from cybershield.auth.dependencies import get_current_user
from cybershield.database.models.user import User
from cybershield.deception.schemas import (
    CanaryToken,
    CanaryGenerateRequest,
    TripwireAlert,
    DecoyServiceStatus,
    DeceptionStatsResponse,
)
from cybershield.deception.engine import DeceptionEngine

router = APIRouter(prefix="/api/deception", tags=["Deception Technology & Honeypots"])


class CanaryVerifyRequest(BaseModel):
    input_text: str = Field(..., description="Text payload or query to scan for tripwires")
    source_ip: str = Field(default="10.0.0.99", description="Source IP address of adversary")


class TrapSimulateRequest(BaseModel):
    trap_type: str = Field(..., description="SSH, SMB, HTTP_ADMIN, or DATABASE")
    source_ip: str = Field(default="10.0.0.99")
    payload: Dict[str, Any] = Field(default_factory=dict)


@router.get("/traps", response_model=List[DecoyServiceStatus])
async def list_decoy_traps(
    current_user: User = Depends(get_current_user),
):
    """List all deployed decoy services, ports, and interaction telemetry."""
    return DeceptionEngine.list_traps()


@router.get("/canaries", response_model=List[CanaryToken])
async def list_canary_tokens(
    current_user: User = Depends(get_current_user),
):
    """List active deception canaries (API keys, honeyfiles, decoy accounts)."""
    return DeceptionEngine.list_canaries()


@router.post("/canaries/generate", response_model=CanaryToken)
async def generate_canary_token(
    request: CanaryGenerateRequest,
    current_user: User = Depends(get_current_user),
):
    """Generate a new specialized canary honeytoken."""
    return DeceptionEngine.generate_canary(request)


@router.post("/canaries/verify")
async def verify_canary_trip(
    request: CanaryVerifyRequest,
    current_user: User = Depends(get_current_user),
):
    """Test or verify if an input payload trips an active canary token."""
    alert = DeceptionEngine.check_canary_trip(request.input_text, request.source_ip)
    return {
        "tripped": alert is not None,
        "alert": alert.model_dump() if alert else None,
    }


@router.post("/traps/simulate", response_model=TripwireAlert)
async def simulate_trap_interaction(
    request: TrapSimulateRequest,
    current_user: User = Depends(get_current_user),
):
    """Simulate attacker interaction against decoy trap service."""
    tt = request.trap_type.upper()
    sip = request.source_ip
    p = request.payload

    if tt == "SSH":
        u = p.get("username", "admin")
        pw = p.get("password", "root123")
        return DeceptionEngine.trigger_ssh_trap(u, pw, sip)
    elif tt == "SMB":
        s = p.get("share_name", "FINANCE_ARCHIVE$")
        act = p.get("action", "READ_FILE")
        return DeceptionEngine.trigger_smb_trap(s, act, sip)
    elif tt == "HTTP_ADMIN":
        path = p.get("path", "/phpmyadmin")
        m = p.get("method", "GET")
        return DeceptionEngine.trigger_http_trap(path, m, sip)
    elif tt == "DATABASE":
        cmd = p.get("command", "KEYS *")
        return DeceptionEngine.trigger_db_trap(cmd, sip)
    else:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unsupported trap type '{request.trap_type}'. Valid: SSH, SMB, HTTP_ADMIN, DATABASE",
        )


@router.get("/stats", response_model=DeceptionStatsResponse)
async def get_deception_statistics(
    current_user: User = Depends(get_current_user),
):
    """Retrieve deception posture metrics, decoy health, and tripwire incident history."""
    return DeceptionEngine.get_stats()
