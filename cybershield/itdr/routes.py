"""
Identity Threat Detection and Response (ITDR) REST API Routes.
Exposes endpoints for Kerberos ticket inspection, DCSync replication analysis, and AD posture.
"""

from typing import Any, Dict, List, Optional
from fastapi import APIRouter, HTTPException, Query, status

from cybershield.itdr.detector import IdentityThreatDetector
from cybershield.itdr.schemas import (
    ADAccount,
    DirectoryReplicationTelemetry,
    IdentityPostureOverview,
    ITDRAlert,
    KerberosTicketTelemetry,
)

itdr_router = APIRouter(prefix="/api/itdr", tags=["Identity Threat Detection & Response (ITDR)"])
itdr_engine = IdentityThreatDetector()


@itdr_router.get("/alerts", response_model=List[ITDRAlert])
async def list_alerts(limit: int = Query(50, ge=1, le=500)):
    """List active and historical identity threat alerts."""
    return itdr_engine.get_alerts(limit=limit)


@itdr_router.post("/analyze/kerberos", response_model=Optional[ITDRAlert])
async def analyze_kerberos(ticket: KerberosTicketTelemetry):
    """Analyze incoming Kerberos ticket request for Kerberoasting, AS-REP Roasting, or Golden/Silver tickets."""
    return itdr_engine.analyze_kerberos_ticket(ticket)


@itdr_router.post("/analyze/replication", response_model=Optional[ITDRAlert])
async def analyze_replication(rep: DirectoryReplicationTelemetry):
    """Analyze Directory Replication Service (DRS) request for DCSync attacks."""
    return itdr_engine.analyze_directory_replication(rep)


@itdr_router.get("/posture", response_model=IdentityPostureOverview)
async def get_posture():
    """Retrieve Active Directory security posture score and risky account statistics."""
    return itdr_engine.get_posture_overview()


@itdr_router.get("/accounts", response_model=List[ADAccount])
async def list_accounts():
    """List Active Directory accounts and inspect Kerberos SPN and preauth status."""
    return itdr_engine.list_accounts()
