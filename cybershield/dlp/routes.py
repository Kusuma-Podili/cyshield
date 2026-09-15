"""
Data Loss Prevention (DLP) REST API Routes.
Exposes endpoints for content inspection, redaction masking, and incident tracking.
"""

from typing import Any, Dict, List
from fastapi import APIRouter, HTTPException, Query, status
from pydantic import BaseModel

from cybershield.dlp.engine import DataLossPreventionEngine
from cybershield.dlp.schemas import (
    DLPInspectRequest,
    DLPInspectResult,
    DLPRule,
)

dlp_router = APIRouter(prefix="/api/dlp", tags=["Data Loss Prevention (DLP)"])
dlp_engine = DataLossPreventionEngine()


class MaskPayload(BaseModel):
    text: str


@soar_mask_route := dlp_router.post("/mask")
async def mask_text_endpoint(payload: MaskPayload):
    """Redact sensitive PII, PCI, and cloud secrets from text."""
    masked = dlp_engine.mask_content(payload.text)
    return {"original_length": len(payload.text), "masked_text": masked}


@dlp_router.post("/inspect", response_model=DLPInspectResult)
async def inspect_content(request: DLPInspectRequest):
    """Scan content for sensitive data and execute enforcement policy (BLOCK, MASK, ALERT)."""
    return dlp_engine.inspect_content(request)


@dlp_router.get("/rules", response_model=List[DLPRule])
async def list_rules():
    """List configured DLP detection rules and compliance standards."""
    return dlp_engine.list_rules()


@dlp_router.get("/incidents", response_model=List[DLPInspectResult])
async def list_incidents(limit: int = Query(50, ge=1, le=500)):
    """List historical DLP violation incidents."""
    return dlp_engine.get_incidents(limit=limit)


@dlp_router.get("/stats")
async def get_stats():
    """Get DLP metrics on inspected streams, blocked transmissions, and data type breakdowns."""
    return dlp_engine.get_stats()
