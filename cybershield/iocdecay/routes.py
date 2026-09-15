"""
IoC Aging and Exponential Decay Engine REST API routes.
"""

from typing import Any, Dict, List, Optional
from fastapi import APIRouter, HTTPException, Query, status

from cybershield.iocdecay.engine import IOCDecayEngine
from cybershield.iocdecay.schemas import (
    DecayEvaluationResult,
    DecayIndicator,
    IOCStatus,
    SightingRecordRequest,
)

iocdecay_router = APIRouter(prefix="/api/iocdecay", tags=["Threat Feeds & IoC Aging Engine"])
_decay_engine = IOCDecayEngine()


@iocdecay_router.get("/indicators", response_model=List[DecayIndicator])
async def list_indicators(status: Optional[IOCStatus] = None):
    """List all tracked IoCs with real-time decayed confidence scores."""
    return _decay_engine.list_indicators(status_filter=status)


@iocdecay_router.post("/indicators", response_model=DecayIndicator, status_code=status.HTTP_201_CREATED)
async def create_indicator(indicator: DecayIndicator):
    """Add a new threat intelligence indicator to the decay engine."""
    return _decay_engine.add_indicator(indicator)


@iocdecay_router.get("/indicators/{indicator_id}", response_model=DecayIndicator)
async def get_indicator(indicator_id: str):
    """Retrieve details and confidence score for a specific IoC."""
    ind = _decay_engine.get_indicator(indicator_id)
    if not ind:
        raise HTTPException(status_code=404, detail=f"Indicator '{indicator_id}' not found")
    return ind


@iocdecay_router.post("/sighting", response_model=DecayIndicator)
async def record_ioc_sighting(req: SightingRecordRequest):
    """
    Record telemetry sighting of an indicator.
    Reinforces confidence score and resets decay baseline.
    """
    return _decay_engine.record_sighting(req)


@iocdecay_router.post("/sweep", response_model=List[DecayEvaluationResult])
async def trigger_decay_sweep():
    """Manually invoke global half-life decay calculation across all indicators."""
    return _decay_engine.execute_decay_sweep()


@iocdecay_router.get("/active-feed")
async def get_active_firewall_feed(min_confidence: float = Query(40.0, ge=0.0, le=100.0)):
    """Export pruned, high-confidence active threat feed for boundary firewalls."""
    return _decay_engine.get_active_firewall_feed(min_confidence=min_confidence)


@iocdecay_router.get("/overview")
async def get_iocdecay_overview():
    """Executive metrics on tracked indicators, decay distributions, and pruned count."""
    return _decay_engine.get_overview_metrics()
