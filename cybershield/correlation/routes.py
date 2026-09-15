"""
Complex Event Processing (CEP) REST API Routes.
Exposes endpoints for managing correlation rules, streaming events for temporal analysis, and querying alerts.
"""

from typing import Any, Dict, List, Optional, Union
from fastapi import APIRouter, HTTPException, Query, status
from pydantic import BaseModel, Field

from cybershield.correlation.engine import TemporalCorrelationEngine
from cybershield.correlation.schemas import CorrelatedIncidentAlert, CorrelationRule

correlation_router = APIRouter(prefix="/api/correlation", tags=["Temporal Event Correlation (CEP)"])
cep_engine = TemporalCorrelationEngine()


@correlation_router.get("/rules", response_model=List[CorrelationRule])
async def list_rules():
    """List all registered correlation rules."""
    return cep_engine.list_rules()


@correlation_router.post("/rules", response_model=CorrelationRule, status_code=status.HTTP_201_CREATED)
async def create_rule(rule: CorrelationRule):
    """Register a new temporal correlation rule."""
    return cep_engine.register_rule(rule)


@correlation_router.get("/rules/{rule_id}", response_model=CorrelationRule)
async def get_rule(rule_id: str):
    """Get correlation rule by ID."""
    rule = cep_engine.get_rule(rule_id)
    if not rule:
        raise HTTPException(status_code=404, detail=f"Rule {rule_id} not found")
    return rule


@correlation_router.delete("/rules/{rule_id}")
async def delete_rule(rule_id: str):
    """Delete a correlation rule."""
    success = cep_engine.delete_rule(rule_id)
    if not success:
        raise HTTPException(status_code=404, detail=f"Rule {rule_id} not found")
    return {"status": "deleted", "rule_id": rule_id}


class EventIngestPayload(BaseModel):
    events: List[Dict[str, Any]] = Field(default_factory=list)


@correlation_router.post("/process", response_model=List[CorrelatedIncidentAlert])
async def process_events(payload: EventIngestPayload):
    """Feed events into CEP sliding window buffer and return triggered alerts."""
    return cep_engine.process_batch(payload.events)


@correlation_router.get("/alerts", response_model=List[CorrelatedIncidentAlert])
async def get_alerts(limit: int = Query(50, ge=1, le=500)):
    """Retrieve recent correlated incident alerts."""
    return cep_engine.get_emitted_alerts(limit=limit)


@correlation_router.get("/stats")
async def get_stats():
    """Get CEP engine runtime statistics."""
    return cep_engine.get_stats()
