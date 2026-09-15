"""REST API Endpoints for Endpoint Detection & Response (EDR) Fleet Management."""

from __future__ import annotations

from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status

from cybershield.auth.dependencies import get_current_user
from cybershield.database.models.user import User
from cybershield.edr.manager import edr_manager
from cybershield.edr.schemas import (
    EDRAgentRegistrationRequest,
    EDRAgentRegistrationResponse,
    EDRBehavioralAlert,
    EDRCommand,
    EDRCommandDispatch,
    EDRHeartbeatRequest,
    EDRHeartbeatResponse,
    EDRTelemetryBatchRequest,
)

router = APIRouter(prefix="/api/edr", tags=["Endpoint Detection & Response (EDR)"])


@router.post(
    "/agents/register",
    response_model=EDRAgentRegistrationResponse,
    summary="Enroll New EDR Endpoint Sensor",
)
async def register_agent(req: EDRAgentRegistrationRequest) -> EDRAgentRegistrationResponse:
    """Enroll a new endpoint sensor and receive authentication token."""
    return edr_manager.register_agent(req)


@router.post(
    "/agents/{agent_id}/heartbeat",
    response_model=EDRHeartbeatResponse,
    summary="Process Agent Heartbeat & Retrieve Queued Commands",
)
async def process_heartbeat(
    agent_id: str,
    req: EDRHeartbeatRequest,
) -> EDRHeartbeatResponse:
    """Update agent resource telemetry and deliver pending response actions."""
    if req.agent_id != agent_id:
        req.agent_id = agent_id
    return edr_manager.process_heartbeat(req)


@router.post(
    "/agents/{agent_id}/telemetry",
    response_model=List[EDRBehavioralAlert],
    summary="Ingest Endpoint Process, FIM & Socket Telemetry",
)
async def ingest_telemetry(
    agent_id: str,
    batch: EDRTelemetryBatchRequest,
) -> List[EDRBehavioralAlert]:
    """Analyze endpoint telemetry batch through behavioral heuristic engine."""
    if batch.agent_id != agent_id:
        batch.agent_id = agent_id
    return edr_manager.ingest_telemetry(batch)


@router.get(
    "/agents",
    summary="List All Managed Endpoint Agents",
)
async def list_agents(
    current_user: User = Depends(get_current_user),
) -> List[dict]:
    """Retrieve full inventory of managed endpoint sensors."""
    return edr_manager.list_agents()


@router.get(
    "/agents/{agent_id}",
    summary="Get Endpoint Agent Details",
)
async def get_agent(
    agent_id: str,
    current_user: User = Depends(get_current_user),
) -> dict:
    """Retrieve specific endpoint sensor telemetry and state."""
    agent = edr_manager.get_agent(agent_id)
    if not agent:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Agent '{agent_id}' not found")
    return agent


@router.post(
    "/agents/{agent_id}/commands",
    response_model=EDRCommand,
    summary="Dispatch Remediation Command to Endpoint Agent",
)
async def queue_agent_command(
    agent_id: str,
    req: EDRCommandDispatch,
    current_user: User = Depends(get_current_user),
) -> EDRCommand:
    """Queue containment or remediation action (ISOLATE_NETWORK, KILL_PROCESS, QUARANTINE_FILE)."""
    cmd = edr_manager.queue_command(
        agent_id=agent_id,
        action=req.action,
        target=req.target,
        parameters=req.parameters,
    )
    if not cmd:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Agent '{agent_id}' not found")
    return cmd


@router.get(
    "/alerts",
    response_model=List[EDRBehavioralAlert],
    summary="List EDR Host Behavioral Alerts",
)
async def list_alerts(
    agent_id: Optional[str] = Query(None),
    current_user: User = Depends(get_current_user),
) -> List[EDRBehavioralAlert]:
    """Retrieve host-level behavioral alerts with optional agent filter."""
    return edr_manager.list_alerts(agent_id=agent_id)
