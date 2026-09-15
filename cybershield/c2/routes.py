"""
C2 Threat Emulation REST API Routes.
Exposes endpoints for listener management, beacon check-ins, task dispatch, and result collection.
"""

from typing import Any, Dict, List, Optional
from fastapi import APIRouter, HTTPException, Query, status
from pydantic import BaseModel

from cybershield.c2.engine import C2EmulationEngine
from cybershield.c2.schemas import (
    BeaconCheckinPayload,
    BeaconSession,
    BeaconTaskResultPayload,
    C2CommandType,
    C2Listener,
    C2Task,
)

c2_router = APIRouter(prefix="/api/c2", tags=["C2 Threat Emulation Framework"])
c2_engine = C2EmulationEngine()


class QueueTaskPayload(BaseModel):
    command: C2CommandType
    arguments: Dict[str, Any] = {}


@c2_router.get("/listeners", response_model=List[C2Listener])
async def list_listeners():
    """List configured C2 listening endpoints."""
    return c2_engine.list_listeners()


@c2_router.post("/listeners", response_model=C2Listener, status_code=status.HTTP_201_CREATED)
async def create_listener(listener: C2Listener):
    """Create and start a new C2 listener."""
    return c2_engine.create_listener(listener)


@c2_router.get("/sessions", response_model=List[BeaconSession])
async def list_sessions():
    """List active and connected adversary beacon sessions."""
    return c2_engine.list_sessions()


@c2_router.get("/sessions/{session_id}", response_model=BeaconSession)
async def get_session(session_id: str):
    """Get details and status of a specific beacon session."""
    session = c2_engine.get_session(session_id)
    if not session:
        raise HTTPException(status_code=404, detail=f"Session '{session_id}' not found")
    return session


@c2_router.post("/sessions/{session_id}/tasks", response_model=C2Task, status_code=status.HTTP_201_CREATED)
async def queue_task(session_id: str, payload: QueueTaskPayload):
    """Queue a command for execution on the target beacon."""
    try:
        return c2_engine.queue_task(session_id, payload.command, payload.arguments)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


@c2_router.post("/beacon/checkin", response_model=List[C2Task])
async def beacon_checkin(payload: BeaconCheckinPayload):
    """Agent heartbeat check-in to fetch pending queued tasks."""
    return c2_engine.handle_checkin(payload)


@c2_router.post("/beacon/response", response_model=C2Task)
async def beacon_response(payload: BeaconTaskResultPayload):
    """Deliver task execution output back to C2 controller."""
    return c2_engine.record_task_result(payload)


@c2_router.get("/tasks/{task_id}", response_model=C2Task)
async def get_task(task_id: str):
    """Retrieve output of a completed task."""
    task = c2_engine.get_task_result(task_id)
    if not task:
        raise HTTPException(status_code=404, detail=f"Task '{task_id}' not found")
    return task
