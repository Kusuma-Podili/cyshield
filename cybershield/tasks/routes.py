"""
CyberShield Enterprise - Background Tasks & Distributed Worker Pool REST API
Provides endpoints to submit, inspect, cancel, and monitor asynchronous background tasks,
worker telemetry, and live event bus activity.
"""

from __future__ import annotations

from typing import List, Dict, Any, Optional
from fastapi import APIRouter, Depends, HTTPException, status, Query
from sqlalchemy.ext.asyncio import AsyncSession

from cybershield.database.session import get_db
from cybershield.database.models.user import User
from cybershield.database.models.role import Permission
from cybershield.auth import require_permission
from cybershield.audit.service import AuditService
from cybershield.tasks.schemas import (
    TaskSubmitRequest,
    TaskResponse,
    WorkerPoolStatusResponse,
)
from cybershield.tasks.manager import task_manager
from cybershield.tasks.event_bus import event_bus

router = APIRouter(prefix="/api/tasks", tags=["Distributed Tasks & Background Workers"])


@router.get("", response_model=List[TaskResponse], summary="List Background Tasks")
async def list_tasks(
    status: Optional[str] = Query(None, description="Filter by status (QUEUED, PROCESSING, SUCCESS, FAILED, CANCELLED)"),
    task_type: Optional[str] = Query(None, description="Filter by task type"),
    limit: int = Query(50, ge=1, le=200, description="Max tasks to return"),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.TASKS_VIEW)),
):
    """List asynchronous background tasks with filtering by status and category."""
    return await task_manager.list_tasks(status=status, task_type=task_type, limit=limit)


@router.post("", response_model=TaskResponse, status_code=status.HTTP_201_CREATED, summary="Submit Background Task")
async def submit_task(
    req: TaskSubmitRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.TASKS_SUBMIT)),
):
    """Submit a new decoupled background task to the prioritized worker pool."""
    task_data = await task_manager.submit_task(
        task_type=req.task_type,
        payload=req.payload,
        priority=req.priority,
        submitted_by=current_user.username,
        session=db,
    )

    await AuditService.log_event(
        db=db,
        action="TASK_SUBMITTED",
        resource=f"task:{task_data['id']}",
        username=current_user.username,
        user_id=current_user.id,
        details={"task_type": task_data["task_type"], "priority": task_data["priority"]},
        status="SUCCESS",
    )

    return task_data


@router.get("/workers/status", response_model=WorkerPoolStatusResponse, summary="Get Worker Pool Health")
async def get_worker_pool_status(
    current_user: User = Depends(require_permission(Permission.TASKS_VIEW)),
):
    """Query real-time worker pool telemetry, active worker heartbeats, and queue depth."""
    return await task_manager.get_pool_status()


@router.get("/events/history", response_model=List[Dict[str, Any]], summary="Get Event Bus Message History")
async def get_event_bus_history(
    limit: int = Query(50, ge=1, le=200, description="Max event packets"),
    topic_prefix: Optional[str] = Query(None, description="Filter by topic prefix"),
    current_user: User = Depends(require_permission(Permission.TASKS_VIEW)),
):
    """Query recent published topic messages from the asynchronous event bus."""
    return event_bus.get_history(limit=limit, topic_prefix=topic_prefix)


@router.get("/{task_id}", response_model=TaskResponse, summary="Get Background Task Details")
async def get_task_details(
    task_id: str,
    current_user: User = Depends(require_permission(Permission.TASKS_VIEW)),
):
    """Retrieve execution state, live progress percentage, logs, and results for a specific task."""
    task_data = await task_manager.get_task(task_id)
    if not task_data:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Background task '{task_id}' not found.",
        )
    return task_data


@router.post("/{task_id}/cancel", summary="Cancel Background Task")
async def cancel_task(
    task_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.TASKS_CANCEL)),
):
    """Send cancellation signal to terminate a pending or executing background task."""
    success = await task_manager.cancel_task(task_id)
    if not success:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Task '{task_id}' not found or could not be cancelled.",
        )

    await AuditService.log_event(
        db=db,
        action="TASK_CANCELLED",
        resource=f"task:{task_id}",
        username=current_user.username,
        user_id=current_user.id,
        details={"task_id": task_id},
        status="SUCCESS",
    )

    return {"status": "CANCELLED", "task_id": task_id, "message": f"Cancellation signal issued for task {task_id}."}
