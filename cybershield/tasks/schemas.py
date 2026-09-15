"""
CyberShield Enterprise - Background Tasks & Worker Pool Pydantic Schemas
Defines request and response data contracts for task submission,
telemetry tracking, cancellation, and worker pool health monitoring.
"""

from __future__ import annotations

from typing import Dict, Any, List, Optional
from pydantic import BaseModel, Field

from cybershield.database.models.tasks import TaskStatus, TaskPriority, TaskType


class TaskSubmitRequest(BaseModel):
    """Schema for submitting an asynchronous background task."""
    task_type: TaskType = Field(..., description="Category of the asynchronous task to execute")
    priority: TaskPriority = Field(default=TaskPriority.NORMAL, description="Scheduling priority level")
    payload: Dict[str, Any] = Field(default_factory=dict, description="Input parameters and task arguments")


class TaskResponse(BaseModel):
    """Schema representing background task execution status and results."""
    id: str = Field(..., description="Unique task identifier")
    task_type: str = Field(..., description="Category of the task")
    status: str = Field(..., description="Current lifecycle state (QUEUED, PROCESSING, SUCCESS, FAILED, CANCELLED)")
    priority: str = Field(..., description="Priority level")
    progress_pct: float = Field(..., description="Execution progress percentage (0.0 to 100.0)")
    payload: Dict[str, Any] = Field(default_factory=dict, description="Input payload parameters")
    result: Dict[str, Any] = Field(default_factory=dict, description="Task output and execution results")
    error_message: Optional[str] = Field(None, description="Error message if execution failed")
    worker_id: Optional[str] = Field(None, description="Worker ID currently or previously handling the task")
    submitted_by: str = Field(..., description="User or subsystem that submitted the task")
    queued_at: Optional[str] = Field(None, description="Timestamp when the task was queued")
    started_at: Optional[str] = Field(None, description="Timestamp when worker began execution")
    completed_at: Optional[str] = Field(None, description="Timestamp when task finished or failed")
    duration_sec: float = Field(0.0, description="Total execution duration in seconds")
    execution_log: List[str] = Field(default_factory=list, description="Step-by-step trace messages")


class WorkerStatusResponse(BaseModel):
    """Schema for individual task worker telemetry."""
    worker_id: str = Field(..., description="Unique worker instance ID")
    status: str = Field(..., description="Worker state (IDLE, BUSY, OFFLINE)")
    current_task_id: Optional[str] = Field(None, description="ID of task currently being processed")
    tasks_completed: int = Field(0, description="Total successful tasks processed")
    tasks_failed: int = Field(0, description="Total failed tasks encountered")
    uptime_sec: float = Field(..., description="Seconds since worker process launched")
    last_heartbeat: str = Field(..., description="Timestamp of most recent heartbeat")


class WorkerPoolStatusResponse(BaseModel):
    """Schema for aggregated background worker pool health and queue telemetry."""
    total_workers: int = Field(..., description="Configured worker concurrency limit")
    active_workers: int = Field(..., description="Count of workers currently processing tasks")
    idle_workers: int = Field(..., description="Count of idle workers ready for new jobs")
    queued_tasks: int = Field(..., description="Number of tasks waiting in queue")
    processing_tasks: int = Field(..., description="Number of tasks currently in flight")
    completed_today: int = Field(..., description="Total completed tasks in current cycle")
    failed_today: int = Field(..., description="Total failed tasks in current cycle")
    workers: List[WorkerStatusResponse] = Field(default_factory=list, description="Detailed status per worker")
