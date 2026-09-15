"""
CyberShield Enterprise - Background Tasks & Distributed Jobs Database Models
Provides persistent state tracking, worker assignment, progress telemetry,
and result payloads for distributed asynchronous tasks.
"""

from __future__ import annotations

import enum
from datetime import datetime
from typing import Dict, Any, List, Optional
from sqlalchemy import Column, String, Integer, Float, DateTime, Boolean, Text, JSON, Enum as SQLEnum, Index

from cybershield.database.session import Base


class TaskStatus(str, enum.Enum):
    QUEUED = "QUEUED"
    PROCESSING = "PROCESSING"
    SUCCESS = "SUCCESS"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"


class TaskPriority(str, enum.Enum):
    LOW = "LOW"
    NORMAL = "NORMAL"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class TaskType(str, enum.Enum):
    TELEMETRY_INGESTION = "TELEMETRY_INGESTION"
    MALWARE_ANALYSIS = "MALWARE_ANALYSIS"
    INTEL_SYNC = "INTEL_SYNC"
    SOAR_PLAYBOOK = "SOAR_PLAYBOOK"
    ML_RETRAIN = "ML_RETRAIN"
    ETL_PIPELINE = "ETL_PIPELINE"
    CUSTOM_JOB = "CUSTOM_JOB"


class BackgroundTaskModel(Base):
    """Persistent ledger of asynchronous background jobs and distributed worker tasks."""
    __tablename__ = "background_tasks"

    id = Column(String(64), primary_key=True, index=True)
    task_type = Column(SQLEnum(TaskType), default=TaskType.CUSTOM_JOB, nullable=False, index=True)
    status = Column(SQLEnum(TaskStatus), default=TaskStatus.QUEUED, nullable=False, index=True)
    priority = Column(SQLEnum(TaskPriority), default=TaskPriority.NORMAL, nullable=False, index=True)

    progress_pct = Column(Float, default=0.0, nullable=False)
    payload = Column(JSON, default=dict, nullable=False)
    result = Column(JSON, default=dict, nullable=False)
    error_message = Column(Text, nullable=True)

    worker_id = Column(String(64), nullable=True, index=True)
    submitted_by = Column(String(128), default="system", nullable=False, index=True)

    queued_at = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)
    started_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)
    duration_sec = Column(Float, default=0.0)

    execution_log = Column(JSON, default=list, nullable=False)

    __table_args__ = (
        Index("idx_tasks_status_prio", "status", "priority"),
        Index("idx_tasks_type_status", "task_type", "status"),
        Index("idx_tasks_queued_at", "queued_at"),
    )

    def to_dict(self) -> Dict[str, Any]:
        """Serialize task record to dictionary representation."""
        return {
            "id": self.id,
            "task_type": self.task_type.value if hasattr(self.task_type, "value") else str(self.task_type),
            "status": self.status.value if hasattr(self.status, "value") else str(self.status),
            "priority": self.priority.value if hasattr(self.priority, "value") else str(self.priority),
            "progress_pct": round(self.progress_pct, 1),
            "payload": self.payload or {},
            "result": self.result or {},
            "error_message": self.error_message,
            "worker_id": self.worker_id,
            "submitted_by": self.submitted_by,
            "queued_at": self.queued_at.isoformat() if self.queued_at else None,
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "duration_sec": round(self.duration_sec or 0.0, 3),
            "execution_log": self.execution_log or [],
        }
