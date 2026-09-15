"""
CyberShield Enterprise - Background Tasks & Distributed Worker Pool Manager
Orchestrates task queues, concurrency, handler routing, cancellation tokens,
and worker lifecycle management.
"""

from __future__ import annotations

import asyncio
import logging
import uuid
from datetime import datetime
from typing import Dict, Any, List, Optional, Callable, Set

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, desc, and_

from cybershield.database.session import async_session_factory
from cybershield.database.models.tasks import BackgroundTaskModel, TaskStatus, TaskPriority, TaskType
from cybershield.tasks.worker import TaskWorker
from cybershield.tasks.event_bus import event_bus
from cybershield.tasks.handlers.telemetry_handler import handle_telemetry_ingestion
from cybershield.tasks.handlers.malware_handler import handle_malware_analysis
from cybershield.tasks.handlers.intel_handler import handle_intel_sync
from cybershield.tasks.handlers.soar_handler import handle_soar_playbook

logger = logging.getLogger("cybershield.tasks.manager")


class TaskManager:
    """Central Task Orchestrator & Distributed Worker Pool."""

    def __init__(self, concurrency: int = 4):
        self.concurrency = concurrency
        self.workers: List[TaskWorker] = []
        self._handlers: Dict[str, Callable] = {}
        self._cancellation_tokens: Set[str] = set()
        self._queue: asyncio.PriorityQueue = asyncio.PriorityQueue()
        self._is_started = False
        self._lock = asyncio.Lock()

        # Register default specialized handlers
        self.register_handler(TaskType.TELEMETRY_INGESTION.value, handle_telemetry_ingestion)
        self.register_handler(TaskType.MALWARE_ANALYSIS.value, handle_malware_analysis)
        self.register_handler(TaskType.INTEL_SYNC.value, handle_intel_sync)
        self.register_handler(TaskType.SOAR_PLAYBOOK.value, handle_soar_playbook)

    def register_handler(self, task_type: str, handler: Callable) -> None:
        """Register callable handler function for a task category."""
        self._handlers[task_type] = handler
        logger.debug("Registered handler for task type '%s'", task_type)

    def get_handler(self, task_type: str) -> Optional[Callable]:
        """Retrieve registered handler by task type string."""
        return self._handlers.get(task_type)

    async def start_pool(self) -> None:
        """Initialize and start background worker pool."""
        if self._is_started:
            return

        self._is_started = True
        self.workers = [
            TaskWorker(worker_id=f"WORKER-{i+1:02d}", manager=self)
            for i in range(self.concurrency)
        ]
        for w in self.workers:
            w.start()

        logger.info("TaskManager worker pool initialized with %d concurrent workers.", len(self.workers))

    async def stop_pool(self) -> None:
        """Gracefully shut down all background workers."""
        self._is_started = False
        for w in self.workers:
            await w.stop()
        self.workers.clear()
        logger.info("TaskManager worker pool stopped.")

    async def submit_task(
        self,
        task_type: TaskType,
        payload: Dict[str, Any],
        priority: TaskPriority = TaskPriority.NORMAL,
        submitted_by: str = "system",
        session: Optional[AsyncSession] = None,
    ) -> Dict[str, Any]:
        """
        Submit a new background job.
        Persists task record and enqueues for worker processing.
        """
        now = datetime.utcnow()
        task_id = f"TASK-{now.strftime('%Y%m%d')}-{uuid.uuid4().hex[:8].upper()}"

        # Priority ordering: CRITICAL=0, HIGH=1, NORMAL=2, LOW=3
        prio_rank = {
            TaskPriority.CRITICAL: 0,
            TaskPriority.HIGH: 1,
            TaskPriority.NORMAL: 2,
            TaskPriority.LOW: 3,
        }.get(priority, 2)

        task_record = BackgroundTaskModel(
            id=task_id,
            task_type=task_type,
            status=TaskStatus.QUEUED,
            priority=priority,
            progress_pct=0.0,
            payload=payload or {},
            result={},
            submitted_by=submitted_by,
            queued_at=now,
            execution_log=[f"Task queued with priority {priority.value} at {now.isoformat()}"],
        )

        if session:
            session.add(task_record)
            await session.commit()
        else:
            async with async_session_factory() as sess:
                sess.add(task_record)
                await sess.commit()

        # Enqueue item: tuple (prio_rank, task_dict)
        await self._queue.put((
            prio_rank,
            {
                "id": task_id,
                "task_type": task_type.value,
                "payload": payload,
            }
        ))

        await event_bus.publish("task.queued", {
            "task_id": task_id,
            "task_type": task_type.value,
            "priority": priority.value,
        })

        return task_record.to_dict()

    async def fetch_next_task(self, worker_id: str) -> Optional[Dict[str, Any]]:
        """Fetch next pending task from prioritized queue."""
        if self._queue.empty():
            return None
        try:
            _, task_data = await asyncio.wait_for(self._queue.get(), timeout=0.1)
            # Check if task was cancelled while sitting in queue
            if self.is_cancelled(task_data["id"]):
                async with async_session_factory() as sess:
                    t = await sess.get(BackgroundTaskModel, task_data["id"])
                    if t and t.status == TaskStatus.QUEUED:
                        t.status = TaskStatus.CANCELLED
                        t.completed_at = datetime.utcnow()
                        await sess.commit()
                return None
            return task_data
        except (asyncio.TimeoutError, asyncio.QueueEmpty):
            return None

    def is_cancelled(self, task_id: str) -> bool:
        """Check if a cancellation token has been issued for this task."""
        return task_id in self._cancellation_tokens

    async def cancel_task(self, task_id: str) -> bool:
        """Issue cancellation signal for a queued or processing task."""
        self._cancellation_tokens.add(task_id)

        async with async_session_factory() as sess:
            task = await sess.get(BackgroundTaskModel, task_id)
            if not task:
                return False

            if task.status == TaskStatus.QUEUED:
                task.status = TaskStatus.CANCELLED
                task.completed_at = datetime.utcnow()
                task.execution_log = list(task.execution_log or []) + ["Task cancelled before worker pickup."]
                await sess.commit()

            await event_bus.publish("task.cancelled", {"task_id": task_id})
            return True

    async def get_task(self, task_id: str) -> Optional[Dict[str, Any]]:
        """Retrieve task details by ID."""
        async with async_session_factory() as sess:
            task = await sess.get(BackgroundTaskModel, task_id)
            return task.to_dict() if task else None

    async def list_tasks(
        self,
        status: Optional[str] = None,
        task_type: Optional[str] = None,
        limit: int = 50,
    ) -> List[Dict[str, Any]]:
        """Query task ledger with optional filters."""
        async with async_session_factory() as sess:
            stmt = select(BackgroundTaskModel)
            conditions = []

            if status:
                conditions.append(BackgroundTaskModel.status == TaskStatus(status.upper()))
            if task_type:
                conditions.append(BackgroundTaskModel.task_type == TaskType(task_type.upper()))

            if conditions:
                stmt = stmt.where(and_(*conditions))

            stmt = stmt.order_by(desc(BackgroundTaskModel.queued_at)).limit(limit)
            records = (await sess.execute(stmt)).scalars().all()
            return [r.to_dict() for r in records]

    async def get_pool_status(self) -> Dict[str, Any]:
        """Aggregate telemetry from worker pool and task queues."""
        active_workers = sum(1 for w in self.workers if w.current_task_id is not None)
        idle_workers = len(self.workers) - active_workers

        async with async_session_factory() as sess:
            queued_count = (
                await sess.execute(
                    select(func.count(BackgroundTaskModel.id)).where(BackgroundTaskModel.status == TaskStatus.QUEUED)
                )
            ).scalar_one()

            processing_count = (
                await sess.execute(
                    select(func.count(BackgroundTaskModel.id)).where(BackgroundTaskModel.status == TaskStatus.PROCESSING)
                )
            ).scalar_one()

            completed_today = (
                await sess.execute(
                    select(func.count(BackgroundTaskModel.id)).where(BackgroundTaskModel.status == TaskStatus.SUCCESS)
                )
            ).scalar_one()

            failed_today = (
                await sess.execute(
                    select(func.count(BackgroundTaskModel.id)).where(BackgroundTaskModel.status == TaskStatus.FAILED)
                )
            ).scalar_one()

        return {
            "total_workers": len(self.workers),
            "active_workers": active_workers,
            "idle_workers": idle_workers,
            "queued_tasks": queued_count,
            "processing_tasks": processing_count,
            "completed_today": completed_today,
            "failed_today": failed_today,
            "workers": [w.get_status() for w in self.workers],
        }


# Global Task Manager Instance
task_manager = TaskManager(concurrency=4)
