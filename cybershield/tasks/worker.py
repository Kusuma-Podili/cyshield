"""
CyberShield Enterprise - Asynchronous Distributed Task Worker
Executes decoupled background jobs with concurrency limits, cancellation tokens,
progress reporting, and isolated failure domains.
"""

from __future__ import annotations

import asyncio
import logging
import time
import traceback
from datetime import datetime
from typing import Dict, Any, Optional, Callable

from cybershield.database.session import async_session_factory
from cybershield.database.models.tasks import BackgroundTaskModel, TaskStatus, TaskType
from cybershield.tasks.event_bus import event_bus

logger = logging.getLogger("cybershield.tasks.worker")


class TaskWorker:
    """Enterprise Async Background Worker."""

    def __init__(self, worker_id: str, manager: Any):
        self.worker_id = worker_id
        self.manager = manager
        self.is_running = False
        self.current_task_id: Optional[str] = None
        self.tasks_completed = 0
        self.tasks_failed = 0
        self.started_at = time.time()
        self.last_heartbeat = datetime.utcnow()
        self._worker_task: Optional[asyncio.Task] = None

    def start(self) -> None:
        """Launch worker loop as asynchronous task."""
        if not self.is_running:
            self.is_running = True
            self.started_at = time.time()
            self._worker_task = asyncio.create_task(self._run_loop())
            logger.info("Worker '%s' started and listening for background tasks.", self.worker_id)

    async def stop(self) -> None:
        """Gracefully stop worker loop."""
        self.is_running = False
        if self._worker_task and not self._worker_task.done():
            self._worker_task.cancel()
            try:
                await self._worker_task
            except asyncio.CancelledError:
                pass
        logger.info("Worker '%s' stopped.", self.worker_id)

    async def _run_loop(self) -> None:
        """Main worker execution loop polling for queued tasks."""
        while self.is_running:
            self.last_heartbeat = datetime.utcnow()
            task_data = await self.manager.fetch_next_task(self.worker_id)

            if not task_data:
                await asyncio.sleep(0.5)
                continue

            task_id = task_data["id"]
            self.current_task_id = task_id
            start_perf = time.perf_counter()

            try:
                logger.info("Worker '%s' processing task '%s' (type: %s)", self.worker_id, task_id, task_data["task_type"])
                await self._execute_task(task_id, task_data["task_type"], task_data["payload"])
                self.tasks_completed += 1
            except asyncio.CancelledError:
                logger.warning("Task '%s' was cancelled on worker '%s'", task_id, self.worker_id)
                await self._mark_task_cancelled(task_id)
            except Exception as e:
                self.tasks_failed += 1
                logger.error("Error processing task '%s' on worker '%s': %s", task_id, self.worker_id, str(e), exc_info=True)
                await self._mark_task_failed(task_id, str(e), traceback.format_exc(), time.perf_counter() - start_perf)
            finally:
                self.current_task_id = None

    async def _execute_task(self, task_id: str, task_type_str: str, payload: Dict[str, Any]) -> None:
        """Dispatch task to registered handler with live progress updating."""
        handler = self.manager.get_handler(task_type_str)
        if not handler:
            raise ValueError(f"No task handler registered for type: '{task_type_str}'")

        # Mark task as processing
        now = datetime.utcnow()
        async with async_session_factory() as session:
            db_task = await session.get(BackgroundTaskModel, task_id)
            if db_task:
                db_task.status = TaskStatus.PROCESSING
                db_task.started_at = now
                db_task.worker_id = self.worker_id
                db_task.progress_pct = 5.0
                db_task.execution_log = [f"Worker '{self.worker_id}' picked up task at {now.isoformat()}"]
                await session.commit()

        await event_bus.publish("task.started", {"task_id": task_id, "worker_id": self.worker_id})

        # Local progress callback closure
        async def update_progress(pct: float, log_msg: str) -> None:
            # Check for cancellation
            if self.manager.is_cancelled(task_id):
                raise asyncio.CancelledError(f"Task {task_id} received cancellation signal")

            async with async_session_factory() as session:
                db_task = await session.get(BackgroundTaskModel, task_id)
                if db_task:
                    db_task.progress_pct = min(100.0, max(0.0, pct))
                    current_log = list(db_task.execution_log or [])
                    current_log.append(f"[{datetime.utcnow().strftime('%H:%M:%S')}] {log_msg}")
                    db_task.execution_log = current_log
                    await session.commit()

            await event_bus.publish("task.progress", {
                "task_id": task_id,
                "progress_pct": pct,
                "message": log_msg,
            })

        # Provide a sync-callable adapter for handlers
        def progress_callback_sync(pct: float, log_msg: str):
            asyncio.create_task(update_progress(pct, log_msg))

        start_time = time.perf_counter()
        result_payload = await handler(payload, progress_callback_sync)
        duration = round(time.perf_counter() - start_time, 3)

        # Mark task as completed
        completed_at = datetime.utcnow()
        async with async_session_factory() as session:
            db_task = await session.get(BackgroundTaskModel, task_id)
            if db_task:
                db_task.status = TaskStatus.SUCCESS
                db_task.progress_pct = 100.0
                db_task.result = result_payload or {}
                db_task.completed_at = completed_at
                db_task.duration_sec = duration
                current_log = list(db_task.execution_log or [])
                current_log.append(f"Execution completed successfully in {duration}s")
                db_task.execution_log = current_log
                await session.commit()

        await event_bus.publish("task.completed", {
            "task_id": task_id,
            "worker_id": self.worker_id,
            "duration_sec": duration,
            "result": result_payload,
        })

    async def _mark_task_failed(self, task_id: str, error_msg: str, stack_trace: str, duration: float) -> None:
        """Record task failure state in database."""
        async with async_session_factory() as session:
            db_task = await session.get(BackgroundTaskModel, task_id)
            if db_task:
                db_task.status = TaskStatus.FAILED
                db_task.error_message = error_msg
                db_task.completed_at = datetime.utcnow()
                db_task.duration_sec = round(duration, 3)
                current_log = list(db_task.execution_log or [])
                current_log.append(f"FAILED: {error_msg}")
                db_task.execution_log = current_log
                await session.commit()

        await event_bus.publish("task.failed", {
            "task_id": task_id,
            "worker_id": self.worker_id,
            "error": error_msg,
        })

    async def _mark_task_cancelled(self, task_id: str) -> None:
        """Record task cancellation in database."""
        async with async_session_factory() as session:
            db_task = await session.get(BackgroundTaskModel, task_id)
            if db_task:
                db_task.status = TaskStatus.CANCELLED
                db_task.completed_at = datetime.utcnow()
                current_log = list(db_task.execution_log or [])
                current_log.append("Task was cancelled by operator.")
                db_task.execution_log = current_log
                await session.commit()

        await event_bus.publish("task.cancelled", {
            "task_id": task_id,
            "worker_id": self.worker_id,
        })

    def get_status(self) -> Dict[str, Any]:
        """Return worker telemetry dictionary."""
        return {
            "worker_id": self.worker_id,
            "status": "BUSY" if self.current_task_id else "IDLE" if self.is_running else "OFFLINE",
            "current_task_id": self.current_task_id,
            "tasks_completed": self.tasks_completed,
            "tasks_failed": self.tasks_failed,
            "uptime_sec": round(time.time() - self.started_at, 1) if self.is_running else 0.0,
            "last_heartbeat": self.last_heartbeat.isoformat(),
        }
