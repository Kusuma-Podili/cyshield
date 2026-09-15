"""
C2 Threat Emulation and Red Team Engine.
Manages encrypted listeners, beacon agent check-ins, jitter scheduling, and task queues.
"""

import random
import uuid
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

from cybershield.c2.schemas import (
    BeaconCheckinPayload,
    BeaconSession,
    BeaconSessionStatus,
    BeaconTaskResultPayload,
    C2CommandType,
    C2Listener,
    C2ListenerProtocol,
    C2Task,
)


class C2EmulationEngine:
    """Adversary C2 Framework Engine for Purple Teaming and Evasion Testing."""

    def __init__(self):
        self._listeners: Dict[str, C2Listener] = {}
        self._sessions: Dict[str, BeaconSession] = {}
        # Queued tasks: session_id -> List[C2Task]
        self._task_queues: Dict[str, List[C2Task]] = {}
        self._completed_tasks: Dict[str, C2Task] = {}
        self._seed_default_listener()

    def _seed_default_listener(self):
        """Seed default HTTPS emulation listener and an initial beacon session."""
        default_listener = C2Listener(
            listener_id="LISTENER-HTTPS-PRIMARY",
            name="Primary HTTPS Ingress Listener",
            protocol=C2ListenerProtocol.HTTPS,
            bind_ip="0.0.0.0",
            port=8443,
            domain_fronting_host="cdn-telemetry.azureedge.net",
            status="RUNNING",
            total_beacons_connected=1,
        )
        self._listeners[default_listener.listener_id] = default_listener

        session = BeaconSession(
            session_id="BEACON-W11-FINANCE",
            listener_id=default_listener.listener_id,
            hostname="FIN-WORKSTATION-01",
            internal_ip="10.0.4.15",
            os_name="Windows 11 Enterprise",
            pid=3840,
            process_name="msedge.exe",
            user_context="CORP\\jdoe",
            is_elevated=False,
            sleep_interval_sec=30.0,
            jitter_pct=25.0,
            last_checkin=datetime.utcnow(),
            status=BeaconSessionStatus.ACTIVE,
        )
        self._sessions[session.session_id] = session
        self._task_queues[session.session_id] = []

    def list_listeners(self) -> List[C2Listener]:
        return list(self._listeners.values())

    def get_listener(self, listener_id: str) -> Optional[C2Listener]:
        return self._listeners.get(listener_id)

    def create_listener(self, listener: C2Listener) -> C2Listener:
        self._listeners[listener.listener_id] = listener
        return listener

    def list_sessions(self) -> List[BeaconSession]:
        # Check staleness: if last check-in > 3x sleep interval, mark DISCONNECTED
        now = datetime.utcnow()
        for s in self._sessions.values():
            max_tolerated_delay = s.sleep_interval_sec * 3
            if (now - s.last_checkin).total_seconds() > max_tolerated_delay:
                if s.status == BeaconSessionStatus.ACTIVE:
                    s.status = BeaconSessionStatus.DISCONNECTED
            s.queued_tasks_count = len(self._task_queues.get(s.session_id, []))
        return list(self._sessions.values())

    def get_session(self, session_id: str) -> Optional[BeaconSession]:
        s = self._sessions.get(session_id)
        if s:
            s.queued_tasks_count = len(self._task_queues.get(session_id, []))
        return s

    @staticmethod
    def calculate_jittered_interval(base_interval_sec: float, jitter_pct: float) -> float:
        """Calculate next sleep interval with randomized jitter."""
        fraction = jitter_pct / 100.0
        min_sec = max(1.0, base_interval_sec * (1.0 - fraction))
        max_sec = base_interval_sec * (1.0 + fraction)
        return round(random.uniform(min_sec, max_sec), 2)

    def queue_task(self, session_id: str, command: C2CommandType, arguments: Dict[str, Any]) -> C2Task:
        """Queue a task for the target beacon agent."""
        if session_id not in self._sessions:
            raise ValueError(f"Beacon session '{session_id}' not found")

        task = C2Task(
            task_id=f"TASK-{uuid.uuid4().hex[:8].upper()}",
            session_id=session_id,
            command=command,
            arguments=arguments,
            status="PENDING",
            created_at=datetime.utcnow(),
        )

        self._task_queues.setdefault(session_id, []).append(task)
        return task

    def handle_checkin(self, payload: BeaconCheckinPayload) -> List[C2Task]:
        """Beacon agent check-in: updates heartbeat and retrieves queued tasks."""
        session = self._sessions.get(payload.session_id)
        if not session:
            # Register new beacon session automatically
            session = BeaconSession(
                session_id=payload.session_id,
                listener_id="LISTENER-HTTPS-PRIMARY",
                hostname=f"HOST-{payload.session_id[-4:]}",
                internal_ip="10.0.1.50",
                last_checkin=datetime.utcnow(),
                status=BeaconSessionStatus.ACTIVE,
            )
            self._sessions[session.session_id] = session

        session.last_checkin = datetime.utcnow()
        session.status = BeaconSessionStatus.ACTIVE

        # Pop pending tasks to dispatch
        queue = self._task_queues.get(session.session_id, [])
        dispatched_tasks = []
        for t in queue:
            t.status = "DISPATCHED"
            dispatched_tasks.append(t)

        self._task_queues[session.session_id] = []
        return dispatched_tasks

    def record_task_result(self, payload: BeaconTaskResultPayload) -> C2Task:
        """Record output returned by a beacon agent."""
        session = self._sessions.get(payload.session_id)
        if session:
            session.last_checkin = datetime.utcnow()

        task = C2Task(
            task_id=payload.task_id,
            session_id=payload.session_id,
            command=C2CommandType.SHELL,
            status=payload.status,
            completed_at=datetime.utcnow(),
            output=payload.output,
        )
        self._completed_tasks[payload.task_id] = task
        return task

    def get_task_result(self, task_id: str) -> Optional[C2Task]:
        return self._completed_tasks.get(task_id)
