"""
Unit and Integration Tests for C2 Threat Emulation Framework Subsystem.
Verifies listeners, beacon sessions, jittered intervals, task queues, and REST APIs.
"""

import pytest
from fastapi.testclient import TestClient

from cybershield.api.server import app
from cybershield.c2.engine import C2EmulationEngine
from cybershield.c2.schemas import (
    BeaconCheckinPayload,
    BeaconTaskResultPayload,
    C2CommandType,
    C2Listener,
    C2ListenerProtocol,
)


@pytest.fixture
def c2_engine():
    return C2EmulationEngine()


@pytest.fixture
def client():
    return TestClient(app)


def test_listener_and_session_initialization(c2_engine):
    listeners = c2_engine.list_listeners()
    assert len(listeners) >= 1
    assert listeners[0].protocol == C2ListenerProtocol.HTTPS

    sessions = c2_engine.list_sessions()
    assert len(sessions) >= 1
    assert sessions[0].session_id == "BEACON-W11-FINANCE"


def test_jitter_interval_bounds():
    base = 60.0
    jitter = 30.0  # 30% -> [42.0, 78.0]

    for _ in range(50):
        val = C2EmulationEngine.calculate_jittered_interval(base, jitter)
        assert 42.0 <= val <= 78.0


def test_task_queue_and_checkin_dispatch(c2_engine):
    session_id = "BEACON-W11-FINANCE"

    # Queue task
    task = c2_engine.queue_task(
        session_id=session_id,
        command=C2CommandType.SHELL,
        arguments={"cmd": "whoami /all"},
    )
    assert task.status == "PENDING"

    session = c2_engine.get_session(session_id)
    assert session.queued_tasks_count == 1

    # Check-in should pop and dispatch task
    dispatched = c2_engine.handle_checkin(BeaconCheckinPayload(session_id=session_id))
    assert len(dispatched) == 1
    assert dispatched[0].task_id == task.task_id
    assert dispatched[0].status == "DISPATCHED"

    # Queue should now be empty
    session_after = c2_engine.get_session(session_id)
    assert session_after.queued_tasks_count == 0


def test_beacon_task_result_recording(c2_engine):
    payload = BeaconTaskResultPayload(
        session_id="BEACON-W11-FINANCE",
        task_id="TASK-TEST-001",
        status="COMPLETED",
        output="CORP\\jdoe\nMandatory Label\\Medium Mandatory Level",
    )
    task = c2_engine.record_task_result(payload)

    assert task.task_id == "TASK-TEST-001"
    assert task.status == "COMPLETED"
    assert "CORP\\jdoe" in task.output

    retrieved = c2_engine.get_task_result("TASK-TEST-001")
    assert retrieved is not None
    assert retrieved.output == task.output


def test_c2_api_endpoints(client):
    # 1. List listeners
    resp = client.get("/api/c2/listeners")
    assert resp.status_code == 200
    assert len(resp.json()) >= 1

    # 2. List sessions
    resp = client.get("/api/c2/sessions")
    assert resp.status_code == 200
    sessions = resp.json()
    assert len(sessions) >= 1
    session_id = sessions[0]["session_id"]

    # 3. Queue task via API
    task_payload = {
        "command": "SHELL",
        "arguments": {"cmd": "ipconfig /all"},
    }
    resp = client.post(f"/api/c2/sessions/{session_id}/tasks", json=task_payload)
    assert resp.status_code == 201
    task_id = resp.json()["task_id"]

    # 4. Beacon check-in via API
    checkin_payload = {"session_id": session_id}
    resp = client.post("/api/c2/beacon/checkin", json=checkin_payload)
    assert resp.status_code == 200
    tasks = resp.json()
    assert len(tasks) >= 1
    assert tasks[0]["task_id"] == task_id

    # 5. Beacon deliver response via API
    res_payload = {
        "session_id": session_id,
        "task_id": task_id,
        "status": "COMPLETED",
        "output": "Windows IP Configuration\nIPv4 Address: 10.0.4.15",
    }
    resp = client.post("/api/c2/beacon/response", json=res_payload)
    assert resp.status_code == 200
    assert resp.json()["status"] == "COMPLETED"

    # 6. Retrieve completed task
    resp = client.get(f"/api/c2/tasks/{task_id}")
    assert resp.status_code == 200
    assert "10.0.4.15" in resp.json()["output"]
