"""
CyberShield Enterprise - Distributed Tasks & Event Bus Automated Test Suite
Validates Event Bus wildcard pub/sub routing, prioritized task queueing,
specialized async handlers, worker pool telemetry, and REST API RBAC boundaries.
"""

import asyncio
from datetime import datetime
import pytest
import pytest_asyncio
from httpx import AsyncClient, ASGITransport

from cybershield.api.server import app
from cybershield.database.session import init_db, async_session_factory
from cybershield.database.models.user import UserRole
from cybershield.database.models.tasks import BackgroundTaskModel, TaskStatus, TaskPriority, TaskType
from cybershield.auth.security import create_access_token
from cybershield.tasks.event_bus import EventBus
from cybershield.tasks.manager import TaskManager
from cybershield.tasks.handlers.telemetry_handler import handle_telemetry_ingestion
from cybershield.tasks.handlers.malware_handler import handle_malware_analysis
from cybershield.tasks.handlers.intel_handler import handle_intel_sync
from cybershield.tasks.handlers.soar_handler import handle_soar_playbook


@pytest_asyncio.fixture(autouse=True)
async def ensure_db():
    """Ensure database schema is initialized."""
    await init_db()


@pytest_asyncio.fixture
async def client():
    """Create async test client."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as ac:
        yield ac


@pytest_asyncio.fixture
async def admin_token(client: AsyncClient):
    """Authenticate as superadmin or generate authorized JWT."""
    login_resp = await client.post("/api/auth/login", json={
        "username_or_email": "superadmin",
        "password": "CyberShield2026!"
    })
    if login_resp.status_code == 200:
        return login_resp.json()["access_token"]
    return create_access_token(
        data={"sub": "1", "username": "superadmin", "role": UserRole.SUPER_ADMIN.value, "user_id": 1}
    )


@pytest_asyncio.fixture
async def viewer_token(client: AsyncClient):
    """Create token for read-only VIEWER role."""
    uname = "task_viewer_test"
    await client.post("/api/auth/register", json={
        "username": uname,
        "email": f"{uname}@enterprise.corp",
        "password": "ViewerPassword123!",
        "full_name": "Task Viewer User"
    })
    login_resp = await client.post("/api/auth/login", json={
        "username_or_email": uname,
        "password": "ViewerPassword123!"
    })
    if login_resp.status_code == 200:
        return login_resp.json()["access_token"]

    async with async_session_factory() as session:
        from cybershield.database.models.user import User
        from sqlalchemy import select
        u = (await session.execute(select(User).where(User.username == uname))).scalar_one_or_none()
        if u:
            return create_access_token(data={"sub": str(u.id), "username": u.username, "role": u.role, "user_id": u.id})
    return create_access_token(data={"sub": "1", "username": "superadmin", "role": UserRole.VIEWER.value, "user_id": 1})


@pytest.mark.asyncio
async def test_event_bus_wildcards_and_isolation():
    """Verify Event Bus pub/sub, single-token (*), multi-token (#) wildcards, and exception isolation."""
    bus = EventBus()
    received_exact = []
    received_single_wildcard = []
    received_multi_wildcard = []

    async def on_exact(topic, data):
        received_exact.append((topic, data))

    async def on_single(topic, data):
        received_single_wildcard.append((topic, data))

    async def on_multi(topic, data):
        received_multi_wildcard.append((topic, data))

    async def failing_subscriber(topic, data):
        raise RuntimeError("Simulated subscriber crash")

    bus.subscribe("alert.critical", on_exact)
    bus.subscribe("alert.*", on_single)
    bus.subscribe("alert.#", on_multi)
    bus.subscribe("alert.critical", failing_subscriber)

    # Publish message 1
    count = await bus.publish("alert.critical", {"id": "ALT-101", "sev": "CRITICAL"})
    assert count == 4
    assert len(received_exact) == 1
    assert len(received_single_wildcard) == 1
    assert len(received_multi_wildcard) == 1

    # Publish message 2 (multi-token child topic)
    count2 = await bus.publish("alert.network.lateral_movement", {"id": "ALT-102"})
    assert count2 == 1  # Only alert.# matches
    assert len(received_exact) == 1
    assert len(received_single_wildcard) == 1
    assert len(received_multi_wildcard) == 2

    # Check history
    hist = bus.get_history(limit=10)
    assert len(hist) == 2
    assert hist[0]["topic"] == "alert.critical"
    assert hist[1]["topic"] == "alert.network.lateral_movement"


@pytest.mark.asyncio
async def test_task_priority_queueing():
    """Verify TaskManager prioritized ordering: CRITICAL > HIGH > NORMAL > LOW."""
    manager = TaskManager(concurrency=2)

    # Enqueue in reverse priority order
    await manager.submit_task(TaskType.CUSTOM_JOB, {"val": 1}, priority=TaskPriority.LOW)
    await manager.submit_task(TaskType.CUSTOM_JOB, {"val": 2}, priority=TaskPriority.NORMAL)
    await manager.submit_task(TaskType.CUSTOM_JOB, {"val": 3}, priority=TaskPriority.CRITICAL)
    await manager.submit_task(TaskType.CUSTOM_JOB, {"val": 4}, priority=TaskPriority.HIGH)

    # Dequeue 1: must be CRITICAL
    t1 = await manager.fetch_next_task("W1")
    assert t1["payload"]["val"] == 3

    # Dequeue 2: must be HIGH
    t2 = await manager.fetch_next_task("W1")
    assert t2["payload"]["val"] == 4

    # Dequeue 3: must be NORMAL
    t3 = await manager.fetch_next_task("W1")
    assert t3["payload"]["val"] == 2

    # Dequeue 4: must be LOW
    t4 = await manager.fetch_next_task("W1")
    assert t4["payload"]["val"] == 1


@pytest.mark.asyncio
async def test_specialized_handlers():
    """Verify specialized async task handlers execute and produce valid outputs."""
    progress_logs = []

    def progress_tracker(pct, msg):
        progress_logs.append((pct, msg))

    # 1. Telemetry Ingestion Handler
    res_tel = await handle_telemetry_ingestion(
        {"source_type": "SYSLOG", "default_host": "SRV-TEST-01"},
        progress_tracker,
    )
    assert res_tel["events_ingested"] >= 10
    assert "anomalies_detected" in res_tel

    # 2. Malware Binary Analysis Handler
    res_mal = await handle_malware_analysis(
        {"file_name": "suspicious.exe", "format": "PE"},
        progress_tracker,
    )
    assert res_mal["file_name"] == "suspicious.exe"
    assert res_mal["entropy"] > 0
    assert len(res_mal["ctph_fuzzy_hash"]) > 0
    assert "threat_score" in res_mal

    # 3. Threat Intel Sync Handler
    res_intel = await handle_intel_sync(
        {"feed_name": "Test-Feed-A"},
        progress_tracker,
    )
    assert res_intel["iocs_synced"] >= 4
    assert res_intel["status"] == "HEALTHY"

    # 4. SOAR Playbook Handler
    res_soar = await handle_soar_playbook(
        {"playbook_name": "TEST_CONTAINMENT", "target_host": "192.168.1.99"},
        progress_tracker,
    )
    assert len(res_soar["actions_executed"]) >= 3
    assert res_soar["containment_status"] == "CONTAINED"


@pytest.mark.asyncio
async def test_task_cancellation():
    """Verify task cancellation sets status to CANCELLED in database."""
    manager = TaskManager(concurrency=2)
    task_data = await manager.submit_task(TaskType.CUSTOM_JOB, {"data": "test"}, priority=TaskPriority.LOW)
    task_id = task_data["id"]

    # Cancel task
    cancelled = await manager.cancel_task(task_id)
    assert cancelled is True

    # Check task status in DB
    updated = await manager.get_task(task_id)
    assert updated["status"] == "CANCELLED"


@pytest.mark.asyncio
async def test_rest_api_tasks_crud_and_status(client: AsyncClient, admin_token: str):
    """Verify REST API /api/tasks endpoints (submit, list, detail, worker status, event history)."""
    headers = {"Authorization": f"Bearer {admin_token}"}

    # 1. Submit task
    submit_res = await client.post("/api/tasks", json={
        "task_type": "TELEMETRY_INGESTION",
        "priority": "HIGH",
        "payload": {"default_host": "SRV-API-TEST"}
    }, headers=headers)
    assert submit_res.status_code == 201
    task_obj = submit_res.json()
    task_id = task_obj["id"]
    assert task_obj["task_type"] == "TELEMETRY_INGESTION"
    assert task_obj["priority"] == "HIGH"
    assert task_obj["status"] in ["QUEUED", "PROCESSING", "SUCCESS"]

    # 2. List tasks
    list_res = await client.get("/api/tasks", headers=headers)
    assert list_res.status_code == 200
    tasks_list = list_res.json()
    assert len(tasks_list) >= 1
    ids = [t["id"] for t in tasks_list]
    assert task_id in ids

    # 3. Get task details
    detail_res = await client.get(f"/api/tasks/{task_id}", headers=headers)
    assert detail_res.status_code == 200
    assert detail_res.json()["id"] == task_id

    # 4. Worker Pool Status
    pool_res = await client.get("/api/tasks/workers/status", headers=headers)
    assert pool_res.status_code == 200
    pool_data = pool_res.json()
    assert "total_workers" in pool_data
    assert "queued_tasks" in pool_data

    # 5. Event Bus History
    ev_res = await client.get("/api/tasks/events/history", headers=headers)
    assert ev_res.status_code == 200
    assert isinstance(ev_res.json(), list)

    # 6. Cancel task
    cancel_res = await client.post(f"/api/tasks/{task_id}/cancel", headers=headers)
    assert cancel_res.status_code == 200
    assert cancel_res.json()["status"] == "CANCELLED"


@pytest.mark.asyncio
async def test_rest_api_tasks_rbac_boundaries(client: AsyncClient, viewer_token: str):
    """Verify RBAC boundaries: Viewer can list tasks but cannot submit or cancel."""
    viewer_headers = {"Authorization": f"Bearer {viewer_token}"}

    # 1. Viewer can view tasks
    view_res = await client.get("/api/tasks", headers=viewer_headers)
    assert view_res.status_code == 200

    # 2. Viewer CANNOT submit task (requires TASKS_SUBMIT)
    submit_res = await client.post("/api/tasks", json={
        "task_type": "MALWARE_ANALYSIS",
        "priority": "NORMAL",
        "payload": {}
    }, headers=viewer_headers)
    assert submit_res.status_code == 403

    # 3. Viewer CANNOT cancel task (requires TASKS_CANCEL)
    cancel_res = await client.post("/api/tasks/TASK-FAKE-ID/cancel", headers=viewer_headers)
    assert cancel_res.status_code == 403
