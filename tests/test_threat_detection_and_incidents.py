"""
CyberShield Enterprise - Threat Detection, Incidents & SOAR Automated Test Suite
Validates Sigma/YARA detection rule management, dry-run AST evaluation,
multi-stage attack chain correlation, incident lifecycle, and SOAR containment execution.
"""

import uuid
import pytest
import pytest_asyncio
from httpx import AsyncClient, ASGITransport
from datetime import datetime

from cybershield.api.server import app
from cybershield.database.session import async_session_factory, init_db
from cybershield.database.models.user import User, UserRole
from cybershield.auth.security import create_access_token
from cybershield.detection.correlator import AttackChainCorrelator
from cybershield.database.models.network import NetworkDevice, DeviceStatus
from cybershield.database.models.incidents_and_rules import (
    DetectionRuleModel,
    IncidentModel,
    IncidentTimelineModel,
    IncidentSeverity,
    IncidentStatus,
    IncidentType,
    KillChainPhase,
    RuleType,
)
from cybershield.database.models.events_and_alerts import (
    AlertModel,
    EventSeverity,
    AlertStatus,
    DetectionEngineType,
)

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
    """Authenticate as superadmin and retrieve valid JWT token."""
    login_resp = await client.post("/api/auth/login", json={
        "username_or_email": "superadmin",
        "password": "CyberShield2026!"
    })
    if login_resp.status_code == 200:
        return login_resp.json()["access_token"]
    return create_access_token(
        data={"sub": "1", "username": "superadmin", "role": UserRole.SUPER_ADMIN.value, "user_id": 1}
    )


@pytest.mark.asyncio
async def test_detection_rules_seeding_and_list(client: AsyncClient, admin_token: str):
    """Verify default Sigma and YARA rules are seeded and listed via API."""
    headers = {"Authorization": f"Bearer {admin_token}"}
    response = await client.get("/api/detection/rules", headers=headers)
    assert response.status_code == 200
    data = response.json()
    assert "items" in data
    assert data["total"] > 0
    rule_types = {r["rule_type"] for r in data["items"]}
    assert "SIGMA" in rule_types or "YARA" in rule_types


@pytest.mark.asyncio
async def test_custom_sigma_rule_creation_and_validation(client: AsyncClient, admin_token: str):
    """Test creating a custom Sigma detection rule with AST compilation."""
    headers = {"Authorization": f"Bearer {admin_token}"}
    rule_payload = {
        "name": "Suspicious Cobalt Strike Pipe Name",
        "description": "Detects named pipe creation matching Cobalt Strike default beacon pattern",
        "rule_type": "SIGMA",
        "severity": "CRITICAL",
        "raw_content": """title: Cobalt Strike Named Pipe
logsource:
    category: pipe_creation
detection:
    selection:
        PipeName|contains:
            - 'msagent_'
            - 'status_'
    condition: selection
level: critical
tags:
    - attack.defense_evasion
    - attack.t1055"""
    }
    response = await client.post("/api/detection/rules", json=rule_payload, headers=headers)
    assert response.status_code == 201
    data = response.json()
    assert data["name"] == "Suspicious Cobalt Strike Pipe Name"
    assert data["severity"] == "CRITICAL"
    assert data["rule_type"] == "SIGMA"
    assert any("defense" in t.lower() for t in data["mitre_tactics"])


@pytest.mark.asyncio
async def test_toggle_detection_rule_active_state(client: AsyncClient, admin_token: str):
    """Test enabling and disabling a detection rule."""
    headers = {"Authorization": f"Bearer {admin_token}"}
    # List rules to get an ID
    list_res = await client.get("/api/detection/rules", headers=headers)
    first_rule = list_res.json()["items"][0]
    rule_id = first_rule["id"]
    orig_state = first_rule["is_enabled"]

    # Toggle
    toggle_res = await client.post(f"/api/detection/rules/{rule_id}/toggle", headers=headers)
    assert toggle_res.status_code == 200
    assert toggle_res.json()["is_enabled"] == (not orig_state)

    # Revert toggle
    revert_res = await client.post(f"/api/detection/rules/{rule_id}/toggle", headers=headers)
    assert revert_res.status_code == 200
    assert revert_res.json()["is_enabled"] == orig_state


@pytest.mark.asyncio
async def test_dry_run_rule_evaluation(client: AsyncClient, admin_token: str):
    """Verify dry-run testing of Sigma rule AST against mock event."""
    headers = {"Authorization": f"Bearer {admin_token}"}
    test_req = {
        "rule_type": "SIGMA",
        "raw_content": """title: Mimikatz Sekurlsa Detection
logsource:
    category: process_creation
detection:
    selection:
        CommandLine|contains:
            - 'sekurlsa'
            - 'logonpasswords'
    condition: selection
level: critical""",
        "test_payload": {
            "process_name": "mimikatz.exe",
            "command_line": "mimikatz.exe privilege::debug sekurlsa::logonpasswords exit",
            "host_name": "dc-primary.corp"
        }
    }
    response = await client.post("/api/detection/rules/test", json=test_req, headers=headers)
    assert response.status_code == 200
    data = response.json()
    assert data["matched"] is True
    assert data["execution_time_ms"] >= 0


@pytest.mark.asyncio
async def test_attack_chain_correlator_logic():
    """Verify multi-stage attack chain correlation engine synthesizes an incident."""
    correlator = AttackChainCorrelator(correlation_window_minutes=30, risk_threshold=60)

    alerts = [
        AlertModel(
            id="ALT-CHAIN-01",
            alert_code="ALT-2026-9001",
            title="Suspicious PowerShell Cradle Download",
            description="PowerShell downloaded payload from external IP",
            severity=EventSeverity.HIGH,
            status=AlertStatus.NEW,
            engine=DetectionEngineType.SIGMA,
            rule_id="SIGMA-01",
            rule_name="PowerShell Cradle",
            host_name="ws-finance-01.corp",
            host_ip="192.168.1.105",
            mitre_tactic="Execution",
            mitre_technique_id="T1059.001",
            deduplication_hash="SIGMA:PS_CRADLE:ws-finance-01",
            created_at=datetime.utcnow(),
        ),
        AlertModel(
            id="ALT-CHAIN-02",
            alert_code="ALT-2026-9002",
            title="Mimikatz Memory Dump LSASS",
            description="LSASS memory dump executed via sekurlsa",
            severity=EventSeverity.CRITICAL,
            status=AlertStatus.NEW,
            engine=DetectionEngineType.SIGMA,
            rule_id="SIGMA-02",
            rule_name="Mimikatz LSASS",
            host_name="ws-finance-01.corp",
            host_ip="192.168.1.105",
            mitre_tactic="Credential Access",
            mitre_technique_id="T1003.001",
            deduplication_hash="SIGMA:MIMIKATZ:ws-finance-01",
            created_at=datetime.utcnow(),
        ),
        AlertModel(
            id="ALT-CHAIN-03",
            alert_code="ALT-2026-9003",
            title="High Volume Outbound Egress to Suspicious Port",
            description="1.8 GB outbound exfiltration spike detected",
            severity=EventSeverity.HIGH,
            status=AlertStatus.NEW,
            engine=DetectionEngineType.SURICATA,
            rule_id="NETFLOW-01",
            rule_name="Exfiltration Spike",
            host_name="ws-finance-01.corp",
            host_ip="192.168.1.105",
            mitre_tactic="Exfiltration",
            mitre_technique_id="T1048",
            deduplication_hash="NETFLOW:EXFIL:ws-finance-01",
            created_at=datetime.utcnow(),
        ),
    ]

    result = correlator.evaluate_alert_cluster("ws-finance-01.corp", alerts)
    assert result is not None
    assert result["severity"] == "CRITICAL"
    assert len(result["associated_alert_ids"]) == 3
    assert "ws-finance-01.corp" in result["impacted_hosts"]
    assert result["risk_score"] >= 60


@pytest.mark.asyncio
async def test_incident_creation_and_listing(client: AsyncClient, admin_token: str):
    """Test manual creation of a security incident case and query via API."""
    headers = {"Authorization": f"Bearer {admin_token}"}
    payload = {
        "title": "Suspected LockBit 3.0 Ransomware Activity",
        "summary": "Shadow volume copies deleted and suspicious .lockbit file renaming observed on file server.",
        "severity": "CRITICAL",
        "incident_type": "RANSOMWARE",
        "kill_chain_phase": "IMPACT",
        "impacted_hosts": ["nas-eng-01.corp"],
        "impacted_users": ["svc_storage"],
        "assigned_playbook": "IR-01: Ransomware Containment & Host Isolation"
    }
    create_res = await client.post("/api/incidents", json=payload, headers=headers)
    assert create_res.status_code == 201
    created = create_res.json()
    assert created["id"].startswith("INC-")
    assert created["title"] == payload["title"]
    assert created["status"] == "OPEN"

    # Query list
    list_res = await client.get("/api/incidents", headers=headers)
    assert list_res.status_code == 200
    items = list_res.json()["items"]
    assert any(i["id"] == created["id"] for i in items)


@pytest.mark.asyncio
async def test_incident_status_progression_and_timeline(client: AsyncClient, admin_token: str):
    """Test advancing incident through lifecycle states and appending timeline evidence."""
    headers = {"Authorization": f"Bearer {admin_token}"}

    # Create incident
    payload = {
        "title": "Unauthorized SSH Brute Force Incident",
        "summary": "Multiple failed SSH root logins followed by successful session on bastion.",
        "severity": "HIGH",
        "incident_type": "UNAUTHORIZED_ACCESS",
        "kill_chain_phase": "INITIAL_ACCESS",
        "impacted_hosts": ["bastion-01.corp"],
    }
    create_res = await client.post("/api/incidents", json=payload, headers=headers)
    inc_id = create_res.json()["id"]

    # Transition to TRIAGED
    patch_res = await client.patch(
        f"/api/incidents/{inc_id}/status",
        json={"status": "TRIAGED", "comment": "Assigned to Tier 2 SOC Analyst"},
        headers=headers
    )
    assert patch_res.status_code == 200
    assert patch_res.json()["status"] == "TRIAGED"

    # Add forensic timeline note
    timeline_res = await client.post(
        f"/api/incidents/{inc_id}/timeline",
        json={
            "action_type": "FORENSIC_ANALYSIS",
            "description": "Extracted auth.log from bastion. Malicious source IP 198.51.100.22 identified.",
            "evidence_reference": "SHA256:7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069"
        },
        headers=headers
    )
    assert timeline_res.status_code == 201
    assert timeline_res.json()["action_type"] == "FORENSIC_ANALYSIS"

    # Fetch full dossier
    dossier_res = await client.get(f"/api/incidents/{inc_id}", headers=headers)
    assert dossier_res.status_code == 200
    dossier = dossier_res.json()
    assert len(dossier["timeline"]) >= 2  # CASE_OPENED + STATUS_CHANGE + FORENSIC_ANALYSIS


@pytest.mark.asyncio
async def test_soar_containment_execution_and_device_sync(client: AsyncClient, admin_token: str):
    """Verify executing SOAR containment on an incident quarantines host in NetworkDevice DB."""
    headers = {"Authorization": f"Bearer {admin_token}"}
    test_id = f"dev-soar-{uuid.uuid4().hex[:6]}"
    test_mac = f"00:1A:2B:3C:{uuid.uuid4().hex[:2].upper()}:{uuid.uuid4().hex[:2].upper()}"
    test_host = f"comp-ws-{uuid.uuid4().hex[:4]}.corp"

    # Ensure device exists in DB
    async with async_session_factory() as session:
        dev = NetworkDevice(
            id=test_id,
            hostname=test_host,
            ip_address="10.0.10.99",
            mac_address=test_mac,
            device_type="WORKSTATION",
            status=DeviceStatus.ONLINE.value,
            risk_score=20,
            created_at=datetime.utcnow(),
            updated_at=datetime.utcnow(),
        )
        session.add(dev)
        await session.commit()

    # Create incident targeting this host
    create_res = await client.post(
        "/api/incidents",
        json={
            "title": f"Active Malware on {test_host}",
            "summary": "Trojan beaconing detected from endpoint.",
            "severity": "CRITICAL",
            "impacted_hosts": [test_host],
        },
        headers=headers
    )
    inc_id = create_res.json()["id"]

    # Execute SOAR ISOLATE_HOST containment
    soar_res = await client.post(
        f"/api/incidents/{inc_id}/contain",
        json={
            "action_type": "ISOLATE_HOST",
            "target": test_host,
            "parameters": {"reason": "Automated incident response quarantine"}
        },
        headers=headers
    )
    assert soar_res.status_code == 200
    soar_data = soar_res.json()
    assert soar_data["success"] is True
    assert soar_data["current_status"] == "CONTAINED"

    # Verify device status updated in database
    async with async_session_factory() as session:
        from sqlalchemy import select
        res = await session.execute(select(NetworkDevice).where(NetworkDevice.id == test_id))
        dev_in_db = res.scalar_one_or_none()
        assert dev_in_db is not None
        assert dev_in_db.status == DeviceStatus.ISOLATED.value


@pytest.mark.asyncio
async def test_kpi_metrics_endpoints(client: AsyncClient, admin_token: str):
    """Test incident and detection KPI aggregation endpoints."""
    headers = {"Authorization": f"Bearer {admin_token}"}

    inc_kpi_res = await client.get("/api/incidents/kpis", headers=headers)
    assert inc_kpi_res.status_code == 200
    inc_kpis = inc_kpi_res.json()
    assert "total_incidents" in inc_kpis
    assert "open_incidents" in inc_kpis
    assert "avg_mttr_minutes" in inc_kpis

    det_kpi_res = await client.get("/api/detection/kpis", headers=headers)
    assert det_kpi_res.status_code == 200
    det_kpis = det_kpi_res.json()
    assert "total_rules" in det_kpis
    assert "active_rules" in det_kpis
    assert "sigma_rules" in det_kpis
