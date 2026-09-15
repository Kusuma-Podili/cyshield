"""
Unit and integration tests for Ransomware Canary & VSS Sentinel Subsystem.
"""

import pytest
from fastapi.testclient import TestClient

from cybershield.api.server import app
from cybershield.ransomware.schemas import (
    FileModificationEvent,
    RansomwareThreatLevel,
    VSSCommandInspectionRequest,
)
from cybershield.ransomware.sentinel import RansomwareSentinelEngine


@pytest.fixture
def sentinel():
    return RansomwareSentinelEngine()


@pytest.fixture
def client():
    return TestClient(app)


def test_seeded_canary_bait_files(sentinel):
    canaries = sentinel.list_canaries()
    assert len(canaries) >= 3
    assert any("!_Q4_Audit" in c.file_path for c in canaries)
    assert any("!_Board_Strategy" in c.file_path for c in canaries)


def test_deploy_host_canary_suite(sentinel):
    deployed = sentinel.deploy_host_canaries("WS-FIN-12", r"C:\Users\Analyst\Documents")
    assert len(deployed) >= 4
    for c in deployed:
        assert c.host_id == "WS-FIN-12"
        assert c.file_path.startswith(r"C:\Users\Analyst\Documents\!")


def test_vss_shadow_copy_tampering_detection(sentinel):
    # 1. vssadmin delete shadows
    req1 = VSSCommandInspectionRequest(
        host_id="SRV-DB-01",
        process_name="cmd.exe",
        command_line="vssadmin.exe delete shadows /all /quiet"
    )
    alert1 = sentinel.inspect_vss_command(req1)
    assert alert1 is not None
    assert alert1.threat_level == RansomwareThreatLevel.CRITICAL_OUTBREAK
    assert "Volume Shadow Copy Deletion" in alert1.reason

    # 2. wmic shadowcopy delete
    req2 = VSSCommandInspectionRequest(
        host_id="SRV-DB-01",
        process_name="wmic.exe",
        command_line="wmic shadowcopy delete"
    )
    alert2 = sentinel.inspect_vss_command(req2)
    assert alert2 is not None
    assert alert2.threat_level == RansomwareThreatLevel.CRITICAL_OUTBREAK

    # 3. Benign command
    req_benign = VSSCommandInspectionRequest(
        host_id="SRV-DB-01",
        process_name="powershell.exe",
        command_line="Get-Service -Name Spooler"
    )
    assert sentinel.inspect_vss_command(req_benign) is None


def test_canary_bait_trip_detection(sentinel):
    canary_path = r"C:\Shares\Finance\!_Q4_Audit_Confidential.docx"
    event = FileModificationEvent(
        event_id="EVT-CANARY-01",
        host_id="SRV-FILE-01",
        file_path=canary_path,
        old_extension=".docx",
        new_extension=".docx",
        pre_entropy=4.1,
        post_entropy=7.92,
        process_name="unknown_payload.exe",
        process_pid=9182
    )
    alert = sentinel.inspect_file_modification(event)
    assert alert is not None
    assert alert.threat_level == RansomwareThreatLevel.CRITICAL_OUTBREAK
    assert "Decoy Canary File Tripped" in alert.reason
    assert alert.host_quarantine_recommended is True


def test_ransomware_extension_appending(sentinel):
    event = FileModificationEvent(
        event_id="EVT-EXT-01",
        host_id="WS-DEV-02",
        file_path=r"C:\Projects\source_code.zip.locked",
        old_extension=".zip",
        new_extension=".locked",
        pre_entropy=5.0,
        post_entropy=7.89,
        process_name="locker.exe",
        process_pid=4402
    )
    alert = sentinel.inspect_file_modification(event)
    assert alert is not None
    assert alert.threat_level == RansomwareThreatLevel.CRITICAL_OUTBREAK
    assert ".locked" in alert.detected_extensions


def test_high_entropy_encryption_burst(sentinel):
    host = "WS-CORP-44"
    for i in range(3):
        evt = FileModificationEvent(
            event_id=f"EVT-BURST-{i}",
            host_id=host,
            file_path=r"C:\Data\file_{}.dat".format(i),
            old_extension=".dat",
            new_extension=".dat",
            pre_entropy=3.8,
            post_entropy=7.88,
            process_name="suspicious_enc.exe",
            process_pid=8821
        )
        alert = sentinel.inspect_file_modification(evt)
        if i == 2:
            assert alert is not None
            assert alert.threat_level == RansomwareThreatLevel.HIGH
            assert "Rapid cryptographic encryption burst" in alert.reason


def test_ransomware_api_lifecycle(client):
    # 1. List canaries
    c_res = client.get("/api/ransomware/canaries")
    assert c_res.status_code == 200
    assert len(c_res.json()) >= 3

    # 2. Deploy canaries via API
    deploy_res = client.post("/api/ransomware/canaries/deploy?host_id=WS-TEST-HOST&base_dir=C:\\Users\\Public")
    assert deploy_res.status_code == 201
    assert len(deploy_res.json()) >= 4

    # 3. Inspect command via API
    cmd_payload = {
        "host_id": "SRV-TEST",
        "process_name": "cmd.exe",
        "command_line": "wbadmin delete catalog -quiet"
    }
    cmd_res = client.post("/api/ransomware/inspect/command", json=cmd_payload)
    assert cmd_res.status_code == 200
    assert cmd_res.json() is not None
    assert cmd_res.json()["threat_level"] == "CRITICAL_OUTBREAK"

    # 4. Inspect file event via API
    evt_payload = {
        "event_id": "EVT-API-01",
        "host_id": "SRV-TEST",
        "file_path": "C:\\Docs\\report.pdf.blackcat",
        "old_extension": ".pdf",
        "new_extension": ".blackcat",
        "pre_entropy": 4.5,
        "post_entropy": 7.9,
        "process_name": "blackcat.exe",
        "process_pid": 1234
    }
    evt_res = client.post("/api/ransomware/inspect/file-event", json=evt_payload)
    assert evt_res.status_code == 200
    assert evt_res.json() is not None
    assert ".blackcat" in evt_res.json()["detected_extensions"]

    # 5. List alerts
    alerts_res = client.get("/api/ransomware/alerts")
    assert alerts_res.status_code == 200
    assert len(alerts_res.json()) >= 2

    # 6. Get overview
    ovr_res = client.get("/api/ransomware/overview")
    assert ovr_res.status_code == 200
    assert ovr_res.json()["total_deployed_canaries"] >= 7
