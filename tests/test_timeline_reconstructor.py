"""Tests for CyberShield Enterprise - Forensics Timeline Reconstructor & Memory Dissector.
Verifies cross-host clock skew normalization, NTFS timestomping detection,
memory VAD tree shellcode dissection, episode clustering, and REST API routes.
"""

import json
import pytest
from datetime import datetime, timezone, timedelta
from starlette.testclient import TestClient

from cybershield.api.server import app
from cybershield.timeline.schemas import (
    ArtifactSourceType,
    AttackPhase,
    ForensicArtifact,
    MemoryVADNode,
)
from cybershield.timeline.reconstructor import ForensicsTimelineReconstructor


@pytest.fixture
def client():
    return TestClient(app)


@pytest.fixture
def reconstructor():
    engine = ForensicsTimelineReconstructor()

    # Configure clock skew for a drift-prone workstation (+5000ms drift)
    engine.set_host_clock_skew("ws-finance-02", -5000)

    # Seed baseline artifacts
    t0 = datetime(2026, 9, 12, 10, 0, 0, tzinfo=timezone.utc)

    # 1. Initial Access
    a1 = ForensicArtifact(
        artifact_id="art-01",
        source_type=ArtifactSourceType.EVTX_SECURITY,
        host_id="ws-sales-01",
        raw_timestamp=t0,
        entity_subject="outlook.exe",
        action_verb="SPAWN_CHILD",
        target_object="invoice_macro.vbs",
        attack_phase=AttackPhase.INITIAL_ACCESS,
    )

    # 2. Execution (2 minutes later)
    a2 = ForensicArtifact(
        artifact_id="art-02",
        source_type=ArtifactSourceType.PREFETCH_EXECUTION,
        host_id="ws-sales-01",
        raw_timestamp=t0 + timedelta(minutes=2),
        entity_subject="wscript.exe",
        action_verb="EXECUTE_PAYLOAD",
        target_object="powershell.exe",
        attack_phase=AttackPhase.EXECUTION,
    )

    # 3. Credential Access (15 minutes later - should create new episode)
    a3 = ForensicArtifact(
        artifact_id="art-03",
        source_type=ArtifactSourceType.AMCACHE,
        host_id="ws-sales-01",
        raw_timestamp=t0 + timedelta(minutes=17),
        entity_subject="powershell.exe",
        action_verb="INVOKE_MIMIKATZ",
        target_object="lsass.exe",
        attack_phase=AttackPhase.CREDENTIAL_ACCESS,
    )

    # 4. Lateral Movement to ws-finance-02 (20 minutes later)
    a4 = ForensicArtifact(
        artifact_id="art-04",
        source_type=ArtifactSourceType.EVTX_SECURITY,
        host_id="ws-finance-02",
        raw_timestamp=t0 + timedelta(minutes=20, milliseconds=5000),  # Raw has +5s skew
        entity_subject="smb_client",
        action_verb="REMOTE_ADMIN_SHARE",
        target_object="C$\\Windows\\Temp\\beacon.dll",
        attack_phase=AttackPhase.LATERAL_MOVEMENT,
    )

    engine.ingest_artifact(a1)
    engine.ingest_artifact(a2)
    engine.ingest_artifact(a3)
    engine.ingest_artifact(a4)

    return engine


# =========================================================================
# Unit Tests: Clock Skew Normalization
# =========================================================================

def test_clock_skew_normalization(reconstructor):
    # Verify artifact on ws-finance-02 was shifted back by 5000ms
    art4 = reconstructor.artifacts["art-04"]
    expected_time = datetime(2026, 9, 12, 10, 20, 0, tzinfo=timezone.utc)
    assert art4.normalized_utc_timestamp == expected_time
    assert art4.clock_skew_offset_ms == -5000


# =========================================================================
# Unit Tests: NTFS Timestomp Anti-Forensics Detection
# =========================================================================

def test_timestomp_detection_rollback(reconstructor):
    fn_time = datetime(2026, 9, 12, 14, 30, 0, tzinfo=timezone.utc)
    # Attacker rolled SI back to year 2021
    si_time = datetime(2021, 5, 1, 12, 0, 0, tzinfo=timezone.utc)

    res = reconstructor.detect_ntfs_timestomp(
        file_path="C:\\Windows\\System32\\drivers\\rootkit.sys",
        host_id="ws-finance-02",
        standard_info_time=si_time,
        file_name_time=fn_time,
    )
    assert res.is_timestomped is True
    assert res.delta_seconds > 10000
    assert "rolled back" in res.details.lower()


def test_timestomp_detection_zero_microsecond_truncation(reconstructor):
    fn_time = datetime(2026, 9, 12, 14, 30, 0, 451234, tzinfo=timezone.utc)
    # SI timestamp has 0 microseconds
    si_time = datetime(2026, 9, 12, 14, 30, 0, 0, tzinfo=timezone.utc)

    res = reconstructor.detect_ntfs_timestomp(
        file_path="C:\\Users\\admin\\payload.exe",
        host_id="ws-dev-01",
        standard_info_time=si_time,
        file_name_time=fn_time,
    )
    assert res.is_timestomped is True
    assert "zero microsecond" in res.details.lower()


def test_legitimate_file_not_timestomped(reconstructor):
    t = datetime(2026, 9, 12, 14, 30, 0, 123456, tzinfo=timezone.utc)
    res = reconstructor.detect_ntfs_timestomp(
        file_path="C:\\Windows\\notepad.exe",
        host_id="ws-dev-01",
        standard_info_time=t,
        file_name_time=t,
    )
    assert res.is_timestomped is False


# =========================================================================
# Unit Tests: Memory VAD Dissection
# =========================================================================

def test_memory_vad_shellcode_dissection(reconstructor):
    vad = MemoryVADNode(
        pid=4912,
        process_name="rundll32.exe",
        start_address="0x0000021A4B000000",
        end_address="0x0000021A4B040000",
        protection="PAGE_EXECUTE_READWRITE",
        is_executable=True,
        is_unbacked_memory=True,  # Crucial indicator of injection
        entropy=7.1,
    )

    dissected = reconstructor.dissect_memory_vad(vad)
    assert dissected.is_malicious_injection is True
    assert dissected.shellcode_signature_matched == "CobaltStrike_Beacon_Reflective_Loader"


def test_clean_memory_vad_not_flagged(reconstructor):
    vad = MemoryVADNode(
        pid=1000,
        process_name="svchost.exe",
        start_address="0x00007FF780000000",
        end_address="0x00007FF780020000",
        protection="PAGE_EXECUTE_READ",
        is_executable=True,
        is_unbacked_memory=False,  # Mapped to disk binary
        entropy=5.2,
    )

    dissected = reconstructor.dissect_memory_vad(vad)
    assert dissected.is_malicious_injection is False
    assert dissected.shellcode_signature_matched is None


# =========================================================================
# Unit Tests: Incident Timeline Reconstruction & Clustering
# =========================================================================

def test_incident_timeline_reconstruction(reconstructor):
    timeline = reconstructor.reconstruct_timeline(incident_id="INC-2026-ALPHA")
    assert timeline.incident_id == "INC-2026-ALPHA"
    assert timeline.total_artifacts == 4
    assert len(timeline.episodes) >= 2
    assert timeline.patient_zero_host == "ws-sales-01"
    assert "outlook.exe" in timeline.comprehensive_narrative
    assert "INC-2026-ALPHA" in timeline.comprehensive_narrative


# =========================================================================
# REST API Integration Tests
# =========================================================================

def test_api_timeline_lifecycle(client):
    # 1. Ingest Artifact
    art_payload = {
        "artifact_id": "api-art-01",
        "source_type": "EVTX_SECURITY",
        "host_id": "api-host-01",
        "raw_timestamp": "2026-09-12T10:00:00Z",
        "entity_subject": "cmd.exe",
        "action_verb": "EXECUTE",
        "target_object": "whoami.exe",
        "attack_phase": "EXECUTION",
        "evidence": {},
    }
    resp = client.post("/api/v1/timeline/artifacts", json=art_payload)
    assert resp.status_code == 201
    assert resp.json()["artifact_id"] == "api-art-01"

    # 2. List Artifacts
    resp = client.get("/api/v1/timeline/artifacts")
    assert resp.status_code == 200
    assert len(resp.json()) >= 1

    # 3. Configure Clock Skew
    resp = client.post("/api/v1/timeline/skew?host_id=api-host-01&offset_ms=2500")
    assert resp.status_code == 200
    assert resp.json()["offset_ms"] == 2500

    # 4. Check Timestomp
    resp = client.post(
        "/api/v1/timeline/timestomp/check"
        "?file_path=C%3A%5Cbad.dll"
        "&standard_info_time=2020-01-01T00%3A00%3A00Z"
        "&file_name_time=2026-09-12T10%3A00%3A00Z"
    )
    assert resp.status_code == 200
    assert resp.json()["is_timestomped"] is True

    # 5. Dissect Memory VAD
    vad_payload = {
        "pid": 6000,
        "process_name": "powershell.exe",
        "start_address": "0x10000000",
        "end_address": "0x10020000",
        "protection": "PAGE_EXECUTE_READWRITE",
        "is_executable": True,
        "is_unbacked_memory": True,
        "entropy": 7.4,
    }
    resp = client.post("/api/v1/timeline/memory/dissect", json=vad_payload)
    assert resp.status_code == 200
    assert resp.json()["is_malicious_injection"] is True

    # 6. Reconstruct Incident Timeline
    resp = client.post("/api/v1/timeline/reconstruct?incident_id=INC-TEST-001")
    assert resp.status_code == 201
    tl_data = resp.json()
    assert tl_data["incident_id"] == "INC-TEST-001"
    tl_id = tl_data["timeline_id"]

    # 7. Get Reconstructed Timeline
    resp = client.get(f"/api/v1/timeline/{tl_id}")
    assert resp.status_code == 200
    assert resp.json()["timeline_id"] == tl_id
