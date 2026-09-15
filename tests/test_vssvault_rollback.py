"""Tests for CyberShield Enterprise - Autonomous Cryptographic Ransomware Rollback & VSS Vault.
Verifies out-of-band HMAC snapshot sealing, anti-recovery command interception,
autonomous pre-encryption file state rollback, and REST API endpoints.
"""

import json
from datetime import datetime, timezone
import pytest
from starlette.testclient import TestClient

from cybershield.api.server import app
from cybershield.vssvault.schemas import (
    AntiRecoveryTechnique,
    FileDeltaEntry,
    CommandInspectionRequest,
    RollbackRequest,
)
from cybershield.vssvault.vault import VSSCryptographicVault


@pytest.fixture
def client():
    return TestClient(app)


@pytest.fixture
def vault():
    return VSSCryptographicVault()


# =========================================================================
# Unit Tests: Immutable Snapshots & Anti-Recovery Interception
# =========================================================================

def test_create_and_verify_immutable_snapshot(vault):
    files = [
        FileDeltaEntry(
            file_path="C:\\Corp\\Finance\\ledger.xlsx",
            original_sha256="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            file_size_bytes=1048576,
        ),
        FileDeltaEntry(
            file_path="C:\\Corp\\Legal\\contracts.pdf",
            original_sha256="ca978112ca1bbdcafac231b39a23dc4da786eff8147c4e72b9807785afee48bb",
            file_size_bytes=2097152,
        ),
    ]

    snapshot = vault.create_immutable_snapshot(volume_label="C:", files=files)
    assert snapshot.tracked_files_count == 2
    assert snapshot.is_locked is True
    assert len(snapshot.hmac_signature) == 64  # SHA-256 hex string
    assert vault.verify_snapshot_hmac(snapshot) is True


def test_tamper_detection_in_snapshot(vault):
    snapshot = vault.create_immutable_snapshot(volume_label="D:", files=[])
    assert vault.verify_snapshot_hmac(snapshot) is True

    # Tamper with snapshot metadata
    snapshot.tracked_files_count = 999
    assert vault.verify_snapshot_hmac(snapshot) is False


def test_intercept_vssadmin_shadow_delete(vault):
    req = CommandInspectionRequest(
        process_id=6600,
        process_name="cmd.exe",
        command_line="vssadmin.exe delete shadows /all /quiet",
        parent_process="powershell.exe",
    )

    alert = vault.inspect_command(req)
    assert alert is not None
    assert alert.technique == AntiRecoveryTechnique.VSSADMIN_SHADOW_DELETE
    assert alert.severity == "CRITICAL"
    assert "T1490" in alert.mitre_technique
    assert vault.blocked_attempts_counter == 1


def test_intercept_wmic_and_bcdedit_purge(vault):
    # WMIC shadowcopy delete
    req_wmic = CommandInspectionRequest(
        process_id=6601,
        process_name="wmic.exe",
        command_line="wmic shadowcopy delete",
    )
    alert_wmic = vault.inspect_command(req_wmic)
    assert alert_wmic is not None
    assert alert_wmic.technique == AntiRecoveryTechnique.WMIC_SHADOWCOPY_PURGE

    # BCDEDIT recovery disable
    req_bcd = CommandInspectionRequest(
        process_id=6602,
        process_name="bcdedit.exe",
        command_line="bcdedit /set {default} recoveryenabled No",
    )
    alert_bcd = vault.inspect_command(req_bcd)
    assert alert_bcd is not None
    assert alert_bcd.technique == AntiRecoveryTechnique.BCDEDIT_RECOVERY_DISABLED


def test_benign_command_no_alert(vault):
    req = CommandInspectionRequest(
        process_id=1234,
        process_name="notepad.exe",
        command_line="notepad.exe C:\\Users\\User\\Documents\\notes.txt",
    )
    assert vault.inspect_command(req) is None


def test_execute_cryptographic_rollback(vault):
    files = [
        FileDeltaEntry(
            file_path="C:\\Data\\file1.doc",
            original_sha256="abc123hash",
            file_size_bytes=50000,
        ),
        FileDeltaEntry(
            file_path="C:\\Data\\file2.doc",
            original_sha256="def456hash",
            file_size_bytes=75000,
        ),
    ]
    snapshot = vault.create_immutable_snapshot(files=files)

    # Rollback all files
    req_all = RollbackRequest(snapshot_id=snapshot.snapshot_id)
    resp_all = vault.execute_rollback(req_all)
    assert resp_all.status == "ROLLBACK_SUCCESSFUL"
    assert resp_all.files_reverted_count == 2
    assert resp_all.total_bytes_restored == 125000
    assert resp_all.integrity_verified is True

    # Rollback targeted single file
    req_target = RollbackRequest(
        snapshot_id=snapshot.snapshot_id,
        target_files=["C:\\Data\\file1.doc"],
    )
    resp_target = vault.execute_rollback(req_target)
    assert resp_target.files_reverted_count == 1
    assert resp_target.total_bytes_restored == 50000


# =========================================================================
# Integration Tests: FastAPI REST Endpoints
# =========================================================================

def test_api_create_snapshot_and_rollback(client):
    # Create snapshot via API
    snap_resp = client.post("/api/v1/vssvault/snapshots/create?volume_label=E:")
    assert snap_resp.status_code == 201
    snap_data = snap_resp.json()
    snapshot_id = snap_data["snapshot_id"]
    assert "hmac_signature" in snap_data

    # Test rollback endpoint
    rollback_req = RollbackRequest(snapshot_id=snapshot_id)
    rollback_resp = client.post(
        "/api/v1/vssvault/rollback",
        json=json.loads(rollback_req.model_dump_json()),
    )
    assert rollback_resp.status_code == 200
    assert rollback_resp.json()["status"] == "ROLLBACK_SUCCESSFUL"


def test_api_intercept_command_and_query_status(client):
    req = CommandInspectionRequest(
        process_id=9876,
        process_name="cmd.exe",
        command_line="wbadmin.exe delete catalog -quiet",
    )
    intercept_resp = client.post(
        "/api/v1/vssvault/intercept/command",
        json=json.loads(req.model_dump_json()),
    )
    assert intercept_resp.status_code == 200
    data = intercept_resp.json()
    assert data["is_threat_intercepted"] is True

    # Query /threats endpoint
    threats_resp = client.get("/api/v1/vssvault/threats")
    assert threats_resp.status_code == 200
    assert len(threats_resp.json()) >= 1

    # Query /status endpoint
    status_resp = client.get("/api/v1/vssvault/status")
    assert status_resp.status_code == 200
    status_data = status_resp.json()
    assert status_data["vault_tamper_evident"] is True
    assert status_data["anti_recovery_attempts_blocked"] >= 1
