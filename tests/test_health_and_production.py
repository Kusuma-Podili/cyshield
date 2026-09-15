"""Automated Tests for Phase 10: System Health, Diagnostics, Backup & Production Tooling."""

import os
import pytest
import pytest_asyncio
from httpx import AsyncClient, ASGITransport

from cybershield.api.server import app
from cybershield.database.session import async_session_factory
from cybershield.health.service import HealthService, SystemMetricsCollector
from cybershield.health.schemas import SystemHealthStatus
from cybershield.core.backup import BackupService
from cybershield.audit.vault import AuditVault


@pytest.mark.asyncio
async def test_health_summary_liveness():
    """Verify lightweight liveness probe generation."""
    summary = HealthService.get_summary()
    assert summary.status == SystemHealthStatus.HEALTHY
    assert summary.uptime_seconds >= 0
    assert summary.version is not None


@pytest.mark.asyncio
async def test_system_metrics_collector():
    """Verify zero-dependency hardware telemetry collector."""
    mem = SystemMetricsCollector.get_memory_info()
    assert "total_mb" in mem
    assert "used_mb" in mem
    assert "percent" in mem
    assert mem["total_mb"] > 0
    assert 0.0 <= mem["percent"] <= 100.0

    disk = SystemMetricsCollector.get_disk_info()
    assert "total_gb" in disk
    assert "free_gb" in disk
    assert disk["total_gb"] > 0

    cpu = SystemMetricsCollector.get_cpu_estimate()
    assert isinstance(cpu, float)
    assert 0.0 <= cpu <= 100.0


@pytest.mark.asyncio
async def test_database_health_measurement():
    """Verify database latency and table count diagnostic sampler."""
    async with async_session_factory() as session:
        diag = await HealthService.measure_database_health(session)
        assert diag.status in [SystemHealthStatus.HEALTHY, SystemHealthStatus.DEGRADED]
        assert diag.latency_ms >= 0.0
        assert diag.engine_dialect == "sqlite"
        assert diag.tables_count >= 10
        assert diag.total_records_count >= 0


@pytest.mark.asyncio
async def test_readiness_probe():
    """Verify platform readiness evaluation."""
    async with async_session_factory() as session:
        ready = await HealthService.check_readiness(session)
        assert ready.ready is True
        assert ready.status == SystemHealthStatus.HEALTHY
        assert ready.checks.get("database") is True
        assert ready.checks.get("storage_writable") is True


@pytest.mark.asyncio
async def test_full_subsystem_diagnostics():
    """Verify comprehensive multi-subsystem diagnostic sweep."""
    async with async_session_factory() as session:
        # Ensure genesis block exists
        await AuditVault.initialize_genesis_block(session)
        diag = await HealthService.get_full_diagnostics(session)

        assert diag.status in [SystemHealthStatus.HEALTHY, SystemHealthStatus.DEGRADED]
        assert diag.hardware is not None
        assert diag.database is not None

        # Verify all 10 subsystems are reported
        expected_subsystems = [
            "database",
            "identity_rbac",
            "siem_ingestion",
            "threat_detection",
            "malware_phishing",
            "ml_analytics",
            "etl_pipelines",
            "task_processing",
            "compliance_grc",
            "audit_vault",
        ]
        for sub in expected_subsystems:
            assert sub in diag.subsystems
            assert diag.subsystems[sub].status in [SystemHealthStatus.HEALTHY, SystemHealthStatus.DEGRADED]


@pytest.mark.asyncio
async def test_backup_service_lifecycle_and_tamper_detection():
    """Verify database backup creation, cataloging, verification, and tamper detection."""
    async with async_session_factory() as session:
        await AuditVault.initialize_genesis_block(session)

        # 1. Create Snapshot
        meta = await BackupService.create_snapshot(session, note="Test CI Snapshot", actor_id="ci-test")
        assert meta.filename.startswith("cybershield_backup_")
        assert meta.size_bytes > 0
        assert len(meta.checksum_sha256) == 64
        assert meta.is_verified is True

        # 2. List Snapshots
        listing = BackupService.list_snapshots()
        assert listing.total >= 1
        filenames = [b.filename for b in listing.backups]
        assert meta.filename in filenames

        # 3. Verify Genuine Snapshot
        verify_res = BackupService.verify_snapshot(meta.filename)
        assert verify_res.verified is True
        assert verify_res.checksum_sha256 == meta.checksum_sha256

        # 4. Tamper Detection Test
        tampered_filename = f"tampered_{meta.filename}"
        orig_path = os.path.join(BackupService.BACKUP_DIR, meta.filename)
        tampered_path = os.path.join(BackupService.BACKUP_DIR, tampered_filename)

        with open(orig_path, "rb") as f_in:
            data = f_in.read()
        with open(tampered_path, "wb") as f_out:
            f_out.write(data + b"\xde\xad\xbe\xef_tampered_payload")

        # Record original manifest entry for tampered file with expected original hash
        manifest = BackupService._read_manifest()
        manifest[tampered_filename] = {
            "filename": tampered_filename,
            "size_bytes": len(data) + 25,
            "created_at": meta.created_at.isoformat(),
            "checksum_sha256": meta.checksum_sha256, # Intentionally mismatching!
            "is_verified": True,
        }
        BackupService._write_manifest(manifest)

        # Verify tampered archive fails verification
        tamper_check = BackupService.verify_snapshot(tampered_filename)
        assert tamper_check.verified is False
        assert "ALERT" in tamper_check.message or "mismatch" in tamper_check.message

        # Clean up tampered test file
        if os.path.exists(tampered_path):
            os.remove(tampered_path)
        manifest.pop(tampered_filename, None)
        BackupService._write_manifest(manifest)


@pytest.mark.asyncio
async def test_health_rest_endpoints():
    """Verify HTTP REST endpoints for health, readiness, and diagnostics."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        # Public Liveness Ping
        res_live = await ac.get("/api/health")
        assert res_live.status_code == 200
        assert res_live.json()["status"] == "HEALTHY"

        # Public Live Endpoint
        res_ping = await ac.get("/api/health/live")
        assert res_ping.status_code == 200
        assert res_ping.json()["status"] == "alive"

        # Public Readiness Probe
        res_ready = await ac.get("/api/health/ready")
        assert res_ready.status_code == 200
        assert res_ready.json()["ready"] is True

        # Diagnostics (Requires authentication)
        # Login as superadmin
        login_resp = await ac.post("/api/auth/login", json={"username_or_email": "superadmin", "password": "CyberShield2026!"})
        assert login_resp.status_code == 200
        token = login_resp.json()["access_token"]
        auth_headers = {"Authorization": f"Bearer {token}"}

        # Query Diagnostics
        res_diag = await ac.get("/api/health/diagnostics", headers=auth_headers)
        assert res_diag.status_code == 200
        diag_body = res_diag.json()
        assert "hardware" in diag_body
        assert "database" in diag_body
        assert "subsystems" in diag_body

        # Query Backups
        res_backups = await ac.get("/api/health/backups", headers=auth_headers)
        assert res_backups.status_code == 200
        assert "backups" in res_backups.json()

        # Create Backup via REST
        res_create_bk = await ac.post("/api/health/backups/create", json={"note": "REST API Test Snapshot"}, headers=auth_headers)
        assert res_create_bk.status_code == 200
        new_bk = res_create_bk.json()
        assert new_bk["is_verified"] is True

        # Verify Backup via REST
        res_verify_bk = await ac.post(f"/api/health/backups/{new_bk['filename']}/verify", headers=auth_headers)
        assert res_verify_bk.status_code == 200
        assert res_verify_bk.json()["verified"] is True


@pytest.mark.asyncio
async def test_cli_programmatic_execution():
    """Verify administrative CLI commands execute without error."""
    from cybershield.cli import cmd_status, cmd_vault_verify, cmd_backup_create, cmd_backup_list, cmd_backup_verify

    # Test status command
    await cmd_status()

    # Test vault verify command
    await cmd_vault_verify()

    # Test backup create command
    await cmd_backup_create(note="Automated CLI Unit Test")

    # Test backup list
    cmd_backup_list()

