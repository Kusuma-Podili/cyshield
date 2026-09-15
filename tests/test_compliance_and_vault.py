"""
CyberShield Enterprise - Regulatory Compliance, Cryptographic Audit Vault,
Report Generator & Platform Settings Automated Test Suite.

Validates:
1. Multi-standard compliance framework catalogs (SOC 2, ISO 27001, NIST CSF, PCI-DSS, HIPAA, GDPR).
2. Automated compliance assessment execution and technical evidence capture.
3. Cryptographic WORM ledger (SHA-256 Merkle hash chaining and HMAC block signing).
4. Deliberate tampering detection and broken chain localization.
5. Verification certificate of authenticity export.
6. Enterprise report generator across Executive, Compliance, Vulnerability, and Incident templates.
7. Dynamic platform runtime settings lifecycle (read, update, validate, reset).
8. REST API endpoints and RBAC permission boundaries.
"""

import pytest
import pytest_asyncio
from httpx import AsyncClient, ASGITransport
from sqlalchemy import select

from cybershield.api.server import app
from cybershield.database.session import init_db, async_session_factory
from cybershield.database.models.user import UserRole
from cybershield.database.models import (
    ComplianceFrameworkModel,
    ComplianceControlModel,
    ComplianceAssessmentModel,
    AuditVaultBlockModel,
    GeneratedReportModel,
    PlatformSettingModel,
)
from cybershield.auth.security import create_access_token
from cybershield.compliance.engine import ComplianceEngine
from cybershield.compliance.service import ComplianceService
from cybershield.audit.vault import AuditVault
from cybershield.reports.service import ReportGeneratorService
from cybershield.settings.manager import SettingsManager


@pytest_asyncio.fixture(autouse=True)
async def ensure_db():
    """Ensure database schema is initialized and Phase 9 seeds exist."""
    await init_db()
    async with async_session_factory() as session:
        await ComplianceEngine.seed_frameworks_if_empty(session)
        await AuditVault.initialize_genesis_block(session)
        await SettingsManager.seed_defaults_if_empty(session)


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
    uname = "compliance_viewer_test"
    await client.post("/api/auth/register", json={
        "username": uname,
        "email": f"{uname}@enterprise.corp",
        "password": "ViewerPassword123!",
        "full_name": "Compliance Viewer User"
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
    return create_access_token(
        data={"sub": "99", "username": uname, "role": UserRole.VIEWER.value, "user_id": 99}
    )


# =========================================================================
# 1. Compliance Engine & Frameworks Tests
# =========================================================================

@pytest.mark.asyncio
async def test_compliance_frameworks_and_controls():
    """Verify default frameworks and controls are seeded with proper metadata."""
    async with async_session_factory() as session:
        frameworks = await ComplianceService.list_frameworks(session)
        assert len(frameworks) >= 6

        fw_ids = [f["id"] for f in frameworks]
        assert "SOC2" in fw_ids
        assert "ISO27001" in fw_ids
        assert "NIST_CSF" in fw_ids
        assert "PCI_DSS" in fw_ids
        assert "HIPAA" in fw_ids
        assert "GDPR" in fw_ids

        # Check SOC 2 controls
        soc2_controls = await ComplianceService.get_framework_controls(session, "SOC2")
        assert len(soc2_controls) >= 6
        codes = [c["control_code"] for c in soc2_controls]
        assert "CC6.1" in codes
        assert "CC7.1" in codes


@pytest.mark.asyncio
async def test_compliance_assessment_execution():
    """Verify automated compliance assessment computes scores and captures evidence."""
    async with async_session_factory() as session:
        assessments = await ComplianceEngine.run_assessment(session, actor="TEST_RUNNER")
        assert len(assessments) >= 6

        for asm in assessments:
            data = asm.to_dict()
            assert data["overall_score"] >= 0.0
            assert data["overall_score"] <= 100.0
            assert "COMPLIANT" in data["status_counts"]
            assert data["assessed_by"] == "TEST_RUNNER"


@pytest.mark.asyncio
async def test_compliance_overview():
    """Verify composite compliance score, letter grade, and gap identification."""
    async with async_session_factory() as session:
        overview = await ComplianceService.get_overview(session)
        assert "global_compliance_score" in overview
        assert 0.0 <= overview["global_compliance_score"] <= 100.0
        assert overview["letter_grade"] in ["A+", "A", "B", "C", "D", "F"]
        assert overview["total_controls"] > 20
        assert isinstance(overview["critical_gaps"], list)


# =========================================================================
# 2. Cryptographic Audit Vault (WORM Ledger) Tests
# =========================================================================

@pytest.mark.asyncio
async def test_audit_vault_genesis_and_chaining():
    """Verify genesis initialization and sequential SHA-256 / HMAC hash chaining."""
    async with async_session_factory() as session:
        # Genesis block check
        genesis = await AuditVault.initialize_genesis_block(session)
        assert genesis.block_index == 0
        assert genesis.is_genesis is True
        assert genesis.previous_block_hash == "0" * 64
        assert len(genesis.block_hash) == 64
        assert len(genesis.hmac_signature) == 64

        # Append new block
        latest_before = (await session.execute(
            select(AuditVaultBlockModel).order_by(AuditVaultBlockModel.block_index.desc()).limit(1)
        )).scalar_one()

        b1 = await AuditVault.record_block(
            db=session,
            action="SECURITY_RULE_DEPLOYED",
            actor_id="secadmin",
            actor_role="SECURITY_ADMIN",
            entity_type="RULE",
            entity_id="RULE-SIGMA-001",
            payload_data={"rule_name": "Suspicious PowerShell Execution"},
        )
        assert b1.block_index == latest_before.block_index + 1
        assert b1.previous_block_hash == latest_before.block_hash

        # Verify whole chain
        report = await AuditVault.verify_chain(session)
        assert report["is_valid"] is True
        assert report["total_blocks"] >= 2
        assert report["tampered_block_index"] is None
        assert report["verification_seal"] is not None


@pytest.mark.asyncio
async def test_audit_vault_tamper_detection():
    """Verify that any modification to a historical block is caught by the verifier."""
    async with async_session_factory() as session:
        # Record a test block
        b = await AuditVault.record_block(
            db=session,
            action="CONTAINMENT_EXECUTED",
            actor_id="secadmin",
            actor_role="SECURITY_ADMIN",
            entity_type="DEVICE",
            entity_id="DEV-999",
            payload_data={"status": "QUARANTINED"},
        )
        block_idx = b.block_index

        # Deliberately tamper with the payload in the database directly
        res = await session.execute(
            select(AuditVaultBlockModel).where(AuditVaultBlockModel.block_index == block_idx)
        )
        tampered_block = res.scalar_one()
        tampered_block.payload_data = {"status": "UNQUARANTINED_UNAUTHORIZED_TAMPER"}
        await session.commit()

        # Run verification and assert it catches the exact tampered block
        report = await AuditVault.verify_chain(session)
        assert report["is_valid"] is False
        assert report["tampered_block_index"] == block_idx
        assert "tampering detected" in report["error_message"].lower()

        # Revert tampering to restore clean test state
        tampered_block.payload_data = {"status": "QUARANTINED"}
        await session.commit()


@pytest.mark.asyncio
async def test_audit_vault_certificate_export():
    """Verify Certificate of Authenticity generation with digital seal."""
    async with async_session_factory() as session:
        cert = await AuditVault.export_tamper_proof(session)
        assert "CERT-WORM-" in cert["certificate_id"]
        assert cert["issuer"] == "CyberShield Enterprise Cryptographic Audit Vault"
        assert cert["status"] in ["VALID_AND_UNCOMPROMISED", "COMPROMISED_TAMPER_DETECTED"]
        assert len(cert["digital_seal"]) == 64


# =========================================================================
# 3. Report Generator Tests
# =========================================================================

@pytest.mark.asyncio
async def test_report_generation_all_templates():
    """Verify all 4 report templates render valid HTML and JSON output."""
    templates = [
        "EXECUTIVE_POSTURE",
        "COMPLIANCE_ATTESTATION",
        "VULNERABILITY_ASSESSMENT",
        "INCIDENT_DOSSIER",
    ]

    async with async_session_factory() as session:
        for tpl in templates:
            report = await ReportGeneratorService.generate_report(
                db=session,
                report_type_str=tpl,
                format_str="HTML",
                title=f"Test {tpl} Report",
                actor="TEST_AUDITOR",
            )
            assert report.id.startswith("RPT-")
            assert report.report_type.value == tpl
            assert len(report.content_html) > 200
            assert "<!DOCTYPE html>" in report.content_html
            assert report.file_size_bytes > 0

        # Test JSON format
        json_report = await ReportGeneratorService.generate_report(
            db=session,
            report_type_str="EXECUTIVE_POSTURE",
            format_str="JSON",
            actor="TEST_AUDITOR",
        )
        assert json_report.format.value == "JSON"
        assert json_report.raw_data is not None


# =========================================================================
# 4. Platform Settings Tests
# =========================================================================

@pytest.mark.asyncio
async def test_platform_settings_lifecycle():
    """Verify reading, updating, validating, and resetting platform settings."""
    async with async_session_factory() as session:
        # 1. List all settings
        all_settings = await SettingsManager.list_settings(session)
        assert len(all_settings) >= 10

        # 2. Filter by category
        sec_settings = await SettingsManager.list_settings(session, category="SECURITY_POLICY")
        assert len(sec_settings) >= 3

        # 3. Update setting with valid value
        updated = await SettingsManager.update_setting(
            session,
            key="security.password_min_length",
            value_str="16",
            actor="SUPERADMIN_TEST",
        )
        assert updated["value"] == 16
        assert updated["raw_value"] == "16"
        assert updated["updated_by"] == "SUPERADMIN_TEST"

        # 4. Reset setting to default
        reset = await SettingsManager.reset_setting(
            session,
            key="security.password_min_length",
            actor="SUPERADMIN_TEST",
        )
        assert reset["value"] == 12
        assert reset["raw_value"] == "12"

        # 5. Invalid type validation test
        with pytest.raises(ValueError):
            await SettingsManager.update_setting(
                session,
                key="security.password_min_length",
                value_str="not_a_number",
                actor="SUPERADMIN_TEST",
            )


# =========================================================================
# 5. REST API & RBAC Endpoints Tests
# =========================================================================

@pytest.mark.asyncio
async def test_compliance_and_vault_rest_endpoints(client: AsyncClient, admin_token: str, viewer_token: str):
    """Verify REST API endpoints and RBAC permissions."""
    headers_admin = {"Authorization": f"Bearer {admin_token}"}
    headers_viewer = {"Authorization": f"Bearer {viewer_token}"}

    # 1. Compliance Overview
    res = await client.get("/api/compliance/overview", headers=headers_admin)
    assert res.status_code == 200
    assert "global_compliance_score" in res.json()

    # 2. Compliance Frameworks
    res = await client.get("/api/compliance/frameworks", headers=headers_admin)
    assert res.status_code == 200
    assert len(res.json()) >= 6

    # 3. Run Compliance Assessment (Requires COMPLIANCE_ASSESS permission)
    res = await client.post("/api/compliance/assess?framework_id=SOC2", headers=headers_admin)
    assert res.status_code == 200

    # Viewer should be forbidden from triggering assessments
    res = await client.post("/api/compliance/assess?framework_id=SOC2", headers=headers_viewer)
    assert res.status_code == 403

    # 4. Audit Vault Blocks
    res = await client.get("/api/audit/vault/blocks", headers=headers_admin)
    assert res.status_code == 200
    assert "items" in res.json()

    # 5. Audit Vault Verify
    res = await client.post("/api/audit/vault/verify", headers=headers_admin)
    assert res.status_code == 200
    assert "is_valid" in res.json()

    # 6. Audit Vault Certificate
    res = await client.get("/api/audit/vault/certificate", headers=headers_admin)
    assert res.status_code == 200
    assert "certificate_id" in res.json()

    # 7. Generate Report
    res = await client.post("/api/reports/generate", headers=headers_admin, json={
        "report_type": "EXECUTIVE_POSTURE",
        "format": "HTML",
        "title": "API Test Posture Report",
    })
    assert res.status_code == 201
    report_id = res.json()["id"]

    # 8. List Reports
    res = await client.get("/api/reports", headers=headers_admin)
    assert res.status_code == 200
    assert res.json()["total"] >= 1

    # 9. Download Report
    res = await client.get(f"/api/reports/{report_id}/download", headers=headers_admin)
    assert res.status_code == 200
    assert "text/html" in res.headers["content-type"]

    # 10. Platform Settings API
    res = await client.get("/api/settings", headers=headers_admin)
    assert res.status_code == 200
    assert len(res.json()) >= 10

    # 11. Update Setting via API
    res = await client.put(
        "/api/settings/soar.auto_quarantine_risk_cutoff",
        headers=headers_admin,
        json={"value": "90.0"},
    )
    assert res.status_code == 200
    assert res.json()["value"] == 90.0

    # 12. Reset Setting via API
    res = await client.post(
        "/api/settings/soar.auto_quarantine_risk_cutoff/reset",
        headers=headers_admin,
    )
    assert res.status_code == 200
    assert res.json()["value"] == 85.0
