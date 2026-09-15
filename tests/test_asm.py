"""
Unit and Integration Tests for Attack Surface Management (ASM) Subsystem.
Verifies external asset discovery, service banner analysis, dangerous port exposure, and REST APIs.
"""

import pytest
from fastapi.testclient import TestClient

from cybershield.api.server import app
from cybershield.asm.scanner import AttackSurfaceScanner
from cybershield.asm.schemas import (
    ASMScanRequest,
    AssetExposureType,
    ExposureSeverity,
)


@pytest.fixture
def scanner():
    return AttackSurfaceScanner()


@pytest.fixture
def client():
    return TestClient(app)


def test_seeded_assets_and_issues(scanner):
    assets = scanner.list_assets()
    assert len(assets) >= 2

    # Check high-risk bastion asset with RDP
    bastion = next((a for a in assets if "bastion" in a.identifier), None)
    assert bastion is not None
    assert 3389 in bastion.open_ports
    assert bastion.risk_score >= 80.0

    # Check critical RDP issue
    issues = scanner.list_issues(severity=ExposureSeverity.CRITICAL)
    assert len(issues) >= 1
    assert any("RDP" in i.title for i in issues)


def test_scan_execution_and_subdomain_discovery(scanner):
    req = ASMScanRequest(
        root_domain="target-corp.com",
        include_cloud_storage=True,
        port_scan_intensity="STANDARD",
    )
    job = scanner.run_scan(req)

    assert job.status == "COMPLETED"
    assert job.assets_discovered_count >= 8
    assert job.duration_ms > 0

    # Verify discovered assets
    assets = scanner.list_assets()
    target_subs = [a for a in assets if a.primary_domain == "target-corp.com"]
    assert len(target_subs) >= 8

    # Verify cloud bucket was identified
    bucket_asset = next((a for a in target_subs if a.asset_type == AssetExposureType.CLOUD_STORAGE), None)
    assert bucket_asset is not None
    assert "public-assets" in bucket_asset.identifier


def test_overview_metrics(scanner):
    metrics = scanner.get_overview_metrics()
    assert metrics.total_assets >= 2
    assert metrics.exposed_services_count >= 2
    assert 3389 in metrics.dangerous_ports_exposed
    assert metrics.average_asset_risk > 0.0


def test_asm_api_endpoints(client):
    # 1. List assets
    resp = client.get("/api/asm/assets")
    assert resp.status_code == 200
    assets = resp.json()
    assert len(assets) >= 2
    asset_id = assets[0]["id"]

    # 2. Get specific asset
    resp = client.get(f"/api/asm/assets/{asset_id}")
    assert resp.status_code == 200
    assert resp.json()["id"] == asset_id

    # 3. Trigger perimeter scan via API
    scan_req = {
        "root_domain": "fintech-defense.org",
        "include_cloud_storage": True,
        "port_scan_intensity": "STANDARD",
    }
    resp = client.post("/api/asm/scan", json=scan_req)
    assert resp.status_code == 202
    job_data = resp.json()
    assert job_data["status"] == "COMPLETED"
    assert "job_id" in job_data
    job_id = job_data["job_id"]

    # 4. Get job status
    resp = client.get(f"/api/asm/jobs/{job_id}")
    assert resp.status_code == 200
    assert resp.json()["job_id"] == job_id

    # 5. List issues
    resp = client.get("/api/asm/issues")
    assert resp.status_code == 200
    assert len(resp.json()) >= 1

    # 6. Overview
    resp = client.get("/api/asm/overview")
    assert resp.status_code == 200
    overview = resp.json()
    assert overview["total_assets"] >= 5
    assert overview["average_asset_risk"] > 0
