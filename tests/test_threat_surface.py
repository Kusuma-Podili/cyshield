"""Tests for CyberShield Enterprise - Autonomous Threat Surface Graph & Shadow Cloud Reconciler.
Verifies CMDB drift detection, shadow cloud discovery, exposed management port alerts,
dangling DNS subdomain takeover evaluation, and REST API routes.
"""

import json
from datetime import datetime, timezone
import pytest
from starlette.testclient import TestClient

from cybershield.api.server import app
from cybershield.surface.schemas import (
    CloudAssetType,
    SurfaceThreatType,
    CloudAsset,
    DNSTakeoverCheckRequest,
    ReconciliationRequest,
)
from cybershield.surface.reconciler import ThreatSurfaceReconciler


@pytest.fixture
def client():
    return TestClient(app)


@pytest.fixture
def reconciler():
    return ThreatSurfaceReconciler()


# =========================================================================
# Unit Tests: Surface Reconciliation & Shadow Cloud Discovery
# =========================================================================

def test_reconcile_shadow_asset_and_exposed_port(reconciler):
    # Sanctioned production web server
    sanctioned = CloudAsset(
        asset_id="vm-sanctioned-01",
        asset_name="prod-web-01",
        asset_type=CloudAssetType.VIRTUAL_MACHINE,
        region="us-east-1",
        ip_address="54.120.10.5",
        fqdn="web01.corp.com",
        is_sanctioned_cmdb=True,
        open_ports=[80, 443],
    )

    # Observed assets: sanctioned web server + 1 shadow rogue database with exposed port 5432
    observed_web = CloudAsset(
        asset_id="vm-sanctioned-01",
        asset_name="prod-web-01",
        asset_type=CloudAssetType.VIRTUAL_MACHINE,
        region="us-east-1",
        ip_address="54.120.10.5",
        fqdn="web01.corp.com",
        open_ports=[80, 443],
    )
    observed_shadow_db = CloudAsset(
        asset_id="vm-shadow-99",
        asset_name="dev-test-postgres",
        asset_type=CloudAssetType.MANAGED_DATABASE,
        region="us-east-1",
        ip_address="54.120.99.88",
        open_ports=[5432],  # Exposed Postgres port
    )

    req = ReconciliationRequest(
        sanctioned_assets=[sanctioned],
        observed_live_assets=[observed_web, observed_shadow_db],
    )

    report = reconciler.reconcile_assets(req)
    assert report.total_sanctioned_assets == 1
    assert report.total_observed_assets == 2
    assert report.shadow_unmanaged_count == 1
    assert len(report.threats_detected) >= 2  # 1 shadow asset + 1 exposed port alert

    threat_types = {t.threat_type for t in report.threats_detected}
    assert SurfaceThreatType.SHADOW_UNMANAGED_ASSET in threat_types
    assert SurfaceThreatType.EXPOSED_MANAGEMENT_PORT in threat_types
    assert report.attack_surface_score < 100.0


def test_reconcile_unauthorized_region_and_public_s3_bucket(reconciler):
    # Bucket deployed in unauthorized region with public read access
    live_bucket = CloudAsset(
        asset_id="s3-leak-01",
        asset_name="corp-financial-backups",
        asset_type=CloudAssetType.OBJECT_STORAGE_BUCKET,
        region="ap-southeast-2",  # Not in APPROVED_REGIONS
        tags={"public_access": "true"},
    )

    req = ReconciliationRequest(
        sanctioned_assets=[],
        observed_live_assets=[live_bucket],
    )

    report = reconciler.reconcile_assets(req)
    threat_types = {t.threat_type for t in report.threats_detected}
    assert SurfaceThreatType.UNAUTHORIZED_CLOUD_REGION in threat_types
    assert SurfaceThreatType.PUBLIC_OBJECT_STORAGE_LEAK in threat_types


def test_evaluate_dangling_dns_subdomain_takeover(reconciler):
    # Vulnerable AWS S3 dangling CNAME
    req_s3 = DNSTakeoverCheckRequest(
        subdomain="assets.corp.com",
        cname_target="corp-assets-old.s3.amazonaws.com",
        target_http_status=404,
        target_response_body="<Error><Code>NoSuchBucket</Code></Error>",
    )
    alert_s3 = reconciler.evaluate_dns_takeover(req_s3)
    assert alert_s3 is not None
    assert alert_s3.threat_type == SurfaceThreatType.DANGLING_DNS_TAKEOVER_RISK
    assert alert_s3.severity == "CRITICAL"
    assert "T1584.004" in alert_s3.mitre_technique

    # Benign live domain returning 200 OK
    req_healthy = DNSTakeoverCheckRequest(
        subdomain="portal.corp.com",
        cname_target="portal.corp.com.cdn.cloudflare.net",
        target_http_status=200,
        target_response_body="OK",
    )
    assert reconciler.evaluate_dns_takeover(req_healthy) is None


# =========================================================================
# Integration Tests: FastAPI REST Endpoints
# =========================================================================

def test_api_reconcile_assets_endpoint(client):
    req = ReconciliationRequest(
        sanctioned_assets=[],
        observed_live_assets=[
            CloudAsset(
                asset_id="api-vm-01",
                asset_name="untracked-k8s-node",
                asset_type=CloudAssetType.KUBERNETES_CLUSTER,
                region="us-east-1",
                open_ports=[22],
            )
        ],
    )
    resp = client.post(
        "/api/v1/surface/assets/reconcile",
        json=json.loads(req.model_dump_json()),
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["shadow_unmanaged_count"] == 1
    assert len(data["threats_detected"]) >= 1

    # Check /shadow/assets endpoint
    shadow_resp = client.get("/api/v1/surface/shadow/assets")
    assert shadow_resp.status_code == 200
    shadows = shadow_resp.json()
    assert any(s["asset_id"] == "api-vm-01" for s in shadows)


def test_api_dns_takeover_check_and_threats(client):
    req = DNSTakeoverCheckRequest(
        subdomain="docs.corp.com",
        cname_target="my-docs.github.io",
        target_http_status=404,
        target_response_body="There isn't a GitHub Pages site here",
    )
    resp = client.post(
        "/api/v1/surface/dns/takeover/check",
        json=json.loads(req.model_dump_json()),
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["is_takeover_vulnerable"] is True

    # Check /threats endpoint
    threats_resp = client.get("/api/v1/surface/threats")
    assert threats_resp.status_code == 200
    assert len(threats_resp.json()) >= 1
