"""
Unit and integration tests for Multi-Tenant Architecture & vSOC Segregation.
"""

import pytest
from fastapi.testclient import TestClient

from cybershield.api.server import app
from cybershield.multitenant.schemas import (
    TenantCreateRequest,
    TenantQuota,
    TenantRole,
    TenantTier,
)
from cybershield.multitenant.service import TenantManager


@pytest.fixture
def manager():
    return TenantManager()


@pytest.fixture
def client():
    return TestClient(app)


def test_seeded_tenants(manager):
    tenants = manager.list_tenants()
    assert len(tenants) >= 3
    t_ids = [t.tenant_id for t in tenants]
    assert "TENANT-CORP-HQ" in t_ids
    assert "TENANT-FIN-DIV" in t_ids
    assert "TENANT-HEALTH-SUB" in t_ids


def test_create_custom_tenant(manager):
    req = TenantCreateRequest(
        name="APAC Regional Security Unit",
        slug="apac-region",
        tier=TenantTier.ENTERPRISE,
        contact_email="apac-sec@corp.global",
        custom_quota=TenantQuota(max_devices=1000, max_eps=2500)
    )
    tenant = manager.create_tenant(req)
    assert tenant.tenant_id == "TENANT-APAC_REGION"
    assert tenant.quota.max_devices == 1000
    assert tenant.quota.max_eps == 2500
    assert manager.get_tenant("TENANT-APAC_REGION") is not None


def test_user_tenant_scoped_assignment(manager):
    mapping = manager.assign_user_to_tenant(
        user_id="analyst-john",
        tenant_id="TENANT-FIN-DIV",
        role=TenantRole.SOC_ANALYST
    )
    assert mapping.user_id == "analyst-john"
    assert mapping.tenant_id == "TENANT-FIN-DIV"
    assert mapping.role == TenantRole.SOC_ANALYST

    users = manager.get_tenant_users("TENANT-FIN-DIV")
    assert any(u.user_id == "analyst-john" for u in users)


def test_tenant_boundary_access_verification(manager):
    manager.assign_user_to_tenant("analyst-mary", "TENANT-HEALTH-SUB", TenantRole.SOC_ANALYST)

    # Authorized within HEALTH-SUB
    assert manager.verify_tenant_access("analyst-mary", "TENANT-HEALTH-SUB") is True

    # Unauthorized for FIN-DIV
    assert manager.verify_tenant_access("analyst-mary", "TENANT-FIN-DIV") is False

    # Super-admin has cross-tenant visibility
    assert manager.verify_tenant_access("sec-admin", "TENANT-FIN-DIV") is True


def test_quota_gating(manager):
    # Check EPS quota
    # FIN-DIV has max_eps = 1500, current_eps = 240
    assert manager.check_eps_quota("TENANT-FIN-DIV", 500) is True
    assert manager.check_eps_quota("TENANT-FIN-DIV", 2000) is False

    # Check Device quota
    assert manager.check_device_quota("TENANT-FIN-DIV") is True


def test_tenant_usage_metrics(manager):
    usage = manager.get_tenant_usage("TENANT-CORP-HQ")
    assert usage is not None
    assert usage.max_devices == 2500
    assert usage.device_count == 420
    assert usage.device_utilization_pct > 0.0
    assert usage.is_over_quota is False


def test_multitenant_api_lifecycle(client):
    # 1. List tenants
    res = client.get("/api/tenants")
    assert res.status_code == 200
    tenants = res.json()
    assert len(tenants) >= 3

    # 2. Get specific tenant
    det_res = client.get("/api/tenants/TENANT-CORP-HQ")
    assert det_res.status_code == 200
    assert det_res.json()["name"] == "Global Enterprise Headquarters"

    # 3. Create tenant via API
    create_payload = {
        "name": "Cloud Operations Division",
        "slug": "cloud-ops",
        "tier": "PROFESSIONAL",
        "contact_email": "cloud-sec@enterprise.com"
    }
    create_res = client.post("/api/tenants", json=create_payload)
    assert create_res.status_code == 201
    created_id = create_res.json()["tenant_id"]

    # 4. Get usage via API
    usage_res = client.get(f"/api/tenants/{created_id}/usage")
    assert usage_res.status_code == 200
    assert usage_res.json()["device_count"] == 0

    # 5. Assign user via API
    assign_res = client.post(f"/api/tenants/{created_id}/users?user_id=devops-bob&role=TENANT_ADMIN")
    assert assign_res.status_code == 201

    # 6. List tenant users via API
    users_res = client.get(f"/api/tenants/{created_id}/users")
    assert users_res.status_code == 200
    assert any(u["user_id"] == "devops-bob" for u in users_res.json())

    # 7. Get overview
    ovr_res = client.get("/api/tenants/overview")
    assert ovr_res.status_code == 200
    assert ovr_res.json()["total_tenants"] >= 4
