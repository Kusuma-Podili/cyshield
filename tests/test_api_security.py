"""
Unit and integration tests for API Security & Shadow API Discovery Subsystem.
"""

import pytest
from fastapi.testclient import TestClient

from cybershield.api.server import app
from cybershield.apisec.gateway import APISecurityGateway
from cybershield.apisec.schemas import (
    APIRiskLevel,
    APISpecEndpoint,
    APITrafficLog,
    OWASPAPIType,
)


@pytest.fixture
def gateway():
    return APISecurityGateway()


@pytest.fixture
def client():
    return TestClient(app)


def test_shadow_api_discovery(gateway):
    log = APITrafficLog(
        log_id="LOG-001",
        client_ip="192.168.1.50",
        method="GET",
        path="/api/v1/internal/hidden-metrics",
        headers={"Authorization": "Bearer token123"}
    )
    findings = gateway.inspect_transaction(log)
    assert len(findings) >= 1
    assert any(f.threat_type == OWASPAPIType.SHADOW_API for f in findings)
    assert any(s["path"] == "/api/v1/internal/hidden-metrics" for s in gateway.get_shadow_endpoints())


def test_zombie_api_discovery(gateway):
    log = APITrafficLog(
        log_id="LOG-002",
        client_ip="10.0.1.20",
        method="POST",
        path="/api/v0/auth/legacy-token",
        headers={"Authorization": "Bearer token123"}
    )
    findings = gateway.inspect_transaction(log)
    assert any(f.threat_type == OWASPAPIType.ZOMBIE_API for f in findings)
    assert any(z["path"] == "/api/v0/auth/legacy-token" for z in gateway.get_zombie_endpoints())


def test_broken_function_level_authorization(gateway):
    log = APITrafficLog(
        log_id="LOG-003",
        client_ip="10.0.4.15",
        method="POST",
        path="/api/v1/admin/users/delete",
        headers={"Authorization": "Bearer token123"},
        user_role="standard_user"
    )
    findings = gateway.inspect_transaction(log)
    assert any(f.threat_type == OWASPAPIType.BFLA for f in findings)
    bfla_finding = next(f for f in findings if f.threat_type == OWASPAPIType.BFLA)
    assert bfla_finding.severity == APIRiskLevel.CRITICAL


def test_mass_assignment_detection(gateway):
    log = APITrafficLog(
        log_id="LOG-004",
        client_ip="10.0.3.11",
        method="POST",
        path="/api/v1/users",
        headers={"Authorization": "Bearer token123"},
        request_body={
            "username": "attacker",
            "email": "attacker@evil.com",
            "is_admin": True,
            "role": "superadmin"
        },
        user_role="user"
    )
    findings = gateway.inspect_transaction(log)
    assert any(f.threat_type == OWASPAPIType.MASS_ASSIGNMENT for f in findings)


def test_unrestricted_resource_consumption(gateway):
    log = APITrafficLog(
        log_id="LOG-005",
        client_ip="10.0.3.12",
        method="GET",
        path="/api/v1/devices",
        headers={"Authorization": "Bearer token123"},
        query_params={"limit": "99999", "offset": "0"}
    )
    findings = gateway.inspect_transaction(log)
    assert any(f.threat_type == OWASPAPIType.RESOURCE_CONSUMPTION for f in findings)


def test_broken_authentication_missing_token(gateway):
    log = APITrafficLog(
        log_id="LOG-006",
        client_ip="10.0.3.14",
        method="GET",
        path="/api/v1/users",
        headers={}  # Missing Authorization header
    )
    findings = gateway.inspect_transaction(log)
    assert any(f.threat_type == OWASPAPIType.BROKEN_AUTH for f in findings)


def test_bola_idor_enumeration(gateway):
    ip = "192.168.10.88"
    for i in range(4):
        log = APITrafficLog(
            log_id=f"LOG-IDOR-{i}",
            client_ip=ip,
            method="GET",
            path=f"/api/v1/users/user_{100 + i}",
            headers={"Authorization": "Bearer valid_token"}
        )
        findings = gateway.inspect_transaction(log)
        if i == 3:
            assert any(f.threat_type == OWASPAPIType.BOLA_IDOR for f in findings)


def test_apisec_api_lifecycle(client):
    # 1. List registered endpoints
    eps_res = client.get("/api/apisec/endpoints")
    assert eps_res.status_code == 200
    assert len(eps_res.json()) >= 6

    # 2. Register custom endpoint
    new_ep = {
        "path": "/api/v2/reports/summary",
        "method": "GET",
        "is_deprecated": False,
        "requires_auth": True
    }
    reg_res = client.post("/api/apisec/endpoints", json=new_ep)
    assert reg_res.status_code == 201

    # 3. Inspect transaction via API
    tx_payload = {
        "log_id": "TX-API-01",
        "client_ip": "172.16.5.99",
        "method": "GET",
        "path": "/api/v1/secret-backdoor-test",
        "headers": {"Authorization": "Bearer token"}
    }
    inspect_res = client.post("/api/apisec/inspect", json=tx_payload)
    assert inspect_res.status_code == 200
    findings = inspect_res.json()
    assert len(findings) >= 1
    assert findings[0]["threat_type"] == "SHADOW_API"

    # 4. List shadow APIs
    shadow_res = client.get("/api/apisec/shadow-apis")
    assert shadow_res.status_code == 200
    assert any(s["path"] == "/api/v1/secret-backdoor-test" for s in shadow_res.json())

    # 5. List findings
    find_res = client.get("/api/apisec/findings")
    assert find_res.status_code == 200
    assert len(find_res.json()) >= 1

    # 6. Overview
    ovr_res = client.get("/api/apisec/overview")
    assert ovr_res.status_code == 200
    assert ovr_res.json()["shadow_endpoints_count"] >= 1
