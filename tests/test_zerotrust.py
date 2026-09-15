"""
Unit and Integration Tests for Zero Trust Architecture Subsystem.
Verifies continuous posture assessment, dynamic trust scoring, PDP access decisions, and REST APIs.
"""

import pytest
from fastapi.testclient import TestClient

from cybershield.api.server import app
from cybershield.zerotrust.evaluator import TrustScoreEvaluator
from cybershield.zerotrust.policy_engine import ZeroTrustPolicyEngine
from cybershield.zerotrust.schemas import (
    AccessContext,
    AccessDecisionType,
    DevicePosture,
    ResourceSensitivityTier,
    ZeroTrustPolicy,
)


@pytest.fixture
def evaluator():
    return TrustScoreEvaluator()


@pytest.fixture
def zt_engine():
    return ZeroTrustPolicyEngine()


@pytest.fixture
def client():
    return TestClient(app)


def test_device_health_evaluation(evaluator):
    # Fully healthy endpoint
    healthy = DevicePosture(
        device_id="DEV-WIN-001",
        os_name="Windows 11 Enterprise",
        os_version="23H2",
        edr_agent_healthy=True,
        disk_encryption_enabled=True,
        firewall_enabled=True,
        secure_boot_enabled=True,
        jailbroken_or_rooted=False,
        pending_critical_patches=0,
        compliance_passed=True,
    )
    score, reasons = evaluator.evaluate_device_health(healthy)
    assert score == 100.0
    assert len(reasons) == 0

    # Compromised endpoint (rooted + missing patches)
    unhealthy = DevicePosture(
        device_id="DEV-UNHEALTHY-01",
        os_name="Android",
        os_version="13",
        edr_agent_healthy=False,
        disk_encryption_enabled=False,
        firewall_enabled=False,
        secure_boot_enabled=False,
        jailbroken_or_rooted=True,
        pending_critical_patches=3,
        compliance_passed=False,
    )
    score_unhealthy, reasons_unhealthy = evaluator.evaluate_device_health(unhealthy)
    assert score_unhealthy == 0.0
    assert any("rooted" in r.lower() for r in reasons_unhealthy)
    assert any("edr" in r.lower() for r in reasons_unhealthy)


def test_network_context_impossible_travel(evaluator):
    ctx_normal = AccessContext(
        user_id="alice@corp.local",
        user_role="SOC_ANALYST",
        source_ip="10.0.1.15",
        device_posture=DevicePosture(device_id="DEV-1", os_name="Win", os_version="11"),
        target_resource_id="SRV-VAULT",
        target_resource_tier=ResourceSensitivityTier.TIER_1_CRITICAL,
        client_tls_version="TLSv1.3",
        impossible_travel_detected=False,
        mfa_verified=True,
    )
    score_norm, _ = evaluator.evaluate_network_context(ctx_normal)
    assert score_norm == 100.0

    ctx_travel = ctx_normal.model_copy(update={"impossible_travel_detected": True, "source_ip": "198.51.100.4"})
    score_travel, reasons = evaluator.evaluate_network_context(ctx_travel)
    assert score_travel <= 30.0
    assert any("impossible travel" in r.lower() for r in reasons)


def test_zt_policy_engine_allow_tier1(zt_engine):
    ctx = AccessContext(
        user_id="admin_john",
        user_role="SEC_ADMIN",
        source_ip="10.10.0.5",
        device_posture=DevicePosture(
            device_id="DEV-ADMIN-SECURE",
            os_name="Windows 11",
            os_version="23H2",
            edr_agent_healthy=True,
            disk_encryption_enabled=True,
            firewall_enabled=True,
            secure_boot_enabled=True,
            jailbroken_or_rooted=False,
            pending_critical_patches=0,
            compliance_passed=True,
        ),
        target_resource_id="VAULT-DC-PRIMARY",
        target_resource_tier=ResourceSensitivityTier.TIER_1_CRITICAL,
        client_tls_version="TLSv1.3",
        mfa_verified=True,
        ueba_anomaly_score=5.0,
    )
    eval_result = zt_engine.evaluate_access(ctx)
    assert eval_result.decision == AccessDecisionType.ALLOW
    assert eval_result.composite_trust_score >= 85.0


def test_zt_policy_engine_isolate_rooted_device(zt_engine):
    ctx = AccessContext(
        user_id="bob@corp.local",
        user_role="DEVELOPER",
        source_ip="192.168.1.10",
        device_posture=DevicePosture(
            device_id="DEV-ROOTED-PHONE",
            os_name="Android",
            os_version="14",
            jailbroken_or_rooted=True,
        ),
        target_resource_id="GIT-REPO-INTERNAL",
        target_resource_tier=ResourceSensitivityTier.TIER_2_RESTRICTED,
    )
    eval_result = zt_engine.evaluate_access(ctx)
    assert eval_result.decision == AccessDecisionType.ISOLATE_DEVICE
    assert any("quarantine" in s.lower() for s in eval_result.remediation_steps)


def test_zt_policy_engine_step_up_mfa(zt_engine):
    # Device healthy but no MFA on standard resource
    ctx = AccessContext(
        user_id="carol@corp.local",
        user_role="EMPLOYEE",
        source_ip="10.2.1.20",
        device_posture=DevicePosture(
            device_id="DEV-CAROL-PC",
            os_name="Windows 11",
            os_version="23H2",
            edr_agent_healthy=True,
            disk_encryption_enabled=True,
        ),
        target_resource_id="INTRANET-PORTAL",
        target_resource_tier=ResourceSensitivityTier.TIER_3_STANDARD,
        mfa_verified=False,
        ueba_anomaly_score=20.0,
    )
    eval_result = zt_engine.evaluate_access(ctx)
    assert eval_result.decision in [AccessDecisionType.STEP_UP_MFA, AccessDecisionType.ALLOW]


def test_zerotrust_api_endpoints(client):
    # 1. List policies
    resp = client.get("/api/zerotrust/policies")
    assert resp.status_code == 200
    policies = resp.json()
    assert len(policies) >= 4

    # 2. Evaluate access via API
    payload = {
        "user_id": "test_user_api",
        "user_role": "SOC_ANALYST",
        "source_ip": "10.0.5.20",
        "device_posture": {
            "device_id": "DEV-TEST-API",
            "os_name": "Ubuntu 22.04 LTS",
            "os_version": "5.15.0",
            "edr_agent_healthy": True,
            "disk_encryption_enabled": True,
            "firewall_enabled": True,
            "secure_boot_enabled": True,
            "jailbroken_or_rooted": False,
            "pending_critical_patches": 0,
            "compliance_passed": True,
        },
        "target_resource_id": "SRV-CLUSTER-01",
        "target_resource_tier": "TIER_2_RESTRICTED",
        "request_protocol": "HTTPS",
        "client_tls_version": "TLSv1.3",
        "mfa_verified": True,
        "ueba_anomaly_score": 10.0,
    }
    resp = client.post("/api/zerotrust/evaluate", json=payload)
    assert resp.status_code == 200
    res_data = resp.json()
    assert res_data["decision"] == "ALLOW"
    assert res_data["composite_trust_score"] >= 75.0

    # 3. Get history
    resp = client.get("/api/zerotrust/history?device_id=DEV-TEST-API")
    assert resp.status_code == 200
    history = resp.json()
    assert len(history) >= 1
    assert history[0]["device_id"] == "DEV-TEST-API"

    # 4. Overview metrics
    resp = client.get("/api/zerotrust/overview")
    assert resp.status_code == 200
    metrics = resp.json()
    assert metrics["total_evaluations"] >= 1
