"""
Unit and Integration Tests for Network Microsegmentation Subsystem.
Verifies policy definitions, firewall compiler (nftables, iptables, k8s, AWS), and flow drift evaluation.
"""

import pytest
from fastapi.testclient import TestClient

from cybershield.api.server import app
from cybershield.microseg.compiler import MicrosegmentationCompiler
from cybershield.microseg.schemas import (
    FlowEvaluationRequest,
    TargetFirewallFormat,
    WorkloadTier,
)


@pytest.fixture
def compiler():
    return MicrosegmentationCompiler()


@pytest.fixture
def client():
    return TestClient(app)


def test_default_rules_and_listing(compiler):
    rules = compiler.list_rules()
    assert len(rules) >= 4
    rule_ids = [r.rule_id for r in rules]
    assert "RULE-WEB-TO-APP" in rule_ids
    assert "RULE-BLOCK-WEB-TO-DB" in rule_ids


def test_compiler_nftables(compiler):
    res = compiler.compile_ruleset(TargetFirewallFormat.NFTABLES)
    assert res.target_format == TargetFirewallFormat.NFTABLES
    assert res.rule_count >= 4
    assert "table inet cybershield_microseg" in res.generated_code
    assert "policy drop;" in res.generated_code


def test_compiler_kubernetes_network_policy(compiler):
    res = compiler.compile_ruleset(TargetFirewallFormat.KUBERNETES_NETWORK_POLICY)
    assert "NetworkPolicy" in res.generated_code
    assert "podSelector" in res.generated_code
    assert "app_backend" in res.generated_code or "database" in res.generated_code


def test_compiler_windows_firewall(compiler):
    res = compiler.compile_ruleset(TargetFirewallFormat.WINDOWS_FIREWALL)
    assert "New-NetFirewallRule" in res.generated_code
    assert "-DefaultInboundAction Block" in res.generated_code


def test_flow_evaluation_allowed(compiler):
    # Allowed flow: Web Frontend -> App Backend:8080
    flow = FlowEvaluationRequest(
        src_ip="10.0.1.10",
        dst_ip="10.0.2.20",
        src_tier=WorkloadTier.WEB_FRONTEND,
        dst_tier=WorkloadTier.APP_BACKEND,
        protocol="TCP",
        dst_port=8080,
    )
    violation = compiler.evaluate_flow(flow)
    assert violation is None


def test_flow_evaluation_explicit_deny(compiler):
    # Explicit DENY: Web Frontend -> Database
    flow = FlowEvaluationRequest(
        src_ip="10.0.1.10",
        dst_ip="10.0.3.30",
        src_tier=WorkloadTier.WEB_FRONTEND,
        dst_tier=WorkloadTier.DATABASE,
        protocol="TCP",
        dst_port=5432,
    )
    violation = compiler.evaluate_flow(flow)
    assert violation is not None
    assert violation.severity == "CRITICAL"
    assert "DENY policy matched" in violation.reason


def test_flow_evaluation_zero_trust_implicit_deny(compiler):
    # Implicit DENY: Workstation trying to access Database directly on port 5432
    flow = FlowEvaluationRequest(
        src_ip="192.168.1.55",
        dst_ip="10.0.3.30",
        src_tier=WorkloadTier.CORP_WORKSTATION,
        dst_tier=WorkloadTier.DATABASE,
        protocol="TCP",
        dst_port=5432,
    )
    violation = compiler.evaluate_flow(flow)
    assert violation is not None
    assert "Default Deny" in violation.reason


def test_microseg_api_endpoints(client):
    # 1. List rules
    resp = client.get("/api/microseg/rules")
    assert resp.status_code == 200
    assert len(resp.json()) >= 4

    # 2. Compile to iptables via API
    compile_payload = {"target_format": "IPTABLES"}
    resp = client.post("/api/microseg/compile", json=compile_payload)
    assert resp.status_code == 200
    assert "iptables -A FORWARD" in resp.json()["generated_code"]

    # 3. Evaluate flow via API
    flow_payload = {
        "src_ip": "10.0.1.5",
        "dst_ip": "10.0.3.15",
        "src_tier": "WEB_FRONTEND",
        "dst_tier": "DATABASE",
        "protocol": "TCP",
        "dst_port": 5432,
    }
    resp = client.post("/api/microseg/evaluate-flow", json=flow_payload)
    assert resp.status_code == 200
    violation = resp.json()
    assert violation is not None
    assert violation["severity"] == "CRITICAL"

    # 4. List violations
    resp = client.get("/api/microseg/violations")
    assert resp.status_code == 200
    assert len(resp.json()) >= 1
