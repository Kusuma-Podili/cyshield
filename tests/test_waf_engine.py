"""
Unit and integration tests for Web Application Firewall (WAF) & OWASP CRS Engine.
"""

import pytest
from fastapi.testclient import TestClient

from cybershield.api.server import app
from cybershield.waf.engine import WAFEngine
from cybershield.waf.schemas import (
    WAFAction,
    WAFInspectionRequest,
    WAFPolicyConfig,
    WAFRuleCategory,
)


@pytest.fixture
def engine():
    return WAFEngine()


@pytest.fixture
def client():
    return TestClient(app)


def test_sql_injection_detection(engine):
    req = WAFInspectionRequest(
        client_ip="192.168.1.10",
        method="GET",
        uri="/api/search",
        query_string="id=1' OR '1'='1' --"
    )
    res = engine.inspect_request(req)
    assert res.is_blocked is True
    assert res.http_status_code == 403
    assert res.action == WAFAction.BLOCK
    assert res.total_anomaly_score >= 5
    assert any(m.category == WAFRuleCategory.SQL_INJECTION for m in res.matched_rules)


def test_cross_site_scripting_detection(engine):
    req = WAFInspectionRequest(
        client_ip="192.168.1.11",
        method="POST",
        uri="/submit/comment",
        body='{"comment": "<script>alert(document.cookie)</script>"}'
    )
    res = engine.inspect_request(req)
    assert res.is_blocked is True
    assert res.http_status_code == 403
    assert any(m.category == WAFRuleCategory.XSS for m in res.matched_rules)


def test_command_injection_detection(engine):
    req = WAFInspectionRequest(
        client_ip="192.168.1.12",
        method="POST",
        uri="/api/ping",
        body="host=127.0.0.1; whoami"
    )
    res = engine.inspect_request(req)
    assert res.is_blocked is True
    assert any(m.category == WAFRuleCategory.COMMAND_INJECTION for m in res.matched_rules)


def test_path_traversal_lfi_detection(engine):
    req = WAFInspectionRequest(
        client_ip="192.168.1.13",
        method="GET",
        uri="/view",
        query_string="file=../../../../etc/passwd"
    )
    res = engine.inspect_request(req)
    assert res.is_blocked is True
    assert any(m.category == WAFRuleCategory.PATH_TRAVERSAL for m in res.matched_rules)


def test_ssrf_detection(engine):
    req = WAFInspectionRequest(
        client_ip="192.168.1.14",
        method="GET",
        uri="/proxy",
        query_string="url=http://169.254.169.254/latest/meta-data/"
    )
    res = engine.inspect_request(req)
    assert res.is_blocked is True
    assert any(m.category == WAFRuleCategory.SSRF for m in res.matched_rules)


def test_clean_request_allowed(engine):
    req = WAFInspectionRequest(
        client_ip="192.168.1.15",
        method="GET",
        uri="/api/products",
        query_string="category=electronics&page=2&sort=asc"
    )
    res = engine.inspect_request(req)
    assert res.is_blocked is False
    assert res.http_status_code == 200
    assert res.action == WAFAction.ALLOW
    assert res.total_anomaly_score == 0


def test_waf_policy_config_monitoring_mode(engine):
    # Set to MONITOR mode
    engine.update_config(WAFPolicyConfig(action_mode=WAFAction.MONITOR, blocking_threshold=5))
    req = WAFInspectionRequest(
        client_ip="192.168.1.16",
        method="GET",
        uri="/test",
        query_string="q=' union select null,null--"
    )
    res = engine.inspect_request(req)
    assert res.action == WAFAction.MONITOR
    assert res.is_blocked is False
    assert res.total_anomaly_score >= 5


def test_waf_api_lifecycle(client):
    # 1. List rules
    rules_res = client.get("/api/waf/rules")
    assert rules_res.status_code == 200
    assert len(rules_res.json()) >= 6

    # 2. Inspect clean request via API
    clean_payload = {
        "client_ip": "10.0.1.5",
        "method": "GET",
        "uri": "/dashboard",
        "query_string": "view=grid"
    }
    clean_res = client.post("/api/waf/inspect", json=clean_payload)
    assert clean_res.status_code == 200
    assert clean_res.json()["action"] == "ALLOW"
    assert clean_res.json()["is_blocked"] is False

    # 3. Inspect malicious attack payload via API
    attack_payload = {
        "client_ip": "10.0.1.99",
        "method": "POST",
        "uri": "/login",
        "body": "username=admin' or '1'='1&password=foo"
    }
    attack_res = client.post("/api/waf/inspect", json=attack_payload)
    assert attack_res.status_code == 200
    assert attack_res.json()["action"] == "BLOCK"
    assert attack_res.json()["is_blocked"] is True

    # 4. Get and update config
    cfg_res = client.get("/api/waf/config")
    assert cfg_res.status_code == 200
    assert cfg_res.json()["blocking_threshold"] >= 1

    # 5. Get overview
    ovr_res = client.get("/api/waf/overview")
    assert ovr_res.status_code == 200
    assert ovr_res.json()["total_requests_inspected"] >= 2
    assert ovr_res.json()["total_requests_blocked"] >= 1
