"""
Unit and integration tests for DNS Firewall & Protective C2 Sinkholing Subsystem.
"""

import pytest
from fastapi.testclient import TestClient

from cybershield.api.server import app
from cybershield.dnsfw.engine import DNSFirewallEngine
from cybershield.dnsfw.schemas import (
    DNSAction,
    DNSFirewallRule,
    DNSInspectionRequest,
    DNSQueryType,
    DNSSinkholeHit,
)


@pytest.fixture
def engine():
    return DNSFirewallEngine()


@pytest.fixture
def client():
    return TestClient(app)


def test_rpz_wildcard_matching(engine):
    req = DNSInspectionRequest(
        client_ip="10.0.1.25",
        domain="stage2.cobaltstrike-beacon.net",
        query_type=DNSQueryType.A
    )
    res = engine.inspect_query(req)
    assert res.action == DNSAction.SINKHOLE
    assert res.resolved_ip == "10.254.254.254"
    assert res.matched_rule_id == "RPZ-C2-001"


def test_phishing_nxdomain_block(engine):
    req = DNSInspectionRequest(
        client_ip="10.0.2.14",
        domain="login-microsoft-auth-verify.com",
        query_type=DNSQueryType.A
    )
    res = engine.inspect_query(req)
    assert res.action == DNSAction.BLOCK_NXDOMAIN
    assert res.resolved_ip is None
    assert "Matched RPZ policy" in res.block_reason


def test_dga_domain_detection(engine):
    # DGA sample with high consonant density & entropy
    req = DNSInspectionRequest(
        client_ip="10.0.5.99",
        domain="zkvrfptqwbnmx9.biz",
        query_type=DNSQueryType.A
    )
    res = engine.inspect_query(req)
    assert res.action == DNSAction.SINKHOLE
    assert res.is_dga_detected is True
    assert res.shannon_entropy > 3.0

    # Legitimate common domain should be permitted
    legit_req = DNSInspectionRequest(
        client_ip="10.0.5.99",
        domain="api.github.com",
        query_type=DNSQueryType.A
    )
    legit_res = engine.inspect_query(legit_req)
    assert legit_res.action == DNSAction.ALLOW
    assert legit_res.is_dga_detected is False


def test_dns_tunneling_detection(engine):
    # Exfiltration query containing high-entropy base32 chunk in TXT record
    exfil_domain = "mfzgwotkmy2wmztdn5wgyzls.tunnel.attacker-domain.org"
    req = DNSInspectionRequest(
        client_ip="10.0.3.10",
        domain=exfil_domain,
        query_type=DNSQueryType.TXT
    )
    res = engine.inspect_query(req)
    assert res.action == DNSAction.SINKHOLE
    assert res.is_tunneling_detected is True


def test_suspicious_tld_filtering(engine):
    req = DNSInspectionRequest(
        client_ip="10.0.1.50",
        domain="free-giftcard-update.top",
        query_type=DNSQueryType.A
    )
    res = engine.inspect_query(req)
    assert res.action == DNSAction.BLOCK_NXDOMAIN
    assert "Restricted high-abuse Top-Level Domain" in res.block_reason


def test_sinkhole_hit_recording_and_retrieval(engine):
    hit = DNSSinkholeHit(
        hit_id="HIT-001",
        client_ip="10.0.4.88",
        sinkhole_ip="10.254.254.254",
        requested_domain="stage2.cobaltstrike-beacon.net",
        protocol="HTTP",
        user_agent="Mozilla/5.0 (Windows NT 10.0; Win64; x64) Trident/7.0",
        payload_preview="GET /submit.php?id=3819 HTTP/1.1"
    )
    engine.record_sinkhole_hit(hit)

    hits = engine.list_sinkhole_hits()
    assert len(hits) >= 1
    assert hits[0].hit_id == "HIT-001"
    assert hits[0].client_ip == "10.0.4.88"


def test_rpz_rule_crud(engine):
    new_rule = DNSFirewallRule(
        rule_id="RPZ-TEST-CUSTOM",
        domain_pattern="*.badsite.test",
        action=DNSAction.BLOCK_NXDOMAIN,
        category="MALWARE_SITE",
        description="Custom block rule"
    )
    engine.add_rule(new_rule)
    assert len([r for r in engine.list_rules() if r.rule_id == "RPZ-TEST-CUSTOM"]) == 1

    # Delete rule
    assert engine.delete_rule("RPZ-TEST-CUSTOM") is True
    assert engine.delete_rule("NON_EXISTENT") is False


def test_dnsfw_api_lifecycle(client):
    # 1. Inspect query via API
    inspect_payload = {
        "client_ip": "192.168.1.100",
        "domain": "test.cobaltstrike-beacon.net",
        "query_type": "A"
    }
    resp = client.post("/api/dnsfw/inspect", json=inspect_payload)
    assert resp.status_code == 200
    inspect_data = resp.json()
    assert inspect_data["action"] == "SINKHOLE"
    assert inspect_data["resolved_ip"] == "10.254.254.254"

    # 2. List rules
    rules_resp = client.get("/api/dnsfw/rules")
    assert rules_resp.status_code == 200
    assert len(rules_resp.json()) >= 4

    # 3. Create custom rule
    rule_payload = {
        "rule_id": "RPZ-API-TEST",
        "domain_pattern": "*.malicious-api-test.com",
        "action": "BLOCK_NXDOMAIN",
        "category": "TEST_CATEGORY",
        "description": "API created test rule"
    }
    create_resp = client.post("/api/dnsfw/rules", json=rule_payload)
    assert create_resp.status_code == 201

    # 4. Delete rule
    del_resp = client.delete("/api/dnsfw/rules/RPZ-API-TEST")
    assert del_resp.status_code == 200

    # 5. Record sinkhole hit via API
    hit_payload = {
        "hit_id": "HIT-API-99",
        "client_ip": "10.0.8.12",
        "sinkhole_ip": "10.254.254.254",
        "requested_domain": "c2.test.net",
        "protocol": "HTTPS"
    }
    hit_resp = client.post("/api/dnsfw/sinkhole/hits", json=hit_payload)
    assert hit_resp.status_code == 201

    # 6. List sinkhole hits
    list_hits_resp = client.get("/api/dnsfw/sinkhole/hits")
    assert list_hits_resp.status_code == 200
    assert len(list_hits_resp.json()) >= 1

    # 7. Get Overview
    ovr_resp = client.get("/api/dnsfw/overview")
    assert ovr_resp.status_code == 200
    assert ovr_resp.json()["total_queries_inspected"] >= 1
