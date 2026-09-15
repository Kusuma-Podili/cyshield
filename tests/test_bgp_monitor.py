"""
Unit and integration tests for BGP Route Hijacking & Peering Monitor.
"""

import pytest
from fastapi.testclient import TestClient

from cybershield.api.server import app
from cybershield.bgp.monitor import BGPMonitorEngine
from cybershield.bgp.schemas import (
    BGPHijackType,
    BGPRouteAnnouncement,
    RouteOriginAuthorization,
    RPKIValidationState,
)


@pytest.fixture
def engine():
    return BGPMonitorEngine()


@pytest.fixture
def client():
    return TestClient(app)


def test_rpki_valid_announcement(engine):
    ann = BGPRouteAnnouncement(
        message_id="BGP-MSG-001",
        prefix="198.51.100.0/24",
        origin_asn=64500,
        as_path=[174, 3356, 64500],
    )
    result = engine.evaluate_announcement(ann)
    assert result.rpki_status == RPKIValidationState.VALID
    assert result.is_hijack_detected is False
    assert result.alert is None


def test_bgp_origin_hijack_detection(engine):
    # Rogue AS66666 announcing protected prefix 198.51.100.0/24
    ann = BGPRouteAnnouncement(
        message_id="BGP-MSG-HIJACK-1",
        prefix="198.51.100.0/24",
        origin_asn=66666,
        as_path=[1299, 66666],
    )
    result = engine.evaluate_announcement(ann)
    assert result.rpki_status == RPKIValidationState.INVALID_ASN
    assert result.is_hijack_detected is True
    assert result.alert is not None
    assert result.alert.hijack_type == BGPHijackType.ORIGIN_HIJACK
    assert result.alert.authorized_asn == 64500
    assert result.alert.rogue_asn == 66666


def test_bgp_subprefix_hijack_detection(engine):
    # Announcing /25 sub-prefix where max_length is /24
    ann = BGPRouteAnnouncement(
        message_id="BGP-MSG-SUBPREFIX-1",
        prefix="198.51.100.0/25",
        origin_asn=64500,
        as_path=[3356, 64500],
    )
    result = engine.evaluate_announcement(ann)
    assert result.rpki_status == RPKIValidationState.INVALID_MAX_LENGTH
    assert result.is_hijack_detected is True
    assert result.alert is not None
    assert result.alert.hijack_type == BGPHijackType.SUBPREFIX_HIJACK


def test_bogon_prefix_announcement(engine):
    # Private RFC 1918 prefix announced to public internet
    ann = BGPRouteAnnouncement(
        message_id="BGP-BOGON-1",
        prefix="10.200.0.0/16",
        origin_asn=65001,
        as_path=[65001],
    )
    result = engine.evaluate_announcement(ann)
    assert result.is_hijack_detected is True
    assert result.alert is not None
    assert result.alert.hijack_type == BGPHijackType.BOGON_ANNOUNCEMENT


def test_roa_registration_crud(engine):
    new_roa = RouteOriginAuthorization(
        roa_id="ROA-CUSTOM-99",
        prefix="198.18.0.0/15",
        origin_asn=64510,
        max_length=20,
        ta_name="LACNIC-RPKI"
    )
    engine.add_roa(new_roa)
    roas = engine.list_roas()
    assert any(r.roa_id == "ROA-CUSTOM-99" for r in roas)


def test_bgp_api_lifecycle(client):
    # 1. List ROAs
    roas_res = client.get("/api/bgp/roas")
    assert roas_res.status_code == 200
    assert len(roas_res.json()) >= 3

    # 2. Evaluate valid announcement via API
    eval_payload = {
        "message_id": "MSG-API-VALID",
        "prefix": "203.0.113.0/24",
        "origin_asn": 64501,
        "as_path": [174, 64501]
    }
    eval_res = client.post("/api/bgp/evaluate", json=eval_payload)
    assert eval_res.status_code == 200
    assert eval_res.json()["rpki_status"] == "VALID"
    assert eval_res.json()["is_hijack_detected"] is False

    # 3. Evaluate hijack via API
    hijack_payload = {
        "message_id": "MSG-API-HIJACK",
        "prefix": "203.0.113.0/24",
        "origin_asn": 99999,
        "as_path": [1299, 99999]
    }
    hijack_res = client.post("/api/bgp/evaluate", json=hijack_payload)
    assert hijack_res.status_code == 200
    assert hijack_res.json()["is_hijack_detected"] is True
    assert hijack_res.json()["alert"]["hijack_type"] == "ORIGIN_HIJACK"

    # 4. List Alerts
    alerts_res = client.get("/api/bgp/alerts")
    assert alerts_res.status_code == 200
    assert len(alerts_res.json()) >= 1

    # 5. Create ROA via API
    roa_payload = {
        "roa_id": "ROA-API-01",
        "prefix": "198.51.200.0/24",
        "origin_asn": 64520,
        "max_length": 24,
        "ta_name": "ARIN-RPKI"
    }
    roa_create_res = client.post("/api/bgp/roas", json=roa_payload)
    assert roa_create_res.status_code == 201

    # 6. Overview
    ovr_res = client.get("/api/bgp/overview")
    assert ovr_res.status_code == 200
    assert ovr_res.json()["total_announcements_evaluated"] >= 2
