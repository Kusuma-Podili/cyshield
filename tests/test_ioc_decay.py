"""
Unit and integration tests for Threat Feeds & Automated IoC Aging / Decay Engine.
"""

from datetime import datetime, timedelta
import pytest
from fastapi.testclient import TestClient

from cybershield.api.server import app
from cybershield.iocdecay.engine import IOCDecayEngine
from cybershield.iocdecay.schemas import (
    DecayIndicator,
    IOCStatus,
    IOCType,
    SightingRecordRequest,
)


@pytest.fixture
def engine():
    return IOCDecayEngine()


@pytest.fixture
def client():
    return TestClient(app)


def test_half_life_exponential_decay(engine):
    t0 = datetime.utcnow() - timedelta(days=7)  # exactly 1 half-life ago for IPV4 (7 days)
    ind = DecayIndicator(
        indicator_id="IOC-TEST-1",
        value="198.51.100.1",
        ioc_type=IOCType.IPV4,
        initial_confidence=100.0,
        current_confidence=100.0,
        last_decay_calc=t0,
        status=IOCStatus.ACTIVE
    )
    result = engine.calculate_decay(ind, now=datetime.utcnow())

    # 100 * 2^(-7/7) = 50.0
    assert abs(result.new_confidence - 50.0) < 1.0
    assert result.status in [IOCStatus.DECAYING, IOCStatus.ACTIVE]


def test_indicator_expiration_and_pruning(engine):
    # After 3 half-lives (21 days for IPV4), confidence is 90 * 2^(-3) = 11.25, below min_retention (20.0)
    t0 = datetime.utcnow() - timedelta(days=22)
    ind = DecayIndicator(
        indicator_id="IOC-TEST-EXPIRE",
        value="203.0.113.99",
        ioc_type=IOCType.IPV4,
        initial_confidence=90.0,
        current_confidence=90.0,
        last_decay_calc=t0,
        status=IOCStatus.ACTIVE
    )
    result = engine.calculate_decay(ind, now=datetime.utcnow())
    assert result.new_confidence < 20.0
    assert result.status == IOCStatus.EXPIRED
    assert result.is_pruned is True


def test_sighting_reinforcement_boost(engine):
    # Setup decaying indicator
    t0 = datetime.utcnow() - timedelta(days=10)
    ind = DecayIndicator(
        indicator_id="IOC-TEST-BOOST",
        value="c2-reobserved.com",
        ioc_type=IOCType.DOMAIN,
        initial_confidence=85.0,
        current_confidence=40.0,
        last_decay_calc=t0,
        status=IOCStatus.DECAYING
    )
    engine.add_indicator(ind)

    # Record sighting
    sighting_req = SightingRecordRequest(
        indicator_value="c2-reobserved.com",
        ioc_type=IOCType.DOMAIN,
        sighting_source="EDR_NETWORK_TELEMETRY"
    )
    updated = engine.record_sighting(sighting_req)
    assert updated.current_confidence > 40.0
    assert updated.status == IOCStatus.ACTIVE
    assert updated.sighting_count >= 2


def test_whitelisted_indicator_does_not_decay(engine):
    t0 = datetime.utcnow() - timedelta(days=100)
    ind = DecayIndicator(
        indicator_id="IOC-WHITE",
        value="dns.google",
        ioc_type=IOCType.DOMAIN,
        initial_confidence=100.0,
        current_confidence=100.0,
        last_decay_calc=t0,
        status=IOCStatus.WHITELISTED
    )
    result = engine.calculate_decay(ind, now=datetime.utcnow())
    assert result.new_confidence == 100.0
    assert result.status == IOCStatus.WHITELISTED


def test_active_firewall_feed_filtering(engine):
    feed = engine.get_active_firewall_feed(min_confidence=30.0)
    assert len(feed) >= 1
    for item in feed:
        assert item["confidence"] >= 30.0


def test_iocdecay_api_lifecycle(client):
    # 1. List indicators
    res = client.get("/api/iocdecay/indicators")
    assert res.status_code == 200
    inds = res.json()
    assert len(inds) >= 1
    sample_id = inds[0]["indicator_id"]

    # 2. Get specific indicator
    det_res = client.get(f"/api/iocdecay/indicators/{sample_id}")
    assert det_res.status_code == 200
    assert det_res.json()["indicator_id"] == sample_id

    # 3. Create indicator via API
    create_payload = {
        "indicator_id": "IOC-API-001",
        "value": "192.0.2.200",
        "ioc_type": "IPV4",
        "initial_confidence": 95.0,
        "current_confidence": 95.0,
        "sighting_count": 1,
        "status": "ACTIVE",
        "source_feed": "TEST_FEED",
        "tags": ["api_test"]
    }
    create_res = client.post("/api/iocdecay/indicators", json=create_payload)
    assert create_res.status_code == 201

    # 4. Record sighting via API
    sight_payload = {
        "indicator_value": "192.0.2.200",
        "ioc_type": "IPV4",
        "sighting_source": "HONEYPOT_HIT"
    }
    sight_res = client.post("/api/iocdecay/sighting", json=sight_payload)
    assert sight_res.status_code == 200
    assert sight_res.json()["sighting_count"] == 2

    # 5. Trigger sweep
    sweep_res = client.post("/api/iocdecay/sweep")
    assert sweep_res.status_code == 200
    assert len(sweep_res.json()) >= 1

    # 6. Get active feed
    feed_res = client.get("/api/iocdecay/active-feed?min_confidence=50")
    assert feed_res.status_code == 200
    assert len(feed_res.json()) >= 1

    # 7. Get Overview
    ovr_res = client.get("/api/iocdecay/overview")
    assert ovr_res.status_code == 200
    assert ovr_res.json()["total_tracked_indicators"] >= 1
