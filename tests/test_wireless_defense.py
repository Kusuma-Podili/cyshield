"""Tests for CyberShield Enterprise - Autonomous Wireless & RF Cyber Defense Engine.
Verifies Rogue AP / Evil Twin detection, Deauthentication flood DoS tracking,
BLE beacon tracking, Airspace sanitation calculation, and REST API endpoints.
"""

import json
from datetime import datetime, timezone, timedelta
import pytest
from starlette.testclient import TestClient

from cybershield.api.server import app
from cybershield.wireless.schemas import (
    WirelessProtocol,
    WirelessThreatType,
    WirelessFrameType,
    WirelessFrame,
    WirelessAccessPoint,
    AirspaceSanitationReport,
)
from cybershield.wireless.defense import WirelessDefenseEngine


@pytest.fixture
def client():
    return TestClient(app)


@pytest.fixture
def engine():
    return WirelessDefenseEngine()


# =========================================================================
# Unit Tests: Wireless Defense Engine
# =========================================================================

def test_whitelist_sanctioned_ap(engine):
    ap = engine.register_sanctioned_ap(
        bssid="00:14:22:01:23:45",
        ssid="Corp-Secure-WiFi",
        channel=36,
        encryption="WPA3_SAE",
    )
    assert ap.bssid == "00:14:22:01:23:45"
    assert ap.ssid == "Corp-Secure-WiFi"
    assert ap.is_corporate_sanctioned is True
    assert "00:14:22:01:23:45" in engine.sanctioned_bssids
    assert "Corp-Secure-WiFi" in engine.corporate_ssids


def test_benign_sanctioned_beacon_ingestion(engine):
    engine.register_sanctioned_ap(
        bssid="00:14:22:01:23:45",
        ssid="Corp-Secure-WiFi",
        channel=36,
    )

    frame = WirelessFrame(
        frame_id="frame-001",
        protocol=WirelessProtocol.WIFI_80211,
        source_mac="00:14:22:01:23:45",
        dest_mac="ff:ff:ff:ff:ff:ff",
        bssid="00:14:22:01:23:45",
        frame_type=WirelessFrameType.MANAGEMENT_BEACON,
        signal_rssi=-50,
        channel=36,
        payload_snippet="Corp-Secure-WiFi",
    )

    alert = engine.ingest_frame(frame)
    assert alert is None
    assert "00:14:22:01:23:45" in engine.observed_aps
    assert engine.observed_aps["00:14:22:01:23:45"].is_corporate_sanctioned is True


def test_detect_evil_twin_rogue_ap(engine):
    # Legitimate AP exists
    engine.register_sanctioned_ap(
        bssid="00:14:22:01:23:45",
        ssid="Corp-Secure-WiFi",
        channel=36,
    )

    # Rogue AP broadcasts the same SSID from an unauthorized MAC
    rogue_frame = WirelessFrame(
        frame_id="frame-rogue-001",
        protocol=WirelessProtocol.WIFI_80211,
        source_mac="de:ad:be:ef:13:37",
        dest_mac="ff:ff:ff:ff:ff:ff",
        bssid="de:ad:be:ef:13:37",
        frame_type=WirelessFrameType.MANAGEMENT_BEACON,
        signal_rssi=-42,
        channel=36,
        payload_snippet="Corp-Secure-WiFi",
    )

    alert = engine.ingest_frame(rogue_frame)
    assert alert is not None
    assert alert.threat_type == WirelessThreatType.EVIL_TWIN_ROGUE_AP
    assert alert.severity == "CRITICAL"
    assert alert.detected_bssid_or_mac == "de:ad:be:ef:13:37"
    assert "T1557.002" in alert.mitre_technique
    assert len(engine.alerts) == 1


def test_detect_deauth_flood_dos(engine):
    now = datetime.now(timezone.utc)
    target_ap = "00:14:22:01:23:45"
    victim_client = "aa:bb:cc:dd:ee:01"
    attacker_mac = "66:55:44:33:22:11"

    alert = None
    # Send 10 deauth frames within 1 second
    for i in range(10):
        frame = WirelessFrame(
            frame_id=f"frame-deauth-{i}",
            protocol=WirelessProtocol.WIFI_80211,
            source_mac=attacker_mac,
            dest_mac=victim_client,
            bssid=target_ap,
            frame_type=WirelessFrameType.MANAGEMENT_DEAUTH,
            signal_rssi=-45,
            channel=36,
            timestamp=now + timedelta(milliseconds=i * 50),
        )
        alert = engine.ingest_frame(frame)

    assert alert is not None
    assert alert.threat_type == WirelessThreatType.DEAUTH_FLOOD_DOS
    assert alert.severity == "HIGH"
    assert alert.detected_bssid_or_mac == attacker_mac
    assert victim_client in alert.affected_clients


def test_ble_tracker_stalking_detection(engine):
    now = datetime.now(timezone.utc)
    ble_mac = "f0:99:b8:12:34:56"

    alert = None
    for i in range(30):
        frame = WirelessFrame(
            frame_id=f"frame-ble-{i}",
            protocol=WirelessProtocol.BLE_BLUETOOTH,
            source_mac=ble_mac,
            dest_mac="ff:ff:ff:ff:ff:ff",
            frame_type=WirelessFrameType.BLE_ADVERTISEMENT,
            signal_rssi=-50,
            timestamp=now + timedelta(seconds=i),
        )
        alert = engine.ingest_frame(frame)

    assert alert is not None
    assert alert.threat_type == WirelessThreatType.BLE_TRACKER_STALKING
    assert alert.detected_bssid_or_mac == ble_mac
    assert alert.signal_rssi == -50


def test_airspace_sanitation_report(engine):
    # Setup: 1 sanctioned AP, 1 rogue AP, and trigger an Evil Twin alert
    engine.register_sanctioned_ap(
        bssid="00:14:22:01:23:45",
        ssid="Corp-Secure-WiFi",
    )
    rogue_frame = WirelessFrame(
        frame_id="frame-rogue-002",
        protocol=WirelessProtocol.WIFI_80211,
        source_mac="de:ad:be:ef:99:99",
        dest_mac="ff:ff:ff:ff:ff:ff",
        bssid="de:ad:be:ef:99:99",
        frame_type=WirelessFrameType.MANAGEMENT_BEACON,
        signal_rssi=-48,
        payload_snippet="Corp-Secure-WiFi",
    )
    engine.ingest_frame(rogue_frame)

    report = engine.get_airspace_report()
    assert report.total_aps_scanned == 2
    assert report.sanctioned_aps_count == 1
    assert report.rogue_aps_count == 1
    assert report.active_threats_count == 1
    assert report.airspace_health_index < 100.0


# =========================================================================
# Integration Tests: FastAPI REST Endpoints
# =========================================================================

def test_api_whitelist_access_point(client):
    resp = client.post(
        "/api/v1/wireless/whitelist",
        params={
            "bssid": "00:aa:bb:cc:dd:ee",
            "ssid": "Corp-Campus-Guest",
            "channel": 40,
            "encryption": "WPA3_SAE",
        },
    )
    assert resp.status_code == 201
    data = resp.json()
    assert data["bssid"] == "00:aa:bb:cc:dd:ee"
    assert data["is_corporate_sanctioned"] is True


def test_api_ingest_frame_and_query_threats(client):
    frame = WirelessFrame(
        frame_id="api-frame-001",
        protocol=WirelessProtocol.WIFI_80211,
        source_mac="11:22:33:44:55:66",
        dest_mac="ff:ff:ff:ff:ff:ff",
        bssid="11:22:33:44:55:66",
        frame_type=WirelessFrameType.MANAGEMENT_BEACON,
        signal_rssi=-40,
        payload_snippet="Corp-Secure-WiFi",  # Triggers Evil Twin
    )

    resp = client.post(
        "/api/v1/wireless/frames",
        json=json.loads(frame.model_dump_json()),
    )
    assert resp.status_code == 201
    res_data = resp.json()
    assert res_data["status"] == "ingested"
    assert res_data["threat_detected"] is True

    # Check /threats endpoint
    threats_resp = client.get("/api/v1/wireless/threats")
    assert threats_resp.status_code == 200
    threats = threats_resp.json()
    assert len(threats) >= 1

    # Check /aps endpoint
    aps_resp = client.get("/api/v1/wireless/aps")
    assert aps_resp.status_code == 200
    aps = aps_resp.json()
    assert len(aps) >= 1

    # Check /airspace endpoint
    airspace_resp = client.get("/api/v1/wireless/airspace")
    assert airspace_resp.status_code == 200
    airspace = airspace_resp.json()
    assert airspace["total_aps_scanned"] >= 1
    assert "airspace_health_index" in airspace
