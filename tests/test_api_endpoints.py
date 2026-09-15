"""Integration tests for CyberShield Enterprise REST API Endpoints."""

import pytest
from starlette.testclient import TestClient
from cybershield.api.server import app

client = TestClient(app)


def test_system_metrics_endpoint():
    """Verify system health, version, and engine status endpoint."""
    response = client.get("/api/v1/system/metrics")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "OPERATIONAL_OPTIMAL"
    assert "IsolationForest_Anomaly_Engine" in data["engines_online"]
    assert "Sigma_Condition_Matcher" in data["engines_online"]


def test_alerts_endpoint():
    """Verify listing alerts endpoint."""
    response = client.get("/api/v1/alerts")
    assert response.status_code == 200
    assert isinstance(response.json(), list)


def test_incidents_endpoint():
    """Verify incident cases listing endpoint."""
    response = client.get("/api/v1/incidents")
    assert response.status_code == 200
    incidents = response.json()
    assert len(incidents) >= 1
    assert "INC-" in incidents[0]["incident_id"]


def test_telemetry_ingest_and_csql():
    """Verify ingesting log and querying via CS-QL endpoint."""
    ingest_resp = client.post("/api/v1/telemetry/ingest", json={
        "raw": "<34>Sep 12 10:00:00 srv01 sshd[999]: Accepted publickey for analyst from 10.0.1.20 port 52310"
    })
    assert ingest_resp.status_code == 200
    evt = ingest_resp.json()
    assert evt["host_name"] == "srv01"

    # Query via CS-QL
    csql_resp = client.post("/api/v1/telemetry/csql", json={
        "query": "host_name == 'srv01'",
        "target": "events"
    })
    assert csql_resp.status_code == 200
    res_data = csql_resp.json()
    assert res_data["total_matched"] >= 1


def test_threat_intel_cve_endpoint():
    """Verify CVE catalog retrieval."""
    response = client.get("/api/v1/intel/cve")
    assert response.status_code == 200
    cves = response.json()
    cve_ids = [c["cve_id"] for c in cves]
    assert "CVE-2024-3094" in cve_ids
    assert "CVE-2021-44228" in cve_ids


def test_simulation_ransomware_endpoint():
    """Verify triggering simulated attack through REST API."""
    response = client.post("/api/v1/simulation/ransomware", json={
        "host": "ws-test-sim.corp",
        "user": "victim_user"
    })
    assert response.status_code == 200
    data = response.json()
    assert data["scenario"] == "Ransomware Detonation"
    assert data["playbook_status"] == "COMPLETED"
