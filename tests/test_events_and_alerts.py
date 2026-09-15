"""
CyberShield Enterprise - Integration Tests for Security Events, Parsers & Alert Triage
Tests Suricata, Windows Events, NetFlow parsers, batch ingestion, database persistence,
CS-QL threat hunting, alert deduplication, noise suppression, and triage workflows.
"""

import json
import uuid
import asyncio
import pytest
from starlette.testclient import TestClient

from cybershield.api.server import app
from cybershield.database.session import init_db, async_session_factory
from cybershield.network.subnet_service import SubnetService
from cybershield.network.device_service import DeviceService
from cybershield.alerts.service import AlertService
from cybershield.events.service import EventsService
from cybershield.ingestion.siem_parsers import (
    SuricataEveParser,
    WindowsSecurityEventParser,
    NetFlowParser,
    MultiFormatLogIngester,
)

client = TestClient(app)


@pytest.fixture(scope="module", autouse=True)
def setup_database():
    """Initialize schema and seed enterprise subnets, devices, alerts, and events."""
    async def _setup():
        await init_db()
        async with async_session_factory() as session:
            await SubnetService(session).seed_enterprise_subnets()
            await DeviceService(session).seed_enterprise_devices()
            await AlertService(session).seed_default_alerts()
            await EventsService(session).seed_default_events()
    asyncio.run(_setup())


@pytest.fixture(scope="module")
def admin_token():
    """Authenticate as superadmin."""
    login_resp = client.post("/api/auth/login", json={
        "username_or_email": "superadmin",
        "password": "CyberShield2026!"
    })
    assert login_resp.status_code == 200
    return login_resp.json()["access_token"]


def test_suricata_eve_json_parser():
    """Verify Suricata EVE parser accurately extracts dimensions for alerts, DNS, and HTTP."""
    # 1. Test IDS alert
    alert_raw = {
        "timestamp": "2026-09-12T08:30:00.123456Z",
        "event_type": "alert",
        "src_ip": "198.51.100.99",
        "src_port": 54321,
        "dest_ip": "10.0.2.15",
        "dest_port": 443,
        "proto": "TCP",
        "alert": {
            "action": "allowed",
            "signature": "ET EXPLOIT Spring4Shell RCE (CVE-2022-22965)",
            "severity": 1
        }
    }
    parsed = SuricataEveParser.parse(json.dumps(alert_raw))
    assert parsed is not None
    assert parsed["severity"].value == "HIGH"
    assert parsed["source_type"].value == "SURICATA"
    assert parsed["source_ip"] == "198.51.100.99"
    assert parsed["destination_ip"] == "10.0.2.15"
    assert "Spring4Shell" in parsed["message"]
    assert parsed["is_anomalous"] is True

    # 2. Test DNS query
    dns_raw = {
        "timestamp": "2026-09-12T08:31:00Z",
        "event_type": "dns",
        "src_ip": "10.0.1.108",
        "src_port": 61234,
        "dest_ip": "10.0.3.10",
        "dest_port": 53,
        "proto": "UDP",
        "dns": {"type": "A", "rrname": "evil-c2-domain.ru"}
    }
    parsed_dns = SuricataEveParser.parse(json.dumps(dns_raw))
    assert parsed_dns["event_type"].value == "DNS_QUERY"
    assert "evil-c2-domain.ru" in parsed_dns["message"]


def test_windows_security_event_parser():
    """Verify Windows Event parser extracts logon, process execution, and log clearing."""
    # 1. Event 4688: Process creation
    p4688 = WindowsSecurityEventParser.parse_json({
        "EventID": 4688,
        "Computer": "dc-primary.corp",
        "EventData": {
            "NewProcessName": "C:\\Windows\\System32\\powershell.exe",
            "CommandLine": "powershell.exe -enc SQBYAE0A...",
            "SubjectUserName": "Administrator"
        }
    })
    assert p4688["event_type"].value == "PROCESS_CREATION"
    assert p4688["user_name"] == "Administrator"
    assert "powershell.exe" in p4688["process_name"]

    # 2. Event 4625: Failed logon
    p4625 = WindowsSecurityEventParser.parse_json({
        "EventID": 4625,
        "Computer": "ws-finance-08.corp",
        "EventData": {
            "TargetUserName": "cfo_vip",
            "IpAddress": "198.51.100.42"
        }
    })
    assert p4625["event_type"].value == "AUTHENTICATION_ATTEMPT"
    assert p4625["severity"].value == "MEDIUM"
    assert p4625["is_anomalous"] is True

    # 3. Event 1102: Audit log cleared (Defense Evasion)
    p1102 = WindowsSecurityEventParser.parse_json({
        "EventID": 1102,
        "Computer": "dc-primary.corp",
        "EventData": {"SubjectUserName": "attacker"}
    })
    assert p1102["event_type"].value == "SECURITY_LOG_CLEARED"
    assert p1102["severity"].value == "CRITICAL"
    assert p1102["is_anomalous"] is True


def test_netflow_parser_and_exfil():
    """Verify NetFlow parser detects anomalous outbound high-volume exfiltration."""
    flow = {
        "ipv4_src_addr": "10.0.1.108",
        "ipv4_dst_addr": "203.0.113.50",
        "l4_src_port": 49152,
        "l4_dst_port": 443,
        "protocol_str": "TCP",
        "in_bytes": 250 * 1024 * 1024,  # 250 MB
        "in_pkts": 180000
    }
    parsed = NetFlowParser.parse(flow)
    assert parsed["event_type"].value == "FLOW_STATISTICS"
    assert parsed["severity"].value == "HIGH"
    assert parsed["is_anomalous"] is True
    assert "EXFILTRATION SPIKE" in parsed["message"]


def test_batch_telemetry_ingest_and_query(admin_token):
    """Verify posting batch logs via REST API, persistence, and retrieval."""
    headers = {"Authorization": f"Bearer {admin_token}"}
    uid = uuid.uuid4().hex[:6]

    batch = [
        json.dumps({
            "event_type": "alert",
            "src_ip": f"198.51.100.{int(uid[:2], 16) % 200}",
            "src_port": 40123,
            "dest_ip": "10.0.2.15",
            "dest_port": 443,
            "proto": "TCP",
            "alert": {"signature": f"Test Ingest IDS Signature {uid}", "severity": 2}
        }),
        json.dumps({
            "EventID": 4688,
            "Computer": f"ws-test-{uid}.corp",
            "EventData": {
                "NewProcessName": "C:\\Windows\\System32\\calc.exe",
                "CommandLine": "calc.exe",
                "SubjectUserName": f"user_{uid}"
            }
        }),
    ]

    ingest_resp = client.post("/api/events/ingest", json={"logs": batch}, headers=headers)
    assert ingest_resp.status_code == 201
    res = ingest_resp.json()
    assert res["accepted_count"] == 2
    assert res["failed_count"] == 0
    assert res["status"] == "SUCCESS"

    # Query events list and verify presence
    list_resp = client.get(f"/api/events?search={uid}", headers=headers)
    assert list_resp.status_code == 200
    events_data = list_resp.json()
    assert events_data["total"] >= 1


def test_csql_database_query_execution(admin_token):
    """Verify executing CS-QL threat hunting queries against database events."""
    headers = {"Authorization": f"Bearer {admin_token}"}
    payload = {
        "query": "event_type == 'PROCESS_CREATION' or severity == 'CRITICAL' | limit 10",
        "target": "events",
        "limit": 10
    }
    resp = client.post("/api/events/csql", json=payload, headers=headers)
    assert resp.status_code == 200
    data = resp.json()
    assert data["query"] == payload["query"]
    assert data["execution_time_ms"] >= 0.0
    assert isinstance(data["results"], list)


def test_alert_creation_and_deduplication(admin_token):
    """Verify that posting identical alerts triggers sliding-window deduplication."""
    headers = {"Authorization": f"Bearer {admin_token}"}
    uid = uuid.uuid4().hex[:6]
    rule_id = f"sigma-mimikatz-{uid}"
    host = f"dc-cluster-{uid}.corp"

    alert_payload = {
        "title": f"Mimikatz Process Injection {uid}",
        "description": "LSASS memory dumping attempt intercepted by CyberShield.",
        "severity": "CRITICAL",
        "engine": "SIGMA",
        "rule_id": rule_id,
        "rule_name": "Mimikatz LSASS Dump",
        "host_name": host,
        "host_ip": "10.0.3.10",
        "user_name": "SYSTEM",
        "mitre_tactic": "Credential Access",
        "mitre_technique_id": "T1003.001",
        "mitre_technique_name": "OS Credential Dumping"
    }

    # 1. Create first alert
    resp1 = client.post("/api/alerts", json=alert_payload, headers=headers)
    assert resp1.status_code == 201
    alt1 = resp1.json()
    assert alt1["occurrence_count"] == 1
    first_id = alt1["id"]

    # 2. Post duplicate alert immediately
    resp2 = client.post("/api/alerts", json=alert_payload, headers=headers)
    assert resp2.status_code == 201
    alt2 = resp2.json()
    assert alt2["id"] == first_id  # Same alert updated
    assert alt2["occurrence_count"] == 2


def test_alert_suppression_filter(admin_token):
    """Verify that suppression rule suppresses matching incoming alerts."""
    headers = {"Authorization": f"Bearer {admin_token}"}
    uid = uuid.uuid4().hex[:6]

    # Create suppression rule
    sup_payload = {
        "name": f"Suppress Backup Job {uid}",
        "rule_name_pattern": f"Large Backup Copy {uid}",
        "host_pattern": "backup-.*",
        "reason": "Scheduled nightly backup job is legitimate."
    }
    sup_resp = client.post("/api/alerts/suppression", json=sup_payload, headers=headers)
    assert sup_resp.status_code == 201

    # Ingest matching alert
    alert_payload = {
        "title": f"Large Backup File Transfer {uid}",
        "description": "Over 500GB transferred.",
        "severity": "LOW",
        "engine": "CUSTOM_RULE",
        "rule_id": f"backup-rule-{uid}",
        "rule_name": f"Large Backup Copy {uid}",
        "host_name": "backup-srv-01.corp",
        "host_ip": "10.0.3.90",
        "user_name": "backup_agent"
    }
    alt_resp = client.post("/api/alerts", json=alert_payload, headers=headers)
    assert alt_resp.status_code == 201
    alert_data = alt_resp.json()
    assert alert_data["suppressed"] is True
    assert "Matched rule" in alert_data["suppression_reason"]


def test_alert_triage_workflow_and_notes(admin_token):
    """Verify analyst triage lifecycle: status change, notes, and resolution."""
    headers = {"Authorization": f"Bearer {admin_token}"}

    # Target seeded mimikatz alert
    alt_id = "alt-mimikatz-01"

    # 1. Advance status to UNDER_INVESTIGATION
    triage_payload = {
        "status": "UNDER_INVESTIGATION",
        "note": "Analyst assigned. Beginning host memory dump analysis."
    }
    t_resp = client.post(f"/api/alerts/{alt_id}/triage", json=triage_payload, headers=headers)
    assert t_resp.status_code == 200
    triaged = t_resp.json()
    assert triaged["status"] == "UNDER_INVESTIGATION"
    assert len(triaged["triage_notes"]) >= 2

    # 2. Append additional note
    note_resp = client.post(
        f"/api/alerts/{alt_id}/notes",
        json={"note": "Memory dump confirms LSASS read handle from PID 1420."},
        headers=headers
    )
    assert note_resp.status_code == 200
    with_note = note_resp.json()
    assert any("PID 1420" in n["note"] for n in with_note["triage_notes"])

    # 3. Resolve alert
    resolve_payload = {
        "status": "RESOLVED",
        "resolution_summary": "Remediated via host isolation and active process kill."
    }
    res_resp = client.post(f"/api/alerts/{alt_id}/triage", json=resolve_payload, headers=headers)
    assert res_resp.status_code == 200
    assert res_resp.json()["status"] == "RESOLVED"
    assert res_resp.json()["resolved_at"] is not None


def test_alert_escalate_to_incident(admin_token):
    """Verify escalating an alert into a formal Security Incident."""
    headers = {"Authorization": f"Bearer {admin_token}"}
    alt_id = "alt-ransom-02"

    payload = {
        "incident_title": "Active Ransomware Epidemic on ws-finance-08",
        "priority": "CRITICAL",
        "initial_containment": True
    }
    resp = client.post(f"/api/alerts/{alt_id}/escalate", json=payload, headers=headers)
    assert resp.status_code == 200
    data = resp.json()
    assert "inc-case-" in data["incident_id"]
    assert data["status"] == "ESCALATED"


def test_alert_and_event_kpis(admin_token):
    """Verify aggregated alert and event queue metrics endpoints."""
    headers = {"Authorization": f"Bearer {admin_token}"}

    # Alert KPIs
    alt_kpi = client.get("/api/alerts/kpis", headers=headers)
    assert alt_kpi.status_code == 200
    ak = alt_kpi.json()
    assert ak["total_alerts"] >= 4
    assert ak["critical_alerts"] >= 1
    assert len(ak["top_affected_hosts"]) >= 1

    # Event Stats
    ev_stats = client.get("/api/events/stats", headers=headers)
    assert ev_stats.status_code == 200
    es = ev_stats.json()
    assert es["total_events"] >= 6
    assert es["events_per_second"] >= 0.0
    assert "source_breakdown" in es
