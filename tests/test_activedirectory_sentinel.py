"""Tests for CyberShield Enterprise - Autonomous Active Directory & Kerberos Attack Sentinel.
Verifies Golden Ticket, Silver Ticket, AS-REP Roasting, DCSync abuse, Kerberoasting detection,
Domain Hygiene posture calculation, and REST API endpoints.
"""

import json
from datetime import datetime, timezone
import pytest
from starlette.testclient import TestClient

from cybershield.api.server import app
from cybershield.activedirectory.schemas import (
    KerberosTicketType,
    KerberosEncryptionType,
    ADAttackTechnique,
    KerberosTicketInspectionRequest,
    DCSecurityEvent,
)
from cybershield.activedirectory.sentinel import ActiveDirectorySentinel


@pytest.fixture
def client():
    return TestClient(app)


@pytest.fixture
def sentinel():
    return ActiveDirectorySentinel(domain_fqdn="CORP.LOCAL")


# =========================================================================
# Unit Tests: Kerberos Ticket & AD Attack Detection
# =========================================================================

def test_detect_golden_ticket_forgery(sentinel):
    # Forged TGT with 30-day (720h) lifetime and injected Domain Admin RID 512
    req = KerberosTicketInspectionRequest(
        ticket_id="tkt-golden-01",
        ticket_type=KerberosTicketType.TGT_TICKET_GRANTING_TICKET,
        client_principal="attacker_user@CORP.LOCAL",
        service_principal="krbtgt/CORP.LOCAL",
        encryption_type=KerberosEncryptionType.RC4_HMAC_NT,
        ticket_lifetime_hours=720.0,
        pac_groups_rids=[512, 513],
        is_account_privileged=False,
    )

    alert = sentinel.inspect_kerberos_ticket(req)
    assert alert is not None
    assert alert.threat_technique == ADAttackTechnique.GOLDEN_TICKET_FORGERY
    assert alert.severity == "CRITICAL"
    assert "T1558.001" in alert.mitre_technique
    assert "KRBTGT" in alert.countermeasure


def test_detect_silver_ticket_forgery(sentinel):
    # Forged TGS targeting MSSQL database service with injected Enterprise Admin RID 519
    req = KerberosTicketInspectionRequest(
        ticket_id="tkt-silver-01",
        ticket_type=KerberosTicketType.TGS_SERVICE_TICKET,
        client_principal="standard_contractor@CORP.LOCAL",
        service_principal="MSSQLSvc/sql01.corp.local:1433",
        encryption_type=KerberosEncryptionType.AES256_CTS_HMAC_SHA1_96,
        ticket_lifetime_hours=8.0,
        pac_groups_rids=[519, 513],
        is_account_privileged=False,
    )

    alert = sentinel.inspect_kerberos_ticket(req)
    assert alert is not None
    assert alert.threat_technique == ADAttackTechnique.SILVER_TICKET_FORGERY
    assert alert.severity == "CRITICAL"
    assert "T1558.002" in alert.mitre_technique


def test_detect_asrep_roasting_vulnerability(sentinel):
    req = KerberosTicketInspectionRequest(
        ticket_id="tkt-asrep-01",
        ticket_type=KerberosTicketType.TGT_TICKET_GRANTING_TICKET,
        client_principal="legacy_service@CORP.LOCAL",
        service_principal="krbtgt/CORP.LOCAL",
        encryption_type=KerberosEncryptionType.RC4_HMAC_NT,
        ticket_lifetime_hours=10.0,
        pac_groups_rids=[513],
        preauth_required=False,
    )

    alert = sentinel.inspect_kerberos_ticket(req)
    assert alert is not None
    assert alert.threat_technique == ADAttackTechnique.ASREP_ROASTING
    assert alert.severity == "HIGH"
    assert "T1558.004" in alert.mitre_technique


def test_detect_dcsync_replication_abuse(sentinel):
    event = DCSecurityEvent(
        event_id=4662,
        source_workstation="FINANCE-WS-88",
        source_ip="192.168.10.45",
        target_user="Administrator",
        access_mask="{1131f6aa-9c07-11d1-f79f-00c04fc2dcd2}",
    )

    alert = sentinel.inspect_dc_event(event)
    assert alert is not None
    assert alert.threat_technique == ADAttackTechnique.DCSYNC_REPLICATION_ABUSE
    assert alert.severity == "CRITICAL"
    assert "T1003.006" in alert.mitre_technique


def test_authorized_dc_replication_no_alert(sentinel):
    event = DCSecurityEvent(
        event_id=4662,
        source_workstation="CORP-DC-PRIMARY$",
        source_ip="10.0.0.2",
        target_user="krbtgt",
        access_mask="{1131f6aa-9c07-11d1-f79f-00c04fc2dcd2}",
    )

    alert = sentinel.inspect_dc_event(event)
    assert alert is None


def test_detect_kerberoasting_campaign(sentinel):
    source = "WORKSTATION-01"
    alert = None
    for i in range(3):
        event = DCSecurityEvent(
            event_id=4769,
            source_workstation=source,
            source_ip="10.10.1.25",
            target_user="svc_backup",
            service_name=f"BackupSvc/host{i}:8080",
            ticket_encryption_type="0x17",
        )
        alert = sentinel.inspect_dc_event(event)

    assert alert is not None
    assert alert.threat_technique == ADAttackTechnique.KERBEROASTING
    assert alert.severity == "HIGH"
    assert "T1558.003" in alert.mitre_technique


def test_domain_hygiene_posture_evaluation(sentinel):
    # Clean posture
    report_clean = sentinel.evaluate_domain_posture(
        krbtgt_age_days=30,
        unconstrained_delegation_count=0,
        preauth_disabled_count=0,
    )
    assert report_clean.domain_hygiene_score >= 90.0
    assert report_clean.posture_status == "STRONG_RESILIENT"

    # Degraded posture with old krbtgt and delegation risks
    report_risky = sentinel.evaluate_domain_posture(
        krbtgt_age_days=240,
        unconstrained_delegation_count=3,
        preauth_disabled_count=2,
    )
    assert report_risky.domain_hygiene_score < 70.0
    assert report_risky.posture_status in {"MODERATE_ELEVATED_RISK", "CRITICAL_COMPROMISE_SUSCEPTIBLE"}


# =========================================================================
# Integration Tests: FastAPI REST Endpoints
# =========================================================================

def test_api_inspect_ticket_endpoint(client):
    req = KerberosTicketInspectionRequest(
        ticket_id="api-tkt-01",
        ticket_type=KerberosTicketType.TGT_TICKET_GRANTING_TICKET,
        client_principal="compromised_user@CORP.LOCAL",
        service_principal="krbtgt/CORP.LOCAL",
        encryption_type=KerberosEncryptionType.RC4_HMAC_NT,
        ticket_lifetime_hours=100.0,
        pac_groups_rids=[512],
        is_account_privileged=False,
    )

    resp = client.post(
        "/api/v1/ad/tickets/inspect",
        json=json.loads(req.model_dump_json()),
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "ticket_inspected"
    assert data["is_threat"] is True
    assert data["threat_technique"] == "GOLDEN_TICKET_FORGERY"


def test_api_inspect_event_and_query_posture(client):
    event = DCSecurityEvent(
        event_id=4662,
        source_workstation="ROGUE-LAPTOP",
        source_ip="192.168.1.99",
        target_user="Administrator",
        access_mask="DS-Replication-Get-Changes-All",
    )

    resp = client.post(
        "/api/v1/ad/events/inspect",
        json=json.loads(event.model_dump_json()),
    )
    assert resp.status_code == 200
    assert resp.json()["is_threat"] is True

    # Check /threats endpoint
    threats_resp = client.get("/api/v1/ad/threats")
    assert threats_resp.status_code == 200
    threats = threats_resp.json()
    assert len(threats) >= 1

    # Check /posture endpoint
    posture_resp = client.get("/api/v1/ad/posture?krbtgt_age_days=100")
    assert posture_resp.status_code == 200
    posture = posture_resp.json()
    assert "domain_hygiene_score" in posture
    assert "posture_status" in posture
