"""
Unit and Integration Tests for Identity Threat Detection and Response (ITDR).
Verifies Kerberoasting, DCSync, AS-REP Roasting, Golden Tickets, AD posture scoring, and REST APIs.
"""

import pytest
from fastapi.testclient import TestClient

from cybershield.api.server import app
from cybershield.itdr.detector import IdentityThreatDetector
from cybershield.itdr.schemas import (
    DirectoryReplicationTelemetry,
    IdentityAttackType,
    IdentityRiskLevel,
    KerberosEncryptionType,
    KerberosTicketTelemetry,
)


@pytest.fixture
def itdr_detector():
    return IdentityThreatDetector()


@pytest.fixture
def client():
    return TestClient(app)


def test_seeded_ad_accounts(itdr_detector):
    accounts = itdr_detector.list_accounts()
    assert len(accounts) >= 3

    # Check SPN account
    sql_acct = itdr_detector.get_account("svc_mssql_prod")
    assert sql_acct is not None
    assert len(sql_acct.service_principal_names) > 0

    # Check AS-REP vulnerable account
    vuln_acct = itdr_detector.get_account("legacy_backup_user")
    assert vuln_acct is not None
    assert vuln_acct.preauth_required is False


def test_kerberoasting_detection(itdr_detector):
    ticket = KerberosTicketTelemetry(
        ticket_id="TKT-ROAST-01",
        request_type="TGS_REQ",
        client_name="compromised_workstation_user",
        service_name="MSSQLSvc/db01.corp.local:1433",
        encryption_type=KerberosEncryptionType.RC4_HMAC,
        ticket_lifetime_hours=10.0,
        client_ip="10.0.5.88",
    )
    alert = itdr_detector.analyze_kerberos_ticket(ticket)

    assert alert is not None
    assert alert.attack_type == IdentityAttackType.KERBEROASTING
    assert alert.severity == IdentityRiskLevel.HIGH
    assert alert.mitre_technique_id == "T1558.003"
    assert "MSSQLSvc" in alert.title


def test_golden_ticket_detection(itdr_detector):
    ticket = KerberosTicketTelemetry(
        ticket_id="TKT-GOLD-01",
        request_type="TGS_REQ",
        client_name="Administrator",
        service_name="krbtgt/CORP.LOCAL",
        encryption_type=KerberosEncryptionType.AES256_CTS_HMAC_SHA1_96,
        ticket_lifetime_hours=8760.0,  # 1 year!
        client_ip="10.0.1.200",
    )
    alert = itdr_detector.analyze_kerberos_ticket(ticket)

    assert alert is not None
    assert alert.attack_type == IdentityAttackType.GOLDEN_TICKET
    assert alert.severity == IdentityRiskLevel.CRITICAL
    assert alert.mitre_technique_id == "T1558.001"


def test_asrep_roasting_detection(itdr_detector):
    ticket = KerberosTicketTelemetry(
        ticket_id="TKT-ASREP-01",
        request_type="AS_REQ",
        client_name="legacy_backup_user",
        service_name="krbtgt/CORP.LOCAL",
        encryption_type=KerberosEncryptionType.AES256_CTS_HMAC_SHA1_96,
        ticket_lifetime_hours=10.0,
        client_ip="10.0.9.15",
    )
    alert = itdr_detector.analyze_kerberos_ticket(ticket)

    assert alert is not None
    assert alert.attack_type == IdentityAttackType.ASREP_ROASTING
    assert alert.mitre_technique_id == "T1558.004"


def test_dcsync_attack_detection(itdr_detector):
    rep = DirectoryReplicationTelemetry(
        request_id="DRS-REQ-001",
        client_ip="192.168.10.45",
        requesting_account="attacker_compromised_user",
        extended_rights_requested=[
            "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2",  # DS-Replication-Get-Changes
            "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2",  # DS-Replication-Get-Changes-All
        ],
        is_registered_domain_controller=False,
    )
    alert = itdr_detector.analyze_directory_replication(rep)

    assert alert is not None
    assert alert.attack_type == IdentityAttackType.DCSYNC
    assert alert.severity == IdentityRiskLevel.CRITICAL
    assert alert.mitre_technique_id == "T1003.006"


def test_privileged_group_tampering(itdr_detector):
    alert = itdr_detector.analyze_privileged_group_change(
        actor="compromised_admin",
        target_user="backdoor_user",
        group_name="Domain Admins",
    )
    assert alert is not None
    assert alert.attack_type == IdentityAttackType.PRIVILEGED_GROUP_TAMPERING
    assert alert.severity == IdentityRiskLevel.CRITICAL


def test_ad_posture_overview(itdr_detector):
    posture = itdr_detector.get_posture_overview()
    assert posture.total_accounts >= 3
    assert posture.spn_accounts_at_risk >= 1
    assert posture.no_preauth_accounts_count >= 1
    assert posture.identity_risk_score > 0.0


def test_itdr_api_endpoints(client):
    # 1. List accounts
    resp = client.get("/api/itdr/accounts")
    assert resp.status_code == 200
    accounts = resp.json()
    assert len(accounts) >= 3

    # 2. Analyze Kerberos ticket via API
    ticket_payload = {
        "ticket_id": "TKT-API-01",
        "request_type": "TGS_REQ",
        "client_name": "analyst_api",
        "service_name": "MSSQLSvc/sql.corp.local:1433",
        "encryption_type": "RC4",
        "ticket_lifetime_hours": 10.0,
        "client_ip": "10.0.1.75",
    }
    resp = client.post("/api/itdr/analyze/kerberos", json=ticket_payload)
    assert resp.status_code == 200
    alert = resp.json()
    assert alert is not None
    assert alert["attack_type"] == "KERBEROASTING"

    # 3. Analyze DCSync via API
    rep_payload = {
        "request_id": "DRS-API-01",
        "client_ip": "10.0.1.99",
        "requesting_account": "rogue_admin",
        "extended_rights_requested": ["DS-Replication-Get-Changes-All"],
        "is_registered_domain_controller": False,
    }
    resp = client.post("/api/itdr/analyze/replication", json=rep_payload)
    assert resp.status_code == 200
    alert_dcsync = resp.json()
    assert alert_dcsync is not None
    assert alert_dcsync["attack_type"] == "DCSYNC"

    # 4. Get posture
    resp = client.get("/api/itdr/posture")
    assert resp.status_code == 200
    posture = resp.json()
    assert posture["total_accounts"] >= 3
    assert posture["identity_risk_score"] > 0

    # 5. List alerts
    resp = client.get("/api/itdr/alerts")
    assert resp.status_code == 200
    assert len(resp.json()) >= 2
