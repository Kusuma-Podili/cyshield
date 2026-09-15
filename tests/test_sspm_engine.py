"""
CyberShield Enterprise - SaaS Security Posture Management (SSPM) Test Suite
Tests OAuth app permission auditing, BEC mailbox forwarding detection,
MFA fatigue push bombing correlation, account hygiene, and REST routes.
"""

import json
from datetime import datetime, timedelta
import pytest
from starlette.testclient import TestClient

from cybershield.api.server import app
from cybershield.sspm.schemas import (
    SaaSPlatform,
    SSPMSeverity,
    OAuthAppGrant,
    MailboxForwardingRule,
    MFAChallengeEvent,
    SaaSAccountAudit,
)
from cybershield.sspm.engine import SaaSSecurityPostureEngine


@pytest.fixture
def engine():
    return SaaSSecurityPostureEngine(enterprise_domain="acmecorp.com")


@pytest.fixture
def client():
    return TestClient(app)


# ------------------------------------------------------------------------------
# 1. OAuth App Auditing Tests
# ------------------------------------------------------------------------------

def test_audit_unverified_critical_oauth_app(engine):
    malicious_grant = OAuthAppGrant(
        app_id="app-12345-trojan",
        app_name="PDF Converter Pro Free",
        publisher_domain="suspicious-hoster.xyz",
        is_publisher_verified=False,
        consenting_user="ceo@acmecorp.com",
        is_admin_consent=False,
        scopes=["User.Read", "Mail.ReadWrite.All", "Files.ReadWrite.All"],
    )
    findings = engine.audit_oauth_app(malicious_grant)
    assert len(findings) >= 1
    f = findings[0]
    assert f.category == "OAUTH_CONSENT_ABUSE"
    assert f.severity == SSPMSeverity.CRITICAL
    assert "Mail.ReadWrite.All" in f.details or "mail.readwrite.all" in f.details


def test_audit_verified_normal_oauth_app(engine):
    legit_grant = OAuthAppGrant(
        app_id="app-slack-official",
        app_name="Slack for M365",
        publisher_domain="slack.com",
        is_publisher_verified=True,
        consenting_user="user@acmecorp.com",
        is_admin_consent=False,
        scopes=["User.Read"],
    )
    findings = engine.audit_oauth_app(legit_grant)
    assert len(findings) == 0


# ------------------------------------------------------------------------------
# 2. Mailbox Forwarding & BEC Detection Tests
# ------------------------------------------------------------------------------

def test_audit_bec_forwarding_and_deletion(engine):
    bec_rule = MailboxForwardingRule(
        rule_id="rule-987",
        mailbox_owner="cfo@acmecorp.com",
        rule_name="Archive Rule",
        forward_to_addresses=["adversary-exfil@external-hacker.com"],
        is_external_forward=True,
        action_delete_or_mark_read=True,
        filter_keywords=["wire", "invoice", "payment"],
    )
    findings = engine.audit_mailbox_rule(bec_rule)
    assert len(findings) >= 1
    f = findings[0]
    assert f.category == "BEC_MAILBOX_FORWARDING"
    assert f.severity == SSPMSeverity.CRITICAL
    assert "adversary-exfil@external-hacker.com" in f.details


def test_audit_internal_normal_mailbox_rule(engine):
    internal_rule = MailboxForwardingRule(
        rule_id="rule-001",
        mailbox_owner="alice@acmecorp.com",
        rule_name="Forward to Backup",
        forward_to_addresses=["alice-backup@acmecorp.com"],
        is_external_forward=False,
        action_delete_or_mark_read=False,
        filter_keywords=[],
    )
    findings = engine.audit_mailbox_rule(internal_rule)
    assert len(findings) == 0


# ------------------------------------------------------------------------------
# 3. MFA Fatigue / Push Bombing Correlation Tests
# ------------------------------------------------------------------------------

def test_detect_mfa_fatigue_push_bombing(engine):
    base_time = datetime.utcnow()
    events = [
        MFAChallengeEvent(
            event_id="ev-1",
            user_principal="finance_lead@acmecorp.com",
            timestamp=base_time,
            result="DENIED",
            client_ip="185.220.101.5",
            device_location="Frankfurt, Germany",
        ),
        MFAChallengeEvent(
            event_id="ev-2",
            user_principal="finance_lead@acmecorp.com",
            timestamp=base_time + timedelta(minutes=2),
            result="DENIED",
            client_ip="185.220.101.5",
            device_location="Frankfurt, Germany",
        ),
        MFAChallengeEvent(
            event_id="ev-3",
            user_principal="finance_lead@acmecorp.com",
            timestamp=base_time + timedelta(minutes=4),
            result="TIMED_OUT",
            client_ip="185.220.101.5",
            device_location="Frankfurt, Germany",
        ),
        MFAChallengeEvent(
            event_id="ev-4",
            user_principal="finance_lead@acmecorp.com",
            timestamp=base_time + timedelta(minutes=6),
            result="APPROVED",
            client_ip="185.220.101.5",
            device_location="Frankfurt, Germany",
        ),
    ]

    findings = engine.detect_mfa_fatigue(events, window_minutes=15)
    assert len(findings) == 1
    f = findings[0]
    assert f.category == "MFA_FATIGUE_ATTACK"
    assert f.severity == SSPMSeverity.CRITICAL
    assert "finance_lead@acmecorp.com" in f.target_entity


# ------------------------------------------------------------------------------
# 4. Account Hygiene & Privileged Guest Auditing Tests
# ------------------------------------------------------------------------------

def test_audit_accounts_posture(engine):
    accounts = [
        SaaSAccountAudit(
            user_principal="contractor_guest#EXT#@acmecorp.com",
            is_guest=True,
            is_privileged_role=True,
            roles=["Global Administrator"],
            mfa_enforced=True,
            days_inactive=10,
            legacy_auth_enabled=False,
        ),
        SaaSAccountAudit(
            user_principal="dormant_admin@acmecorp.com",
            is_guest=False,
            is_privileged_role=True,
            roles=["Exchange Administrator"],
            mfa_enforced=True,
            days_inactive=120,  # > 90 days
            legacy_auth_enabled=False,
        ),
        SaaSAccountAudit(
            user_principal="regular_user@acmecorp.com",
            is_guest=False,
            is_privileged_role=False,
            roles=[],
            mfa_enforced=False,  # No MFA
            days_inactive=5,
            legacy_auth_enabled=True,  # Legacy auth
        )
    ]

    findings = engine.audit_accounts(accounts)
    categories = [f.category for f in findings]
    assert "PRIVILEGED_EXTERNAL_GUEST" in categories
    assert "DORMANT_ADMIN_ACCOUNT" in categories
    assert "MFA_NOT_ENFORCED" in categories
    assert "LEGACY_AUTH_PERMITTED" in categories


# ------------------------------------------------------------------------------
# 5. Holistic Tenant Posture Evaluation Tests
# ------------------------------------------------------------------------------

def test_evaluate_tenant_posture(engine):
    accounts = [
        SaaSAccountAudit(
            user_principal="admin@acmecorp.com",
            is_guest=False,
            is_privileged_role=True,
            roles=["Global Administrator"],
            mfa_enforced=True,
            days_inactive=2,
            legacy_auth_enabled=False,
        )
    ]
    report = engine.evaluate_tenant_posture(accounts=accounts)
    assert report.total_accounts_audited == 1
    assert report.mfa_coverage_percentage == 100.0
    assert report.posture_score == 100.0
    assert report.critical_findings_count == 0


# ------------------------------------------------------------------------------
# 6. REST API Endpoints Tests
# ------------------------------------------------------------------------------

def test_api_audit_oauth(client):
    payload = {
        "app_id": "oauth-test-1",
        "app_name": "Test Tool",
        "publisher_domain": "unverified.io",
        "is_publisher_verified": False,
        "consenting_user": "bob@acmecorp.com",
        "is_admin_consent": False,
        "scopes": ["Directory.ReadWrite.All"],
    }
    response = client.post("/api/v1/sspm/audit/oauth", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert len(data) >= 1
    assert data[0]["category"] == "OAUTH_CONSENT_ABUSE"


def test_api_audit_mailbox(client):
    payload = {
        "rule_id": "mbx-1",
        "mailbox_owner": "victim@acmecorp.com",
        "rule_name": "Forwarding",
        "forward_to_addresses": ["attacker@outside.com"],
        "is_external_forward": True,
        "action_delete_or_mark_read": True,
        "filter_keywords": ["invoice"],
    }
    response = client.post("/api/v1/sspm/audit/mailbox", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert len(data) >= 1
    assert data[0]["severity"] == "CRITICAL"


def test_api_detect_mfa_fatigue(client):
    now_iso = datetime.utcnow().isoformat()
    events = [
        {
            "event_id": f"ev-{i}",
            "user_principal": "alice@acmecorp.com",
            "timestamp": now_iso,
            "result": "DENIED" if i < 3 else "APPROVED",
            "client_ip": "1.2.3.4",
        }
        for i in range(4)
    ]
    response = client.post("/api/v1/sspm/detect/mfa-fatigue", json=events)
    assert response.status_code == 200
    data = response.json()
    assert len(data) == 1
    assert data[0]["category"] == "MFA_FATIGUE_ATTACK"


def test_api_posture_summary_and_health(client):
    summary_resp = client.get("/api/v1/sspm/posture/summary")
    assert summary_resp.status_code == 200
    assert summary_resp.json()["status"] == "active"

    health_resp = client.get("/api/v1/sspm/health")
    assert health_resp.status_code == 200
    assert health_resp.json()["service"] == "sspm-engine"
