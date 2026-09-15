"""Tests for CyberShield Enterprise - Identity Governance & Administration (IGA).
Verifies entitlement management, privilege creep scoring, cross-department role residue,
Separation of Duties (SoD) toxic combination detection, and access certification campaigns.
"""

import json
import pytest
from datetime import datetime, timezone, timedelta
from starlette.testclient import TestClient

from cybershield.api.server import app
from cybershield.iga.schemas import (
    EntitlementType,
    AccountStatus,
    IdentityAccount,
    Entitlement,
    SoDRule,
    CertificationDecisionType,
)
from cybershield.iga.governance import IdentityGovernanceEngine


@pytest.fixture
def client():
    return TestClient(app)


@pytest.fixture
def iga_engine():
    engine = IdentityGovernanceEngine()

    # Seed identities
    alice = IdentityAccount(
        identity_id="emp-alice-01",
        username="ajenkins",
        email="alice.jenkins@enterprise.internal",
        department="Engineering",
        job_title="Senior Platform Engineer",
        manager_id="emp-cto-00",
        past_departments=["QA", "DevOps"],
        last_active_at=datetime.now(timezone.utc),
    )
    bob = IdentityAccount(
        identity_id="emp-bob-02",
        username="bmarley",
        email="bob.marley@enterprise.internal",
        department="Finance",
        job_title="Financial Analyst",
        manager_id="emp-cfo-00",
        past_departments=[],
        last_active_at=datetime.now(timezone.utc) - timedelta(days=120),  # Dormant
    )
    orphan_user = IdentityAccount(
        identity_id="emp-orphan-03",
        username="legacy_bot",
        email="legacy@enterprise.internal",
        department="IT",
        job_title="Script Runner",
        manager_id=None,  # Orphan!
        is_service_account=False,
    )
    engine.add_identity(alice)
    engine.add_identity(bob)
    engine.add_identity(orphan_user)

    # Seed Entitlements
    e1 = Entitlement(
        entitlement_id="ent-git-prod",
        name="GitHub Prod Admin",
        entitlement_type=EntitlementType.ROLE,
        resource="github.com/org",
        department_affinity="Engineering",
        risk_weight=8,
        is_privileged=True,
    )
    e2 = Entitlement(
        entitlement_id="ent-qa-jenkins",
        name="Legacy QA Jenkins Runner",
        entitlement_type=EntitlementType.PERMISSION,
        resource="jenkins.internal/qa",
        department_affinity="QA",  # Cross-dept for Engineering Alice!
        risk_weight=3,
        is_privileged=False,
    )
    e3 = Entitlement(
        entitlement_id="ent-fin-vendor-creator",
        name="AP Vendor Creation",
        entitlement_type=EntitlementType.ROLE,
        resource="sap.erp/vendor",
        department_affinity="Finance",
        risk_weight=6,
        is_privileged=False,
    )
    e4 = Entitlement(
        entitlement_id="ent-fin-payment-releaser",
        name="AP Wire Payment Release",
        entitlement_type=EntitlementType.ROLE,
        resource="sap.erp/payments",
        department_affinity="Finance",
        risk_weight=9,
        is_privileged=True,
    )
    engine.add_entitlement(e1)
    engine.add_entitlement(e2)
    engine.add_entitlement(e3)
    engine.add_entitlement(e4)

    return engine


# =========================================================================
# Unit Tests: Privilege Creep Scoring
# =========================================================================

def test_privilege_creep_minimal_baseline(iga_engine):
    # Grant normal single engineering entitlement to Alice
    iga_engine.assign_entitlement(
        identity_id="emp-alice-01",
        entitlement_id="ent-git-prod",
        justification="Standard DevOps duty",
    )
    metrics = iga_engine.calculate_privilege_creep("emp-alice-01")
    assert metrics.total_entitlements == 1
    assert metrics.privileged_count == 1
    assert metrics.stale_entitlements_count == 0
    assert metrics.cross_department_count == 0
    assert metrics.creep_score < 25.0
    assert metrics.risk_level == "LOW"


def test_privilege_creep_cross_dept_and_stale(iga_engine):
    # Grant multiple entitlements including leftover QA role and stale usage
    now = datetime.now(timezone.utc)
    old_time = now - timedelta(days=150)

    iga_engine.assign_entitlement(
        identity_id="emp-alice-01",
        entitlement_id="ent-git-prod",
        last_used_at=old_time,  # Stale & privileged!
    )
    iga_engine.assign_entitlement(
        identity_id="emp-alice-01",
        entitlement_id="ent-qa-jenkins",  # Cross-department residue!
        last_used_at=old_time,  # Stale!
    )
    iga_engine.assign_entitlement(
        identity_id="emp-alice-01",
        entitlement_id="ent-fin-payment-releaser",  # Another cross-dept + privileged!
        last_used_at=old_time,
    )

    metrics = iga_engine.calculate_privilege_creep("emp-alice-01", now=now)
    assert metrics.total_entitlements == 3
    assert metrics.privileged_count == 2
    assert metrics.stale_entitlements_count == 3
    assert metrics.cross_department_count == 2
    assert metrics.creep_score >= 75.0
    assert metrics.risk_level == "CRITICAL"
    assert "ent-qa-jenkins" in metrics.recommended_pruning
    assert "ent-git-prod" in metrics.recommended_pruning


# =========================================================================
# Unit Tests: Separation of Duties (SoD) Toxic Conflicts
# =========================================================================

def test_sod_conflict_detection(iga_engine):
    # Bob gets both vendor creator AND payment releaser -> classic SOX violation!
    iga_engine.assign_entitlement("emp-bob-02", "ent-fin-vendor-creator")
    iga_engine.assign_entitlement("emp-bob-02", "ent-fin-payment-releaser")

    conflicts = iga_engine.scan_sod_conflicts("emp-bob-02")
    assert len(conflicts) == 1
    report = conflicts[0]
    assert report.rule_id == "sod-fin-001"
    assert report.severity == "CRITICAL"
    assert "SOX_404" in report.regulatory_impact
    assert "ent-fin-vendor-creator" in report.conflicting_entitlements
    assert "ent-fin-payment-releaser" in report.conflicting_entitlements


def test_sod_no_conflict_when_single_role(iga_engine):
    # Bob only gets vendor creator -> no SoD conflict
    iga_engine.assign_entitlement("emp-bob-02", "ent-fin-vendor-creator")
    conflicts = iga_engine.scan_sod_conflicts("emp-bob-02")
    assert len(conflicts) == 0


# =========================================================================
# Unit Tests: Dormant & Orphan Discovery
# =========================================================================

def test_dormant_and_orphan_discovery(iga_engine):
    results = iga_engine.find_dormant_and_orphan_accounts(days_inactive=90)
    dormant_ids = [d.identity_id for d in results["dormant_accounts"]]
    orphan_ids = [o.identity_id for o in results["orphan_accounts"]]

    assert "emp-bob-02" in dormant_ids
    assert "emp-orphan-03" in orphan_ids


# =========================================================================
# Unit Tests: Access Certification Campaign & Revocation
# =========================================================================

def test_certification_campaign_and_revocation(iga_engine):
    asgn = iga_engine.assign_entitlement("emp-alice-01", "ent-qa-jenkins")
    assert asgn.assignment_id in iga_engine.assignments

    campaign = iga_engine.create_campaign("Q3 Engineering Access Audit", reviewer_id="mgr-100")
    assert campaign.status.value == "IN_PROGRESS"

    # Reviewer decides to REVOKE this stale role
    decision = iga_engine.submit_certification_decision(
        campaign_id=campaign.campaign_id,
        identity_id="emp-alice-01",
        entitlement_id="ent-qa-jenkins",
        decision=CertificationDecisionType.REVOKE,
        reviewer_notes="Employee transferred from QA 8 months ago. Deprecate.",
    )

    assert decision.decision == CertificationDecisionType.REVOKE
    # Verify assignment was automatically unlinked
    assert asgn.assignment_id not in iga_engine.assignments
    assert asgn.assignment_id not in iga_engine.identity_assignments["emp-alice-01"]


# =========================================================================
# REST API Integration Tests
# =========================================================================

def test_api_iga_lifecycle(client):
    # 1. Create Identity
    identity_payload = {
        "identity_id": "api-emp-55",
        "username": "charlie_audit",
        "email": "charlie@enterprise.internal",
        "department": "Security",
        "job_title": "SOC Lead",
        "manager_id": "api-emp-01",
        "is_service_account": False,
        "status": "ACTIVE",
    }
    resp = client.post("/api/v1/iga/identities", json=identity_payload)
    assert resp.status_code == 201
    assert resp.json()["username"] == "charlie_audit"

    # 2. Register Entitlement
    ent_payload = {
        "entitlement_id": "api-ent-vault-admin",
        "name": "Audit Vault Administrator",
        "entitlement_type": "ROLE",
        "resource": "vault.cybershield.internal",
        "department_affinity": "Security",
        "risk_weight": 9,
        "is_privileged": True,
    }
    resp = client.post("/api/v1/iga/entitlements", json=ent_payload)
    assert resp.status_code == 201
    assert resp.json()["entitlement_id"] == "api-ent-vault-admin"

    # 3. Assign Entitlement
    resp = client.post("/api/v1/iga/assign?identity_id=api-emp-55&entitlement_id=api-ent-vault-admin&justification=SOC_Lead_Role")
    assert resp.status_code == 201
    assert resp.json()["identity_id"] == "api-emp-55"

    # 4. Get Privilege Creep
    resp = client.get("/api/v1/iga/creep/api-emp-55")
    assert resp.status_code == 200
    creep_data = resp.json()
    assert creep_data["total_entitlements"] == 1
    assert creep_data["privileged_count"] == 1

    # 5. Creep Leaderboard
    resp = client.get("/api/v1/iga/creep-leaderboard")
    assert resp.status_code == 200
    assert isinstance(resp.json(), list)

    # 6. Define SoD Rule
    sod_payload = {
        "rule_id": "sod-api-test",
        "name": "API Test Rule",
        "description": "Rule for testing API",
        "conflicting_entitlement_ids": ["api-ent-vault-admin", "api-ent-rogue"],
        "severity": "HIGH",
        "regulatory_mapping": ["SOC2"],
    }
    resp = client.post("/api/v1/iga/sod/rules", json=sod_payload)
    assert resp.status_code == 201
    assert resp.json()["rule_id"] == "sod-api-test"

    # 7. Scan SoD Conflicts
    resp = client.get("/api/v1/iga/sod/conflicts")
    assert resp.status_code == 200
    assert isinstance(resp.json(), list)

    # 8. Dormant & Orphan Accounts
    resp = client.get("/api/v1/iga/dormant?days_inactive=90")
    assert resp.status_code == 200
    dormant_data = resp.json()
    assert "dormant_accounts" in dormant_data
    assert "orphan_accounts" in dormant_data

    # 9. Create Campaign & Certify
    resp = client.post("/api/v1/iga/campaigns?title=Annual_Access_Review&reviewer_id=mgr-55")
    assert resp.status_code == 201
    cid = resp.json()["campaign_id"]

    resp = client.post(f"/api/v1/iga/campaigns/{cid}/certify?identity_id=api-emp-55&entitlement_id=api-ent-vault-admin&decision=APPROVE")
    assert resp.status_code == 200
    assert resp.json()["decision"] == "APPROVE"
