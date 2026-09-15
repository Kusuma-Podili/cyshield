"""Tests for CyberShield Enterprise - Vulnerability Prioritization & Exploit Prediction (EPSS & VEP).
Verifies EPSS probability forecasting, contextual risk scoring, CISA KEV weaponization matching,
remediation SLA deadlines, fleet triage summaries, and REST API routes.
"""

import json
import pytest
from datetime import datetime, timezone, timedelta
from starlette.testclient import TestClient

from cybershield.api.server import app
from cybershield.vep.schemas import (
    ExploitMaturity,
    RemediationPriority,
    AssetExposure,
    AssetCriticality,
    VulnerabilityContext,
)
from cybershield.vep.prioritizer import VulnerabilityExploitPredictor


@pytest.fixture
def client():
    return TestClient(app)


@pytest.fixture
def predictor():
    return VulnerabilityExploitPredictor()


# =========================================================================
# Unit Tests: EPSS Exploit Forecasting
# =========================================================================

def test_epss_known_cve_lookup(predictor):
    # Log4j weaponized CVE
    res = predictor.predict_epss("CVE-2021-44228")
    assert res.epss_probability > 0.95
    assert res.is_cisa_kev is True
    assert res.known_ransomware_use is True
    assert res.exploit_maturity == ExploitMaturity.RANSOMWARE_CAMPAIGN_WEAPONIZED

    # Ivanti in-the-wild CVE
    res_ivanti = predictor.predict_epss("CVE-2024-21887")
    assert res_ivanti.epss_probability > 0.90
    assert res_ivanti.is_cisa_kev is True


def test_epss_dynamic_regression_unseen_cve(predictor):
    # Uncataloged high-severity CVE
    res = predictor.predict_epss("CVE-2025-99999", cvss_v3=9.8)
    assert 0.0 < res.epss_probability < 1.0
    assert res.epss_percentile > 0.50

    # Low-severity CVE has lower EPSS
    res_low = predictor.predict_epss("CVE-2025-00001", cvss_v3=2.5)
    assert res_low.epss_probability < res.epss_probability


# =========================================================================
# Unit Tests: Contextual Vulnerability Prioritization
# =========================================================================

def test_prioritize_emergency_p0(predictor):
    # Internet-facing portal with CISA KEV Ivanti vulnerability
    ctx = VulnerabilityContext(
        cve_id="CVE-2024-21887",
        asset_id="srv-vpn-01",
        asset_name="Perimeter Gateway",
        cvss_v3_base=9.8,
        asset_exposure=AssetExposure.INTERNET_FACING,
        asset_criticality=AssetCriticality.TIER_1_CORE,
    )
    now = datetime(2026, 9, 12, 12, 0, 0, tzinfo=timezone.utc)
    action = predictor.prioritize_vulnerability(ctx, now=now)

    assert action.remediation_priority == RemediationPriority.P0_EMERGENCY_24H
    assert action.sla_days == 1
    assert action.sla_deadline == now + timedelta(days=1)
    assert action.composite_risk_score >= 80.0
    assert action.is_cisa_kev is True


def test_prioritize_crown_jewel_ransomware_p0(predictor):
    # Domain Controller with Log4Shell (ransomware linked)
    ctx = VulnerabilityContext(
        cve_id="CVE-2021-44228",
        asset_id="dc-01",
        asset_name="Root Domain Controller",
        cvss_v3_base=10.0,
        asset_exposure=AssetExposure.INTERNAL_NETWORK,
        asset_criticality=AssetCriticality.TIER_0_CROWN_JEWEL,
    )
    action = predictor.prioritize_vulnerability(ctx)
    assert action.remediation_priority == RemediationPriority.P0_EMERGENCY_24H
    assert action.known_ransomware_use is True


def test_compensating_controls_risk_reduction(predictor):
    # Same vulnerability with and without compensating controls (e.g. WAF)
    ctx_bare = VulnerabilityContext(
        cve_id="CVE-2024-6387",
        asset_id="srv-web-01",
        asset_name="Web Server",
        cvss_v3_base=8.1,
        asset_exposure=AssetExposure.DMZ_RESTRICTED,
        has_compensating_controls=False,
    )
    ctx_protected = VulnerabilityContext(
        cve_id="CVE-2024-6387",
        asset_id="srv-web-01",
        asset_name="Web Server",
        cvss_v3_base=8.1,
        asset_exposure=AssetExposure.DMZ_RESTRICTED,
        has_compensating_controls=True,
        compensating_controls=["WAF_ModSecurity_CRS", "Microsegmentation"],
    )

    act_bare = predictor.prioritize_vulnerability(ctx_bare)
    act_prot = predictor.prioritize_vulnerability(ctx_protected)

    assert act_prot.composite_risk_score < act_bare.composite_risk_score


# =========================================================================
# Unit Tests: Fleet Triage & Summary
# =========================================================================

def test_fleet_prioritization_and_summary(predictor):
    contexts = [
        VulnerabilityContext(
            cve_id="CVE-2021-44228",
            asset_id="srv-01",
            asset_name="Public Web",
            cvss_v3_base=10.0,
            asset_exposure=AssetExposure.INTERNET_FACING,
            asset_criticality=AssetCriticality.TIER_0_CROWN_JEWEL,
        ),
        VulnerabilityContext(
            cve_id="CVE-2024-6387",
            asset_id="srv-02",
            asset_name="Internal Jump",
            cvss_v3_base=8.1,
            asset_exposure=AssetExposure.INTERNAL_NETWORK,
        ),
        VulnerabilityContext(
            cve_id="CVE-2022-1234",
            asset_id="srv-03",
            asset_name="Airgapped Backup",
            cvss_v3_base=4.0,
            asset_exposure=AssetExposure.AIR_GAPPED,
            asset_criticality=AssetCriticality.TIER_3_NON_PRODUCTION,
        ),
    ]

    actions = [predictor.prioritize_vulnerability(c) for c in contexts]
    summary = predictor.generate_fleet_summary(actions)

    assert summary.total_evaluated == 3
    assert summary.p0_count >= 1
    assert summary.cisa_kev_count >= 1
    assert summary.ransomware_linked_count >= 1
    assert summary.average_epss_probability > 0.0


# =========================================================================
# REST API Integration Tests
# =========================================================================

def test_api_vep_lifecycle(client):
    # 1. Predict EPSS
    resp = client.post("/api/v1/vep/predict?cve_id=CVE-2023-34362&cvss_v3=9.8")
    assert resp.status_code == 200
    epss_data = resp.json()
    assert epss_data["cve_id"] == "CVE-2023-34362"
    assert epss_data["epss_probability"] > 0.90
    assert epss_data["is_cisa_kev"] is True

    # 2. Prioritize Single Vulnerability
    ctx_payload = {
        "cve_id": "CVE-2023-34362",
        "asset_id": "api-srv-corp",
        "asset_name": "Core Enterprise Gateway",
        "cvss_v3_base": 9.8,
        "asset_exposure": "INTERNET_FACING",
        "asset_criticality": "TIER_0_CROWN_JEWEL",
        "has_compensating_controls": False,
        "compensating_controls": [],
    }
    resp = client.post("/api/v1/vep/prioritize", json=ctx_payload)
    assert resp.status_code == 200
    act_data = resp.json()
    assert act_data["remediation_priority"] == "P0_EMERGENCY_24H"
    assert act_data["sla_days"] == 1

    # 3. Batch Fleet Prioritize
    resp = client.post("/api/v1/vep/batch-prioritize", json=[ctx_payload])
    assert resp.status_code == 200
    batch_data = resp.json()
    assert "summary" in batch_data
    assert "ranked_actions" in batch_data
    assert batch_data["summary"]["p0_count"] == 1

    # 4. Get CISA KEV Catalog
    resp = client.get("/api/v1/vep/cisa-kev")
    assert resp.status_code == 200
    kev_list = resp.json()
    assert len(kev_list) >= 4
    assert any(k["cve_id"] == "CVE-2021-44228" for k in kev_list)
