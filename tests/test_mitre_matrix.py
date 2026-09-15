"""Unit & Integration Tests for MITRE ATT&CK & D3FEND Enterprise Matrix Subsystem."""

import pytest
import pytest_asyncio
from httpx import AsyncClient, ASGITransport

from cybershield.api.server import app
from cybershield.mitre.d3fend import D3FENDKnowledgeBase
from cybershield.mitre.engine import mitre_engine


def test_mitre_tactics_list():
    """Verify all 14 MITRE Enterprise tactics exist."""
    tactics = mitre_engine.get_tactics()
    assert len(tactics) == 14
    tactic_ids = [t["id"] for t in tactics]
    assert "TA0001" in tactic_ids  # Initial Access
    assert "TA0002" in tactic_ids  # Execution
    assert "TA0003" in tactic_ids  # Persistence
    assert "TA0004" in tactic_ids  # Privilege Escalation
    assert "TA0005" in tactic_ids  # Defense Evasion
    assert "TA0006" in tactic_ids  # Credential Access
    assert "TA0040" in tactic_ids  # Impact


def test_mitre_technique_lookup_and_subtechniques():
    """Verify technique retrieval with sub-techniques and D3FEND mappings."""
    tech = mitre_engine.get_technique("T1059")
    assert tech is not None
    assert tech.name == "Command and Scripting Interpreter"
    assert tech.tactic == "Execution"
    assert len(tech.sub_techniques) >= 2
    sub_ids = [s.id for s in tech.sub_techniques]
    assert "T1059.001" in sub_ids
    assert "T1059.004" in sub_ids
    assert len(tech.d3fend_countermeasures) >= 2
    d3_ids = [d.d3fend_id for d in tech.d3fend_countermeasures]
    assert "D3-PSA" in d3_ids

    # Search by sub-technique ID
    parent = mitre_engine.get_technique("T1059.001")
    assert parent is not None
    assert parent.id == "T1059"


def test_mitre_technique_search():
    """Verify full-text and platform filtering."""
    # Search by platform
    container_techs = mitre_engine.search_techniques(platform="Containers")
    assert len(container_techs) >= 1
    assert any(t.id == "T1611" for t in container_techs)

    # Search by keyword
    kerb_techs = mitre_engine.search_techniques(query="Kerberos")
    assert len(kerb_techs) >= 1
    assert any(t.id == "T1558" for t in kerb_techs)


def test_mitre_d3fend_catalog():
    """Verify D3FEND catalog and tactic filtering."""
    all_d3 = D3FENDKnowledgeBase.list_all()
    assert len(all_d3) >= 8

    harden_d3 = D3FENDKnowledgeBase.get_by_tactic("Harden")
    assert len(harden_d3) >= 2
    assert any(d.d3fend_id == "D3-ITF" for d in harden_d3)

    detail = D3FENDKnowledgeBase.get("D3-LSA")
    assert detail is not None
    assert "LSASS" in detail.description or "Local Security Authority" in detail.name


def test_mitre_dynamic_coverage_report():
    """Verify calculation of coverage heatmap and defensive gap recommendations."""
    report = mitre_engine.generate_coverage_report()
    assert report.total_enterprise_techniques >= 15
    assert report.covered_techniques >= 5
    assert report.overall_coverage_percentage > 20.0
    assert len(report.tactic_heatmaps) == 14
    assert len(report.recommended_d3fend_countermeasures) >= 1


@pytest.mark.asyncio
async def test_mitre_api_endpoints():
    """Verify REST API endpoints for tactics, techniques, coverage, and D3FEND."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        # 1. Login
        login_resp = await ac.post(
            "/api/auth/login",
            json={"username_or_email": "superadmin", "password": "CyberShield2026!"},
        )
        assert login_resp.status_code == 200
        token = login_resp.json()["access_token"]
        headers = {"Authorization": f"Bearer {token}"}

        # 2. List Tactics
        resp_tactics = await ac.get("/api/mitre/tactics", headers=headers)
        assert resp_tactics.status_code == 200
        assert len(resp_tactics.json()) == 14

        # 3. Search Techniques
        resp_tech = await ac.get("/api/mitre/techniques?platform=Windows", headers=headers)
        assert resp_tech.status_code == 200
        techs = resp_tech.json()
        assert len(techs) >= 5

        # 4. Coverage Report
        resp_cov = await ac.get("/api/mitre/coverage", headers=headers)
        assert resp_cov.status_code == 200
        cov_data = resp_cov.json()
        assert "overall_coverage_percentage" in cov_data
        assert len(cov_data["tactic_heatmaps"]) == 14

        # 5. D3FEND Catalog
        resp_d3 = await ac.get("/api/mitre/d3fend", headers=headers)
        assert resp_d3.status_code == 200
        assert len(resp_d3.json()) >= 8

        # 6. Specific Technique Detail
        resp_det = await ac.get("/api/mitre/techniques/T1003", headers=headers)
        assert resp_det.status_code == 200
        assert resp_det.json()["name"] == "OS Credential Dumping"
