"""
CyberShield Enterprise - Vulnerability Management Automated Test Suite
Validates FIRST CVSS v3.1 mathematical scoring, vector string parsing,
automated asset vulnerability scans, patch priority calculations, and remediation lifecycles.
"""

import pytest
import pytest_asyncio
from httpx import AsyncClient, ASGITransport
from datetime import datetime

from cybershield.api.server import app
from cybershield.database.session import async_session_factory, init_db
from cybershield.database.models.user import User, UserRole
from cybershield.auth.security import create_access_token
from cybershield.vulnerabilities.cvss import CVSSv31Engine
from cybershield.vulnerabilities.service import vulnerability_service
from cybershield.database.models.vulnerabilities import (
    VulnerabilityModel,
    AssetVulnerabilityModel,
    VulnerabilitySeverity,
    VulnerabilityStatus,
)
from cybershield.database.models.network import NetworkDevice, DeviceStatus


@pytest_asyncio.fixture(autouse=True)
async def ensure_db():
    """Ensure database schema is initialized and seeded."""
    await init_db()
    async with async_session_factory() as session:
        await vulnerability_service.seed_default_vulnerabilities(session)


@pytest_asyncio.fixture
async def client():
    """Create async test client."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://testserver") as ac:
        yield ac


@pytest_asyncio.fixture
async def admin_token(client: AsyncClient):
    """Authenticate as superadmin or generate authorized JWT."""
    login_resp = await client.post("/api/auth/login", json={
        "username_or_email": "superadmin",
        "password": "CyberShield2026!"
    })
    if login_resp.status_code == 200:
        return login_resp.json()["access_token"]
    return create_access_token(
        data={"sub": "1", "username": "superadmin", "role": UserRole.SUPER_ADMIN.value, "user_id": 1}
    )


def test_cvss_v31_scoring_mathematics():
    """Verify FIRST CVSS v3.1 scoring formulas match specification benchmarks."""
    # Benchmark 1: Critical RCE (Log4j style)
    # AV:N / AC:L / PR:N / UI:N / S:C / C:H / I:H / A:H -> 10.0
    res_crit = CVSSv31Engine.calculate_scores(
        av="NETWORK", ac="LOW", pr="NONE", ui="NONE",
        scope="CHANGED", conf="HIGH", integ="HIGH", avail="HIGH"
    )
    assert res_crit["base_score"] == 10.0
    assert res_crit["severity"] == "CRITICAL"
    assert "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H" in res_crit["vector_string"]

    # Benchmark 2: EternalBlue (SMBv1 RCE)
    # AV:N / AC:L / PR:N / UI:N / S:U / C:H / I:H / A:H -> 9.8
    res_eb = CVSSv31Engine.calculate_scores(
        av="NETWORK", ac="LOW", pr="NONE", ui="NONE",
        scope="UNCHANGED", conf="HIGH", integ="HIGH", avail="HIGH"
    )
    assert res_eb["base_score"] == 9.8
    assert res_eb["severity"] == "CRITICAL"

    # Benchmark 3: Information Disclosure with Temporal Fix
    # AV:N / AC:L / PR:N / UI:N / S:U / C:H / I:N / A:N -> Base 7.5, with Official Fix (0.95) -> 7.2
    res_temp = CVSSv31Engine.calculate_scores(
        av="NETWORK", ac="LOW", pr="NONE", ui="NONE",
        scope="UNCHANGED", conf="HIGH", integ="NONE", avail="NONE",
        rl="OFFICIAL_FIX"
    )
    assert res_temp["base_score"] == 7.5
    assert res_temp["temporal_score"] <= 7.2
    assert "RL:O" in res_temp["vector_string"]


def test_cvss_vector_string_parser():
    """Verify parsing existing CVSS vector strings."""
    parsed = CVSSv31Engine.parse_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
    assert parsed["base_score"] == 9.8
    assert parsed["severity"] == "CRITICAL"


@pytest.mark.asyncio
async def test_vulnerability_catalog_listing_and_kpis(client: AsyncClient, admin_token: str):
    """Verify seeded CVE catalog records and KPI aggregation via REST API."""
    headers = {"Authorization": f"Bearer {admin_token}"}

    # 1. Fetch catalog
    res = await client.get("/api/vulnerabilities", headers=headers)
    assert res.status_code == 200
    data = res.json()
    assert "items" in data
    assert data["total"] >= 5
    cve_ids = {c["cve_id"] for c in data["items"]}
    assert "CVE-2024-3094" in cve_ids
    assert "CVE-2021-44228" in cve_ids

    # 2. Fetch KPIs
    kpi_res = await client.get("/api/vulnerabilities/kpis", headers=headers)
    assert kpi_res.status_code == 200
    kpis = kpi_res.json()
    assert kpis["total_cves"] >= 5
    assert kpis["critical_cves"] >= 3
    assert "compliance_breakdown" in kpis
    assert kpis["compliance_breakdown"]["PCI-DSS"] > 0


@pytest.mark.asyncio
async def test_asset_vulnerability_scan_and_priority_scoring(client: AsyncClient, admin_token: str):
    """Verify automated asset vulnerability scanner binds CVEs and computes patch priorities."""
    headers = {"Authorization": f"Bearer {admin_token}"}

    # 1. Register a test target machine with SMB port 445 open
    target_id = "dev-scan-test-01"
    async with async_session_factory() as session:
        # Clean up if existed
        from sqlalchemy import delete
        await session.execute(delete(AssetVulnerabilityModel).where(AssetVulnerabilityModel.device_id == target_id))
        await session.execute(delete(NetworkDevice).where(NetworkDevice.id == target_id))
        await session.commit()

        dev = NetworkDevice(
            id=target_id,
            hostname="finance-smb-01.corp",
            ip_address="10.0.20.55",
            mac_address="00:50:56:C0:00:55",
            device_type="SERVER",
            status=DeviceStatus.ONLINE.value,
            os_family="WINDOWS",
            open_ports=[445, 139, 80],
            is_critical_asset=True,
            risk_score=75.0,
            created_at=datetime.utcnow(),
            updated_at=datetime.utcnow(),
        )
        session.add(dev)
        await session.commit()

    # 2. Trigger scan on this device
    scan_res = await client.post("/api/vulnerabilities/scan", json={"device_id": target_id}, headers=headers)
    assert scan_res.status_code == 200
    scan_data = scan_res.json()
    assert scan_data["scanned_devices"] == 1
    assert scan_data["findings_generated"] >= 1

    # 3. Query asset vulnerabilities
    asset_vulns_res = await client.get(f"/api/vulnerabilities/assets?device_id={target_id}", headers=headers)
    assert asset_vulns_res.status_code == 200
    findings = asset_vulns_res.json()["items"]
    assert len(findings) >= 1
    finding = findings[0]
    assert finding["device_id"] == target_id
    assert finding["patch_priority_score"] >= 70.0
    assert finding["status"] == "DISCOVERED"


@pytest.mark.asyncio
async def test_vulnerability_remediation_lifecycle(client: AsyncClient, admin_token: str):
    """Test transitioning asset vulnerability through IN_REMEDIATION to CLOSED."""
    headers = {"Authorization": f"Bearer {admin_token}"}

    # Fetch any asset vulnerability
    list_res = await client.get("/api/vulnerabilities/assets?page_size=1", headers=headers)
    items = list_res.json()["items"]
    assert len(items) > 0
    binding_id = items[0]["id"]

    # Transition to IN_REMEDIATION
    patch_res = await client.patch(
        f"/api/vulnerabilities/assets/{binding_id}/status",
        json={"status": "IN_REMEDIATION", "analyst_notes": "Patch KB500123 queued via WSUS deployment."},
        headers=headers
    )
    assert patch_res.status_code == 200
    assert patch_res.json()["status"] == "IN_REMEDIATION"

    # Transition to CLOSED
    close_res = await client.patch(
        f"/api/vulnerabilities/assets/{binding_id}/status",
        json={"status": "CLOSED", "analyst_notes": "Vulnerability verified remediated post-patch reboot."},
        headers=headers
    )
    assert close_res.status_code == 200
    assert close_res.json()["status"] == "CLOSED"
    assert close_res.json()["remediated_at"] is not None


def test_cwe_knowledge_base():
    """Verify offline CWE taxonomy lookup, search, and category filtering."""
    from cybershield.vulnerabilities.cwe_kb import CWEKnowledgeBase, CWECategory

    cwe_89 = CWEKnowledgeBase.get("CWE-89")
    assert cwe_89 is not None
    assert "SQL" in cwe_89.name
    assert cwe_89.category == CWECategory.INJECTION
    assert len(cwe_89.mitigations) >= 2

    # Search
    results = CWEKnowledgeBase.search("parameterized")
    assert len(results) >= 1
    assert any(c.cwe_id == "CWE-89" for c in results)

    # Category filter
    mem_cwes = CWEKnowledgeBase.get_by_category(CWECategory.MEMORY_SAFETY)
    assert len(mem_cwes) >= 2


def test_cpe_version_matching():
    """Verify CPE 2.3 formatted string parsing and semver range comparison."""
    from cybershield.vulnerabilities.cpe_matcher import CPEMatcher, VersionComparator

    # Version comparison
    assert VersionComparator.compare("2.14.1", "2.15.0") == -1
    assert VersionComparator.compare("5.4.0", "5.4.0") == 0
    assert VersionComparator.compare("10.0.1", "9.9.9") == 1

    # Range constraint satisfaction
    assert VersionComparator.satisfies_constraint("2.14.1", ">= 2.0.0, <= 2.14.1") is True
    assert VersionComparator.satisfies_constraint("2.15.0", ">= 2.0.0, <= 2.14.1") is False
    assert VersionComparator.satisfies_constraint("1.0.1f", ">= 1.0.1, <= 1.0.1f") is True

    # CPE matching
    log4j_cpe = "cpe:2.3:a:apache:log4j:*:*:*:*:*:*:*:*"
    assert CPEMatcher.is_match(
        pkg_vendor="apache",
        pkg_product="log4j",
        installed_version="2.14.1",
        target_cpe_str=log4j_cpe,
        affected_version_range="<= 2.14.1",
    ) is True


def test_epss_offline_scoring():
    """Verify EPSS ground truth lookup and empirical regression calculation."""
    from cybershield.vulnerabilities.epss import EPSSCalculator

    # Landmark CVE lookup
    log4j_epss = EPSSCalculator.calculate_epss("CVE-2021-44228")
    assert log4j_epss.epss_score > 0.90
    assert log4j_epss.percentile > 99.0
    assert log4j_epss.is_actively_exploited is True

    # Unknown CVE regression estimation
    custom_epss = EPSSCalculator.calculate_epss(
        cve_id="CVE-2026-99999",
        cvss_base_score=9.8,
        attack_vector="NETWORK",
        user_interaction="NONE",
        privileges_required="NONE",
        has_public_exploit=True,
    )
    assert custom_epss.epss_score > 0.05
    assert custom_epss.percentile > 50.0


def test_offline_cve_catalog_search():
    """Verify querying offline CVE repository for installed package."""
    from cybershield.vulnerabilities.offline_cve_db import OfflineCVEDatabase

    vulns = OfflineCVEDatabase.find_vulnerabilities_for_package(
        vendor="apache",
        product="log4j",
        version="2.14.0",
    )
    assert len(vulns) >= 1
    assert any(v.cve_id == "CVE-2021-44228" for v in vulns)


def test_sbom_cyclonedx_vulnerability_correlation():
    """Verify SBOM analyzer detects vulnerable components and correlates CVEs."""
    from cybershield.vulnerabilities.sbom_analyzer import SBOMAnalyzer

    sample_cyclonedx = """{
      "bomFormat": "CycloneDX",
      "specVersion": "1.4",
      "version": 1,
      "components": [
        {
          "type": "library",
          "name": "log4j",
          "version": "2.14.1",
          "group": "org.apache.logging.log4j",
          "purl": "pkg:maven/org.apache.logging.log4j/log4j@2.14.1"
        },
        {
          "type": "library",
          "name": "secure-lib",
          "version": "1.0.0"
        }
      ]
    }"""
    report = SBOMAnalyzer.scan_sbom(sample_cyclonedx)
    assert report.total_components == 2
    assert report.vulnerable_components_count == 1
    assert report.critical_cves >= 1
    assert any(f.cve_id == "CVE-2021-44228" for f in report.findings)


@pytest.mark.asyncio
async def test_api_vulnerabilities_cwe_epss_sbom_endpoints(client: AsyncClient, admin_token: str):
    """Verify REST API endpoints for CWE, EPSS, SBOM, and Offline Catalog."""
    headers = {"Authorization": f"Bearer {admin_token}"}

    # 1. CWE Catalog
    res_cwe = await client.get("/api/vulnerabilities/cwe/catalog", headers=headers)
    assert res_cwe.status_code == 200
    assert len(res_cwe.json()) >= 10

    # 2. CWE Detail
    res_cwe_detail = await client.get("/api/vulnerabilities/cwe/CWE-79", headers=headers)
    assert res_cwe_detail.status_code == 200
    assert "Cross-site Scripting" in res_cwe_detail.json()["name"]

    # 3. EPSS Calculation
    res_epss = await client.post(
        "/api/vulnerabilities/epss/calculate",
        json={"cve_id": "CVE-2021-44228"},
        headers=headers,
    )
    assert res_epss.status_code == 200
    assert res_epss.json()["epss_score"] > 0.9

    # 4. SBOM Scan
    sample_spdx = """{
      "spdxVersion": "SPDX-2.3",
      "packages": [
        {
          "name": "log4j",
          "versionInfo": "2.14.1",
          "supplier": "Organization: apache"
        }
      ]
    }"""
    res_sbom = await client.post(
        "/api/vulnerabilities/sbom/scan",
        json={"sbom_raw": sample_spdx},
        headers=headers,
    )
    assert res_sbom.status_code == 200
    assert res_sbom.json()["vulnerable_components_count"] >= 1

    # 5. Offline Catalog
    res_offline = await client.get("/api/vulnerabilities/offline/catalog?is_kev_only=true", headers=headers)
    assert res_offline.status_code == 200
    assert len(res_offline.json()) >= 5

