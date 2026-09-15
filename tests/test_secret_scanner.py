"""Tests for CyberShield Enterprise - Autonomous Secret Sprawl & Token Entropy Scanner.
Verifies Shannon entropy evaluation, regex pattern signatures, secret masking,
remediation lifecycle, statistics computation, and REST API endpoints.
"""

import json
import pytest
from starlette.testclient import TestClient

from cybershield.api.server import app
from cybershield.secrets.schemas import (
    SecretType,
    SecretSeverity,
    ScanTextRequest,
    ScanFileRequest,
)
from cybershield.secrets.scanner import SecretEntropyScanner


@pytest.fixture
def client():
    return TestClient(app)


@pytest.fixture
def scanner():
    return SecretEntropyScanner()


# =========================================================================
# Unit Tests: Entropy & Core Heuristics
# =========================================================================

def test_shannon_entropy_calculation(scanner):
    # Zero / minimal entropy on single repeated character
    low_entropy = scanner.calculate_shannon_entropy("aaaaaaaaaaaaaaaaaaaa")
    assert low_entropy == 0.0

    # High entropy on diversified randomized tokens
    high_entropy = scanner.calculate_shannon_entropy("aZ9$mP1#kL8&vX2@qW0!jR7^")
    assert high_entropy > 4.0

    # Empty string safety
    assert scanner.calculate_shannon_entropy("") == 0.0


def test_metric_entropy_and_charset(scanner):
    data_hex = "0123456789abcdef"
    metric = scanner.calculate_metric_entropy(data_hex)
    assert 0.0 <= metric <= 1.0

    assert scanner.classify_charset("1a2b3c4d5e6f") == "hex"
    assert scanner.classify_charset("aGVsbG8gd29ybGQ=") == "base64"
    assert scanner.classify_charset("UserName123") == "alphanumeric"


def test_secret_masking(scanner):
    token = "".join(["AK", "IA", "IOSFODNN7EXAMPLE"])
    masked = scanner.mask_secret(token)
    assert masked.startswith("AKIA")
    assert masked.endswith("MPLE")
    assert "*" in masked
    assert len(masked) == len(token)


# =========================================================================
# Unit Tests: Deterministic & Heuristic Signatures
# =========================================================================

def test_detect_aws_access_key(scanner):
    fake_key = "".join(["AK", "IA", "1234567890ABCDEF"])
    content = f"""
    # AWS production credentials
    aws_access_key_id = {fake_key}
    region = us-east-1
    """
    summary = scanner.scan_text(content, source_label="deploy.env")
    assert summary.findings_count == 1
    assert summary.critical_count == 1
    finding = summary.findings[0]
    assert finding.secret_type == SecretType.AWS_ACCESS_KEY
    assert finding.severity == SecretSeverity.CRITICAL
    assert finding.remediation_playbook == "revoke_aws_iam_key"


def test_detect_github_pat_and_slack_token(scanner):
    fake_ghp = "".join(["gh", "p_", "1234567890abcdefghijklmnopqrstuvwxyzAB"])
    fake_slack = "".join(["xo", "xb-", "123456789012-123456789012-", "abcdefghijklmnopqrstuvwx"])
    content = f"""
    git_token = "{fake_ghp}"
    slack_webhook = "{fake_slack}"
    """
    summary = scanner.scan_text(content, source_label="ci_cd.yml")
    assert summary.findings_count == 2
    types = {f.secret_type for f in summary.findings}
    assert SecretType.GITHUB_TOKEN in types
    assert SecretType.SLACK_TOKEN in types


def test_detect_database_connection_uri(scanner):
    content = 'DATABASE_URL="postgres://admin:SuperSecretPass123@db.internal.corp:5432/payments"'
    summary = scanner.scan_text(content, source_label="database.py")
    assert summary.findings_count == 1
    finding = summary.findings[0]
    assert finding.secret_type == SecretType.DATABASE_CONNECTION_URI
    assert finding.severity == SecretSeverity.CRITICAL
    assert "SuperSecretPass123" not in finding.raw_snippet_masked


def test_detect_ssh_private_key_header(scanner):
    content = """
    -----BEGIN RSA PRIVATE KEY-----
    MIIEowIBAAKCAQEA0mFk3a4jG9...
    -----END RSA PRIVATE KEY-----
    """
    summary = scanner.scan_text(content, source_label="id_rsa")
    assert summary.findings_count >= 1
    assert any(f.secret_type == SecretType.SSH_RSA_PRIVATE_KEY for f in summary.findings)


def test_detect_high_entropy_secret_assignment(scanner):
    # Variable assignment with proximity keyword 'client_secret' and high-entropy value
    content = 'client_secret = "qK9$wL2#vP8@xM1!rT7^bZ0&yN3*hC5%"'
    summary = scanner.scan_text(content, source_label="auth_service.py", entropy_threshold=4.0)
    assert summary.findings_count >= 1
    finding = [f for f in summary.findings if f.secret_type == SecretType.HIGH_ENTROPY_STRING][0]
    assert finding.proximity_keyword == "client_secret"
    assert finding.entropy >= 4.0


def test_remediation_lifecycle_and_statistics(scanner):
    fake_gcp = "".join(["AIza", "SyD-", "1234567890abcdefghijklmnopqrst"])
    content = f'api_key = "{fake_gcp}"'
    summary = scanner.scan_text(content, source_label="gcp.json")
    finding_id = summary.findings[0].finding_id

    stats_before = scanner.get_statistics()
    assert stats_before.unresolved_findings >= 1

    # Remediate
    remediated = scanner.remediate_finding(finding_id)
    assert remediated is not None
    assert remediated.is_remediated is True

    stats_after = scanner.get_statistics()
    assert stats_after.remediated_findings >= 1


# =========================================================================
# Integration Tests: FastAPI REST Endpoints
# =========================================================================

def test_api_scan_inline_text(client):
    fake_stripe = "".join(["sk", "_live_", "123456789012345678901234"])
    req = ScanTextRequest(
        content=f'STRIPE_KEY = "{fake_stripe}"',
        source_label="billing.py",
    )
    resp = client.post(
        "/api/v1/secrets/scan/text",
        json=json.loads(req.model_dump_json()),
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["findings_count"] >= 1
    assert data["critical_count"] >= 1


def test_api_list_findings_and_remediate(client):
    # First inject finding via scan
    fake_aws = "".join(["AK", "IA", "9988776655443322"])
    req = ScanTextRequest(
        content=f'AWS_KEY="{fake_aws}"',
        source_label="config.py",
    )
    scan_resp = client.post("/api/v1/secrets/scan/text", json=json.loads(req.model_dump_json()))
    finding_id = scan_resp.json()["findings"][0]["finding_id"]

    # List findings
    list_resp = client.get("/api/v1/secrets/findings?unresolved_only=true")
    assert list_resp.status_code == 200
    findings = list_resp.json()
    assert any(f["finding_id"] == finding_id for f in findings)

    # Remediate finding
    rem_resp = client.post(f"/api/v1/secrets/remediate/{finding_id}")
    assert rem_resp.status_code == 200
    assert rem_resp.json()["is_remediated"] is True

    # Check stats endpoint
    stats_resp = client.get("/api/v1/secrets/stats")
    assert stats_resp.status_code == 200
    stats = stats_resp.json()
    assert stats["total_findings"] >= 1
    assert stats["remediated_findings"] >= 1
