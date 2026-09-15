"""
Unit and Integration Tests for Data Loss Prevention (DLP) Subsystem.
Verifies ISO/IEC 7812 Luhn checksums, PII SSN detection, cloud secret redaction, and REST APIs.
"""

import pytest
from fastapi.testclient import TestClient

from cybershield.api.server import app
from cybershield.dlp.engine import DataLossPreventionEngine
from cybershield.dlp.rules import validate_luhn
from cybershield.dlp.schemas import (
    DLPEnforcementAction,
    DLPInspectRequest,
    SensitiveDataType,
)


@pytest.fixture
def dlp_engine():
    return DataLossPreventionEngine()


@pytest.fixture
def client():
    return TestClient(app)


def test_luhn_algorithm():
    # Valid test numbers
    assert validate_luhn("49927398716") is True
    assert validate_luhn("4111111111111111") is True

    # Invalid test numbers
    assert validate_luhn("49927398717") is False
    assert validate_luhn("1234567812345678") is False


def test_credit_card_detection_and_blocking(dlp_engine):
    sample_text = "Please process the invoice payment using card 4111-1111-1111-1111."
    req = DLPInspectRequest(
        content=sample_text,
        action_if_matched=DLPEnforcementAction.BLOCK,
    )
    result = dlp_engine.inspect_content(req)

    assert result.has_violations is True
    assert result.action_taken == DLPEnforcementAction.BLOCK
    assert result.matches_count == 1
    assert result.matches[0].data_type == SensitiveDataType.CREDIT_CARD_PCI
    assert "1111" in result.matches[0].snippet_masked


def test_ssn_detection(dlp_engine):
    text = "Employee John Doe SSN is 123-45-6789 on the form."
    req = DLPInspectRequest(content=text, action_if_matched=DLPEnforcementAction.ALERT_ONLY)
    result = dlp_engine.inspect_content(req)

    assert result.has_violations is True
    assert result.matches[0].data_type == SensitiveDataType.SSN_PII
    assert "***-**-6789" in result.matches[0].snippet_masked


def test_cloud_secrets_and_private_key_detection(dlp_engine):
    fake_aws = "".join(["AK", "IA", "IOSFODNN7EXAMPLE"])
    fake_ghp = "".join(["gh", "p_", "1234567890abcdefghijklmnopqrstuvwxyz"])
    text = f"""
    AWS_KEY = {fake_aws}
    GITHUB_TOKEN = {fake_ghp}
    -----BEGIN RSA PRIVATE KEY-----
    MIIEowIBAAKCAQEA0Y...
    -----END RSA PRIVATE KEY-----
    """
    req = DLPInspectRequest(content=text, action_if_matched=DLPEnforcementAction.MASK)
    result = dlp_engine.inspect_content(req)

    assert result.has_violations is True
    assert result.action_taken == DLPEnforcementAction.MASK
    assert result.matches_count >= 3
    assert result.sanitized_content is not None
    assert fake_aws not in result.sanitized_content
    assert fake_ghp[:14] not in result.sanitized_content


def test_dlp_mask_text(dlp_engine):
    raw = "Customer card: 4111 1111 1111 1111 and SSN: 987-65-4321."
    masked = dlp_engine.mask_content(raw)

    assert "4111 1111 1111 1111" not in masked
    assert "************1111" in masked
    assert "***-**-4321" in masked


def test_dlp_api_endpoints(client):
    # 1. List rules
    resp = client.get("/api/dlp/rules")
    assert resp.status_code == 200
    rules = resp.json()
    assert len(rules) >= 5

    # 2. Inspect content via API
    fake_aws = "".join(["AK", "IA", "IOSFODNN7EXAMPLE"])
    inspect_payload = {
        "content": f"Secret key leak: {fake_aws} for user",
        "action_if_matched": "BLOCK",
    }
    resp = client.post("/api/dlp/inspect", json=inspect_payload)
    assert resp.status_code == 200
    res_data = resp.json()
    assert res_data["has_violations"] is True
    assert res_data["action_taken"] == "BLOCK"

    # 3. Mask content via API
    mask_payload = {"text": "SSN: 123-45-6789"}
    resp = client.post("/api/dlp/mask", json=mask_payload)
    assert resp.status_code == 200
    assert "***-**-6789" in resp.json()["masked_text"]

    # 4. List incidents
    resp = client.get("/api/dlp/incidents")
    assert resp.status_code == 200
    assert len(resp.json()) >= 1

    # 5. Telemetry stats
    resp = client.get("/api/dlp/stats")
    assert resp.status_code == 200
    stats = resp.json()
    assert stats["total_inspections"] >= 1
    assert stats["blocked_transmissions"] >= 1
