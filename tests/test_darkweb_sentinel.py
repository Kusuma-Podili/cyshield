"""Tests for CyberShield Enterprise - Autonomous Dark Web & Leaked Credential Sentinel.
Verifies breach dump ingestion, k-anonymity hash prefix lookups, corporate domain alerts,
and FastAPI REST endpoints.
"""

import hashlib
import json
from datetime import datetime, timezone
import pytest
from starlette.testclient import TestClient

from cybershield.api.server import app
from cybershield.darkweb.schemas import (
    BreachSourceType,
    CredentialExposureSeverity,
    IngestBreachRecordRequest,
    HashPrefixLookupRequest,
    CorporateEmailCheckRequest,
)
from cybershield.darkweb.sentinel import DarkWebCredentialSentinel


@pytest.fixture
def client():
    return TestClient(app)


@pytest.fixture
def sentinel():
    return DarkWebCredentialSentinel(monitored_domains={"corp.enterprise.local", "enterprise.local"})


# =========================================================================
# Unit Tests: Dark Web Ingestion & Exposure Detection
# =========================================================================

def test_ingest_corporate_plaintext_and_cookie_breach(sentinel):
    req = IngestBreachRecordRequest(
        email="cfo@corp.enterprise.local",
        password_hash="5e884898da28047151d0e56f8dc6292773603d0d6aabbdd62a11ef721d1542d8",
        plaintext_password="Summer2025_Secret!",
        source_breach_name="LummaStealer-Executive-Dump",
        source_type=BreachSourceType.INFOSTEALER_LOG,
        has_active_session_cookie=True,
    )

    alert = sentinel.ingest_breach_record(req)
    assert alert is not None
    assert alert.severity == CredentialExposureSeverity.CRITICAL
    assert alert.email == "cfo@corp.enterprise.local"
    assert alert.plaintext_exposed is True
    assert "IMMEDIATE_SESSION_TERMINATION" in alert.recommended_action
    assert len(sentinel.alerts) == 1


def test_ingest_external_email_no_corporate_alert(sentinel):
    req = IngestBreachRecordRequest(
        email="personal_user@gmail.com",
        password_hash="112233445566778899aabbccddeeff0011223344",
        plaintext_password="myPassword123",
        source_breach_name="PublicForumLeak",
        source_type=BreachSourceType.DATABASE_DUMP,
    )

    alert = sentinel.ingest_breach_record(req)
    assert alert is None  # Not a corporate domain, no alert
    assert "personal_user@gmail.com" in sentinel.email_exposures


def test_k_anonymity_hash_prefix_lookup(sentinel):
    password = "Password123!"
    full_hash = hashlib.sha256(password.encode("utf-8")).hexdigest().upper()
    prefix = full_hash[:5]
    suffix = full_hash[5:]

    req = HashPrefixLookupRequest(hash_prefix=prefix)
    resp = sentinel.lookup_hash_prefix(req)

    assert resp.hash_prefix == prefix
    assert resp.matching_suffixes_count >= 1
    # Check that our suffix is in the returned list
    matching_s = [m for m in resp.matches if m.hash_suffix == suffix]
    assert len(matching_s) == 1
    assert matching_s[0].prevalence_count > 0


def test_k_anonymity_non_existent_prefix(sentinel):
    req = HashPrefixLookupRequest(hash_prefix="FFFFF")
    resp = sentinel.lookup_hash_prefix(req)
    assert resp.matching_suffixes_count == 0
    assert len(resp.matches) == 0


def test_check_corporate_email_history(sentinel):
    email = "it_admin@enterprise.local"
    sentinel.ingest_breach_record(
        IngestBreachRecordRequest(
            email=email,
            password_hash="abcd1234efgh5678",
            hash_algorithm="MD5",
            source_breach_name="ComboList2026",
            source_type=BreachSourceType.UNDERGROUND_FORUM,
        )
    )

    exposures = sentinel.check_corporate_email(email)
    assert len(exposures) == 1
    assert exposures[0].email == email
    assert exposures[0].severity == CredentialExposureSeverity.HIGH


# =========================================================================
# Integration Tests: FastAPI REST Endpoints
# =========================================================================

def test_api_ingest_and_check_email(client):
    breach_req = {
        "email": "lead_dev@corp.enterprise.local",
        "password_hash": "a" * 64,
        "plaintext_password": "devPassword999!",
        "source_breach_name": "RedLine-DevDump",
        "source_type": "INFOSTEALER_LOG",
        "has_active_session_cookie": True,
    }

    ingest_resp = client.post("/api/v1/darkweb/ingest/breach", json=breach_req)
    assert ingest_resp.status_code == 201
    assert ingest_resp.json()["is_corporate_compromise"] is True

    # Check email endpoint
    email_check_resp = client.post(
        "/api/v1/darkweb/check/email",
        json={"email": "lead_dev@corp.enterprise.local"},
    )
    assert email_check_resp.status_code == 200
    alerts = email_check_resp.json()
    assert len(alerts) >= 1
    assert alerts[0]["plaintext_exposed"] is True


def test_api_hash_prefix_lookup_and_status(client):
    # Query prefix for Password123!
    known_hash = hashlib.sha256("Password123!".encode("utf-8")).hexdigest().upper()
    prefix = known_hash[:5]
    prefix_req = {"hash_prefix": prefix}
    resp = client.post("/api/v1/darkweb/check/hash/prefix", json=prefix_req)
    assert resp.status_code == 200
    data = resp.json()
    assert data["hash_prefix"] == prefix
    assert data["matching_suffixes_count"] >= 1

    # Check /status endpoint
    status_resp = client.get("/api/v1/darkweb/status")
    assert status_resp.status_code == 200
    stats = status_resp.json()
    assert stats["total_breached_credentials_cataloged"] >= 1
