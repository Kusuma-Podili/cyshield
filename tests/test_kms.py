"""
Unit and Integration Tests for Key Management Service (KMS).
Verifies envelope encryption, KEK/DEK wrapping, AES-256-GCM, key rotation, tamper detection, and REST APIs.
"""

import pytest
from fastapi.testclient import TestClient

from cybershield.api.server import app
from cybershield.kms.engine import KeyManagementEngine
from cybershield.kms.schemas import (
    CryptographicAlgorithm,
    EncryptedDataEnvelope,
    KeyType,
)


@pytest.fixture
def kms():
    return KeyManagementEngine()


@pytest.fixture
def client():
    return TestClient(app)


def test_default_key_and_custom_creation(kms):
    keys = kms.list_keys()
    assert len(keys) >= 1
    master = kms.get_key_metadata("master-kek-primary")
    assert master is not None
    assert master.algorithm == CryptographicAlgorithm.AES_256_GCM
    assert master.version == 1

    # Create ChaCha20-Poly1305 key
    chacha_key = kms.create_key(
        alias="kek-chacha20-edge",
        algorithm=CryptographicAlgorithm.CHACHA20_POLY1305,
    )
    assert chacha_key.alias == "kek-chacha20-edge"
    assert chacha_key.version == 1


def test_envelope_encryption_roundtrip(kms):
    secret_payload = "TOP_SECRET_FORENSIC_EVIDENCE_PAYLOAD_12345"
    envelope = kms.encrypt_envelope("master-kek-primary", secret_payload)

    assert envelope.kek_version == 1
    assert envelope.ciphertext_b64 != secret_payload
    assert envelope.encrypted_dek_b64 is not None

    decrypted = kms.decrypt_envelope(envelope)
    assert decrypted == secret_payload


def test_key_rotation_and_backward_compatibility(kms):
    payload_v1 = "Data encrypted prior to annual key rotation"
    envelope_v1 = kms.encrypt_envelope("master-kek-primary", payload_v1)
    assert envelope_v1.kek_version == 1

    # Rotate key to version 2
    rotated_meta = kms.rotate_key("master-kek-primary")
    assert rotated_meta.version == 2

    # Encrypt new data under version 2
    payload_v2 = "Data encrypted with fresh version 2 key material"
    envelope_v2 = kms.encrypt_envelope("master-kek-primary", payload_v2)
    assert envelope_v2.kek_version == 2

    # Both old and new envelopes must decrypt successfully
    assert kms.decrypt_envelope(envelope_v1) == payload_v1
    assert kms.decrypt_envelope(envelope_v2) == payload_v2


def test_cryptographic_tamper_detection(kms):
    secret = "Classified Defense Secret"
    envelope = kms.encrypt_envelope("master-kek-primary", secret)

    # Tamper with ciphertext
    corrupted_dict = envelope.model_dump()
    # Flip characters in ciphertext
    corrupted_dict["ciphertext_b64"] = "AAAA" + corrupted_dict["ciphertext_b64"][4:]
    tampered_envelope = EncryptedDataEnvelope(**corrupted_dict)

    with pytest.raises(Exception):
        kms.decrypt_envelope(tampered_envelope)


def test_kms_api_endpoints(client):
    # 1. List keys
    resp = client.get("/api/kms/keys")
    assert resp.status_code == 200
    assert len(resp.json()) >= 1

    # 2. Encrypt payload via API
    enc_req = {
        "kek_alias_or_id": "master-kek-primary",
        "plaintext": "API_SECRET_DATABASE_CREDENTIAL_99",
    }
    resp = client.post("/api/kms/encrypt", json=enc_req)
    assert resp.status_code == 200
    envelope_data = resp.json()
    assert "ciphertext_b64" in envelope_data

    # 3. Decrypt payload via API
    dec_req = {"envelope": envelope_data}
    resp = client.post("/api/kms/decrypt", json=dec_req)
    assert resp.status_code == 200
    assert resp.json()["plaintext"] == "API_SECRET_DATABASE_CREDENTIAL_99"

    # 4. Rotate key via API
    resp = client.post("/api/kms/keys/master-kek-primary/rotate")
    assert resp.status_code == 200
    assert resp.json()["version"] >= 2

    # 5. Health & audit
    resp = client.get("/api/kms/health")
    assert resp.status_code == 200
    assert resp.json()["status"] == "HEALTHY"
    assert resp.json()["fips_140_3_compliance_ready"] is True
