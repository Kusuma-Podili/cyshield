"""
Cryptographic Key Management Service (KMS) REST API Routes.
Exposes endpoints for managing root keys, key rotation, envelope encryption, and decryption.
"""

from typing import Any, Dict, List, Optional
from fastapi import APIRouter, HTTPException, Query, status

from cybershield.kms.engine import KeyManagementEngine
from cybershield.kms.schemas import (
    EncryptedDataEnvelope,
    KMSDecryptRequest,
    KMSEncryptRequest,
    KMSKeyCreateRequest,
    KeyMetadata,
)

kms_router = APIRouter(prefix="/api/kms", tags=["Cryptographic Key Management Service (KMS)"])
kms_engine = KeyManagementEngine()


@kms_router.get("/keys", response_model=List[KeyMetadata])
async def list_keys():
    """List metadata for all managed keys (raw keys are strictly zeroized/vault-sealed)."""
    return kms_engine.list_keys()


@kms_router.post("/keys", response_model=KeyMetadata, status_code=status.HTTP_201_CREATED)
async def create_key(request: KMSKeyCreateRequest):
    """Provision a new Key Encryption Key (KEK)."""
    try:
        return kms_engine.create_key(
            alias=request.alias,
            algorithm=request.algorithm,
            key_type=request.key_type,
            rotation_interval_days=request.rotation_interval_days,
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@kms_router.get("/keys/{key_id_or_alias}", response_model=KeyMetadata)
async def get_key(key_id_or_alias: str):
    """Retrieve key lifecycle metadata by key ID or alias."""
    meta = kms_engine.get_key_metadata(key_id_or_alias)
    if not meta:
        raise HTTPException(status_code=404, detail=f"Key '{key_id_or_alias}' not found")
    return meta


@kms_router.post("/keys/{key_id_or_alias}/rotate", response_model=KeyMetadata)
async def rotate_key(key_id_or_alias: str):
    """Rotate key to a new version. Old versions are retained for historical decryption."""
    try:
        return kms_engine.rotate_key(key_id_or_alias)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


@kms_router.post("/encrypt", response_model=EncryptedDataEnvelope)
async def encrypt_data(request: KMSEncryptRequest):
    """Encrypt payload using envelope encryption (ephemeral DEK sealed under KEK)."""
    try:
        return kms_engine.encrypt_envelope(request.kek_alias_or_id, request.plaintext)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


@kms_router.post("/decrypt")
async def decrypt_data(request: KMSDecryptRequest):
    """Decrypt an encrypted envelope and verify cryptographic authenticity."""
    try:
        plaintext = kms_engine.decrypt_envelope(request.envelope)
        return {"envelope_id": request.envelope.envelope_id, "plaintext": plaintext}
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Decryption / Authentication failed: {str(e)}")


@kms_router.get("/health")
async def get_health():
    """Retrieve KMS cryptographic engine health and rotation telemetry."""
    return kms_engine.get_health_and_audit()
