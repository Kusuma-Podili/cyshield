"""
Cryptographic Key Management Service (KMS) Schemas and Models.
Defines KEK/DEK envelope encryption structures, key rotation metadata, and cryptographic audit records.
"""

from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class KeyType(str, Enum):
    ROOT_KEK = "ROOT_KEK"   # Key Encryption Key
    DATA_DEK = "DATA_DEK"   # Data Encryption Key
    HMAC_KEY = "HMAC_KEY"
    SIGNING_KEY = "SIGNING_KEY"


class CryptographicAlgorithm(str, Enum):
    AES_256_GCM = "AES_256_GCM"
    CHACHA20_POLY1305 = "CHACHA20_POLY1305"
    HMAC_SHA256 = "HMAC_SHA256"


class KeyStatus(str, Enum):
    ACTIVE = "ACTIVE"
    ROTATED = "ROTATED"
    DISABLED = "DISABLED"
    PENDING_DELETION = "PENDING_DELETION"


class KeyMetadata(BaseModel):
    """Public metadata describing a KMS key without exposing raw material."""
    key_id: str
    alias: str
    key_type: KeyType
    algorithm: CryptographicAlgorithm
    version: int = 1
    status: KeyStatus = KeyStatus.ACTIVE
    created_at: datetime = Field(default_factory=datetime.utcnow)
    rotation_interval_days: int = 90
    expires_at: Optional[datetime] = None
    encryptions_performed: int = 0
    decryptions_performed: int = 0


class EncryptedDataEnvelope(BaseModel):
    """Envelope encryption payload packaging encrypted DEK and ciphertext."""
    envelope_id: str
    kek_id: str
    kek_version: int
    algorithm: CryptographicAlgorithm
    ciphertext_b64: str
    nonce_b64: str
    tag_b64: str
    encrypted_dek_b64: str
    created_at: datetime = Field(default_factory=datetime.utcnow)


class KMSEncryptRequest(BaseModel):
    """Request to encrypt data using envelope encryption."""
    kek_alias_or_id: str
    plaintext: str


class KMSDecryptRequest(BaseModel):
    """Request to decrypt an encrypted envelope."""
    envelope: EncryptedDataEnvelope


class KMSKeyCreateRequest(BaseModel):
    """Request to provision a new root key."""
    alias: str
    algorithm: CryptographicAlgorithm = CryptographicAlgorithm.AES_256_GCM
    key_type: KeyType = KeyType.ROOT_KEK
    rotation_interval_days: int = 90
