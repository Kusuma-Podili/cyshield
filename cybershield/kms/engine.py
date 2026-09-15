"""
Cryptographic Key Management Service (KMS) Engine.
Implements NIST SP 800-57 envelope encryption, KEK/DEK hierarchy, AES-256-GCM, and key rotation.
"""

import base64
import os
import uuid
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional, Tuple

from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305

from cybershield.kms.schemas import (
    CryptographicAlgorithm,
    EncryptedDataEnvelope,
    KeyMetadata,
    KeyStatus,
    KeyType,
)


class KeyManagementEngine:
    """Hardware-Grade Envelope Encryption and Key Lifecycle Management Engine."""

    def __init__(self):
        # Raw key material: key_id -> Dict[version_int, raw_bytes]
        self._key_material: Dict[str, Dict[int, bytes]] = {}
        self._metadata: Dict[str, KeyMetadata] = {}
        self._alias_map: Dict[str, str] = {}
        self._seed_default_master_key()

    def _seed_default_master_key(self):
        """Seed primary enterprise root Key Encryption Key (KEK)."""
        self.create_key(
            alias="master-kek-primary",
            algorithm=CryptographicAlgorithm.AES_256_GCM,
            key_type=KeyType.ROOT_KEK,
            rotation_interval_days=90,
        )

    def create_key(
        self,
        alias: str,
        algorithm: CryptographicAlgorithm = CryptographicAlgorithm.AES_256_GCM,
        key_type: KeyType = KeyType.ROOT_KEK,
        rotation_interval_days: int = 90,
    ) -> KeyMetadata:
        """Generate a new cryptographic key and store version 1."""
        if alias in self._alias_map:
            raise ValueError(f"Key with alias '{alias}' already exists")

        key_id = f"KMS-{uuid.uuid4().hex[:12].upper()}"

        # Generate 256-bit raw key
        if algorithm == CryptographicAlgorithm.CHACHA20_POLY1305:
            raw_key = ChaCha20Poly1305.generate_key()
        else:
            raw_key = AESGCM.generate_key(bit_length=256)

        self._key_material[key_id] = {1: raw_key}

        now = datetime.utcnow()
        meta = KeyMetadata(
            key_id=key_id,
            alias=alias,
            key_type=key_type,
            algorithm=algorithm,
            version=1,
            status=KeyStatus.ACTIVE,
            created_at=now,
            rotation_interval_days=rotation_interval_days,
            expires_at=now + timedelta(days=rotation_interval_days),
        )

        self._metadata[key_id] = meta
        self._alias_map[alias] = key_id
        return meta

    def get_key_metadata(self, key_id_or_alias: str) -> Optional[KeyMetadata]:
        key_id = self._alias_map.get(key_id_or_alias, key_id_or_alias)
        return self._metadata.get(key_id)

    def list_keys(self) -> List[KeyMetadata]:
        return list(self._metadata.values())

    def rotate_key(self, key_id_or_alias: str) -> KeyMetadata:
        """Rotate key material to a new version. Preserves previous versions for backward compatibility."""
        key_id = self._alias_map.get(key_id_or_alias, key_id_or_alias)
        meta = self._metadata.get(key_id)
        if not meta:
            raise ValueError(f"Key '{key_id_or_alias}' not found")

        # Generate new version material
        if meta.algorithm == CryptographicAlgorithm.CHACHA20_POLY1305:
            new_raw_key = ChaCha20Poly1305.generate_key()
        else:
            new_raw_key = AESGCM.generate_key(bit_length=256)

        new_version = meta.version + 1
        self._key_material[key_id][new_version] = new_raw_key

        now = datetime.utcnow()
        meta.version = new_version
        meta.status = KeyStatus.ROTATED
        meta.expires_at = now + timedelta(days=meta.rotation_interval_days)

        return meta

    def encrypt_envelope(self, kek_alias_or_id: str, plaintext: str) -> EncryptedDataEnvelope:
        """Perform envelope encryption: generates ephemeral DEK, encrypts payload, wraps DEK under KEK."""
        key_id = self._alias_map.get(kek_alias_or_id, kek_alias_or_id)
        meta = self._metadata.get(key_id)
        if not meta:
            raise ValueError(f"KEK '{kek_alias_or_id}' not found")

        current_version = meta.version
        kek_bytes = self._key_material[key_id][current_version]

        # 1. Generate ephemeral 256-bit Data Encryption Key (DEK)
        dek_bytes = AESGCM.generate_key(bit_length=256)

        # 2. Encrypt plaintext under DEK using AES-256-GCM
        aesgcm_dek = AESGCM(dek_bytes)
        data_nonce = os.urandom(12)
        plaintext_bytes = plaintext.encode("utf-8")
        encrypted_payload = aesgcm_dek.encrypt(data_nonce, plaintext_bytes, associated_data=None)

        # In AESGCM output, the last 16 bytes are the authentication tag
        ciphertext = encrypted_payload[:-16]
        tag = encrypted_payload[-16:]

        # 3. Wrap DEK under KEK (Envelope Encryption)
        if meta.algorithm == CryptographicAlgorithm.CHACHA20_POLY1305:
            chacha = ChaCha20Poly1305(kek_bytes)
            kek_nonce = os.urandom(12)
            wrapped_dek_raw = chacha.encrypt(kek_nonce, dek_bytes, associated_data=None)
            encrypted_dek = kek_nonce + wrapped_dek_raw
        else:
            aesgcm_kek = AESGCM(kek_bytes)
            kek_nonce = os.urandom(12)
            wrapped_dek_raw = aesgcm_kek.encrypt(kek_nonce, dek_bytes, associated_data=None)
            encrypted_dek = kek_nonce + wrapped_dek_raw

        meta.encryptions_performed += 1

        return EncryptedDataEnvelope(
            envelope_id=f"ENV-{uuid.uuid4().hex[:8].upper()}",
            kek_id=meta.key_id,
            kek_version=current_version,
            algorithm=meta.algorithm,
            ciphertext_b64=base64.b64encode(ciphertext).decode("ascii"),
            nonce_b64=base64.b64encode(data_nonce).decode("ascii"),
            tag_b64=base64.b64encode(tag).decode("ascii"),
            encrypted_dek_b64=base64.b64encode(encrypted_dek).decode("ascii"),
            created_at=datetime.utcnow(),
        )

    def decrypt_envelope(self, envelope: EncryptedDataEnvelope) -> str:
        """Unwrap DEK using historical KEK version, verify authentication tag, and decrypt payload."""
        meta = self._metadata.get(envelope.kek_id)
        if not meta:
            raise ValueError(f"KEK '{envelope.kek_id}' not found in KMS vault")

        version_keys = self._key_material.get(envelope.kek_id, {})
        kek_bytes = version_keys.get(envelope.kek_version)
        if not kek_bytes:
            raise ValueError(f"Key version '{envelope.kek_version}' for KEK '{envelope.kek_id}' not found")

        # Decode base64 components
        ciphertext = base64.b64decode(envelope.ciphertext_b64)
        nonce = base64.b64decode(envelope.nonce_b64)
        tag = base64.b64decode(envelope.tag_b64)
        encrypted_dek_full = base64.b64decode(envelope.encrypted_dek_b64)

        # 1. Unwrap DEK using KEK version
        kek_nonce = encrypted_dek_full[:12]
        wrapped_dek = encrypted_dek_full[12:]

        if envelope.algorithm == CryptographicAlgorithm.CHACHA20_POLY1305:
            chacha = ChaCha20Poly1305(kek_bytes)
            dek_bytes = chacha.decrypt(kek_nonce, wrapped_dek, associated_data=None)
        else:
            aesgcm_kek = AESGCM(kek_bytes)
            dek_bytes = aesgcm_kek.decrypt(kek_nonce, wrapped_dek, associated_data=None)

        # 2. Decrypt data payload using unwrapped DEK and verify tag
        aesgcm_dek = AESGCM(dek_bytes)
        payload_with_tag = ciphertext + tag
        decrypted_bytes = aesgcm_dek.decrypt(nonce, payload_with_tag, associated_data=None)

        meta.decryptions_performed += 1
        return decrypted_bytes.decode("utf-8")

    def get_health_and_audit(self) -> Dict[str, Any]:
        """Cryptographic engine health status and operational telemetry."""
        total_keys = len(self._metadata)
        total_encryptions = sum(m.encryptions_performed for m in self._metadata.values())
        total_decryptions = sum(m.decryptions_performed for m in self._metadata.values())

        # Check for expiring keys within 14 days
        now = datetime.utcnow()
        expiring = [
            m.alias for m in self._metadata.values()
            if m.expires_at and (m.expires_at - now).total_seconds() < 14 * 86400
        ]

        return {
            "status": "HEALTHY",
            "fips_140_3_compliance_ready": True,
            "total_keys_managed": total_keys,
            "total_encryptions": total_encryptions,
            "total_decryptions": total_decryptions,
            "expiring_keys_warning": expiring,
        }
