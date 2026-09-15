"""Cryptographic Utilities and Digital Evidence Custody for CyberShield Enterprise.

Provides tamper-evident SHA-256 integrity verification, Shannon entropy calculations,
and immutable forensic custody chain validation without external dependencies.
"""

from __future__ import annotations

import hashlib
import hmac
import math
from pathlib import Path
from typing import Union, Dict, Any, List
from datetime import datetime, timezone
from cybershield.core.exceptions import EvidenceIntegrityError


def compute_sha256(data: Union[bytes, str, Path]) -> str:
    """Compute standard SHA-256 hexadecimal digest."""
    hasher = hashlib.sha256()
    if isinstance(data, Path):
        with open(data, "rb") as f:
            while chunk := f.read(65536):
                hasher.update(chunk)
    elif isinstance(data, str):
        hasher.update(data.encode("utf-8"))
    elif isinstance(data, bytes):
        hasher.update(data)
    else:
        raise TypeError(f"Unsupported data type for hashing: {type(data)}")
    return hasher.hexdigest()


def compute_sha1(data: Union[bytes, str, Path]) -> str:
    """Compute standard SHA-1 hexadecimal digest."""
    hasher = hashlib.sha1()
    if isinstance(data, Path):
        with open(data, "rb") as f:
            while chunk := f.read(65536):
                hasher.update(chunk)
    elif isinstance(data, str):
        hasher.update(data.encode("utf-8"))
    elif isinstance(data, bytes):
        hasher.update(data)
    return hasher.hexdigest()


def compute_md5(data: Union[bytes, str, Path]) -> str:
    """Compute standard MD5 hexadecimal digest for legacy correlation."""
    hasher = hashlib.md5()
    if isinstance(data, Path):
        with open(data, "rb") as f:
            while chunk := f.read(65536):
                hasher.update(chunk)
    elif isinstance(data, str):
        hasher.update(data.encode("utf-8"))
    elif isinstance(data, bytes):
        hasher.update(data)
    return hasher.hexdigest()


def calculate_shannon_entropy(data: Union[bytes, str]) -> float:
    """Calculate Shannon entropy (0.0 to 8.0) to detect encrypted/packed content.
    
    A value close to 8.0 indicates high randomness, common in ransomware encryption,
    compressed archives, or obfuscated shellcode. Plaintext is typically 3.5 - 5.0.
    """
    if isinstance(data, str):
        byte_data = data.encode("utf-8", errors="ignore")
    else:
        byte_data = data

    if not byte_data:
        return 0.0

    length = len(byte_data)
    frequency: Dict[int, int] = {}
    for b in byte_data:
        frequency[b] = frequency.get(b, 0) + 1

    entropy = 0.0
    for count in frequency.values():
        probability = count / length
        entropy -= probability * math.log2(probability)

    return round(entropy, 4)


class ChainOfCustodySigner:
    """Cryptographic chain-of-custody ledger for forensic artifacts.
    
    Each new record signs the hash of the previous record, forming an immutable
    blockchain-like audit log ensuring that evidence has not been tampered with.
    """
    def __init__(self, platform_secret: str = "CyberShield-Root-Custody-Key-2026"):
        self._secret = platform_secret.encode("utf-8")

    def create_custody_stamp(
        self,
        artifact_id: str,
        artifact_hash: str,
        analyst: str,
        action: str,
        previous_stamp_hash: str = "0" * 64
    ) -> Dict[str, Any]:
        """Generate a cryptographically sealed custody record."""
        timestamp = datetime.now(timezone.utc).isoformat()
        payload = f"{artifact_id}:{artifact_hash}:{analyst}:{action}:{timestamp}:{previous_stamp_hash}"
        signature = hmac.new(self._secret, payload.encode("utf-8"), hashlib.sha256).hexdigest()

        return {
            "artifact_id": artifact_id,
            "artifact_hash": artifact_hash,
            "analyst": analyst,
            "action": action,
            "timestamp": timestamp,
            "previous_stamp_hash": previous_stamp_hash,
            "signature": signature
        }

    def verify_chain(self, chain: List[Dict[str, Any]]) -> bool:
        """Verify the cryptographic integrity of an entire custody chain."""
        if not chain:
            return True

        for i, stamp in enumerate(chain):
            expected_prev = "0" * 64 if i == 0 else chain[i - 1]["signature"]
            if stamp.get("previous_stamp_hash") != expected_prev:
                raise EvidenceIntegrityError(
                    f"Custody chain broken at step {i}: previous hash mismatch",
                    {"step": i, "record": stamp}
                )

            payload = (
                f"{stamp['artifact_id']}:{stamp['artifact_hash']}:{stamp['analyst']}:"
                f"{stamp['action']}:{stamp['timestamp']}:{stamp['previous_stamp_hash']}"
            )
            recalculated = hmac.new(self._secret, payload.encode("utf-8"), hashlib.sha256).hexdigest()
            if not hmac.compare_digest(stamp.get("signature", ""), recalculated):
                raise EvidenceIntegrityError(
                    f"Custody stamp signature verification failed at step {i}",
                    {"step": i, "record": stamp}
                )

        return True
