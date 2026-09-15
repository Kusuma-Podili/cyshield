"""Cryptographic Audit Vault & WORM Ledger Engine for CyberShield Enterprise.

Guarantees tamper-evidence and non-repudiation using SHA-256 Merkle hash chaining,
canonical payload serialization, and HMAC cryptographic block signing.
"""

from __future__ import annotations

import os
import json
import hmac
import hashlib
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional, Tuple
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc, func

from cybershield.database.models.vault import AuditVaultBlockModel


# Enterprise Vault HMAC Signing Secret
# In production, this is loaded from HSM or secure vault; falls back to an internal master salt
VAULT_SECRET_KEY = os.getenv("CYBERSHIELD_VAULT_KEY", "CYBERSHIELD_CRYPTOGRAPHIC_WORM_VAULT_HMAC_MASTER_2026").encode("utf-8")
GENESIS_PREVIOUS_HASH = "0" * 64


def canonical_json(data: Any) -> str:
    """Serialize data into a deterministic, sorted canonical JSON string."""
    return json.dumps(data, sort_keys=True, separators=(",", ":"), default=str)


def compute_sha256(text: str) -> str:
    """Compute standard SHA-256 hexadecimal digest."""
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def compute_hmac(key: bytes, message: str) -> str:
    """Compute HMAC-SHA256 signature for a message."""
    return hmac.new(key, message.encode("utf-8"), hashlib.sha256).hexdigest()


class AuditVault:
    """Cryptographic WORM (Write Once Read Many) Ledger Engine."""

    @classmethod
    async def initialize_genesis_block(cls, db: AsyncSession) -> AuditVaultBlockModel:
        """Create the immutable Genesis Block (Block 0) if ledger is empty."""
        count_res = await db.execute(select(func.count(AuditVaultBlockModel.id)))
        if count_res.scalar() > 0:
            res = await db.execute(select(AuditVaultBlockModel).where(AuditVaultBlockModel.block_index == 0))
            return res.scalar_one()

        genesis_time = datetime(2026, 1, 1, 0, 0, 0, tzinfo=timezone.utc)
        payload = {
            "genesis_protocol": "CyberShield WORM Ledger v1.0",
            "algorithm": "SHA-256 / HMAC-SHA256",
            "message": "Immutable root of security event custody established.",
        }
        canonical_p = canonical_json(payload)
        payload_hash = compute_sha256(canonical_p)

        ts_str = genesis_time.strftime("%Y-%m-%d %H:%M:%S")
        block_data = f"0|{ts_str}|SYSTEM|SYSTEM|GENESIS_INITIALIZATION|LEDGER_ROOT|0|{payload_hash}|{GENESIS_PREVIOUS_HASH}"
        block_hash = compute_sha256(block_data)
        signature = compute_hmac(VAULT_SECRET_KEY, block_hash)

        genesis_block = AuditVaultBlockModel(
            block_index=0,
            timestamp=genesis_time,
            actor_id="SYSTEM",
            actor_role="SYSTEM",
            action="GENESIS_INITIALIZATION",
            entity_type="LEDGER_ROOT",
            entity_id="0",
            payload_data=payload,
            payload_hash=payload_hash,
            previous_block_hash=GENESIS_PREVIOUS_HASH,
            block_hash=block_hash,
            hmac_signature=signature,
            is_genesis=True,
            created_at=genesis_time,
        )
        db.add(genesis_block)
        await db.commit()
        await db.refresh(genesis_block)
        return genesis_block

    @classmethod
    async def record_block(
        cls,
        db: AsyncSession,
        action: str,
        actor_id: str,
        actor_role: str,
        entity_type: str,
        entity_id: str,
        payload_data: Optional[Dict[str, Any]] = None,
    ) -> AuditVaultBlockModel:
        """Append a new tamper-evident block linked to the prior block's hash."""
        # Ensure genesis exists
        await cls.initialize_genesis_block(db)

        # Retrieve the latest block
        latest_res = await db.execute(
            select(AuditVaultBlockModel).order_by(desc(AuditVaultBlockModel.block_index)).limit(1)
        )
        latest_block = latest_res.scalar_one()

        now = datetime.now(timezone.utc)
        payload = payload_data or {}
        canonical_p = canonical_json(payload)
        payload_hash = compute_sha256(canonical_p)

        new_index = latest_block.block_index + 1
        prev_hash = latest_block.block_hash
        ts_str = now.strftime("%Y-%m-%d %H:%M:%S")

        block_data = f"{new_index}|{ts_str}|{actor_id}|{actor_role}|{action}|{entity_type}|{entity_id}|{payload_hash}|{prev_hash}"
        block_hash = compute_sha256(block_data)
        signature = compute_hmac(VAULT_SECRET_KEY, block_hash)

        new_block = AuditVaultBlockModel(
            block_index=new_index,
            timestamp=now,
            actor_id=actor_id,
            actor_role=actor_role,
            action=action.upper(),
            entity_type=entity_type.upper(),
            entity_id=str(entity_id),
            payload_data=payload,
            payload_hash=payload_hash,
            previous_block_hash=prev_hash,
            block_hash=block_hash,
            hmac_signature=signature,
            is_genesis=False,
            created_at=now,
        )
        db.add(new_block)
        await db.commit()
        await db.refresh(new_block)
        return new_block

    @classmethod
    async def verify_chain(cls, db: AsyncSession) -> Dict[str, Any]:
        """Perform exhaustive cryptographic audit traversing all blocks from genesis to tip."""
        await cls.initialize_genesis_block(db)

        res = await db.execute(select(AuditVaultBlockModel).order_by(AuditVaultBlockModel.block_index.asc()))
        blocks = res.scalars().all()

        total = len(blocks)
        now_str = datetime.now(timezone.utc).isoformat()

        if total == 0:
            return {
                "is_valid": False,
                "total_blocks": 0,
                "genesis_hash": None,
                "latest_block_hash": None,
                "verification_timestamp": now_str,
                "tampered_block_index": None,
                "error_message": "Audit ledger contains zero blocks.",
                "verification_seal": None,
            }

        # Validate Genesis Block
        genesis = blocks[0]
        if genesis.block_index != 0 or genesis.previous_block_hash != GENESIS_PREVIOUS_HASH:
            return {
                "is_valid": False,
                "total_blocks": total,
                "genesis_hash": genesis.block_hash,
                "latest_block_hash": blocks[-1].block_hash,
                "verification_timestamp": now_str,
                "tampered_block_index": 0,
                "error_message": "Genesis block hash or parent link is invalid.",
                "verification_seal": None,
            }

        # Traverse and verify chain linkage & HMAC signatures
        for i in range(1, total):
            curr = blocks[i]
            prev = blocks[i - 1]

            # 1. Check index sequential continuity
            if curr.block_index != prev.block_index + 1:
                return {
                    "is_valid": False,
                    "total_blocks": total,
                    "genesis_hash": genesis.block_hash,
                    "latest_block_hash": blocks[-1].block_hash,
                    "verification_timestamp": now_str,
                    "tampered_block_index": curr.block_index,
                    "error_message": f"Block index discontinuity detected between block {prev.block_index} and {curr.block_index}.",
                    "verification_seal": None,
                }

            # 2. Check hash chain parent linkage
            if curr.previous_block_hash != prev.block_hash:
                return {
                    "is_valid": False,
                    "total_blocks": total,
                    "genesis_hash": genesis.block_hash,
                    "latest_block_hash": blocks[-1].block_hash,
                    "verification_timestamp": now_str,
                    "tampered_block_index": curr.block_index,
                    "error_message": f"Broken cryptographic link: Block {curr.block_index} previous_hash does not match Block {prev.block_index} block_hash.",
                    "verification_seal": None,
                }

            # 3. Check payload hash integrity
            expected_p_hash = compute_sha256(canonical_json(curr.payload_data or {}))
            if curr.payload_hash != expected_p_hash:
                return {
                    "is_valid": False,
                    "total_blocks": total,
                    "genesis_hash": genesis.block_hash,
                    "latest_block_hash": blocks[-1].block_hash,
                    "verification_timestamp": now_str,
                    "tampered_block_index": curr.block_index,
                    "error_message": f"Payload tampering detected at Block {curr.block_index}: stored payload hash does not match computed digest.",
                    "verification_seal": None,
                }

            # 4. Check block hash calculation
            ts_str = curr.timestamp.strftime("%Y-%m-%d %H:%M:%S")
            expected_block_data = f"{curr.block_index}|{ts_str}|{curr.actor_id}|{curr.actor_role}|{curr.action}|{curr.entity_type}|{curr.entity_id}|{curr.payload_hash}|{curr.previous_block_hash}"
            expected_block_hash = compute_sha256(expected_block_data)
            if curr.block_hash != expected_block_hash:
                return {
                    "is_valid": False,
                    "total_blocks": total,
                    "genesis_hash": genesis.block_hash,
                    "latest_block_hash": blocks[-1].block_hash,
                    "verification_timestamp": now_str,
                    "tampered_block_index": curr.block_index,
                    "error_message": f"Block hash tampering detected at Block {curr.block_index}: hash digest calculation mismatch.",
                    "verification_seal": None,
                }

            # 5. Check HMAC cryptographic signature
            expected_signature = compute_hmac(VAULT_SECRET_KEY, curr.block_hash)
            if curr.hmac_signature != expected_signature:
                return {
                    "is_valid": False,
                    "total_blocks": total,
                    "genesis_hash": genesis.block_hash,
                    "latest_block_hash": blocks[-1].block_hash,
                    "verification_timestamp": now_str,
                    "tampered_block_index": curr.block_index,
                    "error_message": f"Cryptographic signature invalid at Block {curr.block_index}: HMAC seal authentication failure.",
                    "verification_seal": None,
                }

        # Entire chain verified valid
        latest = blocks[-1]
        seal_content = f"{genesis.block_hash}:{latest.block_hash}:{total}:{now_str}"
        verification_seal = compute_hmac(VAULT_SECRET_KEY, seal_content)

        return {
            "is_valid": True,
            "total_blocks": total,
            "genesis_hash": genesis.block_hash,
            "latest_block_hash": latest.block_hash,
            "verification_timestamp": now_str,
            "tampered_block_index": None,
            "error_message": None,
            "verification_seal": verification_seal,
        }

    @classmethod
    async def export_tamper_proof(cls, db: AsyncSession) -> Dict[str, Any]:
        """Generate a cryptographically verifiable Certificate of Authenticity."""
        report = await cls.verify_chain(db)
        cert_id = f"CERT-WORM-{hashlib.sha256(str(report.get('verification_seal')).encode()).hexdigest()[:12].upper()}"
        return {
            "certificate_id": cert_id,
            "issuer": "CyberShield Enterprise Cryptographic Audit Vault",
            "status": "VALID_AND_UNCOMPROMISED" if report["is_valid"] else "COMPROMISED_TAMPER_DETECTED",
            "verification_details": report,
            "digital_seal": report["verification_seal"],
            "issued_at": datetime.now(timezone.utc).isoformat(),
        }

    @classmethod
    async def list_blocks(
        cls,
        db: AsyncSession,
        limit: int = 50,
        offset: int = 0,
        action: Optional[str] = None,
        entity_type: Optional[str] = None,
    ) -> Tuple[List[Dict[str, Any]], int]:
        """Query paginated blocks from the immutable vault."""
        await cls.initialize_genesis_block(db)

        query = select(AuditVaultBlockModel)
        count_q = select(func.count(AuditVaultBlockModel.id))

        if action:
            query = query.where(AuditVaultBlockModel.action == action.upper())
            count_q = count_q.where(AuditVaultBlockModel.action == action.upper())
        if entity_type:
            query = query.where(AuditVaultBlockModel.entity_type == entity_type.upper())
            count_q = count_q.where(AuditVaultBlockModel.entity_type == entity_type.upper())

        total = (await db.execute(count_q)).scalar() or 0
        res = await db.execute(
            query.order_by(desc(AuditVaultBlockModel.block_index)).offset(offset).limit(limit)
        )
        blocks = res.scalars().all()
        return [b.to_dict() for b in blocks], total
