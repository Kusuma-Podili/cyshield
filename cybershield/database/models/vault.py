"""Cryptographic Audit Vault (WORM Ledger) Database Models.

Implements an immutable, append-only, tamper-evident block chain ledger
using SHA-256 Merkle links and HMAC cryptographic signatures.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional, Dict, Any
from sqlalchemy import (
    Column,
    Integer,
    String,
    Boolean,
    DateTime,
    Text,
    JSON,
)

from cybershield.database.session import Base


class AuditVaultBlockModel(Base):
    """Immutable audit ledger block secured with cryptographic hash chaining."""

    __tablename__ = "audit_vault_blocks"

    id = Column(Integer, primary_key=True, autoincrement=True)
    block_index = Column(Integer, unique=True, nullable=False, index=True)
    timestamp = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False, index=True)

    actor_id = Column(String(128), default="SYSTEM", nullable=False, index=True)
    actor_role = Column(String(64), default="SYSTEM", nullable=False)
    action = Column(String(128), nullable=False, index=True)
    entity_type = Column(String(64), nullable=False, index=True)
    entity_id = Column(String(128), nullable=False, index=True)

    payload_data = Column(JSON, nullable=True)
    payload_hash = Column(String(64), nullable=False)  # SHA-256 hex
    previous_block_hash = Column(String(64), nullable=False)  # Linked prior block hash
    block_hash = Column(String(64), nullable=False, unique=True, index=True)  # Current block SHA-256
    hmac_signature = Column(String(64), nullable=False)  # HMAC-SHA256 seal

    is_genesis = Column(Boolean, default=False, nullable=False)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "block_index": self.block_index,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "actor_id": self.actor_id,
            "actor_role": self.actor_role,
            "action": self.action,
            "entity_type": self.entity_type,
            "entity_id": self.entity_id,
            "payload_data": self.payload_data or {},
            "payload_hash": self.payload_hash,
            "previous_block_hash": self.previous_block_hash,
            "block_hash": self.block_hash,
            "hmac_signature": self.hmac_signature,
            "is_genesis": self.is_genesis,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }
