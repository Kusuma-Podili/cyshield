"""Audit Log Query REST API Endpoints."""

from __future__ import annotations

from datetime import datetime
from typing import List, Optional, Dict, Any
from fastapi import APIRouter, Depends, Query
from pydantic import BaseModel, ConfigDict
from sqlalchemy.ext.asyncio import AsyncSession

from cybershield.database.session import get_db
from cybershield.database.models import User, Permission
from cybershield.auth.dependencies import require_permission
from cybershield.audit.service import AuditService

router = APIRouter(prefix="/api/audit", tags=["Audit Logs"])


class AuditLogItem(BaseModel):
    """Audit record response schema."""
    model_config = ConfigDict(from_attributes=True)

    id: int
    user_id: Optional[int] = None
    username: str
    action: str
    resource: str
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    status: str
    request_id: Optional[str] = None
    details: Dict[str, Any] = {}
    timestamp: datetime


class AuditLogListResponse(BaseModel):
    items: List[AuditLogItem]
    total: int
    page: int
    page_size: int


@router.get("", response_model=AuditLogListResponse)
async def list_audit_logs(
    action: Optional[str] = None,
    username: Optional[str] = None,
    status: Optional[str] = None,
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=25, ge=1, le=100),
    current_user: User = Depends(require_permission(Permission.AUDIT_VIEW)),
    db: AsyncSession = Depends(get_db),
):
    """Search and filter enterprise security audit trails."""
    offset = (page - 1) * page_size
    items, total = await AuditService.query_logs(
        db, action=action, username=username, status=status, limit=page_size, offset=offset
    )
    serialized = [AuditLogItem.model_validate(i) for i in items]
    return AuditLogListResponse(items=serialized, total=total, page=page, page_size=page_size)


# =========================================================================
# Cryptographic Audit Vault (WORM Ledger) Endpoints
# =========================================================================

from cybershield.audit.vault import AuditVault


class VaultBlockResponse(BaseModel):
    id: int
    block_index: int
    timestamp: Optional[str] = None
    actor_id: str
    actor_role: str
    action: str
    entity_type: str
    entity_id: str
    payload_data: Dict[str, Any] = {}
    payload_hash: str
    previous_block_hash: str
    block_hash: str
    hmac_signature: str
    is_genesis: bool
    created_at: Optional[str] = None


class VaultBlockListResponse(BaseModel):
    items: List[VaultBlockResponse]
    total: int
    page: int
    page_size: int


class VaultVerificationResponse(BaseModel):
    is_valid: bool
    total_blocks: int
    genesis_hash: Optional[str] = None
    latest_block_hash: Optional[str] = None
    verification_timestamp: str
    tampered_block_index: Optional[int] = None
    error_message: Optional[str] = None
    verification_seal: Optional[str] = None


class VaultRecordRequest(BaseModel):
    action: str
    entity_type: str
    entity_id: str
    payload: Optional[Dict[str, Any]] = None


@router.get("/vault/blocks", response_model=VaultBlockListResponse)
async def list_vault_blocks(
    action: Optional[str] = None,
    entity_type: Optional[str] = None,
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=25, ge=1, le=100),
    current_user: User = Depends(require_permission(Permission.VAULT_VIEW)),
    db: AsyncSession = Depends(get_db),
):
    """Retrieve immutable, cryptographically chained blocks from the WORM ledger."""
    offset = (page - 1) * page_size
    items, total = await AuditVault.list_blocks(
        db, limit=page_size, offset=offset, action=action, entity_type=entity_type
    )
    return VaultBlockListResponse(
        items=[VaultBlockResponse(**b) for b in items],
        total=total,
        page=page,
        page_size=page_size,
    )


@router.post("/vault/verify", response_model=VaultVerificationResponse)
async def verify_vault_ledger(
    current_user: User = Depends(require_permission(Permission.VAULT_VERIFY)),
    db: AsyncSession = Depends(get_db),
):
    """Exhaustively verify SHA-256 hash continuity and HMAC seals across the entire ledger."""
    report = await AuditVault.verify_chain(db)
    return VaultVerificationResponse(**report)


@router.get("/vault/certificate")
async def export_vault_certificate(
    current_user: User = Depends(require_permission(Permission.VAULT_VIEW)),
    db: AsyncSession = Depends(get_db),
):
    """Export a cryptographically verifiable Certificate of Authenticity for external compliance audits."""
    return await AuditVault.export_tamper_proof(db)


@router.post("/vault/record", response_model=VaultBlockResponse)
async def record_vault_event(
    req: VaultRecordRequest,
    current_user: User = Depends(require_permission(Permission.VAULT_VERIFY)),
    db: AsyncSession = Depends(get_db),
):
    """Append a high-assurance security event block to the immutable WORM audit ledger."""
    block = await AuditVault.record_block(
        db=db,
        action=req.action,
        actor_id=current_user.username,
        actor_role=current_user.role,
        entity_type=req.entity_type,
        entity_id=req.entity_id,
        payload_data=req.payload,
    )
    return VaultBlockResponse(**block.to_dict())

