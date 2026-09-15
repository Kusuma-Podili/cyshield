"""System Health, Diagnostics & Backup REST API Endpoints."""

from __future__ import annotations

from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from cybershield.database.session import get_db
from cybershield.auth.dependencies import get_current_user
from cybershield.database.models.user import User
from cybershield.database.models.role import Permission, has_permission
from cybershield.health.schemas import (
    HealthSummaryResponse,
    ReadinessResponse,
    DiagnosticsResponse,
    BackupListResponse,
    BackupMetadataResponse,
    BackupCreateRequest,
    BackupVerifyResponse,
)
from cybershield.health.service import HealthService
from cybershield.core.backup import BackupService

router = APIRouter(prefix="/api/health", tags=["System Health & Diagnostics"])


@router.get("", response_model=HealthSummaryResponse)
async def get_liveness():
    """Lightweight liveness probe for orchestrators and load balancers."""
    return HealthService.get_summary()


@router.get("/live")
async def get_live_ping():
    """Container liveness probe endpoint."""
    return {"status": "alive", "uptime": HealthService.get_uptime_seconds()}


@router.get("/ready", response_model=ReadinessResponse)
async def get_readiness(db: AsyncSession = Depends(get_db)):
    """Readiness probe evaluating database connection and core subsystem accessibility."""
    readiness = await HealthService.check_readiness(db)
    if not readiness.ready:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=readiness.model_dump(),
        )
    return readiness


@router.get("/diagnostics", response_model=DiagnosticsResponse)
async def get_diagnostics(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Deep system diagnostics detailing hardware, database pool, and all 10 platform subsystems."""
    if not has_permission(current_user.role, Permission.HEALTH_VIEW):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Insufficient privileges to view system diagnostics.",
        )
    return await HealthService.get_full_diagnostics(db)


@router.get("/backups", response_model=BackupListResponse)
async def list_database_backups(
    current_user: User = Depends(get_current_user),
):
    """List point-in-time database snapshots with cryptographic hashes."""
    if not has_permission(current_user.role, Permission.BACKUP_MANAGE):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Insufficient privileges to manage database backups.",
        )
    return BackupService.list_snapshots()


@router.post("/backups/create", response_model=BackupMetadataResponse)
async def create_database_backup(
    payload: Optional[BackupCreateRequest] = None,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Create a new point-in-time snapshot of the database and seal it in the WORM vault."""
    if not has_permission(current_user.role, Permission.BACKUP_MANAGE):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Insufficient privileges to create database backups.",
        )
    note = payload.note if payload else "Manual on-demand backup"
    return await BackupService.create_snapshot(db, note=note, actor_id=current_user.username)


@router.post("/backups/{filename}/verify", response_model=BackupVerifyResponse)
async def verify_database_backup(
    filename: str,
    current_user: UserModel = Depends(get_current_user),
):
    """Cryptographically verify the SHA-256 checksum of a stored database backup archive."""
    if not has_permission(current_user.role, Permission.BACKUP_MANAGE):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Insufficient privileges to verify database backups.",
        )
    return BackupService.verify_snapshot(filename)
