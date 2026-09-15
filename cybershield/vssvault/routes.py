"""CyberShield Enterprise - Autonomous Cryptographic Ransomware Rollback & VSS Vault Routes.
Exposes endpoints for immutable snapshot creation, anti-recovery command interception,
autonomous file rollback, and vault resilience metrics.
"""

from typing import Dict, List, Optional, Any
from fastapi import APIRouter, HTTPException, Query, status

from .schemas import (
    FileDeltaEntry,
    ImmutableSnapshot,
    CommandInspectionRequest,
    AntiRecoveryAlert,
    RollbackRequest,
    RollbackResponse,
    VSSVaultStatus,
)
from .vault import VSSCryptographicVault

router = APIRouter(prefix="/api/v1/vssvault", tags=["Ransomware Rollback & VSS Vault Sentinel"])

# Singleton vault engine instance
_VSS_VAULT = VSSCryptographicVault()


@router.post("/snapshots/create", response_model=ImmutableSnapshot, status_code=status.HTTP_201_CREATED)
def create_recovery_snapshot(
    volume_label: str = Query(default="C:"),
    files: Optional[List[FileDeltaEntry]] = None,
):
    """Create and seal an immutable out-of-band recovery snapshot."""
    return _VSS_VAULT.create_immutable_snapshot(
        volume_label=volume_label,
        files=files,
    )


@router.post("/intercept/command", response_model=Dict[str, Any], status_code=status.HTTP_200_OK)
def intercept_anti_recovery_command(request: CommandInspectionRequest):
    """Inspect process command line for ransomware anti-recovery / shadow purge operations."""
    alert = _VSS_VAULT.inspect_command(request)
    return {
        "status": "command_evaluated",
        "process_id": request.process_id,
        "is_threat_intercepted": alert is not None,
        "alert": alert,
    }


@router.post("/rollback", response_model=RollbackResponse, status_code=status.HTTP_200_OK)
def trigger_cryptographic_rollback(request: RollbackRequest):
    """Restore pre-encryption file state from tamper-evident snapshot."""
    return _VSS_VAULT.execute_rollback(request)


@router.get("/snapshots", response_model=List[ImmutableSnapshot])
def list_immutable_snapshots():
    """Retrieve all preserved recovery snapshots in cryptographic vault."""
    return list(_VSS_VAULT.snapshots.values())


@router.get("/threats", response_model=List[AntiRecoveryAlert])
def list_anti_recovery_alerts():
    """Retrieve all intercepted anti-recovery / shadow purge security alerts."""
    return _VSS_VAULT.alerts


@router.get("/status", response_model=VSSVaultStatus)
def get_vss_vault_status():
    """Query cryptographic recovery vault protection and resilience status."""
    return _VSS_VAULT.get_status()
