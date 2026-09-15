"""CyberShield Enterprise - Autonomous Cryptographic Ransomware Rollback & VSS Vault Schemas.
Data contracts for immutable snapshots, anti-recovery shadow purge interception,
file rollback execution, and vault resilience.
"""

from enum import Enum
from typing import Dict, List, Optional, Any
from datetime import datetime, timezone
from pydantic import BaseModel, Field


class AntiRecoveryTechnique(str, Enum):
    VSSADMIN_SHADOW_DELETE = "VSSADMIN_SHADOW_DELETE"
    WMIC_SHADOWCOPY_PURGE = "WMIC_SHADOWCOPY_PURGE"
    BCDEDIT_RECOVERY_DISABLED = "BCDEDIT_RECOVERY_DISABLED"
    WBADMIN_BACKUP_PURGE = "WBADMIN_BACKUP_PURGE"
    USN_JOURNAL_DELETION = "USN_JOURNAL_DELETION"


class FileDeltaEntry(BaseModel):
    """Pre-encryption file state preserved in cryptographic vault."""
    file_path: str
    original_sha256: str
    file_size_bytes: int
    content_delta_preview: Optional[str] = None


class ImmutableSnapshot(BaseModel):
    """Out-of-band cryptographically signed system recovery snapshot."""
    snapshot_id: str
    volume_label: str = "C:"
    tracked_files_count: int
    files: List[FileDeltaEntry] = Field(default_factory=list)
    hmac_signature: str = Field(..., description="HMAC-SHA256 vault tamper-evident seal")
    is_locked: bool = True
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class CommandInspectionRequest(BaseModel):
    """Request to inspect system command line for ransomware anti-recovery execution."""
    process_id: int
    process_name: str
    command_line: str
    parent_process: Optional[str] = None


class AntiRecoveryAlert(BaseModel):
    """Security alert raised when a ransomware anti-recovery attempt is thwarted."""
    alert_id: str
    technique: AntiRecoveryTechnique
    mitre_technique: str
    process_id: int
    process_name: str
    command_line: str
    action_enforced: str = "PROCESS_TERMINATE_AND_PREVENT_VSS_PURGE"
    severity: str = "CRITICAL"
    details: str
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class RollbackRequest(BaseModel):
    """Request to restore files from immutable snapshot after ransomware attack."""
    snapshot_id: str
    target_files: Optional[List[str]] = Field(default=None, description="Specific file paths to revert, or None for all")


class RollbackResponse(BaseModel):
    """Outcome of autonomous cryptographic rollback execution."""
    snapshot_id: str
    files_reverted_count: int
    total_bytes_restored: int
    integrity_verified: bool
    status: str = "ROLLBACK_SUCCESSFUL"
    restored_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class VSSVaultStatus(BaseModel):
    """Status and health of cryptographic recovery vault."""
    total_snapshots_preserved: int
    total_files_protected: int
    anti_recovery_attempts_blocked: int
    vault_tamper_evident: bool = True
    active_protection_mode: str = "IMMUTABLE_OUT_OF_BAND"
