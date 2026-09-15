"""
Ransomware Canary & VSS Shadow Copy Sentinel Schemas.
Defines decoy bait files, file entropy heuristics, ransomware extension patterns, and VSS tamper commands.
"""

from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class CanaryFileType(str, Enum):
    WORD = "WORD"
    EXCEL = "EXCEL"
    PDF = "PDF"
    SQL = "SQL"
    DATABASE = "DATABASE"
    TEXT = "TEXT"


class RansomwareThreatLevel(str, Enum):
    BENIGN = "BENIGN"
    SUSPICIOUS = "SUSPICIOUS"
    HIGH = "HIGH"
    CRITICAL_OUTBREAK = "CRITICAL_OUTBREAK"


class CanaryTrapFile(BaseModel):
    """Bait decoy file deployed in target directories to detect ransomware traversal."""
    canary_id: str
    host_id: str
    file_path: str
    file_type: CanaryFileType = CanaryFileType.WORD
    expected_sha256: str
    watermark_token: str
    is_tampered: bool = False
    last_verified: datetime = Field(default_factory=datetime.utcnow)
    created_at: datetime = Field(default_factory=datetime.utcnow)


class FileModificationEvent(BaseModel):
    """File operation telemetry captured by endpoint agent driver / FIM."""
    event_id: str
    host_id: str
    file_path: str
    old_extension: str
    new_extension: str
    pre_entropy: float = 4.2
    post_entropy: float = 7.9
    process_name: str
    process_pid: int
    timestamp: datetime = Field(default_factory=datetime.utcnow)


class VSSCommandInspectionRequest(BaseModel):
    """Process execution requiring inspection for shadow copy / backup destruction."""
    host_id: str
    process_name: str
    command_line: str
    user_context: str = "SYSTEM"


class RansomwareAlert(BaseModel):
    """Alert triggered upon detection of active ransomware encryption or VSS destruction."""
    alert_id: str
    host_id: str
    threat_level: RansomwareThreatLevel
    reason: str
    affected_files: List[str] = Field(default_factory=list)
    detected_extensions: List[str] = Field(default_factory=list)
    process_name: Optional[str] = None
    process_pid: Optional[int] = None
    host_quarantine_recommended: bool = True
    timestamp: datetime = Field(default_factory=datetime.utcnow)
