"""
Firmware and Embedded Binary Security Analysis Schemas and Models.
Defines embedded device architectures, filesystems, entropy profiles, and vulnerability findings.
"""

from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class FirmwareArchitecture(str, Enum):
    ARM = "ARM"
    MIPS = "MIPS"
    MIPSEL = "MIPSEL"
    X86_64 = "X86_64"
    POWERPC = "POWERPC"
    RISCV = "RISCV"
    UNKNOWN = "UNKNOWN"


class FilesystemType(str, Enum):
    SQUASHFS = "SQUASHFS"
    CRAMFS = "CRAMFS"
    JFFS2 = "JFFS2"
    UBIFS = "UBIFS"
    INITRAMFS = "INITRAMFS"
    RAW_BINARY = "RAW_BINARY"


class FindingCategory(str, Enum):
    HARDCODED_SECRET = "HARDCODED_SECRET"
    INSECURE_SERVICE = "INSECURE_SERVICE"
    MISSING_BINARY_PROTECTIONS = "MISSING_BINARY_PROTECTIONS"
    WEAK_CRYPTOGRAPHY = "WEAK_CRYPTOGRAPHY"
    BACKDOOR_ACCOUNT = "BACKDOOR_ACCOUNT"


class FindingSeverity(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class FirmwareFinding(BaseModel):
    """Vulnerability or security flaw discovered in unpacked firmware."""
    id: str
    category: FindingCategory
    severity: FindingSeverity
    title: str
    target_path: str
    description: str
    remediation: str


class EntropyBlock(BaseModel):
    """Entropy score across a chunk of the firmware binary."""
    offset: int
    size: int
    entropy: float  # 0.0 to 8.0


class FirmwareScanResult(BaseModel):
    """Complete security audit report of a firmware image."""
    scan_id: str
    filename: str
    file_size_bytes: int
    sha256_hash: str
    detected_architecture: FirmwareArchitecture
    detected_filesystem: FilesystemType
    mean_entropy: float
    is_packed_or_encrypted: bool
    components_extracted: List[str] = Field(default_factory=list)
    findings: List[FirmwareFinding] = Field(default_factory=list)
    risk_score: float = 20.0  # 0 to 100
    scanned_at: datetime = Field(default_factory=datetime.utcnow)
    duration_ms: float = 0.0


class FirmwareScanRequest(BaseModel):
    """Request to analyze firmware binary."""
    filename: str
    file_bytes_base64: Optional[str] = None
    mock_payload_text: Optional[str] = None
