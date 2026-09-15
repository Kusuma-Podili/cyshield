"""CyberShield Enterprise - Autonomous Secret Sprawl & Token Entropy Scanner Schemas.
Data contracts for leaked credential detection, entropy analysis, and remediation.
"""

from enum import Enum
from typing import Dict, List, Optional, Any
from datetime import datetime, timezone
from pydantic import BaseModel, Field


class SecretType(str, Enum):
    AWS_ACCESS_KEY = "AWS_ACCESS_KEY"
    AWS_SECRET_KEY = "AWS_SECRET_KEY"
    GITHUB_TOKEN = "GITHUB_TOKEN"
    SLACK_TOKEN = "SLACK_TOKEN"
    SSH_RSA_PRIVATE_KEY = "SSH_RSA_PRIVATE_KEY"
    PGP_PRIVATE_KEY = "PGP_PRIVATE_KEY"
    DATABASE_CONNECTION_URI = "DATABASE_CONNECTION_URI"
    JWT_BEARER_TOKEN = "JWT_BEARER_TOKEN"
    GCP_API_KEY = "GCP_API_KEY"
    STRIPE_API_KEY = "STRIPE_API_KEY"
    HIGH_ENTROPY_STRING = "HIGH_ENTROPY_STRING"


class SecretSeverity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class EntropyMetric(BaseModel):
    """Calculated character entropy statistics for a token candidate."""
    shannon_entropy: float = Field(..., ge=0.0, le=8.0, description="Bits per character")
    metric_entropy: float = Field(..., ge=0.0, le=1.0, description="Normalized entropy")
    charset: str = Field(..., description="hex, base64, or alphanumeric")


class SecretFinding(BaseModel):
    """Individual detected credential exposure finding."""
    finding_id: str
    secret_type: SecretType
    severity: SecretSeverity
    raw_snippet_masked: str
    file_path: Optional[str] = None
    line_number: Optional[int] = None
    entropy: float
    rule_name: str
    proximity_keyword: Optional[str] = None
    is_remediated: bool = False
    remediation_playbook: str
    discovered_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class ScanTextRequest(BaseModel):
    """Scan request for an inline text buffer, code snippet, or log entry."""
    content: str = Field(..., description="Raw text or source code to inspect")
    source_label: str = Field(default="inline_snippet", description="Identifier or filename for context")
    entropy_threshold: float = Field(default=4.2, ge=2.0, le=8.0)


class ScanFileRequest(BaseModel):
    """Scan request for a target file on the local filesystem."""
    file_path: str = Field(..., description="Absolute or relative file path")
    entropy_threshold: float = Field(default=4.2, ge=2.0, le=8.0)


class SecretScanSummary(BaseModel):
    """Aggregated scan outcome report."""
    total_scanned_items: int
    findings_count: int
    critical_count: int
    high_count: int
    medium_count: int
    findings: List[SecretFinding]
    scan_duration_ms: float
    scanned_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class SecretStatsResponse(BaseModel):
    """Platform-wide secret posture metrics."""
    total_findings: int
    unresolved_findings: int
    remediated_findings: int
    findings_by_type: Dict[str, int]
