"""
Data Loss Prevention (DLP) Schemas and Models.
Defines sensitive data classifications, detection rules, inspection payloads, and incident events.
"""

from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class SensitiveDataType(str, Enum):
    CREDIT_CARD_PCI = "CREDIT_CARD_PCI"
    SSN_PII = "SSN_PII"
    CLOUD_SECRET = "CLOUD_SECRET"
    PRIVATE_KEY = "PRIVATE_KEY"
    HEALTHCARE_HIPAA = "HEALTHCARE_HIPAA"
    CONFIDENTIAL_MARKER = "CONFIDENTIAL_MARKER"


class DLPSeverity(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class DLPEnforcementAction(str, Enum):
    ALLOW = "ALLOW"
    MASK = "MASK"
    ALERT_ONLY = "ALERT_ONLY"
    BLOCK = "BLOCK"


class DLPMatch(BaseModel):
    """An individual sensitive data match found within inspected content."""
    match_id: str
    data_type: SensitiveDataType
    severity: DLPSeverity
    rule_name: str
    snippet_masked: str
    confidence: float = 90.0
    start_pos: int
    end_pos: int


class DLPInspectRequest(BaseModel):
    """Request payload to scan content for sensitive information."""
    content: str
    source_entity: str = "Web Proxy Egress"
    data_channel: str = "HTTP_POST"  # HTTP_POST, EMAIL, FILE_TRANSFER, CLIPBOARD
    action_if_matched: DLPEnforcementAction = DLPEnforcementAction.BLOCK


class DLPInspectResult(BaseModel):
    """Outcome of DLP inspection."""
    inspection_id: str
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    has_violations: bool
    action_taken: DLPEnforcementAction
    matches_count: int
    matches: List[DLPMatch] = Field(default_factory=list)
    sanitized_content: Optional[str] = None
    execution_time_ms: float = 0.0


class DLPRule(BaseModel):
    """Definition of a DLP pattern matching rule."""
    id: str
    name: str
    data_type: SensitiveDataType
    severity: DLPSeverity
    description: str
    enabled: bool = True
    requires_checksum_validation: bool = False
