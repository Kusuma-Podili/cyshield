"""
Threat Hunting Data Schemas and Models.
Enterprise workspace for hypothesis-driven threat hunting across telemetry,
EDR logs, network dissector flows, and system events.
"""

from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class HuntStatus(str, Enum):
    DRAFT = "DRAFT"
    SCHEDULED = "SCHEDULED"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    ARCHIVED = "ARCHIVED"
    FAILED = "FAILED"


class HuntConfidence(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class HuntFinding(BaseModel):
    """An individual piece of suspicious evidence or anomalous event discovered during a hunt."""
    id: str
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    source_event_id: Optional[str] = None
    technique_id: str
    technique_name: str
    entity_id: str  # host_id, user_name, ip_address
    entity_type: str  # host, user, network, process
    details: Dict[str, Any] = Field(default_factory=dict)
    confidence: HuntConfidence = HuntConfidence.MEDIUM
    risk_score: float = 50.0
    recommended_action: str = ""


class HuntHypothesis(BaseModel):
    """Structured hypothesis for proactive threat hunting."""
    id: str
    title: str
    description: str
    mitre_tactics: List[str] = Field(default_factory=list)
    mitre_technique_ids: List[str] = Field(default_factory=list)
    author: str = "SOC Threat Hunter"
    target_data_sources: List[str] = Field(default_factory=list)  # e.g., ["process", "network", "auth", "dns"]
    query_template: str
    parameters: Dict[str, Any] = Field(default_factory=dict)
    status: HuntStatus = HuntStatus.DRAFT
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)
    tags: List[str] = Field(default_factory=list)


class HuntExecutionRequest(BaseModel):
    """Parameters for executing a hunt."""
    hypothesis_id: str
    lookback_minutes: int = 60
    custom_filters: Dict[str, Any] = Field(default_factory=dict)
    min_confidence: HuntConfidence = HuntConfidence.LOW
    limit: int = 500


class HuntExecutionResult(BaseModel):
    """Result of an executed threat hunt."""
    execution_id: str
    hypothesis_id: str
    status: HuntStatus
    started_at: datetime
    completed_at: Optional[datetime] = None
    duration_ms: float = 0.0
    total_events_scanned: int = 0
    matched_events_count: int = 0
    findings: List[HuntFinding] = Field(default_factory=list)
    extracted_iocs: List[Dict[str, str]] = Field(default_factory=list)  # [{"type": "ip", "value": "..."}, ...]
    aggregate_risk_score: float = 0.0
    summary: str = ""


class HuntTemplate(BaseModel):
    """Pre-configured enterprise hunting template."""
    id: str
    name: str
    category: str
    description: str
    mitre_technique_id: str
    data_sources: List[str]
    default_query: str
    severity: str = "MEDIUM"
