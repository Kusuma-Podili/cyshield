"""Pydantic v2 Schemas for DFIR Forensic Artifact Analysis & Super-Timeline."""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class ArtifactType(str, Enum):
    EVTX = "EVTX"
    MFT = "MFT"
    PREFETCH = "PREFETCH"
    SHIMCACHE = "SHIMCACHE"
    LNK = "LNK"
    AUDITD = "AUDITD"
    MEMORY_STRINGS = "MEMORY_STRINGS"


class FindingSeverity(str, Enum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class ForensicFinding(BaseModel):
    finding_id: str
    severity: FindingSeverity
    title: str
    description: str
    timestamp: datetime
    artifact_source: ArtifactType
    mitre_technique: Optional[str] = None
    iocs: List[str] = Field(default_factory=list)
    evidence_snippet: Dict[str, Any] = Field(default_factory=dict)


class TimelineEvent(BaseModel):
    timestamp: datetime
    event_type: str
    source_artifact: ArtifactType
    entity_name: str
    action: str
    details: Dict[str, Any] = Field(default_factory=dict)
    is_suspicious: bool = False
    finding_id: Optional[str] = None


class DFIRAnalysisResult(BaseModel):
    success: bool = True
    artifact_type: ArtifactType
    filename: str
    parsed_records_count: int = 0
    findings_count: int = 0
    timeline_events_count: int = 0
    execution_time_ms: float = 0.0
    findings: List[ForensicFinding] = Field(default_factory=list)
    timeline: List[TimelineEvent] = Field(default_factory=list)
    summary: Dict[str, Any] = Field(default_factory=dict)
    error_message: Optional[str] = None


class ArtifactAnalyzeRequest(BaseModel):
    artifact_type: ArtifactType
    filename: str = "artifact.bin"
    payload_hex: Optional[str] = None
    payload_base64: Optional[str] = None
    payload_text: Optional[str] = None
    case_id: Optional[str] = None


class SuperTimelineRequest(BaseModel):
    case_id: Optional[str] = None
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    artifact_types: Optional[List[ArtifactType]] = None
    only_suspicious: bool = False


class SuperTimelineResponse(BaseModel):
    total_events: int
    suspicious_events: int
    timeline: List[TimelineEvent]
