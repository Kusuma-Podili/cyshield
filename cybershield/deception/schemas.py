"""Pydantic v2 Schemas for Deception Technology, Canaries & Decoy Traps."""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class TrapType(str, Enum):
    SSH = "SSH"
    SMB = "SMB"
    HTTP_ADMIN = "HTTP_ADMIN"
    DATABASE = "DATABASE"
    FTP = "FTP"
    RDP = "RDP"


class CanaryType(str, Enum):
    API_KEY = "API_KEY"
    HONEYFILE = "HONEYFILE"
    DATABASE_RECORD = "DATABASE_RECORD"
    DNS_TOKEN = "DNS_TOKEN"
    CANARY_USER = "CANARY_USER"


class CanaryToken(BaseModel):
    token_id: str
    canary_type: CanaryType
    name: str
    description: str
    canary_value: str
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    is_tripped: bool = False
    trip_count: int = 0
    last_tripped_at: Optional[datetime] = None
    trip_source_ip: Optional[str] = None
    metadata: Dict[str, Any] = Field(default_factory=dict)


class CanaryGenerateRequest(BaseModel):
    canary_type: CanaryType
    name: str
    description: Optional[str] = "Deception tripwire token"
    target_path_or_host: Optional[str] = None


class TripwireAlert(BaseModel):
    alert_id: str
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    trap_or_canary_id: str
    trap_type: str
    source_ip: str
    source_port: Optional[int] = None
    severity: str = "CRITICAL"
    title: str
    description: str
    attacker_payload: Dict[str, Any] = Field(default_factory=dict)
    mitre_technique: str = "T1078"


class DecoyServiceStatus(BaseModel):
    trap_id: str
    trap_type: TrapType
    name: str
    port: int
    is_active: bool
    total_interactions: int = 0
    last_interaction: Optional[datetime] = None
    details: Dict[str, Any] = Field(default_factory=dict)


class DeceptionStatsResponse(BaseModel):
    total_canaries: int
    active_canaries: int
    tripped_canaries: int
    total_traps: int
    active_traps: int
    total_tripwire_alerts: int
    recent_alerts: List[TripwireAlert] = Field(default_factory=list)
