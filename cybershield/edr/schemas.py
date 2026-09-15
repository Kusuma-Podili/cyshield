"""Pydantic v2 Schemas for Enterprise Endpoint Detection & Response (EDR)."""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class OSPlatform(str, Enum):
    WINDOWS = "WINDOWS"
    LINUX = "LINUX"
    MACOS = "MACOS"


class AgentStatus(str, Enum):
    ONLINE = "ONLINE"
    DEGRADED = "DEGRADED"
    OFFLINE = "OFFLINE"
    ISOLATED = "ISOLATED"


class EDRCommandAction(str, Enum):
    ISOLATE_NETWORK = "ISOLATE_NETWORK"
    RESTORE_NETWORK = "RESTORE_NETWORK"
    KILL_PROCESS = "KILL_PROCESS"
    QUARANTINE_FILE = "QUARANTINE_FILE"
    COLLECT_TRIAGE = "COLLECT_TRIAGE"
    RUN_YARA_SCAN = "RUN_YARA_SCAN"


class ProcessTelemetryEvent(BaseModel):
    pid: int
    ppid: int
    process_name: str
    image_path: str
    command_line: str
    user: str = "SYSTEM"
    sha256: Optional[str] = None
    parent_process_name: Optional[str] = None
    parent_command_line: Optional[str] = None
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class FIMTelemetryEvent(BaseModel):
    file_path: str
    operation: str  # CREATED, MODIFIED, DELETED, PERMISSIONS_CHANGED
    sha256_before: Optional[str] = None
    sha256_after: Optional[str] = None
    process_id: Optional[int] = None
    user: Optional[str] = None
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class NetworkSocketEvent(BaseModel):
    protocol: str = "TCP"
    local_ip: str
    local_port: int
    remote_ip: str
    remote_port: int
    state: str = "ESTABLISHED"
    pid: int
    process_name: str
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class EDRCommand(BaseModel):
    command_id: str
    action: EDRCommandAction
    target: str
    parameters: Dict[str, Any] = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    status: str = "PENDING"  # PENDING, DISPATCHED, EXECUTED, FAILED


class EDRAgentRegistrationRequest(BaseModel):
    hostname: str
    os_platform: OSPlatform
    os_version: str
    architecture: str = "x86_64"
    ip_addresses: List[str] = Field(default_factory=list)
    mac_addresses: List[str] = Field(default_factory=list)
    agent_version: str = "2.4.0"


class EDRAgentRegistrationResponse(BaseModel):
    agent_id: str
    auth_token: str
    heartbeat_interval_sec: int = 15
    enrolled_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class EDRHeartbeatRequest(BaseModel):
    agent_id: str
    status: AgentStatus = AgentStatus.ONLINE
    cpu_usage_pct: float = Field(..., ge=0.0, le=100.0)
    memory_usage_pct: float = Field(..., ge=0.0, le=100.0)
    disk_usage_pct: float = Field(..., ge=0.0, le=100.0)
    active_threats_count: int = 0


class EDRHeartbeatResponse(BaseModel):
    status: str = "ACK"
    next_heartbeat_sec: int = 15
    pending_commands: List[EDRCommand] = Field(default_factory=list)


class EDRTelemetryBatchRequest(BaseModel):
    agent_id: str
    processes: List[ProcessTelemetryEvent] = Field(default_factory=list)
    fim_events: List[FIMTelemetryEvent] = Field(default_factory=list)
    sockets: List[NetworkSocketEvent] = Field(default_factory=list)


class EDRBehavioralAlert(BaseModel):
    alert_id: str
    agent_id: str
    hostname: str
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW
    mitre_technique: str
    title: str
    description: str
    evidence: Dict[str, Any] = Field(default_factory=dict)
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class EDRCommandDispatch(BaseModel):
    action: EDRCommandAction
    target: str
    parameters: Dict[str, Any] = Field(default_factory=dict)
