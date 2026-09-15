"""
C2 Threat Emulation and Red Team Agent Framework Schemas.
Defines listener configurations, beacon sessions, tasks, jitter algorithms, and telemetry.
"""

from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class C2ListenerProtocol(str, Enum):
    HTTPS = "HTTPS"
    HTTP = "HTTP"
    DNS = "DNS"
    WEBSOCKET = "WEBSOCKET"


class BeaconSessionStatus(str, Enum):
    ACTIVE = "ACTIVE"
    DORMANT = "DORMANT"
    DISCONNECTED = "DISCONNECTED"
    TERMINATED = "TERMINATED"


class C2CommandType(str, Enum):
    SHELL = "SHELL"
    SLEEP_CHANGE = "SLEEP_CHANGE"
    DOWNLOAD = "DOWNLOAD"
    UPLOAD = "UPLOAD"
    PORT_SCAN = "PORT_SCAN"
    SYSTEM_SURVEY = "SYSTEM_SURVEY"
    TERMINATE = "TERMINATE"


class C2Listener(BaseModel):
    """C2 command and control listening interface."""
    listener_id: str
    name: str
    protocol: C2ListenerProtocol = C2ListenerProtocol.HTTPS
    bind_ip: str = "0.0.0.0"
    port: int = 8443
    domain_fronting_host: Optional[str] = None
    ssl_cert_subject: Optional[str] = "CN=api.update-telemetry.org"
    status: str = "RUNNING"  # RUNNING, STOPPED
    total_beacons_connected: int = 0


class C2Task(BaseModel):
    """Task queued for execution on a beacon agent."""
    task_id: str
    session_id: str
    command: C2CommandType
    arguments: Dict[str, Any] = Field(default_factory=dict)
    status: str = "PENDING"  # PENDING, DISPATCHED, COMPLETED, FAILED
    created_at: datetime = Field(default_factory=datetime.utcnow)
    completed_at: Optional[datetime] = None
    output: Optional[str] = None


class BeaconSession(BaseModel):
    """An active simulated adversary agent session."""
    session_id: str
    listener_id: str
    hostname: str
    internal_ip: str
    os_name: str = "Windows 11 Pro"
    pid: int = 4096
    process_name: str = "svchost.exe"
    user_context: str = "CORP\\analyst_test"
    is_elevated: bool = False
    sleep_interval_sec: float = 30.0
    jitter_pct: float = 20.0
    last_checkin: datetime = Field(default_factory=datetime.utcnow)
    status: BeaconSessionStatus = BeaconSessionStatus.ACTIVE
    queued_tasks_count: int = 0


class BeaconCheckinPayload(BaseModel):
    """Beacon heartbeat request to C2 listener."""
    session_id: str
    timestamp: datetime = Field(default_factory=datetime.utcnow)


class BeaconTaskResultPayload(BaseModel):
    """Beacon returning output for a task."""
    session_id: str
    task_id: str
    status: str = "COMPLETED"
    output: str
