"""CyberShield Enterprise - Deception Orchestrator Schemas.
Data contracts for canary honeytokens, endpoint memory lures,
high-interaction service emulators, and deterministic deception alerts.
"""

from enum import Enum
from typing import Dict, List, Optional, Any
from datetime import datetime, timezone
from pydantic import BaseModel, Field


class HoneytokenType(str, Enum):
    AWS_KEY = "AWS_KEY"
    KERBEROS_TICKET = "KERBEROS_TICKET"
    DATABASE_CREDENTIAL = "DATABASE_CREDENTIAL"
    API_BEARER_TOKEN = "API_BEARER_TOKEN"
    SSH_PRIVATE_KEY = "SSH_PRIVATE_KEY"
    LSASS_MEMORY_BAIT = "LSASS_MEMORY_BAIT"


class EmulatedServiceType(str, Enum):
    REDIS_CACHE = "REDIS_CACHE"
    POSTGRES_DB = "POSTGRES_DB"
    DOCKER_DAEMON_API = "DOCKER_DAEMON_API"
    SMB_SHARE = "SMB_SHARE"


class Honeytoken(BaseModel):
    """Cryptographically tagged decoy credential or key designed to alert upon use."""
    token_id: str = Field(..., description="Unique canary identifier")
    token_type: HoneytokenType
    decoy_username: str
    token_value: str
    target_service: str
    signature_hash: str
    alerts_triggered_count: int = Field(default=0)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class DeceptionLure(BaseModel):
    """Decoy breadcrumb placed on an enterprise asset (in memory or filesystem)."""
    lure_id: str
    lure_type: HoneytokenType
    deployed_host_id: str
    file_path_or_location: str
    honeytoken_id: str
    is_active: bool = True
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class DeceptionInteractionEvent(BaseModel):
    """Raw adversarial probe or interaction logged by a service emulator."""
    event_id: str
    service_type: EmulatedServiceType
    source_ip: str
    source_port: int
    command_or_query: str
    accessed_honeytoken: Optional[str] = None
    raw_payload: Optional[str] = None
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class DeceptionAlert(BaseModel):
    """High-fidelity zero-false-positive alert triggered by honeytoken or emulator interaction."""
    alert_id: str
    source_ip: str
    adversary_action: str
    service_or_lure: str
    token_id: Optional[str] = None
    severity: str = Field(default="CRITICAL")
    confidence: float = Field(default=1.0)
    mitre_technique: str
    forensic_details: Dict[str, Any] = Field(default_factory=dict)
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class ServiceEmulatorStatus(BaseModel):
    """Status and interaction metrics of an active decoy service."""
    service_type: EmulatedServiceType
    is_active: bool
    port: int
    interactions_count: int
    unique_sources_count: int
