"""Pydantic v2 Schemas for System Health, Diagnostics & Backup Management."""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class SystemHealthStatus(str, Enum):
    """Overall status of the platform or individual subsystem."""
    HEALTHY = "HEALTHY"
    DEGRADED = "DEGRADED"
    CRITICAL = "CRITICAL"
    MAINTENANCE = "MAINTENANCE"


class ComponentHealth(BaseModel):
    """Status information for an individual component or engine."""
    status: SystemHealthStatus = SystemHealthStatus.HEALTHY
    latency_ms: float = Field(default=0.0, description="Response time or evaluation latency in milliseconds")
    message: str = Field(default="Operational", description="Human-readable status summary")
    details: Dict[str, Any] = Field(default_factory=dict, description="Component-specific telemetry details")


class HardwareMetrics(BaseModel):
    """Host machine hardware telemetry metrics."""
    platform: str
    python_version: str
    memory_total_mb: float
    memory_used_mb: float
    memory_available_mb: float
    memory_percent: float
    disk_total_gb: float
    disk_used_gb: float
    disk_free_gb: float
    disk_percent: float
    cpu_percent: float
    process_pid: int
    uptime_seconds: float


class DatabaseDiagnostics(BaseModel):
    """Database connection pool and operational diagnostics."""
    status: SystemHealthStatus
    latency_ms: float
    engine_dialect: str
    database_url_masked: str
    tables_count: int
    total_records_count: int
    pool_overflow: Optional[int] = None
    active_connections: int = 1


class HealthSummaryResponse(BaseModel):
    """Lightweight health response for liveness checks."""
    status: SystemHealthStatus
    version: str
    timestamp: datetime
    uptime_seconds: float


class ReadinessResponse(BaseModel):
    """Readiness probe response verifying vital subsystem operational readiness."""
    status: SystemHealthStatus
    ready: bool
    timestamp: datetime
    checks: Dict[str, bool]
    message: str


class DiagnosticsResponse(BaseModel):
    """Comprehensive system diagnostics telemetry payload."""
    status: SystemHealthStatus
    version: str
    environment: str
    timestamp: datetime
    uptime_seconds: float
    hardware: HardwareMetrics
    database: DatabaseDiagnostics
    subsystems: Dict[str, ComponentHealth]


class BackupMetadataResponse(BaseModel):
    """Snapshot metadata for database backups."""
    filename: str
    size_bytes: int
    created_at: datetime
    checksum_sha256: str
    is_verified: bool
    note: Optional[str] = None


class BackupListResponse(BaseModel):
    """Collection of available database backup archives."""
    total: int
    backups: List[BackupMetadataResponse]


class BackupCreateRequest(BaseModel):
    """Request payload to trigger on-demand database backup snapshot."""
    note: Optional[str] = Field(default="Manual on-demand backup", description="Descriptive annotation for this snapshot")


class BackupVerifyResponse(BaseModel):
    """Cryptographic integrity verification result for a backup archive."""
    filename: str
    verified: bool
    checksum_sha256: str
    calculated_sha256: str
    message: str
