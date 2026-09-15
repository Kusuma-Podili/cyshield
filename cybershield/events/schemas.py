"""
CyberShield Enterprise - Security Events Pydantic v2 Schemas
Validates telemetry ingestion batches, CS-QL threat hunting queries, and event streams.
"""

from datetime import datetime
from typing import List, Optional, Dict, Any, Union
from pydantic import BaseModel, Field, ConfigDict


class SecurityEventBase(BaseModel):
    """Base fields for Normalized Telemetry Event."""
    timestamp: datetime
    event_type: str
    severity: str
    source_type: str
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    source_port: Optional[int] = None
    destination_port: Optional[int] = None
    protocol: Optional[str] = None
    host_name: Optional[str] = None
    user_name: Optional[str] = None
    domain: Optional[str] = None
    process_name: Optional[str] = None
    command_line: Optional[str] = None
    file_path: Optional[str] = None
    message: str
    parsed_fields: Dict[str, Any] = Field(default_factory=dict)
    is_anomalous: bool = False
    anomaly_score: float = 0.0


class SecurityEventResponse(SecurityEventBase):
    """Full telemetry event response."""
    id: str
    raw_log: Optional[str] = None
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class EventPaginatedList(BaseModel):
    """Paginated collection of telemetry events."""
    total: int
    page: int
    page_size: int
    items: List[SecurityEventResponse]


class EventIngestRequest(BaseModel):
    """Batch ingestion request containing raw log lines or structured records."""
    logs: List[Union[str, Dict[str, Any]]] = Field(..., min_length=1, max_length=5000)
    source_hint: Optional[str] = None


class EventIngestResponse(BaseModel):
    """Ingestion summary outcome."""
    accepted_count: int
    failed_count: int
    processing_time_ms: float
    status: str = "SUCCESS"


class CSQLQueryRequest(BaseModel):
    """CS-QL Threat Hunting query against database telemetry."""
    query: str = Field(..., min_length=1, max_length=1000, description="CS-QL query string e.g. process_name == 'mimikatz.exe'")
    target: str = Field(default="events", pattern="^(events|alerts)$")
    limit: int = Field(default=50, ge=1, le=500)


class CSQLQueryResponse(BaseModel):
    """Execution output from CS-QL query engine."""
    query: str
    total_matches: int
    execution_time_ms: float
    results: List[Dict[str, Any]]


class EventStatsResponse(BaseModel):
    """Real-time event processing throughput and breakdown."""
    total_events: int
    events_last_hour: int
    events_per_second: float
    source_breakdown: Dict[str, int]
    event_type_breakdown: Dict[str, int]
    anomalous_events_count: int
