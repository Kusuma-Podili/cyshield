"""
CyberShield Enterprise - Security Alerts Pydantic v2 Schemas
Validates alert creations, triage status transitions, notes, and suppression rules.
"""

from datetime import datetime
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field, ConfigDict


class AlertBase(BaseModel):
    """Base fields for Security Alert."""
    title: str = Field(..., min_length=3, max_length=256, description="Descriptive alert title")
    description: str = Field(..., description="Detailed diagnosis and evidence summary")
    severity: str = Field(default="MEDIUM", description="Alert severity: LOW, MEDIUM, HIGH, CRITICAL")
    engine: str = Field(default="SIGMA", description="Originating detection engine")
    rule_id: str = Field(..., description="Unique rule or signature identifier")
    rule_name: str = Field(..., description="Human-readable rule title")
    source_event_id: Optional[str] = None
    host_name: Optional[str] = None
    host_ip: Optional[str] = None
    user_name: Optional[str] = None
    mitre_tactic: Optional[str] = None
    mitre_technique_id: Optional[str] = None
    mitre_technique_name: Optional[str] = None


class AlertCreate(AlertBase):
    """Schema for creating a new security alert."""
    pass


class AlertUpdate(BaseModel):
    """Schema for updating alert status, assignee, or suppression."""
    status: Optional[str] = None
    assigned_analyst_id: Optional[int] = None
    assigned_analyst_name: Optional[str] = None
    suppressed: Optional[bool] = None
    suppression_reason: Optional[str] = None
    resolution_summary: Optional[str] = None


class TriageNote(BaseModel):
    """Single analyst investigation note."""
    author: str
    timestamp: str
    note: str


class AlertResponse(AlertBase):
    """Detailed response schema representing a triageable security alert."""
    id: str
    alert_code: str
    status: str
    assigned_analyst_id: Optional[int] = None
    assigned_analyst_name: Optional[str] = None
    incident_id: Optional[str] = None
    occurrence_count: int
    first_seen: datetime
    last_seen: datetime
    triage_notes: List[Dict[str, Any]] = Field(default_factory=list)
    suppressed: bool
    suppression_reason: Optional[str] = None
    resolved_at: Optional[datetime] = None
    resolved_by: Optional[str] = None
    resolution_summary: Optional[str] = None
    created_at: datetime
    updated_at: datetime

    model_config = ConfigDict(from_attributes=True)


class AlertPaginatedList(BaseModel):
    """Paginated collection of security alerts."""
    total: int
    page: int
    page_size: int
    items: List[AlertResponse]


class AlertTriageRequest(BaseModel):
    """Request to advance alert through the triage lifecycle."""
    status: str = Field(..., pattern="^(ASSIGNED|UNDER_INVESTIGATION|CONTAINED|RESOLVED|FALSE_POSITIVE)$")
    resolution_summary: Optional[str] = None
    note: Optional[str] = None


class AlertNoteRequest(BaseModel):
    """Request to append an analyst investigation note."""
    note: str = Field(..., min_length=2, max_length=2000, description="Analyst investigative note")


class AlertEscalateRequest(BaseModel):
    """Request to escalate alert into a formal Security Incident."""
    incident_title: Optional[str] = None
    priority: str = Field(default="HIGH", pattern="^(LOW|MEDIUM|HIGH|CRITICAL)$")
    initial_containment: bool = False


class AlertSuppressionRuleCreate(BaseModel):
    """Create a persistent suppression filter."""
    name: str = Field(..., min_length=3, max_length=128)
    rule_name_pattern: Optional[str] = None
    host_pattern: Optional[str] = None
    user_pattern: Optional[str] = None
    reason: str = Field(..., min_length=5)


class AlertSuppressionRuleResponse(AlertSuppressionRuleCreate):
    """Suppression rule response schema."""
    id: str
    created_by: str
    is_active: bool
    created_at: datetime

    model_config = ConfigDict(from_attributes=True)


class AlertKPISummary(BaseModel):
    """Consolidated KPI counters for the SOC alert queue."""
    total_alerts: int
    new_alerts: int
    under_investigation: int
    resolved_alerts: int
    critical_alerts: int
    high_alerts: int
    medium_alerts: int
    low_alerts: int
    mean_time_to_triage_mins: float
    top_affected_hosts: List[Dict[str, Any]]
