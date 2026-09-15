"""
Automated Incident Root Cause Analysis (RCA) & Causal Graph Engine Schemas.
Models causal graph nodes, edges, probabilistic root cause hypotheses, and timeline reconstruction.
"""

from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class CausalNodeType(str, Enum):
    PROCESS_EXECUTION = "PROCESS_EXECUTION"
    NETWORK_CONNECTION = "NETWORK_CONNECTION"
    FILE_MODIFICATION = "FILE_MODIFICATION"
    AUTH_ATTEMPT = "AUTH_ATTEMPT"
    CONFIG_CHANGE = "CONFIG_CHANGE"
    SECURITY_ALERT = "SECURITY_ALERT"


class RootCauseConfidence(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    DEFINITIVE = "DEFINITIVE"


class CausalNode(BaseModel):
    """Vertex in the incident causal progression graph."""
    node_id: str
    node_type: CausalNodeType
    timestamp: datetime
    entity_id: str  # host, user, or IP
    description: str
    attributes: Dict[str, Any] = Field(default_factory=dict)
    is_anomaly: bool = False


class CausalEdge(BaseModel):
    """Directed causal dependency between two events (source caused target)."""
    source_id: str
    target_id: str
    temporal_delta_ms: float
    causal_probability: float = 0.85  # 0.0 to 1.0
    relationship_type: str  # e.g., "SPAWNED_BY", "DOWNLOADED_VIA", "TRIGGERED_BY", "ESCALATED_FROM"


class RootCauseHypothesis(BaseModel):
    """Hypothesized initial root cause event (Patient Zero)."""
    hypothesis_id: str
    root_node_id: str
    summary: str
    initial_access_vector: str
    confidence: RootCauseConfidence
    causal_score: float  # 0 to 100
    evidence_chain: List[str] = Field(default_factory=list)
    recommended_remediations: List[str] = Field(default_factory=list)


class IncidentRCAReport(BaseModel):
    """Consolidated Root Cause Analysis document for an incident."""
    report_id: str
    incident_id: str
    generated_at: datetime = Field(default_factory=datetime.utcnow)
    nodes: List[CausalNode] = Field(default_factory=list)
    edges: List[CausalEdge] = Field(default_factory=list)
    patient_zero_hypothesis: Optional[RootCauseHypothesis] = None
    secondary_hypotheses: List[RootCauseHypothesis] = Field(default_factory=list)
    total_events_analyzed: int = 0
    blast_radius_hosts: List[str] = Field(default_factory=list)


class RCARequest(BaseModel):
    """Request to initiate automated causal analysis on an incident."""
    incident_id: str
    events: List[Dict[str, Any]] = Field(default_factory=list)
