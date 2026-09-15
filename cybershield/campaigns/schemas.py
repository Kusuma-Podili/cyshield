"""
Threat Attribution & Adversary Campaign Graph Schemas and Models.
Implements the Diamond Model of Intrusion Analysis (Adversary, Capability, Infrastructure, Victim).
"""

from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class DiamondVertexType(str, Enum):
    ADVERSARY = "ADVERSARY"
    CAPABILITY = "CAPABILITY"
    INFRASTRUCTURE = "INFRASTRUCTURE"
    VICTIM = "VICTIM"


class CampaignStatus(str, Enum):
    ACTIVE = "ACTIVE"
    CONTAINED = "CONTAINED"
    DORMANT = "DORMANT"
    HISTORICAL = "HISTORICAL"


class AttributionConfidence(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CONFIRMED = "CONFIRMED"


class ThreatActorProfile(BaseModel):
    """Profile of a state-sponsored or cybercrime threat actor group."""
    actor_id: str
    name: str
    aliases: List[str] = Field(default_factory=list)
    country_of_origin: Optional[str] = None
    motivations: List[str] = Field(default_factory=list)  # ESPIONAGE, FINANCIAL, SABOTAGE
    target_sectors: List[str] = Field(default_factory=list)
    signature_ttps: List[str] = Field(default_factory=list)  # MITRE IDs: T1059, T1078, etc.
    known_malware_families: List[str] = Field(default_factory=list)
    observed_infrastructure_patterns: List[str] = Field(default_factory=list)


class CampaignGraphNode(BaseModel):
    """Vertex in the Diamond Model campaign graph."""
    node_id: str
    vertex_type: DiamondVertexType
    label: str
    attributes: Dict[str, Any] = Field(default_factory=dict)
    first_observed: datetime = Field(default_factory=datetime.utcnow)


class CampaignGraphEdge(BaseModel):
    """Directed relationship between vertices in the intrusion graph."""
    source_id: str
    target_id: str
    relation: str  # e.g., "UTILIZES_INFRASTRUCTURE", "TARGETS_VICTIM", "DEPLOYS_CAPABILITY"
    confidence: float = 0.8  # 0.0 to 1.0
    evidence: str = ""


class ThreatCampaign(BaseModel):
    """Cohesive adversary intrusion campaign aggregating disparate alerts and telemetry."""
    campaign_id: str
    name: str
    description: str
    status: CampaignStatus = CampaignStatus.ACTIVE
    attributed_actor: Optional[str] = None
    attribution_confidence: AttributionConfidence = AttributionConfidence.MEDIUM
    attribution_score: float = 65.0  # 0.0 to 100.0
    kill_chain_phases: List[str] = Field(default_factory=list)
    nodes: List[CampaignGraphNode] = Field(default_factory=list)
    edges: List[CampaignGraphEdge] = Field(default_factory=list)
    associated_alert_ids: List[str] = Field(default_factory=list)
    first_seen: datetime = Field(default_factory=datetime.utcnow)
    last_seen: datetime = Field(default_factory=datetime.utcnow)


class CampaignCorrelationRequest(BaseModel):
    """Request to correlate alert indicators into threat campaigns."""
    alert_ids: List[str] = Field(default_factory=list)
    similarity_threshold: float = 0.40
