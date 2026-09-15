"""CyberShield Enterprise - Graph Neural Network & GraphSAGE Schemas.
Defines data structures for heterogeneous enterprise attack graphs, feature vectors,
inductive neural embeddings, and node/path threat classification.
"""

from enum import Enum
from typing import Dict, List, Optional, Any
from datetime import datetime, timezone
from pydantic import BaseModel, Field


class GraphNodeType(str, Enum):
    HOST = "HOST"
    PROCESS = "PROCESS"
    USER = "USER"
    SOCKET = "SOCKET"
    FILE = "FILE"
    REGISTRY = "REGISTRY"
    DNS_QUERY = "DNS_QUERY"
    ALERT = "ALERT"


class GraphEdgeType(str, Enum):
    SPAWNED = "SPAWNED"
    AUTHENTICATED_AS = "AUTHENTICATED_AS"
    CONNECTED_TO = "CONNECTED_TO"
    RESOLVED = "RESOLVED"
    READ_FILE = "READ_FILE"
    MODIFIED_FILE = "MODIFIED_FILE"
    INJECTED_INTO = "INJECTED_INTO"
    LATERAL_ACCESS = "LATERAL_ACCESS"
    TRIGGERED_ALERT = "TRIGGERED_ALERT"


class AggregatorType(str, Enum):
    MEAN = "MEAN"
    POOLING = "POOLING"
    ATTENTION = "ATTENTION"


class ThreatRole(str, Enum):
    BENIGN = "BENIGN"
    SUSPICIOUS_UNUSUAL = "SUSPICIOUS_UNUSUAL"
    LATERAL_PIVOT = "LATERAL_PIVOT"
    C2_BEACON = "C2_BEACON"
    RANSOMWARE_EXECUTOR = "RANSOMWARE_EXECUTOR"
    CREDENTIAL_ACCESS = "CREDENTIAL_ACCESS"
    EXFILTRATION_STAGING = "EXFILTRATION_STAGING"


class SecurityNode(BaseModel):
    """Represents an entity node in the heterogeneous enterprise security graph."""
    node_id: str = Field(..., description="Unique entity identifier (e.g. host-10.0.1.5, proc-4912)")
    node_type: GraphNodeType = Field(..., description="Entity category")
    label: str = Field(..., description="Human-readable display label")
    properties: Dict[str, Any] = Field(default_factory=dict, description="Metadata key-values")
    base_risk_score: float = Field(default=0.0, ge=0.0, le=100.0, description="Heuristic baseline risk")
    is_compromised_seed: bool = Field(default=False, description="Flag indicating ground-truth patient zero or IOC")
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class SecurityEdge(BaseModel):
    """Represents a directed interaction or telemetry link between two security entities."""
    source_id: str = Field(..., description="Source node ID")
    target_id: str = Field(..., description="Target node ID")
    edge_type: GraphEdgeType = Field(..., description="Semantics of interaction")
    weight: float = Field(default=1.0, ge=0.0, description="Edge affinity or interaction frequency")
    properties: Dict[str, Any] = Field(default_factory=dict, description="Connection metadata (bytes, port, cmd)")
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class HeterogeneousGraph(BaseModel):
    """Container for the multi-relational enterprise attack graph."""
    graph_id: str = Field(..., description="Graph identifier or incident snapshot ID")
    tenant_id: str = Field(default="TENANT-DEFAULT", description="Multi-tenant isolation boundary")
    nodes: Dict[str, SecurityNode] = Field(default_factory=dict)
    edges: List[SecurityEdge] = Field(default_factory=list)
    metadata: Dict[str, Any] = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class NodeFeatureVector(BaseModel):
    """Extracted numeric & categorical feature vector for a graph node."""
    node_id: str
    node_type: GraphNodeType
    features: List[float] = Field(..., description="Normalized feature vector for neural layer")
    feature_dimension: int = Field(...)
    feature_names: List[str] = Field(default_factory=list)


class NodeEmbeddingResult(BaseModel):
    """Inductively generated embedding vector from GraphSAGE layers."""
    node_id: str
    node_type: GraphNodeType
    embedding: List[float] = Field(..., description="Dense continuous representation vector")
    embedding_dimension: int
    l2_norm: float
    neighborhood_size: int
    k_hops: int


class ExplanatoryNeighbor(BaseModel):
    """Neighbor node that contributed most significantly to the node's risk rating."""
    neighbor_id: str
    neighbor_type: GraphNodeType
    edge_type: GraphEdgeType
    influence_score: float
    neighbor_label: str


class NodeClassificationResult(BaseModel):
    """Deep learning threat classification result for a graph node."""
    node_id: str
    node_type: GraphNodeType
    label: str
    malicious_prob: float = Field(..., ge=0.0, le=1.0)
    predicted_role: ThreatRole
    confidence: float = Field(..., ge=0.0, le=1.0)
    anomaly_score: float = Field(..., ge=0.0, le=100.0)
    top_influential_neighbors: List[ExplanatoryNeighbor] = Field(default_factory=list)
    mitre_tactics: List[str] = Field(default_factory=list)
    is_threat: bool = False


class AttackPathEvaluationRequest(BaseModel):
    """Request to score an end-to-end multi-hop traversal or alert chain."""
    graph_id: str
    path_nodes: List[str] = Field(..., min_length=2, description="Ordered sequence of node IDs along attack path")
    tenant_id: str = Field(default="TENANT-DEFAULT")


class AttackPathEvaluationResult(BaseModel):
    """Evaluation of an entire sequence of multi-hop pivots across the graph."""
    graph_id: str
    path_nodes: List[str]
    total_path_risk: float = Field(..., ge=0.0, le=100.0)
    average_malicious_prob: float = Field(..., ge=0.0, le=1.0)
    bottleneck_node_id: str
    verdict: str
    is_compromise_chain: bool
    transition_risks: List[Dict[str, Any]] = Field(default_factory=list)
    mitre_killchain_stages: List[str] = Field(default_factory=list)
    recommended_interception_point: str


class GNNTrainRequest(BaseModel):
    """Request to train or calibrate the GraphSAGE weights on an annotated security graph."""
    graph_id: str
    epochs: int = Field(default=20, ge=1, le=200)
    learning_rate: float = Field(default=0.01, ge=0.0001, le=1.0)
    aggregator: AggregatorType = Field(default=AggregatorType.MEAN)
    embedding_dim: int = Field(default=16, ge=4, le=128)


class GNNModelStatus(BaseModel):
    """Operational status and hyperparameter metrics of the GNN subsystem."""
    model_version: str
    trained_graphs_count: int
    total_nodes_embedded: int
    aggregator: AggregatorType
    embedding_dimension: int
    num_layers: int
    last_calibration_time: Optional[datetime] = None
    is_calibrated: bool = True
