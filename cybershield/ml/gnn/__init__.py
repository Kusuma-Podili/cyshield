"""CyberShield Enterprise - Graph Neural Network & GraphSAGE Threat Classifier Subsystem.
Provides inductive representation learning on heterogeneous enterprise security graphs
for malicious node classification, lateral movement detection, and multi-hop attack path scoring.
"""

from .schemas import (
    GraphNodeType,
    GraphEdgeType,
    NodeFeatureVector,
    SecurityNode,
    SecurityEdge,
    HeterogeneousGraph,
    AggregatorType,
    NodeEmbeddingResult,
    NodeClassificationResult,
    AttackPathEvaluationRequest,
    AttackPathEvaluationResult,
)
from .graph import SecurityGraphBuilder
from .sage import GraphSAGELayer, InductiveGraphEmbeddingModel
from .classifier import ThreatGraphNodeClassifier

__all__ = [
    "GraphNodeType",
    "GraphEdgeType",
    "NodeFeatureVector",
    "SecurityNode",
    "SecurityEdge",
    "HeterogeneousGraph",
    "AggregatorType",
    "NodeEmbeddingResult",
    "NodeClassificationResult",
    "AttackPathEvaluationRequest",
    "AttackPathEvaluationResult",
    "SecurityGraphBuilder",
    "GraphSAGELayer",
    "InductiveGraphEmbeddingModel",
    "ThreatGraphNodeClassifier",
]
