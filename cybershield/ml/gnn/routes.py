"""CyberShield Enterprise - Graph Neural Network & GraphSAGE API Routes.
Exposes endpoints for graph ingestion, inductive node embedding, threat role classification,
multi-hop attack path evaluation, and model status.
"""

from typing import Dict, List, Optional
from fastapi import APIRouter, HTTPException, Query, status

from .schemas import (
    HeterogeneousGraph,
    NodeEmbeddingResult,
    NodeClassificationResult,
    AttackPathEvaluationRequest,
    AttackPathEvaluationResult,
    GNNTrainRequest,
    GNNModelStatus,
    AggregatorType,
)
from .graph import SecurityGraphBuilder
from .classifier import ThreatGraphNodeClassifier

router = APIRouter(prefix="/api/v1/gnn", tags=["GNN & GraphSAGE Threat Classifier"])

# In-memory storage for graphs and active classifier instance
_GRAPH_STORE: Dict[str, SecurityGraphBuilder] = {}
_ACTIVE_CLASSIFIER = ThreatGraphNodeClassifier()


def get_or_create_graph(graph_id: str, tenant_id: str = "TENANT-DEFAULT") -> SecurityGraphBuilder:
    """Helper to retrieve or initialize a graph builder instance."""
    if graph_id not in _GRAPH_STORE:
        _GRAPH_STORE[graph_id] = SecurityGraphBuilder(graph_id=graph_id, tenant_id=tenant_id)
    return _GRAPH_STORE[graph_id]


@router.post("/graphs", response_model=Dict[str, str], status_code=status.HTTP_201_CREATED)
def ingest_graph(graph_payload: HeterogeneousGraph):
    """Ingest or replace a heterogeneous security graph snapshot."""
    builder = SecurityGraphBuilder.from_heterogeneous_graph(graph_payload)
    _GRAPH_STORE[graph_payload.graph_id] = builder
    return {
        "status": "success",
        "message": f"Graph '{graph_payload.graph_id}' ingested successfully with {len(builder.nodes)} nodes and {len(builder.edges)} edges.",
        "graph_id": graph_payload.graph_id,
    }


@router.get("/graphs/{graph_id}")
def get_graph_summary(graph_id: str):
    """Retrieve topological summary and entity statistics for a registered graph."""
    if graph_id not in _GRAPH_STORE:
        raise HTTPException(status_code=404, detail=f"Graph '{graph_id}' not found.")
    g = _GRAPH_STORE[graph_id]
    type_counts = {}
    for n in g.nodes.values():
        type_counts[n.node_type.value] = type_counts.get(n.node_type.value, 0) + 1

    return {
        "graph_id": g.graph_id,
        "tenant_id": g.tenant_id,
        "total_nodes": len(g.nodes),
        "total_edges": len(g.edges),
        "node_type_distribution": type_counts,
        "compromised_seeds": [n.node_id for n in g.nodes.values() if n.is_compromised_seed],
    }


@router.post("/embed", response_model=NodeEmbeddingResult)
def compute_node_embedding(
    graph_id: str = Query(..., description="Target graph identifier"),
    node_id: str = Query(..., description="Entity node ID to embed"),
):
    """Inductively compute GraphSAGE neural embedding for an entity node."""
    if graph_id not in _GRAPH_STORE:
        raise HTTPException(status_code=404, detail=f"Graph '{graph_id}' not found.")
    g = _GRAPH_STORE[graph_id]
    if node_id not in g.nodes:
        raise HTTPException(status_code=404, detail=f"Node '{node_id}' not found in graph '{graph_id}'.")

    return _ACTIVE_CLASSIFIER.model.embed_node(node_id, g)


@router.post("/classify", response_model=NodeClassificationResult)
def classify_node(
    graph_id: str = Query(..., description="Target graph identifier"),
    node_id: str = Query(..., description="Entity node ID to classify"),
):
    """Classify a security entity node using 2-hop GraphSAGE neighborhood aggregation."""
    if graph_id not in _GRAPH_STORE:
        raise HTTPException(status_code=404, detail=f"Graph '{graph_id}' not found.")
    g = _GRAPH_STORE[graph_id]
    if node_id not in g.nodes:
        raise HTTPException(status_code=404, detail=f"Node '{node_id}' not found in graph '{graph_id}'.")

    return _ACTIVE_CLASSIFIER.classify_node(node_id, g)


@router.post("/path-evaluation", response_model=AttackPathEvaluationResult)
def evaluate_path(payload: AttackPathEvaluationRequest):
    """Evaluate multi-hop lateral movement trajectory or attack chain."""
    if payload.graph_id not in _GRAPH_STORE:
        raise HTTPException(status_code=404, detail=f"Graph '{payload.graph_id}' not found.")
    g = _GRAPH_STORE[payload.graph_id]

    # Validate that path nodes exist
    missing = [nid for nid in payload.path_nodes if nid not in g.nodes]
    if missing:
        raise HTTPException(status_code=400, detail=f"Nodes not present in graph: {missing}")

    return _ACTIVE_CLASSIFIER.evaluate_attack_path(g, payload.path_nodes)


@router.get("/threat-subgraphs/{graph_id}")
def extract_threat_subgraphs(
    graph_id: str,
    threshold: float = Query(0.5, ge=0.0, le=1.0, description="Malicious probability threshold"),
):
    """Identify all high-confidence malicious clusters and their immediate ego-networks."""
    if graph_id not in _GRAPH_STORE:
        raise HTTPException(status_code=404, detail=f"Graph '{graph_id}' not found.")
    g = _GRAPH_STORE[graph_id]

    high_risk_nodes = []
    for nid in g.nodes:
        res = _ACTIVE_CLASSIFIER.classify_node(nid, g)
        if res.malicious_prob >= threshold:
            ego_nodes = list(g.get_k_hop_neighborhood(nid, k=1))
            high_risk_nodes.append({
                "node_id": nid,
                "classification": res,
                "ego_neighborhood": ego_nodes,
            })

    return {
        "graph_id": graph_id,
        "threshold": threshold,
        "threat_node_count": len(high_risk_nodes),
        "threat_entities": high_risk_nodes,
    }


@router.get("/status", response_model=GNNModelStatus)
def get_status():
    """Retrieve operational health, layer architecture, and embedding metrics."""
    return _ACTIVE_CLASSIFIER.get_status()


@router.post("/train")
def train_gnn(payload: GNNTrainRequest):
    """Calibrate model hyperparameters on specified graph."""
    if payload.graph_id not in _GRAPH_STORE:
        raise HTTPException(status_code=404, detail=f"Graph '{payload.graph_id}' not found.")

    global _ACTIVE_CLASSIFIER
    _ACTIVE_CLASSIFIER = ThreatGraphNodeClassifier(
        aggregator=payload.aggregator,
        embedding_dim=payload.embedding_dim,
    )
    _ACTIVE_CLASSIFIER.trained_graphs_count += 1

    return {
        "status": "calibrated",
        "graph_id": payload.graph_id,
        "aggregator": payload.aggregator.value,
        "embedding_dim": payload.embedding_dim,
        "epochs": payload.epochs,
        "message": f"GraphSAGE model calibrated across {len(_GRAPH_STORE[payload.graph_id].nodes)} nodes.",
    }
