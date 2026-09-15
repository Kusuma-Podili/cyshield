"""REST API Endpoints for Advanced Graph, DGA, and Neural Network Models."""

from __future__ import annotations

from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field

from cybershield.auth.dependencies import get_current_user
from cybershield.database.models.user import User
from cybershield.ml.advanced.autoencoder import NetworkFlowAutoencoder
from cybershield.ml.advanced.dga_classifier import DGAClassificationResult, DGAClassifier
from cybershield.ml.advanced.graph_path import AttackPathResult, IdentityHostGraph

router = APIRouter(prefix="/api/ml/advanced", tags=["Advanced ML & Graph Models"])

# Initialize singletons
attack_graph = IdentityHostGraph()
attack_graph.seed_enterprise_topology()
autoencoder = NetworkFlowAutoencoder()


class AttackPathRequest(BaseModel):
    start_node_id: str = Field(..., description="Starting host or user ID e.g. ws-hr-01")
    target_node_id: str = Field(..., description="Target crown-jewel ID e.g. db-financial-sql")


class DGAClassifyRequest(BaseModel):
    domain: str = Field(..., description="Domain name to evaluate e.g. xkjashdf8923.biz")


class FlowScoreRequest(BaseModel):
    flow_id: str = Field("flow-test-01")
    bytes_in: float = Field(..., description="Inbound bytes")
    bytes_out: float = Field(..., description="Outbound bytes")
    duration_sec: float = Field(..., description="Duration in seconds")
    packet_count: float = Field(..., description="Packet count")
    flag_entropy: Optional[float] = Field(0.5, description="TCP flag entropy [0.0 - 1.0]")


@router.post(
    "/graph/attack-paths",
    response_model=AttackPathResult,
    summary="Calculate Shortest Lateral Movement Attack Path",
)
async def calculate_attack_path(
    req: AttackPathRequest,
    current_user: User = Depends(get_current_user),
) -> AttackPathResult:
    """Compute Dijkstra shortest path and risk score toward crown-jewel assets."""
    return attack_graph.find_shortest_attack_path(
        start_node_id=req.start_node_id,
        target_node_id=req.target_node_id,
    )


@router.get(
    "/graph/pivot-hubs",
    summary="Identify Critical Lateral Pivot Hubs",
)
async def list_pivot_hubs(
    min_degree: int = Query(3, ge=1),
    current_user: User = Depends(get_current_user),
) -> List[Dict[str, Any]]:
    """List vertices with highest topological in/out degree connections."""
    return attack_graph.detect_pivot_hubs(min_degree=min_degree)


@router.post(
    "/dga/classify",
    response_model=DGAClassificationResult,
    summary="Classify C2 DGA Domain via Sequence Analysis",
)
async def classify_dga_domain(
    req: DGAClassifyRequest,
    current_user: User = Depends(get_current_user),
) -> DGAClassificationResult:
    """Evaluate domain Shannon entropy, consonant streaks, and n-gram perplexity."""
    return DGAClassifier.classify_domain(req.domain)


@router.post(
    "/autoencoder/score",
    summary="Score Network Flow via Neural Autoencoder Reconstruction",
)
async def score_flow_autoencoder(
    req: FlowScoreRequest,
    current_user: User = Depends(get_current_user),
) -> dict:
    """Pass flow through autoencoder bottleneck and measure MSE reconstruction loss."""
    res = autoencoder.score_flow(
        flow_id=req.flow_id,
        bytes_in=req.bytes_in,
        bytes_out=req.bytes_out,
        duration=req.duration_sec,
        packet_count=req.packet_count,
        flag_entropy=req.flag_entropy or 0.5,
    )
    return {
        "flow_id": res.flow_id,
        "reconstruction_loss": res.reconstruction_loss,
        "is_anomalous": res.is_anomalous,
        "anomaly_confidence": res.anomaly_confidence,
        "latent_coordinates": res.latent_coordinates,
        "original_vector": res.original_vector,
        "reconstructed_vector": res.reconstructed_vector,
        "deviant_features": res.deviant_features,
    }
