"""Tests for CyberShield Enterprise - Graph Neural Network & GraphSAGE Threat Classifier.
Verifies heterogeneous security graph construction, inductive multi-hop representation learning,
node threat classification, neighbor influence attribution, and REST API routes.
"""

import json
import pytest
from starlette.testclient import TestClient

from cybershield.api.server import app
from cybershield.ml.gnn.schemas import (
    GraphNodeType,
    GraphEdgeType,
    AggregatorType,
    ThreatRole,
    HeterogeneousGraph,
    SecurityNode,
    SecurityEdge,
    AttackPathEvaluationRequest,
    GNNTrainRequest,
)
from cybershield.ml.gnn.graph import SecurityGraphBuilder, FEATURE_DIM
from cybershield.ml.gnn.sage import (
    GraphSAGELayer,
    InductiveGraphEmbeddingModel,
    relu,
    leaky_relu,
    l2_normalize,
    matmul_vec,
)
from cybershield.ml.gnn.classifier import ThreatGraphNodeClassifier, sigmoid


@pytest.fixture
def client():
    return TestClient(app)


@pytest.fixture
def sample_attack_graph() -> SecurityGraphBuilder:
    """Build a realistic multi-hop enterprise intrusion graph."""
    builder = SecurityGraphBuilder(graph_id="graph-campaign-alpha", tenant_id="TENANT-CORP-HQ")

    # Ingress host & user
    builder.add_node("host-workstation-1", GraphNodeType.HOST, "Workstation WS-101", properties={"ip": "10.0.1.15"})
    builder.add_node("user-alice", GraphNodeType.USER, "Alice Jenkins", properties={"is_admin": False})

    # Patient zero process (phishing payload)
    builder.add_node(
        "proc-winword",
        GraphNodeType.PROCESS,
        "WINWORD.EXE",
        properties={"path": "C:\\Program Files\\Microsoft Office\\WINWORD.EXE", "signed": True},
        base_risk_score=15.0,
    )
    builder.add_node(
        "proc-powershell",
        GraphNodeType.PROCESS,
        "powershell.exe",
        properties={"cmdline": "powershell.exe -enc aWV4IChOZXctT2JqZWN0IE5ldC5XZWJDbGllbnQp...", "path": "powershell.exe"},
        base_risk_score=85.0,
        is_compromised_seed=True,
    )

    # C2 External Socket
    builder.add_node(
        "socket-c2",
        GraphNodeType.SOCKET,
        "C2 CobaltStrike Listener",
        properties={"remote_ip": "198.51.100.42", "port": 4444},
        base_risk_score=95.0,
    )

    # Lateral movement target
    builder.add_node("host-dc01", GraphNodeType.HOST, "Domain Controller DC-01", properties={"ip": "10.0.0.1", "is_admin": True})
    builder.add_node(
        "proc-mimikatz",
        GraphNodeType.PROCESS,
        "mimikatz.exe",
        properties={"cmdline": "sekurlsa::logonpasswords", "path": "mimikatz.exe", "signed": False},
        base_risk_score=98.0,
    )

    # Wire up edges
    builder.add_edge("user-alice", "host-workstation-1", GraphEdgeType.AUTHENTICATED_AS)
    builder.add_edge("host-workstation-1", "proc-winword", GraphEdgeType.SPAWNED)
    builder.add_edge("proc-winword", "proc-powershell", GraphEdgeType.SPAWNED, weight=2.0)
    builder.add_edge("proc-powershell", "socket-c2", GraphEdgeType.CONNECTED_TO, weight=5.0)
    builder.add_edge("proc-powershell", "host-dc01", GraphEdgeType.LATERAL_ACCESS, weight=3.0)
    builder.add_edge("host-dc01", "proc-mimikatz", GraphEdgeType.SPAWNED, weight=2.0)

    return builder


# =========================================================================
# Unit Tests: Graph Topology & Feature Extraction
# =========================================================================

def test_graph_builder_basics(sample_attack_graph):
    g = sample_attack_graph
    assert len(g.nodes) == 7
    assert len(g.edges) == 6

    # Verify neighbors
    ps_nbrs = g.get_neighbors("proc-powershell")
    assert "proc-winword" in ps_nbrs
    assert "socket-c2" in ps_nbrs
    assert "host-dc01" in ps_nbrs

    # Verify 2-hop neighborhood
    ego = g.get_k_hop_neighborhood("proc-powershell", k=2)
    assert "host-workstation-1" in ego
    assert "proc-mimikatz" in ego
    assert len(ego) >= 6


def test_feature_vector_extraction(sample_attack_graph):
    g = sample_attack_graph

    feat_ps = g.extract_features("proc-powershell")
    assert feat_ps.feature_dimension == FEATURE_DIM
    assert feat_ps.features[1] == 1.0  # is_process
    assert feat_ps.features[20] == 1.0  # is_compromised_seed
    assert feat_ps.features[8] > 0.8  # norm_base_risk

    feat_sock = g.extract_features("socket-c2")
    assert feat_sock.features[3] == 1.0  # is_socket
    assert feat_sock.features[13] == 1.0  # is_external_conn
    assert feat_sock.features[22] == 1.0  # port_risk_score for 4444


def test_unseen_node_fallback(sample_attack_graph):
    g = sample_attack_graph
    feat = g.extract_features("non-existent-entity")
    assert len(feat.features) == FEATURE_DIM
    assert all(x == 0.0 for x in feat.features)


# =========================================================================
# Unit Tests: GraphSAGE Neural Layers & Aggregators
# =========================================================================

def test_math_primitives():
    assert relu(5.0) == 5.0
    assert relu(-3.0) == 0.0
    assert leaky_relu(-2.0, alpha=0.01) == -0.02
    assert leaky_relu(4.0) == 4.0

    normalized, norm = l2_normalize([3.0, 4.0])
    assert pytest.approx(norm, 0.001) == 5.0
    assert pytest.approx(normalized[0], 0.001) == 0.6
    assert pytest.approx(normalized[1], 0.001) == 0.8

    m = [[1.0, 2.0], [3.0, 4.0]]
    v = [2.0, 1.0]
    res = matmul_vec(m, v)
    assert res == [4.0, 10.0]


def test_graphsage_aggregators():
    layer_mean = GraphSAGELayer(in_dim=4, out_dim=8, aggregator=AggregatorType.MEAN, seed=42)
    layer_pool = GraphSAGELayer(in_dim=4, out_dim=8, aggregator=AggregatorType.POOLING, seed=42)
    layer_attn = GraphSAGELayer(in_dim=4, out_dim=8, aggregator=AggregatorType.ATTENTION, seed=42)

    nbrs = [[1.0, 0.0, 0.5, 0.2], [0.0, 2.0, 0.5, 0.8]]

    agg_mean = layer_mean.aggregate_neighbors("target", nbrs, [1.0, 1.0])
    assert len(agg_mean) == 4
    assert pytest.approx(agg_mean[0], 0.01) == 0.5
    assert pytest.approx(agg_mean[1], 0.01) == 1.0

    agg_pool = layer_pool.aggregate_neighbors("target", nbrs)
    assert len(agg_pool) == 4

    agg_attn = layer_attn.aggregate_neighbors("target", nbrs, [1.0, 2.0])
    assert len(agg_attn) == 4

    # Forward pass
    self_vec = [0.5, 0.5, 0.5, 0.5]
    out_mean = layer_mean.forward_node(self_vec, nbrs)
    assert len(out_mean) == 8
    _, norm = l2_normalize(out_mean)
    assert pytest.approx(norm, 0.01) == 1.0


def test_inductive_embedding_model(sample_attack_graph):
    g = sample_attack_graph
    model = InductiveGraphEmbeddingModel(out_dim=16, aggregator=AggregatorType.MEAN, seed=99)

    emb_ps = model.embed_node("proc-powershell", g)
    assert emb_ps.embedding_dimension == 16
    assert len(emb_ps.embedding) == 16
    assert emb_ps.k_hops == 2
    assert emb_ps.neighborhood_size == 3
    assert pytest.approx(emb_ps.l2_norm, 0.01) == 1.0

    emb_sock = model.embed_node("socket-c2", g)
    emb_alice = model.embed_node("user-alice", g)

    # Similarity check
    sim = model.compute_similarity(emb_ps.embedding, emb_sock.embedding)
    assert -1.0 <= sim <= 1.0

    # Inductive test: dynamically add an unseen lateral host and embed immediately
    g.add_node("host-unseen-sql", GraphNodeType.HOST, "Database Cluster SQL-01", properties={"ip": "10.0.0.50"})
    g.add_edge("proc-mimikatz", "host-unseen-sql", GraphEdgeType.LATERAL_ACCESS)

    emb_sql = model.embed_node("host-unseen-sql", g)
    assert emb_sql.node_id == "host-unseen-sql"
    assert len(emb_sql.embedding) == 16


# =========================================================================
# Unit Tests: Threat Classifier & Path Analyzer
# =========================================================================

def test_node_threat_classification(sample_attack_graph):
    g = sample_attack_graph
    classifier = ThreatGraphNodeClassifier()

    # Powershell seed compromised node
    res_ps = classifier.classify_node("proc-powershell", g)
    assert res_ps.malicious_prob > 0.8
    assert res_ps.is_threat is True
    assert res_ps.predicted_role in [ThreatRole.C2_BEACON, ThreatRole.LATERAL_PIVOT, ThreatRole.CREDENTIAL_ACCESS]
    assert len(res_ps.top_influential_neighbors) > 0

    # User Alice benign
    res_alice = classifier.classify_node("user-alice", g)
    assert res_alice.malicious_prob < 0.5
    assert res_alice.predicted_role == ThreatRole.BENIGN

    # Mimikatz credential access
    res_mimi = classifier.classify_node("proc-mimikatz", g)
    assert res_mimi.malicious_prob > 0.7
    assert res_mimi.predicted_role == ThreatRole.CREDENTIAL_ACCESS
    assert any("TA0006" in t for t in res_mimi.mitre_tactics)


def test_attack_path_evaluation(sample_attack_graph):
    g = sample_attack_graph
    classifier = ThreatGraphNodeClassifier()

    # Malicious multi-hop progression
    path = ["host-workstation-1", "proc-winword", "proc-powershell", "host-dc01", "proc-mimikatz"]
    eval_res = classifier.evaluate_attack_path(g, path)

    assert eval_res.total_path_risk > 50.0
    assert eval_res.is_compromise_chain is True
    assert eval_res.verdict == "CRITICAL_ATTACK_CAMPAIGN"
    assert len(eval_res.transition_risks) == 4
    assert eval_res.bottleneck_node_id in path
    assert "sever" in eval_res.recommended_interception_point.lower() or "quarantine" in eval_res.recommended_interception_point.lower()

    # Invalid path
    with pytest.raises(ValueError):
        classifier.evaluate_attack_path(g, ["single-node"])


# =========================================================================
# REST API Integration Tests
# =========================================================================

def test_api_gnn_workflow(client, sample_attack_graph):
    # 1. Ingest Graph
    g_schema = sample_attack_graph.to_heterogeneous_graph()
    resp = client.post("/api/v1/gnn/graphs", json=json.loads(g_schema.model_dump_json()))
    assert resp.status_code == 201
    assert resp.json()["status"] == "success"

    # 2. Get Graph Summary
    resp = client.get(f"/api/v1/gnn/graphs/{sample_attack_graph.graph_id}")
    assert resp.status_code == 200
    data = resp.json()
    assert data["total_nodes"] == 7
    assert data["total_edges"] == 6
    assert "proc-powershell" in data["compromised_seeds"]

    # 3. Compute Embedding
    resp = client.post(f"/api/v1/gnn/embed?graph_id={sample_attack_graph.graph_id}&node_id=proc-powershell")
    assert resp.status_code == 200
    emb = resp.json()
    assert emb["embedding_dimension"] == 16
    assert len(emb["embedding"]) == 16

    # 4. Classify Node
    resp = client.post(f"/api/v1/gnn/classify?graph_id={sample_attack_graph.graph_id}&node_id=proc-mimikatz")
    assert resp.status_code == 200
    cls_data = resp.json()
    assert cls_data["predicted_role"] == ThreatRole.CREDENTIAL_ACCESS.value
    assert cls_data["malicious_prob"] > 0.6

    # 5. Evaluate Attack Path
    path_req = {
        "graph_id": sample_attack_graph.graph_id,
        "path_nodes": ["proc-powershell", "host-dc01", "proc-mimikatz"],
    }
    resp = client.post("/api/v1/gnn/path-evaluation", json=path_req)
    assert resp.status_code == 200
    path_data = resp.json()
    assert path_data["is_compromise_chain"] is True
    assert path_data["verdict"] == "CRITICAL_ATTACK_CAMPAIGN"

    # 6. Extract Threat Subgraphs
    resp = client.get(f"/api/v1/gnn/threat-subgraphs/{sample_attack_graph.graph_id}?threshold=0.5")
    assert resp.status_code == 200
    sub_data = resp.json()
    assert sub_data["threat_node_count"] >= 2

    # 7. Model Status
    resp = client.get("/api/v1/gnn/status")
    assert resp.status_code == 200
    st = resp.json()
    assert st["is_calibrated"] is True
    assert st["num_layers"] == 2

    # 8. Train / Calibrate
    train_req = {
        "graph_id": sample_attack_graph.graph_id,
        "epochs": 10,
        "learning_rate": 0.05,
        "aggregator": "POOLING",
        "embedding_dim": 16,
    }
    resp = client.post("/api/v1/gnn/train", json=train_req)
    assert resp.status_code == 200
    assert resp.json()["status"] == "calibrated"
