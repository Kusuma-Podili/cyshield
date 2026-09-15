"""Unit & Integration Tests for Advanced Graph, DGA, and Neural Network Models."""

import pytest
import pytest_asyncio
from httpx import AsyncClient, ASGITransport

from cybershield.api.server import app
from cybershield.ml.advanced.autoencoder import NetworkFlowAutoencoder
from cybershield.ml.advanced.dga_classifier import DGAClassifier
from cybershield.ml.advanced.graph_path import IdentityHostGraph


def test_graph_attack_path_dijkstra():
    """Verify Dijkstra algorithm calculates shortest lateral path to crown jewels."""
    graph = IdentityHostGraph()
    graph.seed_enterprise_topology()

    # Calculate path from compromised HR laptop to financial database
    result = graph.find_shortest_attack_path("ws-hr-01", "db-financial-sql")
    assert result.path_found is True
    assert result.hop_count >= 2
    assert "ws-hr-01" == result.path_nodes[0]
    assert "db-financial-sql" == result.path_nodes[-1]
    assert result.risk_score >= 25.0
    assert len(result.choke_points) >= 1


def test_graph_pivot_hubs_detection():
    """Verify identification of high-degree pivot nodes."""
    graph = IdentityHostGraph()
    graph.seed_enterprise_topology()

    hubs = graph.detect_pivot_hubs(min_degree=2)
    assert len(hubs) >= 2
    hub_ids = [h["node_id"] for h in hubs]
    assert any("dc-primary.corp" in hid or "srv-jumpbox-01" in hid for hid in hub_ids)


def test_dga_classifier_malicious():
    """Verify sequence classifier flags high-entropy algorithmic C2 domains."""
    dga_domains = [
        "ajskdfh92834yhsdfkj.biz",
        "x8923hjsdf9.ru",
        "bcdfghjklmnpqrst.info",
    ]
    for d in dga_domains:
        res = DGAClassifier.classify_domain(d)
        assert res.is_dga is True
        assert res.dga_probability >= 0.50
        assert res.shannon_entropy > 3.0


def test_dga_classifier_benign():
    """Verify classifier recognizes natural language corporate domains."""
    benign_domains = [
        "google.com",
        "github.com",
        "microsoft.com",
        "amazon.com",
    ]
    for d in benign_domains:
        res = DGAClassifier.classify_domain(d)
        assert res.is_dga is False
        assert res.dga_probability < 0.40


def test_autoencoder_flow_reconstruction():
    """Verify autoencoder reconstruction error differentiates normal from covert channels."""
    ae = NetworkFlowAutoencoder(anomaly_threshold=0.15)

    # 1. Normal web traffic (balanced in/out)
    normal = ae.score_flow(
        flow_id="f-normal",
        bytes_in=15000,
        bytes_out=8000,
        duration=12.5,
        packet_count=24,
        flag_entropy=0.4,
    )
    assert normal.is_anomalous is False
    assert normal.reconstruction_loss < 0.20

    # 2. Asymmetric covert exfiltration spike (gigabytes outbound in 1 sec)
    exfil = ae.score_flow(
        flow_id="f-exfil",
        bytes_in=10,
        bytes_out=500_000_000,
        duration=0.5,
        packet_count=50_000,
        flag_entropy=0.95,
    )
    assert exfil.is_anomalous is True
    assert exfil.reconstruction_loss >= 0.15
    assert len(exfil.deviant_features) >= 1


@pytest.mark.asyncio
async def test_advanced_ml_api_endpoints():
    """Verify REST API endpoints for graph, DGA, and autoencoder."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        # Authenticate
        login_resp = await ac.post(
            "/api/auth/login",
            json={"username_or_email": "superadmin", "password": "CyberShield2026!"},
        )
        assert login_resp.status_code == 200
        token = login_resp.json()["access_token"]
        headers = {"Authorization": f"Bearer {token}"}

        # 1. Attack Paths
        resp_graph = await ac.post(
            "/api/ml/advanced/graph/attack-paths",
            json={"start_node_id": "ws-hr-01", "target_node_id": "db-financial-sql"},
            headers=headers,
        )
        assert resp_graph.status_code == 200
        path_data = resp_graph.json()
        assert path_data["path_found"] is True

        # 2. Pivot Hubs
        resp_hubs = await ac.get("/api/ml/advanced/graph/pivot-hubs?min_degree=2", headers=headers)
        assert resp_hubs.status_code == 200
        assert len(resp_hubs.json()) >= 1

        # 3. DGA Classification
        resp_dga = await ac.post(
            "/api/ml/advanced/dga/classify",
            json={"domain": "zkpqwertymnbvcxza.com"},
            headers=headers,
        )
        assert resp_dga.status_code == 200
        assert resp_dga.json()["is_dga"] is True

        # 4. Autoencoder Score
        resp_ae = await ac.post(
            "/api/ml/advanced/autoencoder/score",
            json={
                "flow_id": "flow-api-test",
                "bytes_in": 1200,
                "bytes_out": 400,
                "duration_sec": 3.0,
                "packet_count": 8,
            },
            headers=headers,
        )
        assert resp_ae.status_code == 200
        assert "reconstruction_loss" in resp_ae.json()
