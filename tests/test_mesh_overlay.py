"""Tests for CyberShield Enterprise - Autonomous Zero-Trust Micro-Tunneling & Mesh Overlay.
Verifies Curve25519 peer onboarding, ZTNA micro-tunnel access policies,
device posture gating, and REST API routes.
"""

import json
from datetime import datetime, timezone
import pytest
from starlette.testclient import TestClient

from cybershield.api.server import app
from cybershield.overlay.schemas import (
    PeerRole,
    RegisterPeerRequest,
    EvaluateAccessRequest,
)
from cybershield.overlay.mesh import ZeroTrustMeshOverlayEngine


@pytest.fixture
def client():
    return TestClient(app)


@pytest.fixture
def mesh():
    return ZeroTrustMeshOverlayEngine()


# =========================================================================
# Unit Tests: Overlay Peer Identity & ZTNA Policy Enforcement
# =========================================================================

def test_register_overlay_peer(mesh):
    req = RegisterPeerRequest(
        hostname="engineer-macbook-pro",
        role=PeerRole.WORKSTATION,
        device_posture_score=94.5,
    )

    peer = mesh.register_peer(req)
    assert peer.peer_id.startswith("peer-")
    assert peer.overlay_ip.startswith("10.42.1.")
    assert len(peer.public_key_curve25519) > 20
    assert peer.is_authorized is True
    assert peer.peer_id in mesh.peers


def test_evaluate_access_healthy_workstation_to_database(mesh):
    # Register healthy workstation
    ws = mesh.register_peer(
        RegisterPeerRequest(
            hostname="analyst-workstation-01",
            role=PeerRole.WORKSTATION,
            device_posture_score=92.0,
        )
    )

    req = EvaluateAccessRequest(
        source_peer_id=ws.peer_id,
        dest_peer_id="peer-db-01",  # Pre-seeded crown jewel database
        dest_port=5432,
        protocol="TCP",
    )

    decision = mesh.evaluate_access(req)
    assert decision.is_allowed is True
    assert "ChaCha20-Poly1305" in decision.encryption_suite
    assert "Micro-tunnel established" in decision.decision_reason


def test_block_low_posture_workstation_from_crown_jewels(mesh):
    # Workstation with outdated OS or missing EDR (posture score 65.0)
    unhealthy_ws = mesh.register_peer(
        RegisterPeerRequest(
            hostname="unpatched-laptop",
            role=PeerRole.WORKSTATION,
            device_posture_score=65.0,
        )
    )

    req = EvaluateAccessRequest(
        source_peer_id=unhealthy_ws.peer_id,
        dest_peer_id="peer-db-01",
        dest_port=5432,
    )

    decision = mesh.evaluate_access(req)
    assert decision.is_allowed is False
    assert "DENY_LOW_POSTURE_TO_CROWN_JEWELS" in decision.enforced_firewall_rule
    assert mesh.blocked_attempts_counter == 1


def test_block_iot_lateral_movement_to_ssh(mesh):
    # Compromised smart thermostat or IP camera
    iot_node = mesh.register_peer(
        RegisterPeerRequest(
            hostname="smart-hvac-controller",
            role=PeerRole.IOT_EDGE_NODE,
            device_posture_score=85.0,
        )
    )

    req = EvaluateAccessRequest(
        source_peer_id=iot_node.peer_id,
        dest_peer_id="peer-gw-01",
        dest_port=22,  # Attempting SSH pivot!
    )

    decision = mesh.evaluate_access(req)
    assert decision.is_allowed is False
    assert "DENY_IOT_TO_ADMIN_PORTS" in decision.enforced_firewall_rule


def test_mesh_health_report(mesh):
    report = mesh.get_mesh_health()
    assert report.total_active_peers >= 2  # Seeded peers
    assert "ChaCha20-Poly1305" in report.encryption_algorithm
    assert report.mesh_resilience_status == "OPTIMAL_HIGH_AVAILABILITY"


# =========================================================================
# Integration Tests: FastAPI REST Endpoints
# =========================================================================

def test_api_register_peer_and_evaluate_access(client):
    # 1. Register peer via API
    reg_req = {
        "hostname": "api-workstation-99",
        "role": "WORKSTATION",
        "device_posture_score": 95.0,
        "listen_port": 51820,
    }
    reg_resp = client.post("/api/v1/overlay/peers/register", json=reg_req)
    assert reg_resp.status_code == 201
    peer_data = reg_resp.json()
    new_peer_id = peer_data["peer_id"]

    # 2. Evaluate access
    access_req = {
        "source_peer_id": new_peer_id,
        "dest_peer_id": "peer-gw-01",
        "dest_port": 443,
        "protocol": "TCP",
    }
    access_resp = client.post("/api/v1/overlay/policy/evaluate", json=access_req)
    assert access_resp.status_code == 200
    assert access_resp.json()["is_allowed"] is True

    # 3. Check peers endpoint
    peers_resp = client.get("/api/v1/overlay/peers")
    assert peers_resp.status_code == 200
    assert len(peers_resp.json()) >= 3

    # 4. Check mesh status endpoint
    status_resp = client.get("/api/v1/overlay/mesh/status")
    assert status_resp.status_code == 200
    assert status_resp.json()["total_active_peers"] >= 3
