"""Tests for CyberShield Enterprise - Continuous Automated Red Teaming (CART) & Exploit Path Planner.
Verifies attack graph topology, Dijkstra/A* multi-hop exploit planning, choke-point identification,
adversary emulation simulations, and REST API routes.
"""

import json
import pytest
from starlette.testclient import TestClient

from cybershield.api.server import app
from cybershield.cart.schemas import (
    AssetTier,
    SimulatedVulnerability,
    AttackGraphNode,
    AttackGraphEdge,
    AdversaryProfile,
)
from cybershield.cart.planner import AttackGraphModel, ExploitPathPlanner


@pytest.fixture
def client():
    return TestClient(app)


@pytest.fixture
def enterprise_attack_graph() -> AttackGraphModel:
    """Build a realistic multi-tier enterprise attack graph with crown jewels."""
    graph = AttackGraphModel()

    # Tier 3: Perimeter Entry
    dmz_web = AttackGraphNode(
        node_id="srv-web-dmz-01",
        name="Public Customer Portal (DMZ)",
        asset_tier=AssetTier.TIER_3_PERIMETER_EXPOSED,
        ip_address="198.51.100.10",
        vulnerabilities=[
            SimulatedVulnerability(
                vuln_id="vuln-log4j",
                cve_id="CVE-2021-44228",
                title="Apache Log4j JNDI RCE",
                cvss_score=10.0,
                affords_privilege="RCE",
            )
        ],
        value_score=20.0,
    )
    vpn_gw = AttackGraphNode(
        node_id="gw-vpn-perimeter",
        name="Enterprise SSL VPN Gateway",
        asset_tier=AssetTier.TIER_3_PERIMETER_EXPOSED,
        ip_address="198.51.100.20",
        vulnerabilities=[
            SimulatedVulnerability(
                vuln_id="vuln-ivanti",
                cve_id="CVE-2024-21887",
                title="Ivanti Connect Secure Command Injection",
                cvss_score=9.8,
                affords_privilege="RCE",
            )
        ],
        value_score=35.0,
    )

    # Tier 2: Internal Workstations & Jump Host (Choke-Point)
    jump_host = AttackGraphNode(
        node_id="srv-mgmt-jumphost",
        name="Core Management Jump Host",
        asset_tier=AssetTier.TIER_1_INTERNAL_INFRASTRUCTURE,
        ip_address="10.0.10.5",
        vulnerabilities=[
            SimulatedVulnerability(
                vuln_id="vuln-ssh-auth",
                cve_id="CVE-2024-6387",
                title="OpenSSH regreSSHion RCE",
                cvss_score=8.1,
                affords_privilege="RCE",
            )
        ],
        held_credentials=["domain_admin_cached_hash"],
        value_score=60.0,
    )

    ws_dev = AttackGraphNode(
        node_id="ws-dev-alice",
        name="Developer Workstation",
        asset_tier=AssetTier.TIER_2_WORKSTATION,
        ip_address="10.0.20.15",
        value_score=25.0,
    )

    # Tier 0: Crown Jewels
    dc_root = AttackGraphNode(
        node_id="dc-corp-root",
        name="Active Directory Root Domain Controller",
        asset_tier=AssetTier.TIER_0_CROWN_JEWEL,
        ip_address="10.0.0.1",
        vulnerabilities=[
            SimulatedVulnerability(
                vuln_id="vuln-zerologon",
                cve_id="CVE-2020-1472",
                title="Netlogon Privilege Escalation (ZeroLogon)",
                cvss_score=10.0,
                affords_privilege="PRIV_ESC",
            )
        ],
        value_score=100.0,
    )
    swift_gateway = AttackGraphNode(
        node_id="srv-swift-bank",
        name="SWIFT Financial Transaction Core",
        asset_tier=AssetTier.TIER_0_CROWN_JEWEL,
        ip_address="10.0.0.99",
        value_score=100.0,
    )

    graph.add_node(dmz_web)
    graph.add_node(vpn_gw)
    graph.add_node(jump_host)
    graph.add_node(ws_dev)
    graph.add_node(dc_root)
    graph.add_node(swift_gateway)

    # Edges (Exploit & Lateral Movement Paths)
    # 1. dmz_web -> jump_host
    graph.add_edge(
        AttackGraphEdge(
            source_id="srv-web-dmz-01",
            target_id="srv-mgmt-jumphost",
            technique_id="T1190",
            technique_name="Exploit Public-Facing Application",
            required_vuln_id="vuln-ssh-auth",
            success_probability=0.80,
            detection_risk=0.25,
            transition_cost=2.0,
        )
    )

    # 2. vpn_gw -> jump_host
    graph.add_edge(
        AttackGraphEdge(
            source_id="gw-vpn-perimeter",
            target_id="srv-mgmt-jumphost",
            technique_id="T1078",
            technique_name="Valid Accounts Over SSH",
            success_probability=0.90,
            detection_risk=0.15,
            transition_cost=1.5,
        )
    )

    # 3. vpn_gw -> ws_dev
    graph.add_edge(
        AttackGraphEdge(
            source_id="gw-vpn-perimeter",
            target_id="ws-dev-alice",
            technique_id="T1021.001",
            technique_name="Remote Desktop Protocol",
            success_probability=0.75,
            detection_risk=0.20,
            transition_cost=2.0,
        )
    )

    # 4. jump_host -> dc_root
    graph.add_edge(
        AttackGraphEdge(
            source_id="srv-mgmt-jumphost",
            target_id="dc-corp-root",
            technique_id="T1021.002",
            technique_name="SMB / PsExec Lateral Movement",
            required_vuln_id="vuln-zerologon",
            success_probability=0.95,
            detection_risk=0.30,
            transition_cost=1.0,
        )
    )

    # 5. jump_host -> swift_gateway
    graph.add_edge(
        AttackGraphEdge(
            source_id="srv-mgmt-jumphost",
            target_id="srv-swift-bank",
            technique_id="T1078",
            technique_name="Database Admin Impersonation",
            success_probability=0.70,
            detection_risk=0.40,
            transition_cost=3.0,
        )
    )

    return graph


# =========================================================================
# Unit Tests: Attack Graph & Exploit Path Planning
# =========================================================================

def test_attack_graph_model_tiers(enterprise_attack_graph):
    g = enterprise_attack_graph
    assert len(g.nodes) == 6
    assert len(g.edges) == 5

    crown_jewels = g.get_crown_jewels()
    assert len(crown_jewels) == 2
    cj_ids = {c.node_id for c in crown_jewels}
    assert "dc-corp-root" in cj_ids
    assert "srv-swift-bank" in cj_ids

    entry_points = g.get_entry_points()
    assert len(entry_points) == 2
    ep_ids = {e.node_id for e in entry_points}
    assert "srv-web-dmz-01" in ep_ids
    assert "gw-vpn-perimeter" in ep_ids


def test_exploit_path_planning(enterprise_attack_graph):
    planner = ExploitPathPlanner(enterprise_attack_graph)

    # Plan from perimeter VPN to Domain Controller
    plan = planner.plan_exploit_path(
        start_node_id="gw-vpn-perimeter",
        target_node_id="dc-corp-root",
        stealth_weight=0.6,
    )
    assert plan is not None
    assert plan.target_crown_jewel_id == "dc-corp-root"
    assert plan.path_nodes == ["gw-vpn-perimeter", "srv-mgmt-jumphost", "dc-corp-root"]
    assert len(plan.steps) == 2
    assert plan.overall_success_prob > 0.80
    assert 0.0 < plan.cumulative_detection_risk < 1.0
    assert len(plan.recommended_defenses) >= 1
    assert any("zerologon" in d.lower() or "microsegmentation" in d.lower() for d in plan.recommended_defenses)


def test_unreachable_target_returns_none(enterprise_attack_graph):
    planner = ExploitPathPlanner(enterprise_attack_graph)
    # Workstation Alice has no outgoing edges to DC root
    plan = planner.plan_exploit_path(
        start_node_id="ws-dev-alice",
        target_node_id="dc-corp-root",
    )
    assert plan is None


# =========================================================================
# Unit Tests: Strategic Choke-Point Analysis
# =========================================================================

def test_chokepoint_identification(enterprise_attack_graph):
    planner = ExploitPathPlanner(enterprise_attack_graph)
    chokepoints = planner.identify_choke_points()

    assert len(chokepoints) >= 1
    top_choke = chokepoints[0]
    # The jump host bridges all perimeter traffic to both Crown Jewels!
    assert top_choke.choke_node_id == "srv-mgmt-jumphost"
    assert top_choke.severed_paths_count >= 2
    assert top_choke.defensive_impact_score >= 50.0
    assert "CVE-2024-6387" in top_choke.critical_vulnerabilities


# =========================================================================
# Unit Tests: Adversary Campaign Simulation
# =========================================================================

def test_adversary_simulation_execution(enterprise_attack_graph):
    planner = ExploitPathPlanner(enterprise_attack_graph)

    profile = AdversaryProfile(
        profile_id="prof-apt29",
        name="APT29_CozyBear",
        skill_level=9,
        stealth_weight=0.8,
    )

    # Seeded simulation for deterministic test pass
    sim = planner.simulate_campaign(
        profile=profile,
        start_node_id="gw-vpn-perimeter",
        target_crown_jewel_id="dc-corp-root",
        rng_seed=42,
    )

    assert sim.start_node_id == "gw-vpn-perimeter"
    assert sim.target_crown_jewel_id == "dc-corp-root"
    assert sim.total_steps_executed == 2
    assert sim.reached_target is True
    assert len(sim.timeline) == 2
    assert len(planner.simulation_history) == 1


# =========================================================================
# REST API Integration Tests
# =========================================================================

def test_api_cart_lifecycle(client):
    # 1. Add Asset Nodes
    node1 = {
        "node_id": "api-srv-ext",
        "name": "API External Gateway",
        "asset_tier": "TIER_3_PERIMETER_EXPOSED",
        "ip_address": "198.51.100.99",
        "vulnerabilities": [],
        "held_credentials": [],
        "is_compromised": False,
        "value_score": 30.0,
    }
    resp = client.post("/api/v1/cart/nodes", json=node1)
    assert resp.status_code == 201
    assert resp.json()["node_id"] == "api-srv-ext"

    node2 = {
        "node_id": "api-cj-vault",
        "name": "API Key Management Vault",
        "asset_tier": "TIER_0_CROWN_JEWEL",
        "ip_address": "10.0.0.5",
        "vulnerabilities": [],
        "held_credentials": [],
        "is_compromised": False,
        "value_score": 100.0,
    }
    resp = client.post("/api/v1/cart/nodes", json=node2)
    assert resp.status_code == 201

    # 2. Add Edge
    edge_payload = {
        "source_id": "api-srv-ext",
        "target_id": "api-cj-vault",
        "technique_id": "T1190",
        "technique_name": "Exploit API Vulnerability",
        "success_probability": 0.90,
        "detection_risk": 0.20,
        "transition_cost": 1.0,
    }
    resp = client.post("/api/v1/cart/edges", json=edge_payload)
    assert resp.status_code == 201
    assert resp.json()["technique_id"] == "T1190"

    # 3. List Nodes & Edges
    resp = client.get("/api/v1/cart/nodes")
    assert resp.status_code == 200
    assert len(resp.json()) >= 2

    resp = client.get("/api/v1/cart/edges")
    assert resp.status_code == 200
    assert len(resp.json()) >= 1

    # 4. Plan Attack Path
    resp = client.post("/api/v1/cart/plan?start_node_id=api-srv-ext&target_node_id=api-cj-vault")
    assert resp.status_code == 200
    plan_data = resp.json()
    assert plan_data["target_crown_jewel_id"] == "api-cj-vault"
    assert len(plan_data["steps"]) == 1

    # 5. Chokepoints
    resp = client.get("/api/v1/cart/chokepoints")
    assert resp.status_code == 200
    assert isinstance(resp.json(), list)

    # 6. Run Simulation
    resp = client.post("/api/v1/cart/simulate?start_node_id=api-srv-ext&target_crown_jewel_id=api-cj-vault&skill_level=9")
    assert resp.status_code == 201
    sim_data = resp.json()
    assert sim_data["reached_target"] is True

    # 7. List Simulations
    resp = client.get("/api/v1/cart/simulations")
    assert resp.status_code == 200
    assert len(resp.json()) >= 1
