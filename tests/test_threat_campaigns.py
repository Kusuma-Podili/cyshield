"""
Unit and integration tests for Threat Attribution & Adversary Campaign Graph Subsystem.
"""

import pytest
from fastapi.testclient import TestClient

from cybershield.api.server import app
from cybershield.campaigns.engine import CampaignGraphEngine
from cybershield.campaigns.schemas import (
    AttributionConfidence,
    CampaignStatus,
    DiamondVertexType,
)


@pytest.fixture
def engine():
    return CampaignGraphEngine()


@pytest.fixture
def client():
    return TestClient(app)


def test_actor_catalog_initialization(engine):
    actors = engine.list_actors()
    assert len(actors) >= 6
    actor_ids = [a.actor_id for a in actors]
    assert "ACTOR-APT29" in actor_ids
    assert "ACTOR-APT28" in actor_ids
    assert "ACTOR-LAZARUS" in actor_ids
    assert "ACTOR-SANDWORM" in actor_ids
    assert "ACTOR-VOLT-TYPHOON" in actor_ids

    apt29 = engine.get_actor("ACTOR-APT29")
    assert apt29 is not None
    assert "Cozy Bear" in apt29.aliases
    assert "T1195" in apt29.signature_ttps
    assert "SUNBURST" in apt29.known_malware_families


def test_seeded_campaign_graph_structure(engine):
    campaigns = engine.list_campaigns()
    assert len(campaigns) >= 1
    camp = campaigns[0]
    assert camp.status == CampaignStatus.ACTIVE
    assert camp.attributed_actor == "APT29"
    assert camp.attribution_confidence == AttributionConfidence.HIGH

    # Check Diamond Model Vertices
    vertex_types = {n.vertex_type for n in camp.nodes}
    assert DiamondVertexType.ADVERSARY in vertex_types
    assert DiamondVertexType.INFRASTRUCTURE in vertex_types
    assert DiamondVertexType.CAPABILITY in vertex_types
    assert DiamondVertexType.VICTIM in vertex_types

    # Check Directed Relationships
    assert len(camp.edges) >= 4
    relations = {e.relation for e in camp.edges}
    assert "UTILIZES_INFRASTRUCTURE" in relations
    assert "DEPLOYS_CAPABILITY" in relations
    assert "EXECUTES_AGAINST_VICTIM" in relations


def test_attribution_scoring_engine(engine):
    # Test high correlation for Lazarus Group
    observed_ttps = {"T1059.003", "T1055", "T1572"}
    observed_tools = {"Bankshot", "Fallchill"}
    actor, score, conf = engine.compute_attribution(observed_ttps, observed_tools)

    assert actor is not None
    assert actor.actor_id == "ACTOR-LAZARUS"
    assert score >= 60.0
    assert conf in [AttributionConfidence.HIGH, AttributionConfidence.CONFIRMED]

    # Test empty input yields no attribution
    empty_actor, empty_score, empty_conf = engine.compute_attribution(set(), set())
    assert empty_actor is None
    assert empty_score == 0.0
    assert empty_conf == AttributionConfidence.LOW


def test_correlate_raw_alerts_into_campaign(engine):
    alert_stream = [
        {
            "id": "ALT-9001",
            "mitre_technique": "T1485",
            "malware_family": "Industroyer",
            "source_ip": "185.220.101.5",
            "destination_ip": "10.0.10.50",
            "target_host": "SUBSTATION-RTU-01"
        },
        {
            "id": "ALT-9002",
            "mitre_technique": "T0855",
            "malware_family": "BlackEnergy",
            "source_ip": "185.220.101.5",
            "destination_ip": "10.0.10.51",
            "target_host": "SUBSTATION-PLC-02"
        }
    ]

    new_campaign = engine.correlate_alerts(alert_stream)
    assert new_campaign is not None
    assert new_campaign.attributed_actor == "Sandworm Team"
    assert len(new_campaign.nodes) >= 4  # Adversary, C2 IP, TTPs, Victims
    assert len(new_campaign.edges) >= 3
    assert len(new_campaign.associated_alert_ids) == 2


def test_campaign_overview_metrics(engine):
    metrics = engine.get_overview_metrics()
    assert metrics["total_campaigns"] >= 1
    assert metrics["active_campaigns"] >= 1
    assert metrics["tracked_actors"] >= 6
    assert "APT29" in metrics["actor_distribution"]


def test_campaign_api_endpoints(client):
    # 1. List campaigns
    res = client.get("/api/campaigns")
    assert res.status_code == 200
    camps = res.json()
    assert len(camps) >= 1
    camp_id = camps[0]["campaign_id"]

    # 2. Get campaign detail
    res_det = client.get(f"/api/campaigns/{camp_id}")
    assert res_det.status_code == 200
    assert res_det.json()["campaign_id"] == camp_id

    # 3. List actors
    res_act = client.get("/api/campaigns/actors")
    assert res_act.status_code == 200
    assert len(res_act.json()) >= 6

    # 4. Get specific actor
    res_act_det = client.get("/api/campaigns/actors/ACTOR-VOLT-TYPHOON")
    assert res_act_det.status_code == 200
    assert res_act_det.json()["name"] == "Volt Typhoon"

    # 5. Get overview
    res_ovr = client.get("/api/campaigns/overview")
    assert res_ovr.status_code == 200
    assert res_ovr.json()["total_campaigns"] >= 1

    # 6. Correlate alerts endpoint
    correlate_payload = [
        {
            "id": "ALT-TEST-01",
            "mitre_technique": "T1059.005",
            "malware_family": "Carbanak",
            "source_ip": "194.26.29.11",
            "destination_ip": "10.0.5.20",
            "target_host": "POS-TERMINAL-1"
        }
    ]
    res_corr = client.post("/api/campaigns/correlate", json=correlate_payload)
    assert res_corr.status_code == 200
    corr_result = res_corr.json()
    assert corr_result["attributed_actor"] == "FIN7"
    assert len(corr_result["nodes"]) >= 3
