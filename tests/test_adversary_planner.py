"""Tests for CyberShield Enterprise - Autonomous Adversary Emulation & MITRE ATT&CK Planner.
Verifies APT profile compilation, atomic attack sequence simulation, defensive scorecarding,
and REST API endpoints.
"""

import json
from datetime import datetime, timezone
import pytest
from starlette.testclient import TestClient

from cybershield.api.server import app
from cybershield.adversary.schemas import (
    ThreatActorGroup,
    EmulationStepStatus,
    CreateCampaignPlanRequest,
)
from cybershield.adversary.planner import AdversaryEmulationPlanner


@pytest.fixture
def client():
    return TestClient(app)


@pytest.fixture
def planner():
    return AdversaryEmulationPlanner()


# =========================================================================
# Unit Tests: Adversary Profiles & Campaign Execution
# =========================================================================

def test_list_and_verify_adversary_profiles(planner):
    profiles = list(planner.profiles.values())
    assert len(profiles) >= 2

    apt29 = planner.profiles.get(ThreatActorGroup.APT29_COZY_BEAR)
    assert apt29 is not None
    assert "SolarWinds" in apt29.description
    assert any(s.mitre_technique_id == "T1003.001" for s in apt29.attack_steps)

    lockbit = planner.profiles.get(ThreatActorGroup.LOCKBIT_RANSOMWARE)
    assert lockbit is not None
    assert any(s.mitre_technique_id == "T1490" for s in lockbit.attack_steps)


def test_create_and_execute_apt29_campaign(planner):
    req = CreateCampaignPlanRequest(
        campaign_name="Quarterly-RedTeam-APT29-Validation",
        threat_actor=ThreatActorGroup.APT29_COZY_BEAR,
        target_host_id="ws-eval-01",
    )

    plan = planner.create_campaign_plan(req)
    assert plan["campaign_id"].startswith("camp-")
    assert plan["status"] == "PLAN_CREATED"

    # Execute campaign
    scorecard = planner.execute_campaign(plan["campaign_id"])
    assert scorecard.campaign_id == plan["campaign_id"]
    assert scorecard.threat_actor == ThreatActorGroup.APT29_COZY_BEAR
    assert scorecard.total_steps == 4
    assert scorecard.detected_steps >= 3
    assert scorecard.blocked_steps >= 1  # T1003.001 LSASS dump blocked
    assert scorecard.detection_coverage_pct >= 75.0
    assert len(scorecard.tuning_recommendations) >= 1


def test_execute_lockbit_ransomware_campaign(planner):
    req = CreateCampaignPlanRequest(
        campaign_name="LockBit-AntiRecovery-Resilience-Test",
        threat_actor=ThreatActorGroup.LOCKBIT_RANSOMWARE,
    )
    plan = planner.create_campaign_plan(req)
    scorecard = planner.execute_campaign(plan["campaign_id"])

    assert scorecard.total_steps == 3
    assert scorecard.blocked_steps >= 1  # T1490 VSS Purge blocked
    assert scorecard.detection_coverage_pct == 100.0


# =========================================================================
# Integration Tests: FastAPI REST Endpoints
# =========================================================================

def test_api_create_and_execute_campaign(client):
    # 1. Create plan
    plan_req = {
        "campaign_name": "API-Emulation-FIN7",
        "threat_actor": "APT29_COZY_BEAR",
        "target_host_id": "target-sandbox-01",
    }
    plan_resp = client.post("/api/v1/adversary/plans/create", json=plan_req)
    assert plan_resp.status_code == 201
    plan_data = plan_resp.json()
    campaign_id = plan_data["campaign_id"]

    # 2. Execute plan
    exec_resp = client.post(f"/api/v1/adversary/plans/{campaign_id}/execute")
    assert exec_resp.status_code == 200
    scorecard = exec_resp.json()
    assert scorecard["campaign_id"] == campaign_id
    assert scorecard["detection_coverage_pct"] >= 75.0

    # 3. Check profiles endpoint
    prof_resp = client.get("/api/v1/adversary/profiles")
    assert prof_resp.status_code == 200
    assert len(prof_resp.json()) >= 2

    # 4. Check scorecards endpoint
    score_resp = client.get("/api/v1/adversary/scorecards")
    assert score_resp.status_code == 200
    assert len(score_resp.json()) >= 1
