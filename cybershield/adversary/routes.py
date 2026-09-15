"""CyberShield Enterprise - Autonomous Adversary Emulation & MITRE ATT&CK Planner Routes.
Exposes endpoints for adversary plan generation, atomic emulation execution,
threat actor profiles, and defensive scorecards.
"""

from typing import Dict, List, Optional, Any
from fastapi import APIRouter, HTTPException, Query, status

from .schemas import (
    ThreatActorGroup,
    AdversaryProfile,
    CreateCampaignPlanRequest,
    CampaignScorecard,
)
from .planner import AdversaryEmulationPlanner

router = APIRouter(prefix="/api/v1/adversary", tags=["Adversary Emulation & MITRE ATT&CK Planner"])

# Singleton planner engine instance
_ADVERSARY_PLANNER = AdversaryEmulationPlanner()


@router.post("/plans/create", response_model=Dict[str, Any], status_code=status.HTTP_201_CREATED)
def create_adversary_campaign(request: CreateCampaignPlanRequest):
    """Compile an adversary attack sequence plan based on MITRE ATT&CK threat actor personas."""
    return _ADVERSARY_PLANNER.create_campaign_plan(request)


@router.post("/plans/{plan_id}/execute", response_model=CampaignScorecard, status_code=status.HTTP_200_OK)
def execute_adversary_campaign(plan_id: str):
    """Safely execute adversary emulation chain and measure blue team detection & prevention efficacy."""
    return _ADVERSARY_PLANNER.execute_campaign(plan_id)


@router.get("/profiles", response_model=List[AdversaryProfile])
def list_adversary_profiles():
    """Retrieve pre-compiled threat actor profiles (APT29, LockBit, FIN7)."""
    return list(_ADVERSARY_PLANNER.profiles.values())


@router.get("/scorecards", response_model=List[CampaignScorecard])
def list_campaign_scorecards():
    """Retrieve historical defense validation scorecards."""
    return list(_ADVERSARY_PLANNER.scorecards.values())
