"""
Threat Campaign & Adversary Attribution REST API routes.
"""

from typing import Any, Dict, List, Optional
from fastapi import APIRouter, HTTPException, Query, status

from cybershield.campaigns.engine import CampaignGraphEngine
from cybershield.campaigns.schemas import (
    CampaignCorrelationRequest,
    ThreatActorProfile,
    ThreatCampaign,
)

campaigns_router = APIRouter(prefix="/api/campaigns", tags=["Threat Attribution & Adversary Campaigns"])
campaign_engine = CampaignGraphEngine()


@campaigns_router.get("", response_model=List[ThreatCampaign])
async def list_campaigns():
    """List all tracked adversary intrusion campaigns."""
    return campaign_engine.list_campaigns()


@campaigns_router.get("/overview")
async def get_campaigns_overview():
    """High-level metrics on active campaigns, actor distributions, and attribution confidence."""
    return campaign_engine.get_overview_metrics()


@campaigns_router.get("/actors", response_model=List[ThreatActorProfile])
async def list_threat_actors():
    """List curated nation-state and cybercrime threat actor profiles."""
    return campaign_engine.list_actors()


@campaigns_router.get("/actors/{actor_id}", response_model=ThreatActorProfile)
async def get_threat_actor(actor_id: str):
    """Retrieve in-depth dossier for a specific threat actor group."""
    actor = campaign_engine.get_actor(actor_id)
    if not actor:
        raise HTTPException(status_code=404, detail=f"Threat actor '{actor_id}' not found")
    return actor


@campaigns_router.get("/{campaign_id}", response_model=ThreatCampaign)
async def get_campaign(campaign_id: str):
    """Retrieve full Diamond Model graph topology for an intrusion campaign."""
    camp = campaign_engine.get_campaign(campaign_id)
    if not camp:
        raise HTTPException(status_code=404, detail=f"Threat campaign '{campaign_id}' not found")
    return camp


@campaigns_router.post("/correlate", response_model=Optional[ThreatCampaign])
async def correlate_campaign(req: List[Dict[str, Any]]):
    """
    Correlate raw alert indicators, TTPs, and IOCs into a unified Diamond Model campaign.
    Automatically assigns attribution and constructs node/edge graph.
    """
    campaign = campaign_engine.correlate_alerts(req)
    if not campaign:
        raise HTTPException(status_code=400, detail="Unable to correlate campaign from provided alert telemetry")
    return campaign
