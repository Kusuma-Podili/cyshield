"""
CyberShield Enterprise - Threat Hunting Hypothesis Matrix REST Routes
Provides endpoints for hypothesis catalog exploration, multi-engine query transpilation,
telemetry hunt execution, and automated rule hardening.
"""

from fastapi import APIRouter, HTTPException, Depends
from typing import Dict, Any, List

from cybershield.threathunt.schemas import (
    HuntingHypothesis,
    MultiQueryBundle,
    HuntFinding,
    HuntCampaignReport,
)
from cybershield.threathunt.transpiler import ThreatHuntEngine

router = APIRouter(prefix="/api/v1/threathunt", tags=["Threat Hunting Hypothesis Matrix"])

_hunt_engine = ThreatHuntEngine()


def get_hunt_engine() -> ThreatHuntEngine:
    return _hunt_engine


@router.get("/hypotheses", response_model=List[HuntingHypothesis])
def list_hypotheses(engine: ThreatHuntEngine = Depends(get_hunt_engine)):
    """List all registered threat hunting hypotheses mapped to MITRE ATT&CK."""
    return list(engine.hypotheses.values())


@router.get("/hypothesis/{hypothesis_id}", response_model=HuntingHypothesis)
def get_hypothesis(hypothesis_id: str, engine: ThreatHuntEngine = Depends(get_hunt_engine)):
    """Retrieve details and structured predicates for a specific hunting hypothesis."""
    hyp = engine.hypotheses.get(hypothesis_id)
    if not hyp:
        raise HTTPException(status_code=404, detail=f"Hypothesis {hypothesis_id} not found")
    return hyp


@router.post("/transpile/{hypothesis_id}", response_model=MultiQueryBundle)
def transpile_hypothesis(hypothesis_id: str, engine: ThreatHuntEngine = Depends(get_hunt_engine)):
    """Transpile hypothesis into CS-QL, Sigma YAML, Splunk SPL, Microsoft KQL, and Elastic EQL."""
    hyp = engine.hypotheses.get(hypothesis_id)
    if not hyp:
        raise HTTPException(status_code=404, detail=f"Hypothesis {hypothesis_id} not found")
    return engine.transpile_bundle(hyp)


@router.post("/execute/{hypothesis_id}", response_model=List[HuntFinding])
def execute_hunt(
    hypothesis_id: str, telemetry_events: List[Dict[str, Any]], engine: ThreatHuntEngine = Depends(get_hunt_engine)
):
    """Execute hypothesis hunting logic against batch telemetry events and rank by rarity."""
    findings = engine.execute_hunt(hypothesis_id, telemetry_events)
    return findings


@router.post("/campaign/run", response_model=HuntCampaignReport)
def run_hunt_campaign(
    telemetry_events: List[Dict[str, Any]], engine: ThreatHuntEngine = Depends(get_hunt_engine)
):
    """Run full threat hunt campaign across all hypotheses and calculate ATT&CK coverage."""
    return engine.run_hunt_campaign(telemetry_events)


@router.get("/stats/summary")
def get_stats_summary(engine: ThreatHuntEngine = Depends(get_hunt_engine)) -> Dict[str, Any]:
    """Retrieve hunting matrix metrics and supported query dialects."""
    return {
        "status": "active",
        "total_hypotheses": len(engine.hypotheses),
        "supported_engines": ["cs_ql", "sigma", "splunk_spl", "microsoft_kql", "elastic_eql"],
        "mitre_tactics_covered": list(set(h.mitre_tactic for h in engine.hypotheses.values())),
    }


@router.get("/health")
def health():
    return {"status": "healthy", "service": "threathunt-engine", "version": "1.0.0"}
