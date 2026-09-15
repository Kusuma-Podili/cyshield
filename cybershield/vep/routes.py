"""CyberShield Enterprise - Vulnerability Prioritization & Exploit Prediction API Routes.
Exposes endpoints for EPSS probability forecasting, contextual asset risk prioritization,
batch fleet triage, and CISA KEV weaponization auditing.
"""

from typing import Dict, List, Optional, Any
from fastapi import APIRouter, HTTPException, Query, status

from .schemas import (
    EPSSScoreRecord,
    VulnerabilityContext,
    PrioritizedRemediationAction,
    EnterpriseVEPSummary,
)
from .prioritizer import VulnerabilityExploitPredictor

router = APIRouter(prefix="/api/v1/vep", tags=["Vulnerability Prioritization & EPSS Predictor"])

# Active singleton predictor
_PREDICTOR = VulnerabilityExploitPredictor()


@router.post("/predict", response_model=EPSSScoreRecord)
def predict_epss_score(
    cve_id: str = Query(..., description="Target CVE identifier (e.g. CVE-2024-21887)"),
    cvss_v3: float = Query(7.5, ge=0.0, le=10.0),
):
    """Forecast 30-day wild exploitation probability (EPSS) and percentile rank."""
    return _PREDICTOR.predict_epss(cve_id=cve_id, cvss_v3=cvss_v3)


@router.post("/prioritize", response_model=PrioritizedRemediationAction)
def prioritize_vulnerability(context: VulnerabilityContext):
    """Calculate contextual composite risk score, assign remediation priority tier, and determine SLA."""
    return _PREDICTOR.prioritize_vulnerability(context)


@router.post("/batch-prioritize")
def batch_prioritize(contexts: List[VulnerabilityContext]):
    """Triage and rank an enterprise fleet scan with executive posture summary."""
    actions = [_PREDICTOR.prioritize_vulnerability(ctx) for ctx in contexts]
    actions.sort(key=lambda a: a.composite_risk_score, reverse=True)
    summary = _PREDICTOR.generate_fleet_summary(actions)
    return {
        "summary": summary,
        "ranked_actions": actions,
    }


@router.get("/cisa-kev", response_model=List[EPSSScoreRecord])
def get_cisa_kev_catalog():
    """Retrieve catalog of high-risk vulnerabilities confirmed in CISA KEV database."""
    return [r for r in _PREDICTOR.known_cve_db.values() if r.is_cisa_kev]
