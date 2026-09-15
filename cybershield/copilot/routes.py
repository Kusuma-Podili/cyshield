"""CyberShield Enterprise - Autonomous AI SOC Analyst API Routes.
Exposes endpoints for automated alert triage, competing hypothesis analysis,
incident investigations, executive briefs, and shift handover generation.
"""

from typing import Dict, List, Optional, Any
from fastapi import APIRouter, HTTPException, Query, status

from .schemas import (
    AlertTriageRequest,
    InvestigationReport,
    ShiftHandoverReport,
    AnalystMetrics,
)
from .analyst import AutonomousSOCAnalyst

router = APIRouter(prefix="/api/v1/copilot", tags=["Autonomous AI SOC Analyst & Triager"])

# Active singleton analyst engine
_ANALYST = AutonomousSOCAnalyst()


@router.post("/triage", response_model=InvestigationReport, status_code=status.HTTP_201_CREATED)
def triage_alert(request: AlertTriageRequest):
    """Autonomously evaluate an alert using competing hypothesis reasoning and adjudicate a verdict."""
    return _ANALYST.triage_alert(request)


@router.post("/batch-triage", response_model=List[InvestigationReport])
def batch_triage_alerts(requests: List[AlertTriageRequest]):
    """Process a queue of alerts in batch and return adjudicated investigation reports."""
    return [_ANALYST.triage_alert(req) for req in requests]


@router.get("/investigations/{report_id}", response_model=InvestigationReport)
def get_investigation_report(report_id: str):
    """Retrieve detailed forensic adjudication report by ID."""
    if report_id not in _ANALYST.investigations:
        raise HTTPException(status_code=404, detail=f"Investigation report '{report_id}' not found.")
    return _ANALYST.investigations[report_id]


@router.get("/handover", response_model=ShiftHandoverReport)
def generate_shift_handover(
    shift_id: str = Query("SHIFT-DAY-01"),
    hours: int = Query(8, ge=1, le=48),
):
    """Generate executive and technical handover report for incoming SOC analyst shift."""
    return _ANALYST.generate_shift_handover(shift_id=shift_id, hours=hours)


@router.get("/metrics", response_model=AnalystMetrics)
def get_analyst_metrics():
    """Retrieve operational efficiency, noise auto-closure rate, and latency metrics."""
    return _ANALYST.get_metrics()
