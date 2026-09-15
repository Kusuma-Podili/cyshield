"""
Automated Incident Root Cause Analysis (RCA) REST API routes.
"""

from typing import Any, Dict, List, Optional
from fastapi import APIRouter, HTTPException, Query, status

from cybershield.rca.engine import CausalRCAEngine
from cybershield.rca.schemas import (
    IncidentRCAReport,
    RCARequest,
)

rca_router = APIRouter(prefix="/api/rca", tags=["Root Cause Analysis (RCA) & Causal Graph"])
_rca_engine = CausalRCAEngine()


@rca_router.post("/analyze", response_model=IncidentRCAReport)
async def analyze_incident_root_cause(request: RCARequest):
    """
    Constructs a directed causal graph from an incident telemetry stream,
    identifies Patient Zero entry points, and provides ranked remediation steps.
    """
    return _rca_engine.analyze_incident(request)


@rca_router.get("/reports", response_model=List[IncidentRCAReport])
async def list_rca_reports():
    """List all completed Incident Root Cause Analysis reports."""
    return _rca_engine.list_reports()


@rca_router.get("/reports/{report_id}", response_model=IncidentRCAReport)
async def get_rca_report(report_id: str):
    """Retrieve detailed causal graph and patient-zero findings for an RCA investigation."""
    report = _rca_engine.get_report(report_id)
    if not report:
        raise HTTPException(status_code=404, detail=f"RCA Report '{report_id}' not found")
    return report


@rca_router.get("/overview")
async def get_rca_overview():
    """Executive metrics on root cause discovery, blast radius, and causal graph metrics."""
    return _rca_engine.get_overview_metrics()
