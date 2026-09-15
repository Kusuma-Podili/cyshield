"""REST API Endpoints for MITRE ATT&CK & D3FEND Matrix."""

from __future__ import annotations

from typing import Dict, List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status

from cybershield.auth.dependencies import get_current_user
from cybershield.database.models.user import User
from cybershield.mitre.d3fend import D3FENDKnowledgeBase
from cybershield.mitre.engine import mitre_engine
from cybershield.mitre.schemas import (
    D3FENDCountermeasure,
    MatrixCoverageReport,
    TechniqueDetail,
)

router = APIRouter(prefix="/api/mitre", tags=["MITRE ATT&CK & D3FEND Matrix"])


@router.get("/tactics", summary="List All 14 MITRE Enterprise Tactics")
async def list_tactics(
    current_user: User = Depends(get_current_user),
) -> List[Dict[str, str]]:
    """Retrieve all 14 MITRE ATT&CK Enterprise tactics."""
    return mitre_engine.get_tactics()


@router.get("/techniques", summary="Search MITRE ATT&CK Techniques", response_model=List[TechniqueDetail])
async def search_techniques(
    query: Optional[str] = Query(None, description="Search term in technique ID or name"),
    tactic_id: Optional[str] = Query(None, description="Filter by tactic e.g. TA0002"),
    platform: Optional[str] = Query(None, description="Filter by platform e.g. Windows, Linux, Containers"),
    current_user: User = Depends(get_current_user),
) -> List[TechniqueDetail]:
    """Retrieve filtered techniques with sub-techniques and D3FEND countermeasures."""
    return mitre_engine.search_techniques(query=query, tactic_id=tactic_id, platform=platform)


@router.get("/coverage", summary="Get Enterprise Coverage Heatmap & Gap Analysis", response_model=MatrixCoverageReport)
async def get_coverage_report(
    current_user: User = Depends(get_current_user),
) -> MatrixCoverageReport:
    """Calculate real-time enterprise detection coverage and D3FEND countermeasure recommendations."""
    return mitre_engine.generate_coverage_report()


@router.get("/d3fend", summary="List MITRE D3FEND Countermeasures", response_model=List[D3FENDCountermeasure])
async def list_d3fend_countermeasures(
    tactic: Optional[str] = Query(None, description="Filter by D3FEND tactic: Harden, Detect, Isolate, Deceive, Evict"),
    current_user: User = Depends(get_current_user),
) -> List[D3FENDCountermeasure]:
    """Retrieve all MITRE D3FEND defensive countermeasures."""
    if tactic:
        return D3FENDKnowledgeBase.get_by_tactic(tactic)
    return D3FENDKnowledgeBase.list_all()


@router.get("/d3fend/{d3fend_id}", summary="Get D3FEND Countermeasure Detail", response_model=D3FENDCountermeasure)
async def get_d3fend_detail(
    d3fend_id: str,
    current_user: User = Depends(get_current_user),
) -> D3FENDCountermeasure:
    """Retrieve specific D3FEND countermeasure implementation guidance."""
    countermeasure = D3FENDKnowledgeBase.get(d3fend_id)
    if not countermeasure:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"D3FEND countermeasure '{d3fend_id}' not found")
    return countermeasure


@router.get("/techniques/{technique_id}", summary="Get Technique Detail Dossier", response_model=TechniqueDetail)
async def get_technique_detail(
    technique_id: str,
    current_user: User = Depends(get_current_user),
) -> TechniqueDetail:
    """Retrieve full dossier for a specific technique, active rules, and defensive mappings."""
    tech = mitre_engine.get_technique(technique_id)
    if not tech:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Technique '{technique_id}' not found")
    return tech
