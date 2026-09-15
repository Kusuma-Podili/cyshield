"""Incident Case Management & Evidence API Endpoints for CyberShield Enterprise."""

from __future__ import annotations

from typing import List, Optional, Dict, Any
from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel

from cybershield.core.models import Incident, IncidentStatus, Severity, EvidenceArtifact
from cybershield.incidents.case_manager import case_manager
from cybershield.incidents.evidence import evidence_locker
from cybershield.engines.correlation import correlation_engine

router = APIRouter(prefix="/api/v1/incidents", tags=["Incidents"])


class IncidentCreateRequest(BaseModel):
    title: str
    summary: str
    severity: Severity = Severity.HIGH
    lead_analyst: str = "Unassigned"
    affected_hosts: List[str] = []
    affected_users: List[str] = []


class IncidentStatusUpdateRequest(BaseModel):
    status: IncidentStatus
    notes: Optional[str] = None


class EvidenceStoreRequest(BaseModel):
    name: str
    raw_content_b64: Optional[str] = None
    raw_text: Optional[str] = None
    artifact_type: str = "PCAP"
    collector: str = "SOC Analyst"


@router.get("", response_model=List[Incident])
async def list_incidents(status: Optional[IncidentStatus] = None):
    """List all open and historical security incidents."""
    incidents = case_manager.get_all_incidents()
    if status:
        incidents = [i for i in incidents if i.status == status]
    return list(reversed(incidents))


@router.post("", response_model=Incident)
async def create_incident(payload: IncidentCreateRequest):
    """Open a new formal security incident case."""
    return case_manager.create_incident(
        title=payload.title,
        summary=payload.summary,
        severity=payload.severity,
        lead_analyst=payload.lead_analyst,
        affected_hosts=payload.affected_hosts,
        affected_users=payload.affected_users,
    )


@router.get("/graph")
async def get_attack_graph():
    """Retrieve correlated MITRE attack graph nodes and edges for visualization."""
    return correlation_engine.get_attack_graph()


@router.get("/evidence/all", response_model=List[EvidenceArtifact])
async def list_all_evidence():
    """Retrieve all cryptographically sealed forensic evidence artifacts."""
    return evidence_locker.get_all_artifacts()


@router.get("/{incident_id}", response_model=Incident)
async def get_incident(incident_id: str):
    """Fetch incident case file."""
    inc = case_manager.get_incident(incident_id)
    if not inc:
        raise HTTPException(status_code=404, detail=f"Incident '{incident_id}' not found")
    return inc


@router.patch("/{incident_id}/status", response_model=Incident)
async def update_incident_status(incident_id: str, payload: IncidentStatusUpdateRequest):
    """Advance an incident through containment, remediation, and resolution."""
    try:
        return case_manager.update_status(incident_id, payload.status, payload.notes)
    except ValueError as ex:
        raise HTTPException(status_code=404, detail=str(ex))


@router.post("/{incident_id}/evidence", response_model=EvidenceArtifact)
async def seal_evidence(incident_id: str, payload: EvidenceStoreRequest):
    """Seal a new forensic evidence artifact to this incident case."""
    inc = case_manager.get_incident(incident_id)
    if not inc:
        raise HTTPException(status_code=404, detail=f"Incident '{incident_id}' not found")

    content_bytes = (payload.raw_text or "").encode("utf-8")
    artifact = evidence_locker.store_artifact(
        name=payload.name,
        content=content_bytes,
        artifact_type=payload.artifact_type,
        collector=payload.collector,
        incident_id=incident_id
    )
    case_manager.attach_evidence(incident_id, artifact.artifact_id)
    return artifact
