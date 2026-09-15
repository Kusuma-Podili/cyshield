"""
CyberShield Enterprise - Security Incident Management REST Endpoints
Provides endpoints for incident investigation, lifecycle triage,
forensic timeline logging, and automated SOAR containment operations.
"""

from typing import Optional, Dict, Any, List
from fastapi import APIRouter, Depends, HTTPException, status, Query
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from cybershield.database.session import get_db
from cybershield.auth.dependencies import get_current_user, require_role, require_permission
from cybershield.database.models.user import User
from cybershield.database.models.role import UserRole, Permission
from cybershield.audit.service import AuditService
from cybershield.incidents.service import incident_service

router = APIRouter(prefix="/api/incidents", tags=["Security Incidents & Response"])


# Request Schemas
class CreateIncidentRequest(BaseModel):
    title: str = Field(..., min_length=3, max_length=256)
    summary: str = Field(..., min_length=10)
    severity: str = Field(default="HIGH", pattern="^(CRITICAL|HIGH|MEDIUM|LOW|INFORMATIONAL)$")
    incident_type: str = Field(default="MALWARE_INFECTION")
    kill_chain_phase: str = Field(default="EXECUTION")
    lead_analyst: Optional[str] = None
    impacted_hosts: List[str] = Field(default_factory=list)
    impacted_users: List[str] = Field(default_factory=list)
    associated_alert_ids: List[str] = Field(default_factory=list)
    assigned_playbook: Optional[str] = None


class UpdateIncidentStatusRequest(BaseModel):
    status: str = Field(..., pattern="^(OPEN|TRIAGED|CONTAINED|ERADICATED|RECOVERED|CLOSED)$")
    comment: Optional[str] = None


class AddTimelineRequest(BaseModel):
    action_type: str = Field(default="INVESTIGATION_NOTE")
    description: str = Field(..., min_length=3)
    evidence_reference: Optional[str] = None


class ContainmentActionRequest(BaseModel):
    action_type: str = Field(..., description="e.g. ISOLATE_HOST, BLOCK_IP, REVOKE_USER_CREDENTIALS")
    target: str = Field(..., description="Target hostname, IP address, or username")
    parameters: Dict[str, Any] = Field(default_factory=dict)


@router.get("")
async def list_incidents(
    status: Optional[str] = Query("ALL"),
    severity: Optional[str] = Query("ALL"),
    incident_type: Optional[str] = Query("ALL"),
    kill_chain_phase: Optional[str] = Query("ALL"),
    search: Optional[str] = Query(None),
    page: int = Query(1, ge=1),
    page_size: int = Query(25, ge=1, le=100),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Retrieve filtered and paginated security incidents."""
    return await incident_service.list_incidents(
        session=db,
        status=status,
        severity=severity,
        incident_type=incident_type,
        kill_chain_phase=kill_chain_phase,
        search=search,
        page=page,
        page_size=page_size,
    )


@router.get("/kpis")
async def get_incident_kpis(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Retrieve high-level incident response KPI metrics."""
    return await incident_service.get_incident_kpis(db)


@router.get("/{incident_id}")
async def get_incident_dossier(
    incident_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Fetch complete incident case details and timeline history."""
    incident = await incident_service.get_incident_by_id(db, incident_id)
    if not incident:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Incident '{incident_id}' not found")
    
    data = incident.to_dict()
    data["timeline"] = [t.to_dict() for t in (incident.timeline_events or [])]
    return data


@router.post("", status_code=status.HTTP_201_CREATED)
async def create_incident(
    req: CreateIncidentRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.INCIDENTS_CREATE)),
):
    """Open a new formal security incident case."""
    lead = req.lead_analyst or current_user.username
    inc = await incident_service.create_incident(
        session=db,
        title=req.title,
        summary=req.summary,
        severity=req.severity,
        incident_type=req.incident_type,
        kill_chain_phase=req.kill_chain_phase,
        lead_analyst=lead,
        impacted_hosts=req.impacted_hosts,
        impacted_users=req.impacted_users,
        associated_alert_ids=req.associated_alert_ids,
        assigned_playbook=req.assigned_playbook,
    )

    await AuditService.log_event(
        db=db,
        action="CREATE_INCIDENT",
        resource=f"incident:{inc.id}",
        username=current_user.username,
        user_id=current_user.id,
        details={"title": inc.title, "severity": inc.severity, "type": inc.incident_type},
        status="SUCCESS",
    )
    return inc.to_dict()


@router.patch("/{incident_id}/status")
async def update_incident_status(
    incident_id: str,
    req: UpdateIncidentStatusRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.INCIDENTS_UPDATE)),
):
    """Advance an incident through triage, containment, and resolution stages."""
    inc = await incident_service.update_status(
        session=db,
        incident_id=incident_id,
        new_status=req.status,
        author=current_user.username,
        comment=req.comment,
    )
    if not inc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Incident '{incident_id}' not found")

    await AuditService.log_event(
        db=db,
        action="UPDATE_INCIDENT_STATUS",
        resource=f"incident:{incident_id}",
        username=current_user.username,
        user_id=current_user.id,
        details={"new_status": req.status, "comment": req.comment},
        status="SUCCESS",
    )
    return inc.to_dict()


@router.post("/{incident_id}/timeline", status_code=status.HTTP_201_CREATED)
async def add_timeline_entry(
    incident_id: str,
    req: AddTimelineRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.INCIDENTS_UPDATE)),
):
    """Append an analyst finding or forensic note to the incident timeline."""
    entry = await incident_service.add_timeline_entry(
        session=db,
        incident_id=incident_id,
        author=current_user.username,
        action_type=req.action_type,
        description=req.description,
        evidence_reference=req.evidence_reference,
    )
    if not entry:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"Incident '{incident_id}' not found")
    return entry.to_dict()


@router.post("/{incident_id}/contain")
async def execute_soar_containment(
    incident_id: str,
    req: ContainmentActionRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.SOAR_EXECUTE)),
):
    """Execute automated SOAR containment action on a target asset or identity."""
    try:
        result = await incident_service.execute_soar_containment(
            session=db,
            incident_id=incident_id,
            action_type=req.action_type,
            target=req.target,
            author=current_user.username,
            parameters=req.parameters,
        )

        await AuditService.log_event(
            db=db,
            action="SOAR_CONTAINMENT_EXECUTED",
            resource=f"incident:{incident_id}",
            username=current_user.username,
            user_id=current_user.id,
            details={"action_type": req.action_type, "target": req.target, "result": result.get("message")},
            status="SUCCESS",
        )
        return result
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))
