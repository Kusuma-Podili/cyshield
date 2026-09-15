"""
CyberShield Enterprise - Alert Triage & Ingestion REST API Endpoints
Provides SOC analyst triage workflows, notes, incident escalation, and queue KPIs.
"""

from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from cybershield.database.session import get_db
from cybershield.database.models import User, AlertSuppressionRuleModel
from cybershield.auth.dependencies import get_current_user
from cybershield.alerts.schemas import (
    AlertCreate,
    AlertUpdate,
    AlertResponse,
    AlertPaginatedList,
    AlertTriageRequest,
    AlertNoteRequest,
    AlertEscalateRequest,
    AlertKPISummary,
    AlertSuppressionRuleCreate,
    AlertSuppressionRuleResponse,
)
from cybershield.alerts.service import AlertService
from cybershield.audit.service import AuditService
from cybershield.core.logging import get_logger

logger = get_logger("cybershield.api.alerts")
router = APIRouter(prefix="/api/alerts", tags=["Security Alerts"])


@router.get("", response_model=AlertPaginatedList)
async def list_alerts(
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    severity: Optional[str] = Query(None),
    status_filter: Optional[str] = Query(None, alias="status"),
    engine: Optional[str] = Query(None),
    search: Optional[str] = Query(None),
    host_name: Optional[str] = Query(None),
    user_name: Optional[str] = Query(None),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Retrieve paginated security alert queue with multi-dimensional SIEM filters."""
    service = AlertService(db)
    return await service.list_alerts(
        page=page,
        page_size=page_size,
        severity=severity,
        status=status_filter,
        engine=engine,
        search=search,
        host_name=host_name,
        user_name=user_name,
    )


@router.post("", response_model=AlertResponse, status_code=status.HTTP_201_CREATED)
async def create_alert(
    payload: AlertCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Ingest a new detection alert with automated deduplication and suppression checks."""
    service = AlertService(db)
    alert = await service.create_alert(payload)

    await AuditService.log_event(
        db=db,
        action="ALERT_CREATE",
        username=current_user.username,
        user_id=current_user.id,
        resource=f"alert:{alert.id}",
        status="SUCCESS",
        details={"title": alert.title, "severity": alert.severity, "rule": alert.rule_id}
    )
    return alert


@router.get("/kpis", response_model=AlertKPISummary)
async def get_alert_kpis(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Fetch aggregated alert metrics, severity breakdown, and top affected hosts."""
    service = AlertService(db)
    return await service.get_kpis()


@router.get("/suppression", response_model=List[AlertSuppressionRuleResponse])
async def list_suppression_rules(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """List all active alert suppression policies."""
    stmt = select(AlertSuppressionRuleModel).where(AlertSuppressionRuleModel.is_active == True)
    rules = (await db.execute(stmt)).scalars().all()
    return [
        AlertSuppressionRuleResponse(
            id=r.id,
            name=r.name,
            rule_name_pattern=r.rule_name_pattern,
            host_pattern=r.host_pattern,
            user_pattern=r.user_pattern,
            reason=r.reason,
            created_by=r.created_by,
            is_active=r.is_active,
            created_at=r.created_at,
        )
        for r in rules
    ]


@router.post("/suppression", response_model=AlertSuppressionRuleResponse, status_code=status.HTTP_201_CREATED)
async def create_suppression_rule(
    payload: AlertSuppressionRuleCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Declare a new alert noise suppression rule."""
    import uuid
    from datetime import datetime
    rule = AlertSuppressionRuleModel(
        id=f"sup-{uuid.uuid4().hex[:8]}",
        name=payload.name,
        rule_name_pattern=payload.rule_name_pattern,
        host_pattern=payload.host_pattern,
        user_pattern=payload.user_pattern,
        reason=payload.reason,
        created_by=current_user.username,
        is_active=True,
        created_at=datetime.utcnow(),
    )
    db.add(rule)
    await db.commit()
    await db.refresh(rule)

    await AuditService.log_event(
        db=db,
        action="ALERT_SUPPRESSION_CREATE",
        username=current_user.username,
        user_id=current_user.id,
        resource=f"suppression:{rule.id}",
        status="SUCCESS",
        details={"name": rule.name, "reason": rule.reason}
    )
    return AlertSuppressionRuleResponse(
        id=rule.id,
        name=rule.name,
        rule_name_pattern=rule.rule_name_pattern,
        host_pattern=rule.host_pattern,
        user_pattern=rule.user_pattern,
        reason=rule.reason,
        created_by=rule.created_by,
        is_active=rule.is_active,
        created_at=rule.created_at,
    )


@router.get("/{alert_id}", response_model=AlertResponse)
async def get_alert(
    alert_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Fetch single alert record with investigation timeline and linked telemetry."""
    service = AlertService(db)
    alert = await service.get_alert_by_id(alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail=f"Alert '{alert_id}' not found")
    return service._to_response(alert)


@router.post("/{alert_id}/triage", response_model=AlertResponse)
async def triage_alert(
    alert_id: str,
    payload: AlertTriageRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Advance alert status (ASSIGNED, UNDER_INVESTIGATION, RESOLVED, FALSE_POSITIVE)."""
    service = AlertService(db)
    result = await service.triage_alert(alert_id, payload, current_user)
    if not result:
        raise HTTPException(status_code=404, detail=f"Alert '{alert_id}' not found")

    await AuditService.log_event(
        db=db,
        action="ALERT_TRIAGE",
        username=current_user.username,
        user_id=current_user.id,
        resource=f"alert:{alert_id}",
        status="SUCCESS",
        details={"new_status": payload.status, "resolution": payload.resolution_summary}
    )
    return result


@router.post("/{alert_id}/notes", response_model=AlertResponse)
async def add_alert_note(
    alert_id: str,
    payload: AlertNoteRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Append an analyst investigation note to the alert record."""
    service = AlertService(db)
    result = await service.add_note(alert_id, payload.note, current_user)
    if not result:
        raise HTTPException(status_code=404, detail=f"Alert '{alert_id}' not found")

    return result


@router.post("/{alert_id}/escalate")
async def escalate_alert(
    alert_id: str,
    payload: AlertEscalateRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Escalate alert into an enterprise Incident Response Case."""
    service = AlertService(db)
    result = await service.escalate_to_incident(alert_id, payload, current_user)
    if not result:
        raise HTTPException(status_code=404, detail=f"Alert '{alert_id}' not found")

    await AuditService.log_event(
        db=db,
        action="ALERT_ESCALATE_INCIDENT",
        username=current_user.username,
        user_id=current_user.id,
        resource=f"alert:{alert_id}",
        status="SUCCESS",
        details=result
    )
    return result
