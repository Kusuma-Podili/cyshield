"""Alert Management REST API Endpoints for CyberShield Enterprise."""

from __future__ import annotations

from typing import List, Optional
from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel

from cybershield.core.models import Alert, AlertStatus, Severity, now_utc
from cybershield.ingestion.collector import collector

router = APIRouter(prefix="/api/v1/alerts", tags=["Alerts"])


class TriageUpdateRequest(BaseModel):
    status: AlertStatus
    assigned_analyst: Optional[str] = None
    containment_action: Optional[str] = None


@router.get("", response_model=List[Alert])
async def list_alerts(
    severity: Optional[Severity] = None,
    status: Optional[AlertStatus] = None,
    limit: int = Query(default=100, ge=1, le=1000)
):
    """Retrieve security alerts filtered by severity or triage status."""
    alerts = collector.get_recent_alerts(limit=limit)
    if severity:
        alerts = [a for a in alerts if a.severity == severity]
    if status:
        alerts = [a for a in alerts if a.status == status]
    return list(reversed(alerts))


@router.get("/{alert_id}", response_model=Alert)
async def get_alert_by_id(alert_id: str):
    """Fetch complete metadata for a specific security alert."""
    alerts = collector.get_recent_alerts(limit=5000)
    for a in alerts:
        if a.alert_id == alert_id:
            return a
    raise HTTPException(status_code=404, detail=f"Alert '{alert_id}' not found")


@router.patch("/{alert_id}/triage", response_model=Alert)
async def triage_alert(alert_id: str, payload: TriageUpdateRequest):
    """Update analyst assignment and triage status for an alert."""
    alerts = collector.get_recent_alerts(limit=5000)
    for a in alerts:
        if a.alert_id == alert_id:
            a.status = payload.status
            if payload.assigned_analyst:
                a.assigned_analyst = payload.assigned_analyst
            if payload.containment_action:
                a.containment_actions_taken.append(payload.containment_action)
            a.updated_at = now_utc()
            return a
    raise HTTPException(status_code=404, detail=f"Alert '{alert_id}' not found")
