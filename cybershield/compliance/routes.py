"""REST API Endpoints for Regulatory Compliance Subsystem."""

from __future__ import annotations

from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.ext.asyncio import AsyncSession

from cybershield.database.session import get_db
from cybershield.database.models import User, Permission
from cybershield.auth.dependencies import get_current_user, require_permission
from cybershield.compliance.service import ComplianceService
from cybershield.compliance.engine import ComplianceEngine
from cybershield.compliance.schemas import (
    ComplianceOverviewResponse,
    FrameworkResponse,
    ControlResponse,
    AssessmentResponse,
)

router = APIRouter(prefix="/api/compliance", tags=["compliance"])


@router.get(
    "/overview",
    response_model=ComplianceOverviewResponse,
    summary="Get global cross-framework compliance posture",
)
async def get_compliance_overview(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.COMPLIANCE_VIEW)),
):
    """Calculate and return composite compliance score, letter grade, and remediation gaps."""
    return await ComplianceService.get_overview(db)


@router.get(
    "/frameworks",
    response_model=List[FrameworkResponse],
    summary="List all regulatory compliance frameworks",
)
async def list_frameworks(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.COMPLIANCE_VIEW)),
):
    """Return all configured compliance frameworks (SOC2, ISO27001, NIST, PCI-DSS, HIPAA, GDPR)."""
    return await ComplianceService.list_frameworks(db)


@router.get(
    "/frameworks/{framework_id}/controls",
    response_model=List[ControlResponse],
    summary="List controls for a specific framework",
)
async def get_framework_controls(
    framework_id: str,
    status_filter: Optional[str] = Query(None, alias="status"),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.COMPLIANCE_VIEW)),
):
    """Retrieve evaluated control items, scores, and technical evidence for a framework."""
    controls = await ComplianceService.get_framework_controls(db, framework_id, status=status_filter)
    if not controls:
        # Check if framework exists
        frameworks = await ComplianceService.list_frameworks(db)
        if not any(f["id"] == framework_id.upper() for f in frameworks):
            raise HTTPException(status_code=404, detail=f"Compliance framework '{framework_id}' not found.")
    return controls


@router.post(
    "/assess",
    response_model=List[AssessmentResponse],
    summary="Trigger an automated compliance assessment",
)
async def run_compliance_assessment(
    framework_id: Optional[str] = Query(None, description="Optional framework ID to evaluate (or all if omitted)"),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.COMPLIANCE_ASSESS)),
):
    """Run real-time automated assessment across active assets, CVEs, alerts, and audit logs."""
    assessments = await ComplianceEngine.run_assessment(
        db,
        framework_id=framework_id,
        actor=current_user.username,
    )
    return [a.to_dict() for a in assessments]


@router.get(
    "/assessments",
    response_model=List[AssessmentResponse],
    summary="List historical compliance assessment runs",
)
async def list_assessments(
    framework_id: Optional[str] = Query(None),
    limit: int = Query(20, ge=1, le=100),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.COMPLIANCE_VIEW)),
):
    """Retrieve historical assessment snapshots and audit findings."""
    return await ComplianceService.list_assessments(db, framework_id=framework_id, limit=limit)
