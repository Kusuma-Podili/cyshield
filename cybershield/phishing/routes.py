"""
CyberShield Enterprise - Phishing & Email Security REST API Routes
Provides endpoints for deep email inspection, typosquatting domain checking,
and email defense telemetry KPIs.
"""

from __future__ import annotations

from typing import Optional, List
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.ext.asyncio import AsyncSession

from cybershield.database.session import get_db
from cybershield.database.models.user import User
from cybershield.database.models.role import Permission
from cybershield.auth.dependencies import get_current_user, require_permission
from cybershield.audit.service import AuditService
from cybershield.phishing.service import phishing_service
from cybershield.phishing.email_analyzer import EmailSecurityAnalyzer
from cybershield.phishing.schemas import (
    EmailAnalyzeRequest,
    BrandCheckRequest,
    PhishingKPIResponse,
)

router = APIRouter(prefix="/api/phishing", tags=["Phishing & Email Security"])


@router.post("/analyze", summary="Perform Deep Email Inspection")
async def analyze_email(
    req: EmailAnalyzeRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.PHISHING_ANALYZE)),
):
    """Analyze email headers, message body, brand lookalikes, and attachments."""
    attachments_dict = [a.model_dump() for a in req.attachments] if req.attachments else []
    record = await phishing_service.analyze_email(
        session=db,
        headers=req.headers,
        body=req.body,
        attachments=attachments_dict,
    )

    await AuditService.log_event(
        db=db,
        action="ANALYZE_EMAIL_PHISHING",
        resource=f"email:{record['id']}",
        username=current_user.username,
        user_id=current_user.id,
        details={"sender": record["sender"], "classification": record["classification"], "score": record["score"]},
        status="SUCCESS",
    )
    return record


@router.get("/recent", summary="List Recent Email Scans")
async def list_recent_scans(
    limit: int = Query(50, ge=1, le=200),
    current_user: User = Depends(require_permission(Permission.PHISHING_ANALYZE)),
):
    """Fetch recent email analysis records and forensic reports."""
    return phishing_service.get_recent_scans(limit=limit)


@router.get("/kpis", summary="Email Defense KPIs", response_model=PhishingKPIResponse)
async def get_phishing_kpis(
    current_user: User = Depends(require_permission(Permission.PHISHING_ANALYZE)),
):
    """Retrieve aggregate email threat intelligence and brand spoofing metrics."""
    return phishing_service.get_kpis()


@router.post("/brand-check", summary="Check Typosquatting / Lookalike Brand Impersonation")
async def check_brand(
    req: BrandCheckRequest,
    current_user: User = Depends(require_permission(Permission.PHISHING_ANALYZE)),
):
    """Analyze a domain string using Levenshtein distance for brand impersonation."""
    match = EmailSecurityAnalyzer.check_brand_impersonation(req.domain)
    return {
        "domain": req.domain,
        "is_impersonation": match is not None,
        "details": match,
    }
