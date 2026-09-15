"""
CyberShield Enterprise - Threat Intelligence REST API Routes
Provides endpoints for IoC search, rapid Bloom-filter enriched lookup,
STIX/MISP feed ingestion, APT actor profiling, and campaign tracking.
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
from cybershield.intel.feed_service import threat_intel_service
from cybershield.intel.schemas import (
    IoCCreateRequest,
    IoCLookupRequest,
    IoCLookupResponse,
    FeedIngestRequest,
    ThreatIntelKPIResponse,
)

router = APIRouter(prefix="/api/intel", tags=["Threat Intelligence"])


@router.get("/iocs", summary="List Indicators of Compromise (IoCs)")
async def list_iocs(
    indicator_type: Optional[str] = Query(None, description="Filter by IP, DOMAIN, URL, SHA256"),
    threat_type: Optional[str] = Query(None, description="Filter by C2_SERVER, MALWARE_HASH, etc."),
    severity: Optional[str] = Query(None, description="CRITICAL, HIGH, MEDIUM, LOW"),
    min_confidence: Optional[int] = Query(None, ge=0, le=100, description="Minimum confidence 0-100"),
    page: int = Query(1, ge=1),
    page_size: int = Query(25, ge=1, le=100),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.INTEL_VIEW)),
):
    """Retrieve paginated enterprise IoC records."""
    return await threat_intel_service.list_iocs(
        session=db,
        indicator_type=indicator_type,
        threat_type=threat_type,
        severity=severity,
        min_confidence=min_confidence,
        page=page,
        page_size=page_size,
    )


@router.post("/lookup", summary="Sub-Millisecond IoC Lookup & Enrichment", response_model=IoCLookupResponse)
async def lookup_ioc(
    req: IoCLookupRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.INTEL_VIEW)),
):
    """Perform ultra-fast Bloom filter and relational database threat lookup."""
    return await threat_intel_service.lookup_indicator(session=db, indicator=req.indicator)


@router.post("/iocs", status_code=status.HTTP_201_CREATED, summary="Add Custom Threat Indicator")
async def create_ioc(
    req: IoCCreateRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.INTEL_EDIT)),
):
    """Register a new Indicator of Compromise into the threat database."""
    ioc = await threat_intel_service.create_ioc(
        session=db,
        indicator_value=req.indicator_value,
        indicator_type=req.indicator_type,
        threat_type=req.threat_type,
        severity=req.severity,
        confidence_score=req.confidence_score,
        threat_actor=req.threat_actor,
        campaign=req.campaign,
        mitre_tactics=req.mitre_tactics,
        source_feed=req.source_feed,
        expires_in_days=req.expires_in_days or 90,
    )

    await AuditService.log_event(
        db=db,
        action="CREATE_IOC",
        resource=f"ioc:{ioc.indicator_value}",
        username=current_user.username,
        user_id=current_user.id,
        details={"type": ioc.indicator_type, "threat": ioc.threat_type, "confidence": ioc.confidence_score},
        status="SUCCESS",
    )
    return ioc.to_dict()


@router.post("/feed/ingest", summary="Ingest STIX / MISP Feed Bundle")
async def ingest_threat_feed(
    req: FeedIngestRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.INTEL_EDIT)),
):
    """Ingest external threat feed bundle in STIX 2.1 JSON or MISP format."""
    count = await threat_intel_service.ingest_stix_bundle(
        session=db,
        stix_bundle=req.payload,
        feed_name=req.feed_name,
    )

    await AuditService.log_event(
        db=db,
        action="INGEST_THREAT_FEED",
        resource=req.feed_name,
        username=current_user.username,
        user_id=current_user.id,
        details={"format": req.feed_format, "indicators_imported": count},
        status="SUCCESS",
    )
    return {"feed_name": req.feed_name, "indicators_imported": count}


@router.get("/actors", summary="List APT Threat Actor Profiles")
async def list_threat_actors(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.INTEL_VIEW)),
):
    """Fetch nation-state and cybercrime threat actor profiles with known TTPs."""
    return await threat_intel_service.list_threat_actors(db)


@router.get("/campaigns", summary="List Active Threat Campaigns")
async def list_threat_campaigns(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.INTEL_VIEW)),
):
    """Retrieve active and monitored cyber threat campaigns."""
    return await threat_intel_service.list_campaigns(db)


@router.get("/kpis", summary="Threat Intel Metrics", response_model=ThreatIntelKPIResponse)
async def get_threat_intel_kpis(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.INTEL_VIEW)),
):
    """Retrieve threat intelligence telemetry KPIs."""
    return await threat_intel_service.get_intel_kpis(db)
