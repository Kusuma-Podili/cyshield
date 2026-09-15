"""
CyberShield Enterprise - Security Events & Telemetry Ingestion REST API Endpoints
Provides high-throughput SIEM log ingestion, multi-format parsing,
event stream searching, and database-backed CS-QL threat hunting queries.
"""

from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.ext.asyncio import AsyncSession

from cybershield.database.session import get_db
from cybershield.database.models import User
from cybershield.auth.dependencies import get_current_user
from cybershield.events.schemas import (
    SecurityEventResponse,
    EventPaginatedList,
    EventIngestRequest,
    EventIngestResponse,
    CSQLQueryRequest,
    CSQLQueryResponse,
    EventStatsResponse,
)
from cybershield.events.service import EventsService
from cybershield.audit.service import AuditService
from cybershield.core.logging import get_logger

logger = get_logger("cybershield.api.events")
router = APIRouter(prefix="/api/events", tags=["Security Events & Ingestion"])


@router.get("", response_model=EventPaginatedList)
async def list_events(
    page: int = Query(1, ge=1),
    page_size: int = Query(25, ge=1, le=200),
    source_type: Optional[str] = Query(None),
    event_type: Optional[str] = Query(None),
    severity: Optional[str] = Query(None),
    host_name: Optional[str] = Query(None),
    user_name: Optional[str] = Query(None),
    search: Optional[str] = Query(None),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Query normalized enterprise telemetry events with multi-criteria SIEM filters."""
    service = EventsService(db)
    return await service.list_events(
        page=page,
        page_size=page_size,
        source_type=source_type,
        event_type=event_type,
        severity=severity,
        host_name=host_name,
        user_name=user_name,
        search=search,
    )


@router.post("/ingest", response_model=EventIngestResponse, status_code=status.HTTP_201_CREATED)
async def ingest_events(
    payload: EventIngestRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """High-throughput SIEM ingestion endpoint accepting batches of raw logs or JSON records."""
    service = EventsService(db)
    return await service.ingest_batch(payload)


@router.post("/csql", response_model=CSQLQueryResponse)
async def execute_csql_query(
    payload: CSQLQueryRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Execute CS-QL Threat Hunting query against persistent security events."""
    service = EventsService(db)
    result = await service.execute_csql(payload)

    await AuditService.log_event(
        db=db,
        action="CSQL_QUERY_EXECUTE",
        username=current_user.username,
        user_id=current_user.id,
        resource="telemetry:csql",
        status="SUCCESS",
        details={"query": payload.query, "matches": result.total_matches}
    )
    return result


@router.get("/stats", response_model=EventStatsResponse)
async def get_event_stats(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Fetch live telemetry ingestion rates, source distributions, and anomalous event counts."""
    service = EventsService(db)
    return await service.get_stats()
