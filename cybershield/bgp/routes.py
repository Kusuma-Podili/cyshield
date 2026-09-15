"""
BGP Route Hijacking & Peering Monitor REST API routes.
"""

from typing import Any, Dict, List, Optional
from fastapi import APIRouter, HTTPException, Query, status

from cybershield.bgp.monitor import BGPMonitorEngine
from cybershield.bgp.schemas import (
    BGPHijackAlert,
    BGPRouteAnnouncement,
    BGPRouteEvaluationResult,
    RouteOriginAuthorization,
)

bgp_router = APIRouter(prefix="/api/bgp", tags=["BGP Route Hijacking & Peering Monitor"])
_bgp_engine = BGPMonitorEngine()


@bgp_router.post("/evaluate", response_model=BGPRouteEvaluationResult)
async def evaluate_bgp_route(announcement: BGPRouteAnnouncement):
    """
    Validates an incoming BGP route advertisement against RPKI Route Origin Authorizations,
    detecting origin hijacks, sub-prefix hijacks, and bogon route announcements.
    """
    return _bgp_engine.evaluate_announcement(announcement)


@bgp_router.get("/roas", response_model=List[RouteOriginAuthorization])
async def list_roas():
    """List all configured RPKI Route Origin Authorizations (ROAs)."""
    return _bgp_engine.list_roas()


@bgp_router.post("/roas", response_model=RouteOriginAuthorization, status_code=status.HTTP_201_CREATED)
async def create_roa(roa: RouteOriginAuthorization):
    """Register a new cryptographic ROA for prefix origin validation."""
    return _bgp_engine.add_roa(roa)


@bgp_router.get("/alerts", response_model=List[BGPHijackAlert])
async def list_bgp_alerts(limit: int = Query(50, ge=1, le=500)):
    """List detected BGP routing attacks and prefix hijacking alerts."""
    return _bgp_engine.list_alerts()[:limit]


@bgp_router.get("/overview")
async def get_bgp_overview():
    """Executive metrics on evaluated BGP announcements, RPKI ROAs, and route hijacks."""
    return _bgp_engine.get_overview_metrics()
