"""
API Security & Shadow API Discovery REST API routes.
"""

from typing import Any, Dict, List, Optional
from fastapi import APIRouter, HTTPException, Query, status

from cybershield.apisec.gateway import APISecurityGateway
from cybershield.apisec.schemas import (
    APISecurityFinding,
    APISpecEndpoint,
    APITrafficLog,
)

apisec_router = APIRouter(prefix="/api/apisec", tags=["API Security & Shadow API Discovery"])
_gateway = APISecurityGateway()


@apisec_router.post("/inspect", response_model=List[APISecurityFinding])
async def inspect_api_traffic_transaction(log: APITrafficLog):
    """
    Inspects an API transaction in real-time against OWASP API Security Top 10 rules,
    mass assignment vectors, BFLA, and shadow API catalogs.
    """
    return _gateway.inspect_transaction(log)


@apisec_router.get("/endpoints")
async def list_api_endpoints():
    """List all registered and actively discovered API routes."""
    return _gateway.list_endpoints()


@apisec_router.post("/endpoints", status_code=status.HTTP_201_CREATED)
async def register_api_endpoint(endpoint: APISpecEndpoint):
    """Register an approved OpenAPI specification route."""
    _gateway.register_endpoint(endpoint)
    return {"status": "REGISTERED", "path": endpoint.path, "method": endpoint.method}


@apisec_router.get("/shadow-apis")
async def list_shadow_apis():
    """Discover uncataloged and undocumented Shadow APIs operating in production."""
    return _gateway.get_shadow_endpoints()


@apisec_router.get("/zombie-apis")
async def list_zombie_apis():
    """Discover active traffic hitting deprecated and unmaintained Zombie APIs."""
    return _gateway.get_zombie_endpoints()


@apisec_router.get("/findings", response_model=List[APISecurityFinding])
async def list_api_security_findings(limit: int = Query(50, ge=1, le=500)):
    """List detected API vulnerabilities and authorization attacks."""
    return _gateway.list_findings()[:limit]


@apisec_router.get("/overview")
async def get_apisec_overview():
    """Consolidated metrics on API traffic inspection, shadow API count, and OWASP findings."""
    return _gateway.get_overview_metrics()
