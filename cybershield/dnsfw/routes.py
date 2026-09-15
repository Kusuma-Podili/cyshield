"""
DNS Firewall & Protective Sinkholing REST API routes.
"""

from typing import Any, Dict, List, Optional
from fastapi import APIRouter, HTTPException, Query, status

from cybershield.dnsfw.engine import DNSFirewallEngine
from cybershield.dnsfw.schemas import (
    DNSFirewallRule,
    DNSInspectionRequest,
    DNSInspectionResponse,
    DNSSinkholeHit,
)

dnsfw_router = APIRouter(prefix="/api/dnsfw", tags=["DNS Firewall & Protective C2 Sinkhole"])
_dns_engine = DNSFirewallEngine()


@dnsfw_router.post("/inspect", response_model=DNSInspectionResponse)
async def inspect_dns_query(request: DNSInspectionRequest):
    """
    Evaluates outbound DNS domain request in real-time against RPZ policies,
    algorithmic DGA models, and DNS tunneling detectors.
    """
    return _dns_engine.inspect_query(request)


@dnsfw_router.get("/rules", response_model=List[DNSFirewallRule])
async def list_rpz_rules():
    """List all configured Response Policy Zone (RPZ) filtering rules."""
    return _dns_engine.list_rules()


@dnsfw_router.post("/rules", response_model=DNSFirewallRule, status_code=status.HTTP_201_CREATED)
async def create_rpz_rule(rule: DNSFirewallRule):
    """Deploy a new custom DNS Response Policy Zone rule."""
    return _dns_engine.add_rule(rule)


@dnsfw_router.delete("/rules/{rule_id}")
async def delete_rpz_rule(rule_id: str):
    """Remove an RPZ rule from active filtering engine."""
    success = _dns_engine.delete_rule(rule_id)
    if not success:
        raise HTTPException(status_code=404, detail=f"RPZ rule '{rule_id}' not found")
    return {"status": "DELETED", "rule_id": rule_id}


@dnsfw_router.get("/sinkhole/hits", response_model=List[DNSSinkholeHit])
async def list_sinkhole_hits(limit: int = Query(50, ge=1, le=500)):
    """List connection attempts from compromised hosts captured by the C2 sinkhole."""
    return _dns_engine.list_sinkhole_hits(limit=limit)


@dnsfw_router.post("/sinkhole/hits", status_code=status.HTTP_201_CREATED)
async def record_sinkhole_hit(hit: DNSSinkholeHit):
    """Record an inbound connection attempt hitting the sinkhole interface."""
    _dns_engine.record_sinkhole_hit(hit)
    return {"status": "RECORDED", "hit_id": hit.hit_id}


@dnsfw_router.get("/overview")
async def get_dnsfw_overview():
    """Executive metrics on DNS inspection throughput, sinkholed threats, and DGA detections."""
    return _dns_engine.get_overview_metrics()
