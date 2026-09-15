"""
Web Application Firewall (WAF) REST API routes.
"""

from typing import Any, Dict, List, Optional
from fastapi import APIRouter, HTTPException, Query, status

from cybershield.waf.engine import WAFEngine
from cybershield.waf.schemas import (
    WAFInspectionRequest,
    WAFInspectionResult,
    WAFPolicyConfig,
)

waf_router = APIRouter(prefix="/api/waf", tags=["Web Application Firewall (WAF)"])
_waf_engine = WAFEngine()


@waf_router.post("/inspect", response_model=WAFInspectionResult)
async def inspect_http_request(request: WAFInspectionRequest):
    """
    Evaluates incoming HTTP request against OWASP Core Rule Set signatures
    using collaborative anomaly scoring.
    """
    return _waf_engine.inspect_request(request)


@waf_router.get("/rules")
async def list_waf_rules():
    """List all compiled OWASP CRS signatures across SQLi, XSS, RCE, and LFI."""
    return _waf_engine.list_rules()


@waf_router.get("/config", response_model=WAFPolicyConfig)
async def get_waf_configuration():
    """Retrieve active WAF operational policy and anomaly scoring thresholds."""
    return _waf_engine.config


@waf_router.put("/config", response_model=WAFPolicyConfig)
async def update_waf_configuration(new_config: WAFPolicyConfig):
    """Update global WAF anomaly scoring threshold or mode (BLOCK vs MONITOR)."""
    return _waf_engine.update_config(new_config)


@waf_router.get("/overview")
async def get_waf_overview():
    """Executive metrics on total HTTP transactions inspected, blocked attacks, and threat categories."""
    return _waf_engine.get_overview_metrics()
