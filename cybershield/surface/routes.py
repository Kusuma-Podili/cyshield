"""CyberShield Enterprise - Autonomous Threat Surface Graph & Shadow Cloud Reconciler Routes.
Exposes endpoints for CMDB reconciliation, shadow cloud asset discovery,
dangling DNS takeover audits, and attack surface hygiene.
"""

from typing import Dict, List, Optional, Any
from fastapi import APIRouter, HTTPException, Query, status

from .schemas import (
    CloudAsset,
    DNSTakeoverCheckRequest,
    SurfaceThreatAlert,
    ReconciliationRequest,
    ReconciliationReport,
)
from .reconciler import ThreatSurfaceReconciler

router = APIRouter(prefix="/api/v1/surface", tags=["Threat Surface & Shadow Cloud Reconciler"])

# Singleton reconciler instance
_SURFACE_RECONCILER = ThreatSurfaceReconciler()


@router.post("/assets/reconcile", response_model=ReconciliationReport, status_code=status.HTTP_200_OK)
def reconcile_cloud_assets(request: ReconciliationRequest):
    """Reconcile sanctioned CMDB assets against live observed cloud telemetry."""
    return _SURFACE_RECONCILER.reconcile_assets(request)


@router.post("/dns/takeover/check", response_model=Dict[str, Any], status_code=status.HTTP_200_OK)
def evaluate_dns_takeover(request: DNSTakeoverCheckRequest):
    """Audit CNAME record for dangling DNS subdomain takeover vulnerability."""
    alert = _SURFACE_RECONCILER.evaluate_dns_takeover(request)
    return {
        "subdomain": request.subdomain,
        "is_takeover_vulnerable": alert is not None,
        "alert": alert,
    }


@router.get("/shadow/assets", response_model=List[CloudAsset])
def list_shadow_cloud_assets():
    """Retrieve all discovered unmanaged shadow cloud assets."""
    return list(_SURFACE_RECONCILER.shadow_assets.values())


@router.get("/threats", response_model=List[SurfaceThreatAlert])
def list_surface_threat_alerts():
    """Retrieve active attack surface security alerts."""
    return _SURFACE_RECONCILER.alerts
