"""
Attack Surface Management (ASM) REST API Routes.
Exposes endpoints for external asset discovery, exposure issues, and perimeter risk analysis.
"""

from typing import Any, Dict, List, Optional
from fastapi import APIRouter, HTTPException, Query, status

from cybershield.asm.scanner import AttackSurfaceScanner
from cybershield.asm.schemas import (
    ASMOverviewMetrics,
    ASMScanJob,
    ASMScanRequest,
    DiscoveredAsset,
    ExposedIssue,
    ExposureSeverity,
)

asm_router = APIRouter(prefix="/api/asm", tags=["Attack Surface Management (ASM)"])
asm_scanner = AttackSurfaceScanner()


@asm_router.get("/assets", response_model=List[DiscoveredAsset])
async def list_assets():
    """List all discovered perimeter assets."""
    return asm_scanner.list_assets()


@asm_router.get("/assets/{asset_id}", response_model=DiscoveredAsset)
async def get_asset(asset_id: str):
    """Retrieve details of a specific perimeter asset."""
    asset = asm_scanner.get_asset(asset_id)
    if not asset:
        raise HTTPException(status_code=404, detail=f"Asset {asset_id} not found")
    return asset


@asm_router.post("/scan", response_model=ASMScanJob, status_code=status.HTTP_202_ACCEPTED)
async def trigger_scan(request: ASMScanRequest):
    """Trigger an external perimeter attack surface reconnaissance scan."""
    return asm_scanner.run_scan(request)


@asm_router.get("/jobs/{job_id}", response_model=ASMScanJob)
async def get_job(job_id: str):
    """Get status and result of a scan job."""
    job = asm_scanner.get_scan_job(job_id)
    if not job:
        raise HTTPException(status_code=404, detail=f"Job {job_id} not found")
    return job


@asm_router.get("/issues", response_model=List[ExposedIssue])
async def list_issues(severity: Optional[ExposureSeverity] = Query(None)):
    """List identified perimeter exposures and vulnerabilities."""
    return asm_scanner.list_issues(severity=severity)


@asm_router.get("/overview", response_model=ASMOverviewMetrics)
async def get_overview():
    """Retrieve overall attack surface risk overview and exposed dangerous ports."""
    return asm_scanner.get_overview_metrics()
