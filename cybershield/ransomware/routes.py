"""
Ransomware Canary & VSS Shadow Copy Sentinel REST API routes.
"""

from typing import Any, Dict, List, Optional
from fastapi import APIRouter, HTTPException, Query, status

from cybershield.ransomware.schemas import (
    CanaryTrapFile,
    FileModificationEvent,
    RansomwareAlert,
    VSSCommandInspectionRequest,
)
from cybershield.ransomware.sentinel import RansomwareSentinelEngine

ransomware_router = APIRouter(prefix="/api/ransomware", tags=["Ransomware Canary & VSS Sentinel"])
_sentinel = RansomwareSentinelEngine()


@ransomware_router.get("/canaries", response_model=List[CanaryTrapFile])
async def list_canary_files():
    """List all deployed decoy bait files across monitored enterprise assets."""
    return _sentinel.list_canaries()


@ransomware_router.post("/canaries/deploy", response_model=List[CanaryTrapFile], status_code=status.HTTP_201_CREATED)
async def deploy_host_canaries(host_id: str = Query(...), base_dir: str = Query(r"C:\Users\Public\Documents")):
    """Deploy a suite of alphabetical canary decoy bait files on an endpoint."""
    return _sentinel.deploy_host_canaries(host_id=host_id, base_directory=base_dir)


@ransomware_router.post("/inspect/file-event", response_model=Optional[RansomwareAlert])
async def inspect_file_modification_event(event: FileModificationEvent):
    """
    Evaluates endpoint file modification telemetry against canary files,
    known ransomware extensions, and high-entropy encryption bursts.
    """
    return _sentinel.inspect_file_modification(event)


@ransomware_router.post("/inspect/command", response_model=Optional[RansomwareAlert])
async def inspect_process_command(req: VSSCommandInspectionRequest):
    """
    Evaluates process execution commands for Volume Shadow Copy (VSS) deletion
    and backup inhibition (T1490).
    """
    return _sentinel.inspect_vss_command(req)


@ransomware_router.get("/alerts", response_model=List[RansomwareAlert])
async def list_ransomware_alerts(limit: int = Query(50, ge=1, le=500)):
    """List active ransomware outbreaks and triggered canary detections."""
    return _sentinel.list_alerts()[:limit]


@ransomware_router.get("/overview")
async def get_ransomware_overview():
    """Consolidated ransomware posture metrics, tripped canary alarms, and active outbreaks."""
    return _sentinel.get_overview_metrics()
