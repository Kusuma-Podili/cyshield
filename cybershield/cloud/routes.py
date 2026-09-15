"""FastAPI Router for Cloud & Container Security (CSPM / CWPP)."""

from __future__ import annotations

from typing import List, Optional
from fastapi import APIRouter, Depends, Query

from cybershield.auth.dependencies import get_current_user
from cybershield.database.models.user import User
from cybershield.cloud.engine import cloud_engine
from cybershield.cloud.schemas import (
    CloudFindingSeverity,
    CloudPostureResponse,
    CloudProvider,
    CloudSecurityFinding,
    CloudTrailAuditRequest,
    ContainerProcessInspectRequest,
    ContainerRuntimeAlert,
    K8sScanRequest,
    K8sWorkloadScanResult,
)

router = APIRouter(prefix="/api/cloud", tags=["Cloud & Container Security"])


@router.post(
    "/k8s/scan",
    response_model=K8sWorkloadScanResult,
    summary="Audit Kubernetes Workload Manifest",
)
async def scan_k8s_manifest(
    req: K8sScanRequest,
    current_user: User = Depends(get_current_user),
) -> K8sWorkloadScanResult:
    """Audit a Kubernetes YAML/JSON manifest against Pod Security Standards."""
    return cloud_engine.scan_k8s_manifest(req.manifest_raw)


@router.post(
    "/aws/cloudtrail",
    response_model=List[CloudSecurityFinding],
    summary="Audit AWS CloudTrail Audit Records",
)
async def audit_cloudtrail(
    req: CloudTrailAuditRequest,
    current_user: User = Depends(get_current_user),
) -> List[CloudSecurityFinding]:
    """Audit AWS CloudTrail JSON records for root access, evasion, and IAM privilege escalation."""
    return cloud_engine.audit_cloudtrail_records(req.records)


@router.post(
    "/container/inspect",
    response_model=List[ContainerRuntimeAlert],
    summary="Inspect Container Process & Mounts (CWPP)",
)
async def inspect_container_process(
    req: ContainerProcessInspectRequest,
    current_user: User = Depends(get_current_user),
) -> List[ContainerRuntimeAlert]:
    """Inspect running container processes, breakout attempts, and docker.sock abuse."""
    return cloud_engine.inspect_container_process(req)


@router.get(
    "/posture",
    response_model=CloudPostureResponse,
    summary="Get Cloud Security Posture & Compliance Score",
)
async def get_cloud_posture(
    provider: Optional[CloudProvider] = Query(None, description="Filter by cloud provider"),
    current_user: User = Depends(get_current_user),
) -> CloudPostureResponse:
    """Calculate aggregate cloud security posture score (0-100%)."""
    return cloud_engine.get_posture(provider=provider)


@router.get(
    "/findings",
    response_model=List[CloudSecurityFinding],
    summary="List All Cloud Security Findings",
)
async def list_findings(
    provider: Optional[CloudProvider] = Query(None),
    severity: Optional[CloudFindingSeverity] = Query(None),
    current_user: User = Depends(get_current_user),
) -> List[CloudSecurityFinding]:
    """Retrieve all CSPM findings with optional filtering."""
    findings = cloud_engine.get_all_findings()
    if provider:
        findings = [f for f in findings if f.provider == provider]
    if severity:
        findings = [f for f in findings if f.severity == severity]
    return findings


@router.get(
    "/runtime/alerts",
    response_model=List[ContainerRuntimeAlert],
    summary="List CWPP Runtime Alerts",
)
async def list_runtime_alerts(
    current_user: User = Depends(get_current_user),
) -> List[ContainerRuntimeAlert]:
    """Retrieve all container workload protection runtime alerts."""
    return cloud_engine.get_all_runtime_alerts()


@router.delete(
    "/findings",
    summary="Clear Cloud Findings Cache",
)
async def clear_findings(
    current_user: User = Depends(get_current_user),
) -> dict:
    """Clear all cached CSPM findings and CWPP alerts."""
    cloud_engine.clear()
    return {"status": "cleared", "message": "Cloud findings and runtime alerts cleared"}

