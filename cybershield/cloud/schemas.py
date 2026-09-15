"""Pydantic v2 Schemas for Cloud & Container Security (CSPM / CWPP)."""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class CloudProvider(str, Enum):
    AWS = "AWS"
    AZURE = "AZURE"
    GCP = "GCP"
    KUBERNETES = "KUBERNETES"
    DOCKER = "DOCKER"


class CloudFindingSeverity(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class CloudSecurityFinding(BaseModel):
    finding_id: str
    provider: CloudProvider
    severity: CloudFindingSeverity
    title: str
    description: str
    resource_id: str
    mitre_technique: Optional[str] = None
    remediation: str
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class K8sWorkloadScanResult(BaseModel):
    resource_kind: str
    name: str
    namespace: str = "default"
    is_compliant: bool
    total_violations: int
    findings: List[CloudSecurityFinding] = Field(default_factory=list)


class ContainerRuntimeAlert(BaseModel):
    alert_id: str
    container_id: str
    image_name: str
    pod_name: Optional[str] = None
    namespace: Optional[str] = "default"
    severity: CloudFindingSeverity
    title: str
    description: str
    mitre_technique: str
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    evidence: Dict[str, Any] = Field(default_factory=dict)


class K8sScanRequest(BaseModel):
    manifest_raw: str = Field(..., description="YAML or JSON string of Kubernetes Pod/Deployment/DaemonSet manifest")


class CloudTrailAuditRequest(BaseModel):
    records: List[Dict[str, Any]] = Field(..., description="Array of AWS CloudTrail JSON event records")


class ContainerProcessInspectRequest(BaseModel):
    container_id: str
    image_name: str
    pod_name: Optional[str] = "unknown"
    namespace: Optional[str] = "default"
    command_line: str
    working_dir: Optional[str] = "/"
    mounts: List[str] = Field(default_factory=list)
    capabilities: List[str] = Field(default_factory=list)
    user_id: int = 0


class CloudPostureResponse(BaseModel):
    provider: CloudProvider
    compliance_score: float
    total_findings: int
    critical_findings: int
    high_findings: int
    findings: List[CloudSecurityFinding] = Field(default_factory=list)
