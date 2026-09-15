"""CyberShield Enterprise - Autonomous Threat Surface Graph & Shadow Cloud Reconciler Schemas.
Data contracts for CMDB drift detection, shadow cloud assets, dangling DNS takeover,
and cloud attack surface posture scoring.
"""

from enum import Enum
from typing import Dict, List, Optional, Any
from datetime import datetime, timezone
from pydantic import BaseModel, Field


class CloudAssetType(str, Enum):
    VIRTUAL_MACHINE = "VIRTUAL_MACHINE"
    OBJECT_STORAGE_BUCKET = "OBJECT_STORAGE_BUCKET"
    MANAGED_DATABASE = "MANAGED_DATABASE"
    DNS_ZONE_RECORD = "DNS_ZONE_RECORD"
    KUBERNETES_CLUSTER = "KUBERNETES_CLUSTER"
    SERVERLESS_FUNCTION = "SERVERLESS_FUNCTION"


class SurfaceThreatType(str, Enum):
    SHADOW_UNMANAGED_ASSET = "SHADOW_UNMANAGED_ASSET"
    DANGLING_DNS_TAKEOVER_RISK = "DANGLING_DNS_TAKEOVER_RISK"
    PUBLIC_OBJECT_STORAGE_LEAK = "PUBLIC_OBJECT_STORAGE_LEAK"
    EXPOSED_MANAGEMENT_PORT = "EXPOSED_MANAGEMENT_PORT"
    UNAUTHORIZED_CLOUD_REGION = "UNAUTHORIZED_CLOUD_REGION"


class CloudAsset(BaseModel):
    """Normalized cloud or network asset entity."""
    asset_id: str
    asset_name: str
    asset_type: CloudAssetType
    cloud_provider: str = "AWS"  # AWS, Azure, GCP, OnPrem
    region: str = "us-east-1"
    ip_address: Optional[str] = None
    fqdn: Optional[str] = None
    is_sanctioned_cmdb: bool = False
    open_ports: List[int] = Field(default_factory=list)
    tags: Dict[str, str] = Field(default_factory=dict)
    first_seen: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class DNSTakeoverCheckRequest(BaseModel):
    """Request to evaluate a CNAME record for dangling subdomain takeover vulnerability."""
    subdomain: str = Field(..., description="e.g. dev-portal.corp.com")
    cname_target: str = Field(..., description="e.g. corp-dev.s3-website-us-east-1.amazonaws.com")
    target_http_status: int = Field(default=404, description="HTTP status code returned by target")
    target_response_body: Optional[str] = Field(default="NoSuchBucket", description="Response string from provider")


class SurfaceThreatAlert(BaseModel):
    """Security alert raised when a shadow asset or high-risk exposure is detected."""
    alert_id: str
    threat_type: SurfaceThreatType
    asset_id: str
    asset_name: str
    severity: str = "HIGH"
    mitre_technique: str
    details: str
    remediation_action: str
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class ReconciliationRequest(BaseModel):
    """Batch asset reconciliation request between sanctioned CMDB and live telemetry."""
    sanctioned_assets: List[CloudAsset]
    observed_live_assets: List[CloudAsset]


class ReconciliationReport(BaseModel):
    """Consolidated reconciliation audit and shadow cloud findings."""
    total_sanctioned_assets: int
    total_observed_assets: int
    shadow_unmanaged_count: int
    threats_detected: List[SurfaceThreatAlert]
    attack_surface_score: float = Field(..., ge=0.0, le=100.0, description="Hygiene index (100 = optimal)")
    reconciled_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
