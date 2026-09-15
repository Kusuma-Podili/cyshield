"""
Attack Surface Management (ASM) Schemas and Models.
Defines external perimeter discovery, public assets, exposed services, and exposure risk scores.
"""

from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class AssetExposureType(str, Enum):
    DOMAIN = "DOMAIN"
    SUBDOMAIN = "SUBDOMAIN"
    PUBLIC_IP = "PUBLIC_IP"
    EXPOSED_SERVICE = "EXPOSED_SERVICE"
    CLOUD_STORAGE = "CLOUD_STORAGE"
    CERTIFICATE = "CERTIFICATE"


class ExposureSeverity(str, Enum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class ServicePortBanner(BaseModel):
    """Network service banner and TLS properties on an exposed port."""
    port: int
    protocol: str = "TCP"
    service_name: str  # HTTPS, SSH, RDP, SMB, REDIS
    product: Optional[str] = None
    version: Optional[str] = None
    banner_raw: Optional[str] = None
    tls_enabled: bool = False
    tls_cipher: Optional[str] = None
    tls_cert_issuer: Optional[str] = None
    tls_cert_expires: Optional[datetime] = None
    is_dangerous_exposure: bool = False  # e.g., exposed RDP, Telnet, unauthenticated DB


class DiscoveredAsset(BaseModel):
    """External asset discovered during perimeter reconnaissance."""
    id: str
    asset_type: AssetExposureType
    identifier: str  # e.g., "vpn.company.com" or "198.51.100.42"
    primary_domain: str
    organization: str = "Corporate Enterprise"
    hosting_provider: str = "On-Premises DMZ"
    asn: Optional[str] = None
    ip_addresses: List[str] = Field(default_factory=list)
    open_ports: List[int] = Field(default_factory=list)
    services: List[ServicePortBanner] = Field(default_factory=list)
    risk_score: float = 20.0  # 0 to 100
    first_seen: datetime = Field(default_factory=datetime.utcnow)
    last_seen: datetime = Field(default_factory=datetime.utcnow)
    tags: List[str] = Field(default_factory=list)


class ExposedIssue(BaseModel):
    """Identified perimeter exposure vulnerability or hygiene issue."""
    id: str
    asset_id: str
    asset_identifier: str
    severity: ExposureSeverity
    title: str
    description: str
    cve_id: Optional[str] = None
    remediation: str
    discovered_at: datetime = Field(default_factory=datetime.utcnow)


class ASMScanRequest(BaseModel):
    """Request to initiate an attack surface discovery scan."""
    root_domain: str
    include_cloud_storage: bool = True
    port_scan_intensity: str = "STANDARD"  # TOP_100, STANDARD, ALL_65535


class ASMScanJob(BaseModel):
    """Job tracking perimeter discovery execution."""
    job_id: str
    root_domain: str
    status: str = "PENDING"  # PENDING, RUNNING, COMPLETED, FAILED
    started_at: datetime = Field(default_factory=datetime.utcnow)
    completed_at: Optional[datetime] = None
    assets_discovered_count: int = 0
    issues_identified_count: int = 0
    duration_ms: float = 0.0


class ASMOverviewMetrics(BaseModel):
    """Overview telemetry of the organization's external attack surface."""
    total_assets: int
    domains_count: int
    subdomains_count: int
    public_ips_count: int
    exposed_services_count: int
    critical_issues_count: int
    average_asset_risk: float
    dangerous_ports_exposed: List[int]
