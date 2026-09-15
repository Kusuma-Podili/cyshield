"""
Multi-Tenant Architecture & Virtual Security Operations Center (vSOC) Schemas.
Models tenant organizations, quotas, tenant-scoped user memberships, and resource isolation.
"""

from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class TenantTier(str, Enum):
    COMMUNITY = "COMMUNITY"
    PROFESSIONAL = "PROFESSIONAL"
    ENTERPRISE = "ENTERPRISE"
    MSSP_PARTNER = "MSSP_PARTNER"


class TenantRole(str, Enum):
    TENANT_ADMIN = "TENANT_ADMIN"
    SOC_ANALYST = "SOC_ANALYST"
    AUDITOR = "AUDITOR"


class TenantQuota(BaseModel):
    """Resource limits and retention thresholds for a tenant."""
    max_devices: int = 500
    max_eps: int = 1000  # Events Per Second
    data_retention_days: int = 90
    max_custom_rules: int = 50
    storage_gb: int = 250


class TenantProfile(BaseModel):
    """Dedicated virtual organization within the CyberShield platform."""
    tenant_id: str
    name: str
    slug: str
    tier: TenantTier = TenantTier.ENTERPRISE
    quota: TenantQuota = Field(default_factory=TenantQuota)
    current_device_count: int = 0
    current_eps: int = 0
    is_active: bool = True
    contact_email: Optional[str] = None
    created_at: datetime = Field(default_factory=datetime.utcnow)


class TenantUserMapping(BaseModel):
    """Association of a user with a tenant organization and role."""
    mapping_id: str
    user_id: str
    tenant_id: str
    role: TenantRole = TenantRole.SOC_ANALYST
    assigned_at: datetime = Field(default_factory=datetime.utcnow)


class TenantCreateRequest(BaseModel):
    """Request payload to register a new tenant organization."""
    name: str
    slug: str
    tier: TenantTier = TenantTier.ENTERPRISE
    contact_email: Optional[str] = None
    custom_quota: Optional[TenantQuota] = None


class TenantUsageMetrics(BaseModel):
    """Real-time quota consumption and capacity metrics for a tenant."""
    tenant_id: str
    name: str
    device_count: int
    max_devices: int
    device_utilization_pct: float
    current_eps: int
    max_eps: int
    eps_utilization_pct: float
    is_over_quota: bool
