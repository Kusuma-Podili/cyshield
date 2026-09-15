"""CyberShield Enterprise - Identity Governance & Administration (IGA) Schemas.
Data contracts for identity accounts, entitlement catalogs, privilege creep tracking,
Separation of Duties (SoD) policies, and access certification campaigns.
"""

from enum import Enum
from typing import Dict, List, Optional, Any
from datetime import datetime, timezone
from pydantic import BaseModel, Field


class EntitlementType(str, Enum):
    ROLE = "ROLE"
    GROUP = "GROUP"
    PERMISSION = "PERMISSION"
    CLOUD_IAM_POLICY = "CLOUD_IAM_POLICY"
    SERVICE_ACCOUNT_KEY = "SERVICE_ACCOUNT_KEY"
    SUDO_PRIVILEGE = "SUDO_PRIVILEGE"


class AccountStatus(str, Enum):
    ACTIVE = "ACTIVE"
    SUSPENDED = "SUSPENDED"
    TERMINATED = "TERMINATED"
    DORMANT = "DORMANT"


class CertificationStatus(str, Enum):
    PLANNED = "PLANNED"
    IN_PROGRESS = "IN_PROGRESS"
    COMPLETED = "COMPLETED"


class CertificationDecisionType(str, Enum):
    APPROVE = "APPROVE"
    REVOKE = "REVOKE"


class IdentityAccount(BaseModel):
    """Represents an employee, contractor, or service identity in the enterprise."""
    identity_id: str = Field(..., description="Unique employee / principal ID (e.g. emp-1049)")
    username: str = Field(..., description="Corporate login username")
    email: str = Field(..., description="Corporate primary email")
    department: str = Field(..., description="Current business department (e.g. Engineering, Finance)")
    job_title: str = Field(..., description="Current corporate position")
    manager_id: Optional[str] = Field(default=None, description="Direct supervisor ID")
    is_service_account: bool = Field(default=False)
    status: AccountStatus = Field(default=AccountStatus.ACTIVE)
    past_departments: List[str] = Field(default_factory=list, description="Historical departments before lateral transfer")
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    last_active_at: Optional[datetime] = None


class Entitlement(BaseModel):
    """Specific permission, role, or cloud IAM entitlement in catalog."""
    entitlement_id: str = Field(..., description="Unique entitlement identifier (e.g. ent-fin-payment-approver)")
    name: str = Field(..., description="Human-readable entitlement name")
    entitlement_type: EntitlementType
    resource: str = Field(..., description="Target system, application, or AWS ARN")
    department_affinity: Optional[str] = Field(default=None, description="Expected department for this entitlement")
    risk_weight: int = Field(default=1, ge=1, le=10, description="Risk impact rating (10 is domain admin/root)")
    is_privileged: bool = Field(default=False, description="Whether this grants root/admin access")


class IdentityAssignment(BaseModel):
    """Grant of an entitlement to a specific identity."""
    assignment_id: str
    identity_id: str
    entitlement_id: str
    granted_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    expires_at: Optional[datetime] = None
    granted_by: str = Field(default="system")
    justification: Optional[str] = None
    last_used_at: Optional[datetime] = None


class SoDRule(BaseModel):
    """Separation of Duties rule prohibiting toxic combinations of access."""
    rule_id: str
    name: str
    description: str
    conflicting_entitlement_ids: List[str] = Field(..., min_length=2, description="Entitlements that cannot coexist")
    severity: str = Field(default="HIGH", description="LOW, MEDIUM, HIGH, CRITICAL")
    regulatory_mapping: List[str] = Field(default_factory=list, description="SOX_404, PCI_DSS_7, ISO27001_A9")


class PrivilegeCreepMetrics(BaseModel):
    """Detailed privilege creep and entitlement bloat analysis for an identity."""
    identity_id: str
    username: str
    department: str
    total_entitlements: int
    privileged_count: int
    stale_entitlements_count: int
    cross_department_count: int
    creep_score: float = Field(..., ge=0.0, le=100.0, description="Composite privilege creep risk score")
    risk_level: str = Field(..., description="LOW, ELEVATED, HIGH, CRITICAL")
    recommended_pruning: List[str] = Field(default_factory=list, description="Entitlement IDs that should be revoked")


class SoDConflictReport(BaseModel):
    """Incident report for a discovered toxic combination of entitlements."""
    conflict_id: str
    identity_id: str
    username: str
    rule_id: str
    rule_name: str
    severity: str
    conflicting_entitlements: List[str]
    regulatory_impact: List[str]
    remediation_guidance: str
    detected_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class AccessCertificationCampaign(BaseModel):
    """Enterprise periodic user access review campaign."""
    campaign_id: str
    title: str
    target_departments: List[str] = Field(default_factory=list)
    reviewer_id: str
    deadline: Optional[datetime] = None
    status: CertificationStatus = CertificationStatus.IN_PROGRESS
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class AccessCertificationDecision(BaseModel):
    """Reviewer decision on a specific identity entitlement assignment."""
    decision_id: str
    campaign_id: str
    identity_id: str
    entitlement_id: str
    decision: CertificationDecisionType
    reviewer_notes: Optional[str] = None
    decided_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
