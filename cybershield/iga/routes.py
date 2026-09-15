"""CyberShield Enterprise - Identity Governance & Administration API Routes.
Exposes REST endpoints for identity management, entitlement assignments,
privilege creep detection, SoD toxic conflict audits, and access reviews.
"""

from typing import Dict, List, Optional, Any
from fastapi import APIRouter, HTTPException, Query, status

from .schemas import (
    IdentityAccount,
    Entitlement,
    IdentityAssignment,
    SoDRule,
    PrivilegeCreepMetrics,
    SoDConflictReport,
    AccessCertificationCampaign,
    AccessCertificationDecision,
    CertificationDecisionType,
)
from .governance import IdentityGovernanceEngine

router = APIRouter(prefix="/api/v1/iga", tags=["Identity Governance & Privilege Creep"])

# Active singleton governance engine
_IGA_ENGINE = IdentityGovernanceEngine()


@router.post("/identities", response_model=IdentityAccount, status_code=status.HTTP_201_CREATED)
def create_identity(identity: IdentityAccount):
    """Register or onboard an employee or service account identity."""
    return _IGA_ENGINE.add_identity(identity)


@router.get("/identities", response_model=List[IdentityAccount])
def list_identities(department: Optional[str] = None):
    """List registered corporate identities with optional department filtering."""
    identities = list(_IGA_ENGINE.identities.values())
    if department:
        identities = [i for i in identities if i.department.lower() == department.lower()]
    return identities


@router.post("/entitlements", response_model=Entitlement, status_code=status.HTTP_201_CREATED)
def register_entitlement(entitlement: Entitlement):
    """Add a new role, group, or permission to the entitlement catalog."""
    return _IGA_ENGINE.add_entitlement(entitlement)


@router.get("/entitlements", response_model=List[Entitlement])
def list_entitlements():
    """Retrieve all cataloged enterprise entitlements."""
    return list(_IGA_ENGINE.entitlements.values())


@router.post("/assign", response_model=IdentityAssignment, status_code=status.HTTP_201_CREATED)
def assign_entitlement(
    identity_id: str = Query(..., description="Target employee identity ID"),
    entitlement_id: str = Query(..., description="Entitlement ID to grant"),
    justification: Optional[str] = Query(None, description="Business access justification"),
):
    """Grant an entitlement to an identity."""
    try:
        return _IGA_ENGINE.assign_entitlement(
            identity_id=identity_id,
            entitlement_id=entitlement_id,
            justification=justification,
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.get("/creep/{identity_id}", response_model=PrivilegeCreepMetrics)
def get_privilege_creep(identity_id: str):
    """Calculate privilege creep score, stale assignments, and residual cross-department permissions."""
    try:
        return _IGA_ENGINE.calculate_privilege_creep(identity_id)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


@router.get("/creep-leaderboard", response_model=List[PrivilegeCreepMetrics])
def get_privilege_creep_leaderboard(limit: int = Query(20, ge=1, le=100)):
    """Rank enterprise identities with the highest privilege creep risk scores."""
    metrics_list = []
    for iid in _IGA_ENGINE.identities:
        m = _IGA_ENGINE.calculate_privilege_creep(iid)
        metrics_list.append(m)
    metrics_list.sort(key=lambda x: x.creep_score, reverse=True)
    return metrics_list[:limit]


@router.post("/sod/rules", response_model=SoDRule, status_code=status.HTTP_201_CREATED)
def define_sod_rule(rule: SoDRule):
    """Define a Separation of Duties policy rule."""
    _IGA_ENGINE.sod_rules[rule.rule_id] = rule
    return rule


@router.get("/sod/conflicts", response_model=List[SoDConflictReport])
def scan_sod_conflicts(identity_id: Optional[str] = None):
    """Scan enterprise directory for toxic combinations of conflicting entitlements."""
    return _IGA_ENGINE.scan_sod_conflicts(identity_id=identity_id)


@router.get("/dormant")
def get_dormant_and_orphan_accounts(days_inactive: int = Query(90, ge=30, le=730)):
    """Identify stale dormant identities and orphan accounts without valid managers."""
    return _IGA_ENGINE.find_dormant_and_orphan_accounts(days_inactive=days_inactive)


@router.post("/campaigns", response_model=AccessCertificationCampaign, status_code=status.HTTP_201_CREATED)
def create_certification_campaign(
    title: str = Query(..., description="Campaign name"),
    reviewer_id: str = Query(..., description="Reviewing manager ID"),
):
    """Launch an access certification campaign for compliance auditing."""
    return _IGA_ENGINE.create_campaign(title=title, reviewer_id=reviewer_id)


@router.post("/campaigns/{campaign_id}/certify", response_model=AccessCertificationDecision)
def submit_certification_decision(
    campaign_id: str,
    identity_id: str = Query(...),
    entitlement_id: str = Query(...),
    decision: CertificationDecisionType = Query(...),
    reviewer_notes: Optional[str] = Query(None),
):
    """Submit access certification decision (APPROVE or REVOKE)."""
    try:
        return _IGA_ENGINE.submit_certification_decision(
            campaign_id=campaign_id,
            identity_id=identity_id,
            entitlement_id=entitlement_id,
            decision=decision,
            reviewer_notes=reviewer_notes,
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
