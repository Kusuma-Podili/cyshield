"""CyberShield Enterprise - Identity Governance & Administration Engine.
Implements entitlement lifecycle, privilege creep scoring, cross-department role bloat detection,
Separation of Duties (SoD) toxic combination scans, and access certification campaigns.
"""

import uuid
from typing import Dict, List, Optional, Set, Tuple, Any
from datetime import datetime, timezone, timedelta

from .schemas import (
    EntitlementType,
    AccountStatus,
    IdentityAccount,
    Entitlement,
    IdentityAssignment,
    SoDRule,
    PrivilegeCreepMetrics,
    SoDConflictReport,
    CertificationStatus,
    CertificationDecisionType,
    AccessCertificationCampaign,
    AccessCertificationDecision,
)


class IdentityGovernanceEngine:
    """Core management engine for enterprise identity governance, privilege creep, and SoD compliance."""

    def __init__(self):
        self.identities: Dict[str, IdentityAccount] = {}
        self.entitlements: Dict[str, Entitlement] = {}
        # Key: assignment_id, Value: IdentityAssignment
        self.assignments: Dict[str, IdentityAssignment] = {}
        # Index: identity_id -> list of assignment_ids
        self.identity_assignments: Dict[str, List[str]] = {}
        self.sod_rules: Dict[str, SoDRule] = {}
        self.campaigns: Dict[str, AccessCertificationCampaign] = {}
        self.decisions: List[AccessCertificationDecision] = []

        self._seed_default_sod_rules()

    def _seed_default_sod_rules(self):
        """Seed standard regulatory Separation of Duties (SoD) conflict rules."""
        rules = [
            SoDRule(
                rule_id="sod-fin-001",
                name="Accounts Payable Vendor Creation vs Payment Release",
                description="Prevents single principal from creating vendor and authorizing payments.",
                conflicting_entitlement_ids=["ent-fin-vendor-creator", "ent-fin-payment-releaser"],
                severity="CRITICAL",
                regulatory_mapping=["SOX_404", "COSO_IC"],
            ),
            SoDRule(
                rule_id="sod-dev-002",
                name="Production Deployment vs Source Code Commit Bypass",
                description="Prevents developers from pushing code directly to production without peer review.",
                conflicting_entitlement_ids=["ent-git-force-push-main", "ent-k8s-prod-cluster-admin"],
                severity="HIGH",
                regulatory_mapping=["SOC2_CC6", "PCI_DSS_6.4"],
            ),
            SoDRule(
                rule_id="sod-sec-003",
                name="Security Audit Log Administration vs User Provisioning",
                description="Prevents security administrators from altering audit logs of their own user provisioning actions.",
                conflicting_entitlement_ids=["ent-iam-full-admin", "ent-audit-log-purge"],
                severity="CRITICAL",
                regulatory_mapping=["ISO27001_A12.4", "HIPAA_164.312"],
            ),
        ]
        for r in rules:
            self.sod_rules[r.rule_id] = r

    def add_identity(self, identity: IdentityAccount) -> IdentityAccount:
        """Register or update an identity in the IGA repository."""
        self.identities[identity.identity_id] = identity
        if identity.identity_id not in self.identity_assignments:
            self.identity_assignments[identity.identity_id] = []
        return identity

    def add_entitlement(self, entitlement: Entitlement) -> Entitlement:
        """Register an entitlement in the enterprise access catalog."""
        self.entitlements[entitlement.entitlement_id] = entitlement
        return entitlement

    def assign_entitlement(
        self,
        identity_id: str,
        entitlement_id: str,
        granted_by: str = "admin",
        justification: Optional[str] = None,
        expires_at: Optional[datetime] = None,
        last_used_at: Optional[datetime] = None,
    ) -> IdentityAssignment:
        """Grant an entitlement to an identity."""
        if identity_id not in self.identities:
            raise ValueError(f"Identity '{identity_id}' does not exist.")
        if entitlement_id not in self.entitlements:
            raise ValueError(f"Entitlement '{entitlement_id}' does not exist.")

        assignment_id = f"asgn-{uuid.uuid4().hex[:8]}"
        assignment = IdentityAssignment(
            assignment_id=assignment_id,
            identity_id=identity_id,
            entitlement_id=entitlement_id,
            granted_by=granted_by,
            justification=justification,
            expires_at=expires_at,
            last_used_at=last_used_at or datetime.now(timezone.utc),
        )
        self.assignments[assignment_id] = assignment
        self.identity_assignments[identity_id].append(assignment_id)
        return assignment

    def revoke_assignment(self, assignment_id: str) -> bool:
        """Revoke a specific entitlement assignment."""
        if assignment_id not in self.assignments:
            return False
        asgn = self.assignments.pop(assignment_id)
        if asgn.identity_id in self.identity_assignments:
            self.identity_assignments[asgn.identity_id] = [
                aid for aid in self.identity_assignments[asgn.identity_id] if aid != assignment_id
            ]
        return True

    def calculate_privilege_creep(
        self,
        identity_id: str,
        now: Optional[datetime] = None,
    ) -> PrivilegeCreepMetrics:
        """Evaluate privilege creep score, stale permissions, and cross-department residue."""
        identity = self.identities.get(identity_id)
        if not identity:
            raise ValueError(f"Identity '{identity_id}' not found.")

        current_time = now or datetime.now(timezone.utc)
        asgn_ids = self.identity_assignments.get(identity_id, [])

        total_entitlements = len(asgn_ids)
        privileged_count = 0
        stale_count = 0
        cross_dept_count = 0
        recommended_pruning = []

        stale_threshold = timedelta(days=90)

        for aid in asgn_ids:
            asgn = self.assignments.get(aid)
            if not asgn:
                continue
            ent = self.entitlements.get(asgn.entitlement_id)
            if not ent:
                continue

            # 1. Privileged check
            if ent.is_privileged or ent.risk_weight >= 8:
                privileged_count += 1

            # 2. Stale / Unused check
            is_stale = False
            if asgn.last_used_at:
                if (current_time - asgn.last_used_at) > stale_threshold:
                    is_stale = True
            elif (current_time - asgn.granted_at) > stale_threshold:
                is_stale = True

            if is_stale:
                stale_count += 1
                recommended_pruning.append(ent.entitlement_id)

            # 3. Cross-department residual check
            # If entitlement is tagged for a department the employee transferred out of
            if ent.department_affinity and ent.department_affinity != identity.department:
                cross_dept_count += 1
                if ent.entitlement_id not in recommended_pruning:
                    recommended_pruning.append(ent.entitlement_id)

        # Privilege Creep Formula:
        # High-weight combinations of privileged, stale, and cross-department residue
        score = (
            (privileged_count * 12.0)
            + (stale_count * 10.0)
            + (cross_dept_count * 15.0)
            + (total_entitlements * 2.0)
        )
        creep_score = round(min(100.0, score), 2)

        if creep_score >= 75.0:
            risk_level = "CRITICAL"
        elif creep_score >= 50.0:
            risk_level = "HIGH"
        elif creep_score >= 25.0:
            risk_level = "ELEVATED"
        else:
            risk_level = "LOW"

        return PrivilegeCreepMetrics(
            identity_id=identity_id,
            username=identity.username,
            department=identity.department,
            total_entitlements=total_entitlements,
            privileged_count=privileged_count,
            stale_entitlements_count=stale_count,
            cross_department_count=cross_dept_count,
            creep_score=creep_score,
            risk_level=risk_level,
            recommended_pruning=recommended_pruning,
        )

    def scan_sod_conflicts(self, identity_id: Optional[str] = None) -> List[SoDConflictReport]:
        """Audit identities against all Separation of Duties (SoD) policies."""
        targets = [identity_id] if identity_id else list(self.identities.keys())
        conflicts: List[SoDConflictReport] = []

        for iid in targets:
            identity = self.identities.get(iid)
            if not identity:
                continue

            # Gather all active entitlement IDs for this identity
            asgn_ids = self.identity_assignments.get(iid, [])
            held_entitlements: Set[str] = {
                self.assignments[aid].entitlement_id
                for aid in asgn_ids
                if aid in self.assignments
            }

            for rule in self.sod_rules.values():
                req_conflicts = set(rule.conflicting_entitlement_ids)
                if req_conflicts.issubset(held_entitlements):
                    conflicts.append(
                        SoDConflictReport(
                            conflict_id=f"sod-{uuid.uuid4().hex[:8]}",
                            identity_id=identity.identity_id,
                            username=identity.username,
                            rule_id=rule.rule_id,
                            rule_name=rule.name,
                            severity=rule.severity,
                            conflicting_entitlements=list(req_conflicts),
                            regulatory_impact=rule.regulatory_mapping,
                            remediation_guidance=(
                                f"Immediate SoD violation: Identity '{identity.username}' holds conflicting "
                                f"entitlements {list(req_conflicts)}. Revoke at least one to restore compliance "
                                f"with {', '.join(rule.regulatory_mapping)}."
                            ),
                        )
                    )

        return conflicts

    def find_dormant_and_orphan_accounts(
        self,
        days_inactive: int = 90,
        now: Optional[datetime] = None,
    ) -> Dict[str, List[IdentityAccount]]:
        """Identify inactive dormant accounts and orphan accounts lacking managerial oversight."""
        current_time = now or datetime.now(timezone.utc)
        inactivity_threshold = timedelta(days=days_inactive)

        dormant: List[IdentityAccount] = []
        orphans: List[IdentityAccount] = []

        for identity in self.identities.values():
            # Check dormancy
            if identity.status == AccountStatus.DORMANT:
                dormant.append(identity)
            elif identity.last_active_at and (current_time - identity.last_active_at) > inactivity_threshold:
                dormant.append(identity)

            # Check orphans (non-service accounts with no manager or non-existent manager)
            if not identity.is_service_account:
                if not identity.manager_id or identity.manager_id not in self.identities:
                    orphans.append(identity)

        return {
            "dormant_accounts": dormant,
            "orphan_accounts": orphans,
        }

    def create_campaign(
        self,
        title: str,
        reviewer_id: str,
        target_departments: Optional[List[str]] = None,
        deadline: Optional[datetime] = None,
    ) -> AccessCertificationCampaign:
        """Create a user access certification review campaign."""
        cid = f"camp-{uuid.uuid4().hex[:8]}"
        campaign = AccessCertificationCampaign(
            campaign_id=cid,
            title=title,
            target_departments=target_departments or [],
            reviewer_id=reviewer_id,
            deadline=deadline or (datetime.now(timezone.utc) + timedelta(days=30)),
            status=CertificationStatus.IN_PROGRESS,
        )
        self.campaigns[cid] = campaign
        return campaign

    def submit_certification_decision(
        self,
        campaign_id: str,
        identity_id: str,
        entitlement_id: str,
        decision: CertificationDecisionType,
        reviewer_notes: Optional[str] = None,
    ) -> AccessCertificationDecision:
        """Record reviewer decision and automatically revoke access if marked REVOKE."""
        if campaign_id not in self.campaigns:
            raise ValueError(f"Campaign '{campaign_id}' does not exist.")

        dec = AccessCertificationDecision(
            decision_id=f"dec-{uuid.uuid4().hex[:8]}",
            campaign_id=campaign_id,
            identity_id=identity_id,
            entitlement_id=entitlement_id,
            decision=decision,
            reviewer_notes=reviewer_notes,
        )
        self.decisions.append(dec)

        # Enforce revocation immediately if requested
        if decision == CertificationDecisionType.REVOKE:
            asgn_ids = self.identity_assignments.get(identity_id, [])
            for aid in list(asgn_ids):
                if aid in self.assignments and self.assignments[aid].entitlement_id == entitlement_id:
                    self.revoke_assignment(aid)

        return dec
