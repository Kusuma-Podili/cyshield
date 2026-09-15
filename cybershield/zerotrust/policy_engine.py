"""
Zero Trust Policy Decision Point (PDP) and Policy Engine.
Enforces adaptive access control policies aligned with NIST SP 800-207.
"""

import uuid
from datetime import datetime
from typing import Any, Dict, List, Optional

from cybershield.zerotrust.evaluator import TrustScoreEvaluator
from cybershield.zerotrust.schemas import (
    AccessContext,
    AccessDecisionType,
    ResourceSensitivityTier,
    TrustEvaluation,
    ZeroTrustPolicy,
)


DEFAULT_ZT_POLICIES: List[ZeroTrustPolicy] = [
    ZeroTrustPolicy(
        id="POL-TIER-1-CRITICAL",
        name="Tier 1 Crown Jewels Policy",
        description="Strict access control for Domain Controllers, WORM vaults, and core database clusters.",
        resource_tier=ResourceSensitivityTier.TIER_1_CRITICAL,
        min_trust_score_allow=85.0,
        min_trust_score_mfa=70.0,
        require_edr_healthy=True,
        require_disk_encryption=True,
        block_impossible_travel=True,
        max_allowed_ueba_risk=40.0,
    ),
    ZeroTrustPolicy(
        id="POL-TIER-2-RESTRICTED",
        name="Tier 2 Restricted Services Policy",
        description="Access control for internal microservices, CI/CD pipelines, and application backends.",
        resource_tier=ResourceSensitivityTier.TIER_2_RESTRICTED,
        min_trust_score_allow=75.0,
        min_trust_score_mfa=50.0,
        require_edr_healthy=True,
        require_disk_encryption=True,
        block_impossible_travel=True,
        max_allowed_ueba_risk=60.0,
    ),
    ZeroTrustPolicy(
        id="POL-TIER-3-STANDARD",
        name="Tier 3 Standard Enterprise Policy",
        description="Standard policy for corporate email, intranet portals, and general workspace apps.",
        resource_tier=ResourceSensitivityTier.TIER_3_STANDARD,
        min_trust_score_allow=60.0,
        min_trust_score_mfa=40.0,
        require_edr_healthy=False,
        require_disk_encryption=False,
        block_impossible_travel=True,
        max_allowed_ueba_risk=75.0,
    ),
    ZeroTrustPolicy(
        id="POL-TIER-4-PUBLIC",
        name="Tier 4 Public Read-Only Policy",
        description="Permissive policy for public-facing status pages and documentation portals.",
        resource_tier=ResourceSensitivityTier.TIER_4_PUBLIC,
        min_trust_score_allow=20.0,
        min_trust_score_mfa=10.0,
        require_edr_healthy=False,
        require_disk_encryption=False,
        block_impossible_travel=False,
        max_allowed_ueba_risk=95.0,
    ),
]


class ZeroTrustPolicyEngine:
    """Policy Decision Point (PDP) evaluating contextual signals against ZTA policies."""

    def __init__(self):
        self._policies: Dict[str, ZeroTrustPolicy] = {p.id: p for p in DEFAULT_ZT_POLICIES}
        self._evaluator = TrustScoreEvaluator()
        self._evaluations_history: List[TrustEvaluation] = []

    def get_policy(self, policy_id: str) -> Optional[ZeroTrustPolicy]:
        return self._policies.get(policy_id)

    def list_policies(self) -> List[ZeroTrustPolicy]:
        return list(self._policies.values())

    def create_or_update_policy(self, policy: ZeroTrustPolicy) -> ZeroTrustPolicy:
        self._policies[policy.id] = policy
        return policy

    def _get_policy_for_tier(self, tier: ResourceSensitivityTier) -> ZeroTrustPolicy:
        for p in self._policies.values():
            if p.enabled and p.resource_tier == tier:
                return p
        # Fallback to standard
        return self._policies.get("POL-TIER-3-STANDARD", DEFAULT_ZT_POLICIES[2])

    def evaluate_access(self, context: AccessContext) -> TrustEvaluation:
        """Evaluate an access attempt in real-time and return PDP decision."""
        policy = self._get_policy_for_tier(context.target_resource_tier)
        composite_score, breakdown, reasons = self._evaluator.compute_composite_trust(context)
        remediation_steps = []

        # High severity checks: rooted device or extreme impossible travel
        if context.device_posture.jailbroken_or_rooted:
            decision = AccessDecisionType.ISOLATE_DEVICE
            reasons.append("Zero Trust Enforcer: Rooted or jailbroken endpoint detected")
            remediation_steps.append("Initiate device quarantine and forensic analysis")
        elif policy.block_impossible_travel and context.impossible_travel_detected:
            decision = AccessDecisionType.DENY
            reasons.append("Zero Trust Enforcer: Impossible travel velocity violation")
            remediation_steps.append("Reset session and mandate step-up identity verification")
        elif policy.require_edr_healthy and not context.device_posture.edr_agent_healthy:
            decision = AccessDecisionType.DENY
            reasons.append("Zero Trust Enforcer: Mandatory EDR agent is inactive")
            remediation_steps.append("Re-enable CyberShield EDR agent on endpoint")
        elif context.ueba_anomaly_score > policy.max_allowed_ueba_risk:
            decision = AccessDecisionType.DENY
            reasons.append(f"Zero Trust Enforcer: UEBA anomaly score ({context.ueba_anomaly_score}) exceeds policy threshold ({policy.max_allowed_ueba_risk})")
            remediation_steps.append("Perform SOC analyst behavioral review")
        elif composite_score >= policy.min_trust_score_allow:
            decision = AccessDecisionType.ALLOW
            reasons.append(f"Composite trust score ({composite_score}) satisfies tier threshold ({policy.min_trust_score_allow})")
        elif composite_score >= policy.min_trust_score_mfa:
            decision = AccessDecisionType.STEP_UP_MFA
            reasons.append(f"Trust score ({composite_score}) falls in step-up verification range ({policy.min_trust_score_mfa} - {policy.min_trust_score_allow})")
            remediation_steps.append("Prompt user for FIDO2/Hardware Token or Push MFA verification")
        else:
            decision = AccessDecisionType.DENY
            reasons.append(f"Trust score ({composite_score}) is below minimum acceptable threshold ({policy.min_trust_score_mfa})")
            remediation_steps.append("Resolve endpoint health issues and update missing security patches")

        evaluation = TrustEvaluation(
            evaluation_id=f"ZTE-{uuid.uuid4().hex[:8].upper()}",
            timestamp=datetime.utcnow(),
            user_id=context.user_id,
            device_id=context.device_posture.device_id,
            target_resource_id=context.target_resource_id,
            target_tier=context.target_resource_tier,
            composite_trust_score=composite_score,
            trust_breakdown=breakdown,
            decision=decision,
            reasons=reasons,
            remediation_steps=remediation_steps,
        )

        self._evaluations_history.append(evaluation)
        # Keep recent 2000 evaluations
        if len(self._evaluations_history) > 2000:
            self._evaluations_history = self._evaluations_history[-2000:]

        return evaluation

    def get_evaluations_history(
        self, device_id: Optional[str] = None, user_id: Optional[str] = None, limit: int = 100
    ) -> List[TrustEvaluation]:
        """Retrieve evaluation logs filtered by device or user."""
        res = self._evaluations_history
        if device_id:
            res = [e for e in res if e.device_id == device_id]
        if user_id:
            res = [e for e in res if e.user_id == user_id]
        return list(reversed(res))[:limit]

    def get_overview_statistics(self) -> Dict[str, Any]:
        """Aggregate statistics across all evaluations."""
        total = len(self._evaluations_history)
        if total == 0:
            return {
                "total_evaluations": 0,
                "allow_count": 0,
                "mfa_count": 0,
                "deny_count": 0,
                "quarantine_count": 0,
                "average_trust_score": 0.0,
            }

        allow = sum(1 for e in self._evaluations_history if e.decision == AccessDecisionType.ALLOW)
        mfa = sum(1 for e in self._evaluations_history if e.decision == AccessDecisionType.STEP_UP_MFA)
        deny = sum(1 for e in self._evaluations_history if e.decision == AccessDecisionType.DENY)
        quarantine = sum(1 for e in self._evaluations_history if e.decision == AccessDecisionType.ISOLATE_DEVICE)
        avg_score = sum(e.composite_trust_score for e in self._evaluations_history) / total

        return {
            "total_evaluations": total,
            "allow_count": allow,
            "mfa_count": mfa,
            "deny_count": deny,
            "quarantine_count": quarantine,
            "allow_rate_pct": round((allow / total) * 100, 1),
            "average_trust_score": round(avg_score, 1),
        }
