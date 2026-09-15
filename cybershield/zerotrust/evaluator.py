"""
Zero Trust Posture and Continuous Trust Evaluator.
Computes multi-dimensional trust scores based on device health, identity posture,
network encryption, and behavioral anomaly telemetry.
"""

from typing import Tuple, List
from cybershield.zerotrust.schemas import (
    AccessContext,
    DevicePosture,
    TrustEvaluation,
    TrustFactorBreakdown,
)


class TrustScoreEvaluator:
    """Calculates granular trust scores across 4 security dimensions."""

    @staticmethod
    def evaluate_device_health(posture: DevicePosture) -> Tuple[float, List[str]]:
        """Calculate device health score (0-100) and identify failure reasons."""
        score = 0.0
        reasons = []

        if posture.edr_agent_healthy:
            score += 30.0
        else:
            reasons.append("EDR agent is inactive or unhealthy")

        if posture.disk_encryption_enabled:
            score += 25.0
        else:
            reasons.append("Full disk encryption is not enabled")

        if posture.firewall_enabled:
            score += 15.0
        else:
            reasons.append("Host firewall is disabled")

        if posture.secure_boot_enabled:
            score += 15.0
        else:
            reasons.append("Secure Boot is disabled in firmware")

        if posture.compliance_passed:
            score += 15.0
        else:
            reasons.append("Endpoint failed GRC baseline compliance checks")

        # Penalties
        if posture.jailbroken_or_rooted:
            score = max(0.0, score - 50.0)
            reasons.append("Device has been rooted or jailbroken (integrity compromised)")

        if posture.pending_critical_patches > 0:
            patch_penalty = min(30.0, posture.pending_critical_patches * 10.0)
            score = max(0.0, score - patch_penalty)
            reasons.append(f"{posture.pending_critical_patches} critical security patch(es) pending installation")

        return max(0.0, min(100.0, score)), reasons

    @staticmethod
    def evaluate_identity_context(context: AccessContext) -> Tuple[float, List[str]]:
        """Calculate identity trust score based on authentication hygiene."""
        score = 50.0
        reasons = []

        if context.mfa_verified:
            score += 40.0
        else:
            score -= 20.0
            reasons.append("Multi-Factor Authentication (MFA) was not completed")

        if context.user_role in ["SEC_ADMIN", "SYS_ADMIN", "SOC_ANALYST"]:
            score += 10.0

        return max(0.0, min(100.0, score)), reasons

    @staticmethod
    def evaluate_network_context(context: AccessContext) -> Tuple[float, List[str]]:
        """Evaluate transport encryption and geo-velocity anomaly."""
        score = 60.0
        reasons = []

        # Transport security
        if context.client_tls_version == "TLSv1.3":
            score += 20.0
        elif context.client_tls_version == "TLSv1.2":
            score += 10.0
        else:
            score -= 30.0
            reasons.append(f"Insecure transport protocol: {context.client_tls_version}")

        # Impossible travel
        if context.impossible_travel_detected:
            score = max(0.0, score - 50.0)
            reasons.append("Impossible travel velocity detected between consecutive requests")

        # Check internal vs external IP
        is_private = (
            context.source_ip.startswith("10.")
            or context.source_ip.startswith("172.16.")
            or context.source_ip.startswith("192.168.")
            or context.source_ip == "127.0.0.1"
        )
        if is_private:
            score += 20.0

        return max(0.0, min(100.0, score)), reasons

    @staticmethod
    def evaluate_behavioral_score(context: AccessContext) -> Tuple[float, List[str]]:
        """Evaluate behavioral trust based on UEBA anomaly telemetry."""
        reasons = []
        anomaly = max(0.0, min(100.0, context.ueba_anomaly_score))
        behavior_score = 100.0 - anomaly

        if anomaly > 60.0:
            reasons.append(f"High UEBA behavioral anomaly score ({anomaly:.1f})")
        elif anomaly > 35.0:
            reasons.append(f"Moderate UEBA behavioral anomaly score ({anomaly:.1f})")

        return behavior_score, reasons

    def compute_composite_trust(self, context: AccessContext) -> Tuple[float, TrustFactorBreakdown, List[str]]:
        """Calculate weighted composite trust score (0 - 100)."""
        dev_score, dev_reasons = self.evaluate_device_health(context.device_posture)
        id_score, id_reasons = self.evaluate_identity_context(context)
        net_score, net_reasons = self.evaluate_network_context(context)
        beh_score, beh_reasons = self.evaluate_behavioral_score(context)

        # Weights: Device (35%), Identity (25%), Network (20%), Behavior (20%)
        composite = (
            (dev_score * 0.35)
            + (id_score * 0.25)
            + (net_score * 0.20)
            + (beh_score * 0.20)
        )

        breakdown = TrustFactorBreakdown(
            device_health_score=round(dev_score, 1),
            identity_risk_score=round(id_score, 1),
            network_context_score=round(net_score, 1),
            behavioral_score=round(beh_score, 1),
        )

        all_reasons = dev_reasons + id_reasons + net_reasons + beh_reasons
        return round(composite, 1), breakdown, all_reasons
