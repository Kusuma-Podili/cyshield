"""CyberShield Enterprise - Vulnerability Prioritization & Exploit Prediction Engine.
Implements EPSS exploit probability forecasting, CISA KEV weaponization matching,
contextual asset risk scoring, and automated patch SLA scheduling.
"""

import math
import uuid
from typing import Dict, List, Optional, Tuple, Any
from datetime import datetime, timezone, timedelta

from .schemas import (
    ExploitMaturity,
    RemediationPriority,
    AssetExposure,
    AssetCriticality,
    EPSSScoreRecord,
    VulnerabilityContext,
    PrioritizedRemediationAction,
    EnterpriseVEPSummary,
)


class VulnerabilityExploitPredictor:
    """Predicts real-world exploitation probability and computes contextual remediation SLAs."""

    def __init__(self):
        # Known High-Profile CVE Database (CISA KEV, Ransomware, High EPSS)
        self.known_cve_db: Dict[str, EPSSScoreRecord] = {
            "CVE-2021-44228": EPSSScoreRecord(
                cve_id="CVE-2021-44228",
                epss_probability=0.975,
                epss_percentile=0.999,
                is_cisa_kev=True,
                known_ransomware_use=True,
                exploit_maturity=ExploitMaturity.RANSOMWARE_CAMPAIGN_WEAPONIZED,
            ),
            "CVE-2023-34362": EPSSScoreRecord(
                cve_id="CVE-2023-34362",
                epss_probability=0.962,
                epss_percentile=0.998,
                is_cisa_kev=True,
                known_ransomware_use=True,
                exploit_maturity=ExploitMaturity.RANSOMWARE_CAMPAIGN_WEAPONIZED,
            ),
            "CVE-2024-21887": EPSSScoreRecord(
                cve_id="CVE-2024-21887",
                epss_probability=0.941,
                epss_percentile=0.996,
                is_cisa_kev=True,
                known_ransomware_use=False,
                exploit_maturity=ExploitMaturity.ACTIVE_IN_THE_WILD,
            ),
            "CVE-2020-1472": EPSSScoreRecord(
                cve_id="CVE-2020-1472",
                epss_probability=0.912,
                epss_percentile=0.992,
                is_cisa_kev=True,
                known_ransomware_use=True,
                exploit_maturity=ExploitMaturity.RANSOMWARE_CAMPAIGN_WEAPONIZED,
            ),
            "CVE-2024-6387": EPSSScoreRecord(
                cve_id="CVE-2024-6387",
                epss_probability=0.385,
                epss_percentile=0.890,
                is_cisa_kev=False,
                known_ransomware_use=False,
                exploit_maturity=ExploitMaturity.PROOF_OF_CONCEPT,
            ),
        }

    def predict_epss(self, cve_id: str, cvss_v3: float = 7.5) -> EPSSScoreRecord:
        """Retrieve recorded EPSS or dynamically predict exploit probability using regression heuristics."""
        cve_upper = cve_id.strip().upper()
        if cve_upper in self.known_cve_db:
            return self.known_cve_db[cve_upper]

        # Dynamic regression estimate for uncataloged CVEs
        # Base logit derived from CVSS score
        logit = -4.5 + (cvss_v3 * 0.45)

        # Year recency factor
        try:
            year = int(cve_upper.split("-")[1])
            if year >= 2024:
                logit += 0.5
        except Exception:
            pass

        prob = 1.0 / (1.0 + math.exp(-logit))
        prob = round(max(0.0005, min(0.99, prob)), 4)
        percentile = round(min(0.995, max(0.05, prob * 1.05)), 3)

        record = EPSSScoreRecord(
            cve_id=cve_upper,
            epss_probability=prob,
            epss_percentile=percentile,
            is_cisa_kev=False,
            known_ransomware_use=False,
            exploit_maturity=ExploitMaturity.PROOF_OF_CONCEPT if prob > 0.3 else ExploitMaturity.UNPROVEN,
        )
        return record

    def prioritize_vulnerability(
        self,
        context: VulnerabilityContext,
        now: Optional[datetime] = None,
    ) -> PrioritizedRemediationAction:
        """Calculate composite risk score, assign remediation priority tier, and enforce SLA."""
        epss = self.predict_epss(context.cve_id, context.cvss_v3_base)
        current_time = now or datetime.now(timezone.utc)

        # 1. Component Weightings
        # EPSS Score (0..100) - 35% weight
        epss_component = epss.epss_probability * 100.0

        # CVSS Base (0..100) - 25% weight
        cvss_component = context.cvss_v3_base * 10.0

        # Exposure Component (0..100) - 25% weight
        exposure_weights = {
            AssetExposure.INTERNET_FACING: 100.0,
            AssetExposure.DMZ_RESTRICTED: 70.0,
            AssetExposure.INTERNAL_NETWORK: 40.0,
            AssetExposure.AIR_GAPPED: 10.0,
        }
        exposure_component = exposure_weights.get(context.asset_exposure, 40.0)

        # Asset Criticality Component (0..100) - 15% weight
        criticality_weights = {
            AssetCriticality.TIER_0_CROWN_JEWEL: 100.0,
            AssetCriticality.TIER_1_CORE: 75.0,
            AssetCriticality.TIER_2_STANDARD: 50.0,
            AssetCriticality.TIER_3_NON_PRODUCTION: 20.0,
        }
        criticality_component = criticality_weights.get(context.asset_criticality, 50.0)

        raw_score = (
            (epss_component * 0.35)
            + (cvss_component * 0.25)
            + (exposure_component * 0.25)
            + (criticality_component * 0.15)
        )

        # 2. Escalation Modifiers
        if epss.is_cisa_kev:
            raw_score += 20.0
        if epss.known_ransomware_use:
            raw_score += 15.0

        # 3. Compensating Controls Dampening
        if context.has_compensating_controls:
            raw_score *= 0.75  # 25% risk reduction for WAF/microsegmentation

        composite_risk = round(min(100.0, max(0.0, raw_score)), 2)

        # 4. Determine Priority Tier and SLA Days
        if (
            composite_risk >= 80.0
            or (epss.is_cisa_kev and context.asset_exposure == AssetExposure.INTERNET_FACING)
            or (epss.known_ransomware_use and context.asset_criticality == AssetCriticality.TIER_0_CROWN_JEWEL)
        ):
            priority = RemediationPriority.P0_EMERGENCY_24H
            sla_days = 1
            rec_action = f"EMERGENCY PATCH: Deploy immediate out-of-band security update for {context.cve_id} within 24h."
            justification = "Critical threat: Active in-the-wild weaponization coupled with high exposure or Crown Jewel asset."

        elif composite_risk >= 55.0 or epss.epss_probability > 0.40:
            priority = RemediationPriority.P1_HIGH_7D
            sla_days = 7
            rec_action = f"EXPEDITED REMEDIATION: Schedule priority maintenance patch for {context.cve_id} within 7 days."
            justification = "Elevated threat: High exploit probability or core business asset exposure."

        elif composite_risk >= 30.0:
            priority = RemediationPriority.P2_MEDIUM_30D
            sla_days = 30
            rec_action = f"STANDARD CYCLE: Include {context.cve_id} in regular monthly maintenance patching."
            justification = "Moderate threat: Internal asset with limited active exploit telemetry."

        else:
            priority = RemediationPriority.P3_LOW_90D
            sla_days = 90
            rec_action = f"ROUTINE MONITORING: Address {context.cve_id} during quarterly infrastructure refresh."
            justification = "Low threat: Air-gapped or non-critical asset with minimal exploitation likelihood."

        deadline = current_time + timedelta(days=sla_days)

        return PrioritizedRemediationAction(
            action_id=f"vep-{uuid.uuid4().hex[:8]}",
            cve_id=context.cve_id,
            asset_id=context.asset_id,
            asset_name=context.asset_name,
            composite_risk_score=composite_risk,
            epss_probability=epss.epss_probability,
            remediation_priority=priority,
            sla_days=sla_days,
            sla_deadline=deadline,
            is_cisa_kev=epss.is_cisa_kev,
            known_ransomware_use=epss.known_ransomware_use,
            recommended_action=rec_action,
            justification=justification,
        )

    def generate_fleet_summary(self, actions: List[PrioritizedRemediationAction]) -> EnterpriseVEPSummary:
        """Summarize executive vulnerability posture and SLA distribution across fleet."""
        if not actions:
            return EnterpriseVEPSummary(
                total_evaluated=0,
                p0_count=0,
                p1_count=0,
                p2_count=0,
                p3_count=0,
                cisa_kev_count=0,
                ransomware_linked_count=0,
                average_epss_probability=0.0,
            )

        p0 = sum(1 for a in actions if a.remediation_priority == RemediationPriority.P0_EMERGENCY_24H)
        p1 = sum(1 for a in actions if a.remediation_priority == RemediationPriority.P1_HIGH_7D)
        p2 = sum(1 for a in actions if a.remediation_priority == RemediationPriority.P2_MEDIUM_30D)
        p3 = sum(1 for a in actions if a.remediation_priority == RemediationPriority.P3_LOW_90D)
        kev = sum(1 for a in actions if a.is_cisa_kev)
        ransom = sum(1 for a in actions if a.known_ransomware_use)
        avg_epss = sum(a.epss_probability for a in actions) / len(actions)

        return EnterpriseVEPSummary(
            total_evaluated=len(actions),
            p0_count=p0,
            p1_count=p1,
            p2_count=p2,
            p3_count=p3,
            cisa_kev_count=kev,
            ransomware_linked_count=ransom,
            average_epss_probability=round(avg_epss, 4),
        )
