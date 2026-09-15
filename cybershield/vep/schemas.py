"""CyberShield Enterprise - Vulnerability Prioritization & Exploit Prediction Schemas.
Data contracts for EPSS scoring, contextual asset exposure,
remediation SLA deadlines, and enterprise vulnerability summaries.
"""

from enum import Enum
from typing import Dict, List, Optional, Any
from datetime import datetime, timezone
from pydantic import BaseModel, Field


class ExploitMaturity(str, Enum):
    UNPROVEN = "UNPROVEN"
    PROOF_OF_CONCEPT = "PROOF_OF_CONCEPT"
    FUNCTIONAL_EXPLOIT_AVAILABLE = "FUNCTIONAL_EXPLOIT_AVAILABLE"
    ACTIVE_IN_THE_WILD = "ACTIVE_IN_THE_WILD"
    RANSOMWARE_CAMPAIGN_WEAPONIZED = "RANSOMWARE_CAMPAIGN_WEAPONIZED"


class RemediationPriority(str, Enum):
    P0_EMERGENCY_24H = "P0_EMERGENCY_24H"
    P1_HIGH_7D = "P1_HIGH_7D"
    P2_MEDIUM_30D = "P2_MEDIUM_30D"
    P3_LOW_90D = "P3_LOW_90D"


class AssetExposure(str, Enum):
    AIR_GAPPED = "AIR_GAPPED"
    INTERNAL_NETWORK = "INTERNAL_NETWORK"
    DMZ_RESTRICTED = "DMZ_RESTRICTED"
    INTERNET_FACING = "INTERNET_FACING"


class AssetCriticality(str, Enum):
    TIER_0_CROWN_JEWEL = "TIER_0_CROWN_JEWEL"
    TIER_1_CORE = "TIER_1_CORE"
    TIER_2_STANDARD = "TIER_2_STANDARD"
    TIER_3_NON_PRODUCTION = "TIER_3_NON_PRODUCTION"


class EPSSScoreRecord(BaseModel):
    """Exploit Prediction Scoring System (EPSS) probability forecast."""
    cve_id: str = Field(..., description="Target CVE identifier (e.g. CVE-2023-34362)")
    epss_probability: float = Field(..., ge=0.0, le=1.0, description="Probability of exploitation in the wild in next 30 days")
    epss_percentile: float = Field(..., ge=0.0, le=1.0, description="Percentile rank relative to all cataloged CVEs")
    is_cisa_kev: bool = Field(default=False, description="Listed on CISA Known Exploited Vulnerabilities catalog")
    known_ransomware_use: bool = Field(default=False, description="Leveraged by active ransomware syndicates")
    exploit_maturity: ExploitMaturity = ExploitMaturity.UNPROVEN
    calculated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class VulnerabilityContext(BaseModel):
    """Contextual deployment attributes for a vulnerability on an enterprise asset."""
    cve_id: str
    asset_id: str
    asset_name: str
    cvss_v3_base: float = Field(..., ge=0.0, le=10.0)
    asset_exposure: AssetExposure = AssetExposure.INTERNAL_NETWORK
    asset_criticality: AssetCriticality = AssetCriticality.TIER_2_STANDARD
    has_compensating_controls: bool = False
    compensating_controls: List[str] = Field(default_factory=list)


class PrioritizedRemediationAction(BaseModel):
    """Contextualized action plan and SLA for remediating an asset vulnerability."""
    action_id: str
    cve_id: str
    asset_id: str
    asset_name: str
    composite_risk_score: float = Field(..., ge=0.0, le=100.0)
    epss_probability: float
    remediation_priority: RemediationPriority
    sla_days: int
    sla_deadline: datetime
    is_cisa_kev: bool
    known_ransomware_use: bool
    recommended_action: str
    justification: str


class EnterpriseVEPSummary(BaseModel):
    """Executive vulnerability exposure and SLA compliance overview."""
    total_evaluated: int
    p0_count: int
    p1_count: int
    p2_count: int
    p3_count: int
    cisa_kev_count: int
    ransomware_linked_count: int
    average_epss_probability: float
    generated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
