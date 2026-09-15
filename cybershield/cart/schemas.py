"""CyberShield Enterprise - Continuous Automated Red Teaming (CART) Schemas.
Data contracts for enterprise attack graph topology, multi-hop exploit paths,
defensive choke-points, and adversary simulation campaigns.
"""

from enum import Enum
from typing import Dict, List, Optional, Any
from datetime import datetime, timezone
from pydantic import BaseModel, Field


class AssetTier(str, Enum):
    TIER_0_CROWN_JEWEL = "TIER_0_CROWN_JEWEL"
    TIER_1_INTERNAL_INFRASTRUCTURE = "TIER_1_INTERNAL_INFRASTRUCTURE"
    TIER_2_WORKSTATION = "TIER_2_WORKSTATION"
    TIER_3_PERIMETER_EXPOSED = "TIER_3_PERIMETER_EXPOSED"


class ExploitPrerequisite(str, Enum):
    NETWORK_LINE_OF_SIGHT = "NETWORK_LINE_OF_SIGHT"
    VALID_USER_CREDENTIALS = "VALID_USER_CREDENTIALS"
    UNPATCHED_CVE = "UNPATCHED_CVE"
    MISCONFIGURED_IAM = "MISCONFIGURED_IAM"
    WEAK_SSH_KEY = "WEAK_SSH_KEY"


class SimulatedVulnerability(BaseModel):
    """Vulnerability on an enterprise asset available for exploit chaining."""
    vuln_id: str = Field(..., description="Internal vulnerability ID")
    cve_id: str = Field(..., description="Common Vulnerabilities and Exposures ID (e.g. CVE-2024-21887)")
    title: str
    cvss_score: float = Field(..., ge=0.0, le=10.0)
    affords_privilege: str = Field(..., description="RCE, PRIV_ESC, CRED_DUMP, INFO_DISCLOSURE")
    exploit_complexity: str = Field(default="LOW", description="LOW, MEDIUM, HIGH")


class AttackGraphNode(BaseModel):
    """Asset node in the continuous multi-hop attack graph."""
    node_id: str = Field(..., description="Unique asset identifier (e.g. srv-web-01, dc-01)")
    name: str = Field(..., description="Display name")
    asset_tier: AssetTier
    ip_address: str
    vulnerabilities: List[SimulatedVulnerability] = Field(default_factory=list)
    held_credentials: List[str] = Field(default_factory=list, description="Leaked credentials available on asset")
    is_compromised: bool = Field(default=False)
    value_score: float = Field(default=10.0, ge=1.0, le=100.0, description="Criticality to business operations")


class AttackGraphEdge(BaseModel):
    """Directed exploitation or lateral movement link between assets."""
    source_id: str
    target_id: str
    technique_id: str = Field(default="T1021.002", description="MITRE ATT&CK technique")
    technique_name: str = Field(default="SMB/Windows Admin Shares")
    required_vuln_id: Optional[str] = None
    success_probability: float = Field(default=0.85, ge=0.01, le=1.0)
    detection_risk: float = Field(default=0.20, ge=0.01, le=1.0)
    transition_cost: float = Field(default=1.0, ge=0.1)


class ExploitPathStep(BaseModel):
    """Single transition along an end-to-end exploit path."""
    step_order: int
    from_node_id: str
    to_node_id: str
    technique_id: str
    technique_name: str
    vuln_exploited: Optional[str] = None
    step_success_prob: float
    step_detection_risk: float


class ExploitPathPlan(BaseModel):
    """Calculated optimal multi-hop attack trajectory from entry point to Crown Jewel."""
    plan_id: str
    target_crown_jewel_id: str
    target_name: str
    path_nodes: List[str]
    steps: List[ExploitPathStep]
    overall_success_prob: float = Field(..., ge=0.0, le=1.0)
    cumulative_detection_risk: float = Field(..., ge=0.0, le=1.0)
    path_cost: float
    recommended_defenses: List[str] = Field(default_factory=list)


class ChokePointReport(BaseModel):
    """Strategic defensive asset where remediation neutralizes multiple attack paths."""
    choke_node_id: str
    node_name: str
    asset_tier: AssetTier
    severed_paths_count: int
    critical_vulnerabilities: List[str]
    defensive_impact_score: float = Field(..., ge=0.0, le=100.0)


class AdversaryProfile(BaseModel):
    """Threat actor emulation persona with specific capabilities and TTP preferences."""
    profile_id: str
    name: str
    skill_level: int = Field(default=8, ge=1, le=10)
    stealth_weight: float = Field(default=0.7, ge=0.0, le=1.0)
    favored_techniques: List[str] = Field(default_factory=list)


class SimulationRun(BaseModel):
    """Historical execution record of an autonomous red team simulation campaign."""
    run_id: str
    adversary_profile_id: str
    start_node_id: str
    target_crown_jewel_id: str
    reached_target: bool
    total_steps_executed: int
    alert_triggered: bool
    timeline: List[Dict[str, Any]] = Field(default_factory=list)
    executed_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
