"""CyberShield Enterprise - Autonomous Adversary Emulation & MITRE ATT&CK Planner Schemas.
Data contracts for APT profile execution, atomic test simulation, detection gap attribution,
and security defense scorecards.
"""

from enum import Enum
from typing import Dict, List, Optional, Any
from datetime import datetime, timezone
from pydantic import BaseModel, Field


class ThreatActorGroup(str, Enum):
    APT29_COZY_BEAR = "APT29_COZY_BEAR"
    APT28_FANCY_BEAR = "APT28_FANCY_BEAR"
    FIN7_CARBANAK = "FIN7_CARBANAK"
    LOCKBIT_RANSOMWARE = "LOCKBIT_RANSOMWARE"
    WIZARD_SPIDER = "WIZARD_SPIDER"


class EmulationStepStatus(str, Enum):
    PENDING = "PENDING"
    EXECUTED_DETECTED = "EXECUTED_DETECTED"      # Blue team caught the technique!
    EXECUTED_BLOCKED = "EXECUTED_BLOCKED"        # Autonomous prevention blocked it!
    EXECUTED_MISSED = "EXECUTED_MISSED"          # Detection gap identified!


class AtomicAttackStep(BaseModel):
    """Single atomic attack technique in the adversary emulation chain."""
    step_id: str
    mitre_technique_id: str = Field(..., description="e.g. T1082, T1059.001")
    technique_name: str
    tactic: str = "Discovery"
    command_simulation: str
    requires_admin: bool = False
    status: EmulationStepStatus = EmulationStepStatus.PENDING
    detection_subsystem: Optional[str] = None


class AdversaryProfile(BaseModel):
    """Documented threat group persona with associated TTP execution sequence."""
    profile_id: str
    group_name: ThreatActorGroup
    alias: str
    target_sectors: List[str]
    description: str
    attack_steps: List[AtomicAttackStep]


class CreateCampaignPlanRequest(BaseModel):
    """Request to create an adversary campaign execution plan."""
    campaign_name: str
    threat_actor: ThreatActorGroup
    target_host_id: str = "sandbox-endpoint-01"


class CampaignScorecard(BaseModel):
    """Defense effectiveness metrics after campaign execution."""
    campaign_id: str
    threat_actor: ThreatActorGroup
    total_steps: int
    detected_steps: int
    blocked_steps: int
    missed_gaps_count: int
    detection_coverage_pct: float = Field(..., ge=0.0, le=100.0)
    prevention_coverage_pct: float = Field(..., ge=0.0, le=100.0)
    tuning_recommendations: List[str] = Field(default_factory=list)
    completed_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
