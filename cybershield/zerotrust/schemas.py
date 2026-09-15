"""
Zero Trust Architecture (NIST SP 800-207) Schemas and Models.
Defines dynamic trust factors, device posture attributes, contextual access signals, and decisions.
"""

from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class AccessDecisionType(str, Enum):
    ALLOW = "ALLOW"
    STEP_UP_MFA = "STEP_UP_MFA"
    ISOLATE_DEVICE = "ISOLATE_DEVICE"
    DENY = "DENY"


class ResourceSensitivityTier(str, Enum):
    TIER_1_CRITICAL = "TIER_1_CRITICAL"   # Domain Controllers, WORM Vault, Crown Jewels
    TIER_2_RESTRICTED = "TIER_2_RESTRICTED" # Internal APIs, Databases, Build Pipelines
    TIER_3_STANDARD = "TIER_3_STANDARD"     # Intranet, Mail, Collaboration Tools
    TIER_4_PUBLIC = "TIER_4_PUBLIC"         # Public facing read-only assets


class DevicePosture(BaseModel):
    """Real-time posture assessment of an endpoint."""
    device_id: str
    os_name: str
    os_version: str
    edr_agent_healthy: bool = True
    disk_encryption_enabled: bool = True
    firewall_enabled: bool = True
    secure_boot_enabled: bool = True
    jailbroken_or_rooted: bool = False
    pending_critical_patches: int = 0
    installed_antivirus: str = "CyberShield EDR"
    compliance_passed: bool = True


class AccessContext(BaseModel):
    """Contextual telemetry surrounding an access attempt."""
    user_id: str
    user_role: str
    source_ip: str
    device_posture: DevicePosture
    target_resource_id: str
    target_resource_tier: ResourceSensitivityTier
    request_protocol: str = "HTTPS"
    client_tls_version: str = "TLSv1.3"
    geo_country: str = "US"
    geo_city: str = "New York"
    impossible_travel_detected: bool = False
    ueba_anomaly_score: float = 0.0  # 0 to 100 from ML/UEBA engine
    mfa_verified: bool = False
    timestamp: datetime = Field(default_factory=datetime.utcnow)


class TrustFactorBreakdown(BaseModel):
    """Component scores feeding into composite trust calculation."""
    device_health_score: float  # 0 to 100
    identity_risk_score: float   # 0 to 100
    network_context_score: float # 0 to 100
    behavioral_score: float      # 0 to 100


class TrustEvaluation(BaseModel):
    """Complete trust evaluation output."""
    evaluation_id: str
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    user_id: str
    device_id: str
    target_resource_id: str
    target_tier: ResourceSensitivityTier
    composite_trust_score: float  # 0.0 to 100.0
    trust_breakdown: TrustFactorBreakdown
    decision: AccessDecisionType
    reasons: List[str] = Field(default_factory=list)
    remediation_steps: List[str] = Field(default_factory=list)


class ZeroTrustPolicy(BaseModel):
    """Rule defining access criteria based on trust score and resource tier."""
    id: str
    name: str
    description: str
    resource_tier: ResourceSensitivityTier
    min_trust_score_allow: float = 80.0
    min_trust_score_mfa: float = 55.0
    require_edr_healthy: bool = True
    require_disk_encryption: bool = True
    block_impossible_travel: bool = True
    max_allowed_ueba_risk: float = 65.0
    enabled: bool = True
