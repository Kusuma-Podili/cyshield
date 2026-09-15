"""
CyberShield Enterprise - Vulnerability Management Pydantic Schemas
Defines request/response contracts for CVSS calculations, CVE queries,
asset vulnerability scans, and remediation lifecycle updates.
"""

from __future__ import annotations

from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field


class CVSSCalculationRequest(BaseModel):
    attack_vector: str = Field("NETWORK", description="NETWORK, ADJACENT, LOCAL, PHYSICAL")
    attack_complexity: str = Field("LOW", description="LOW, HIGH")
    privileges_required: str = Field("NONE", description="NONE, LOW, HIGH")
    user_interaction: str = Field("NONE", description="NONE, REQUIRED")
    scope: str = Field("UNCHANGED", description="UNCHANGED, CHANGED")
    confidentiality_impact: str = Field("HIGH", description="NONE, LOW, HIGH")
    integrity_impact: str = Field("HIGH", description="NONE, LOW, HIGH")
    availability_impact: str = Field("HIGH", description="NONE, LOW, HIGH")
    exploit_code_maturity: str = Field("NOT_DEFINED", description="NOT_DEFINED, HIGH, FUNCTIONAL, PROOF_OF_CONCEPT, UNPROVEN")
    remediation_level: str = Field("NOT_DEFINED", description="NOT_DEFINED, OFFICIAL_FIX, TEMPORARY_FIX, WORKAROUND, UNAVAILABLE")
    report_confidence: str = Field("NOT_DEFINED", description="NOT_DEFINED, CONFIRMED, REASONABLE, UNKNOWN")


class CVSSCalculationResponse(BaseModel):
    base_score: float
    temporal_score: float
    environmental_score: float
    severity: str
    vector_string: str
    impact_subscore: float
    exploitability_subscore: float


class CreateVulnerabilityRequest(BaseModel):
    cve_id: str = Field(...)
    title: str = Field(...)
    description: str = Field(...)
    cwe_id: Optional[str] = Field("CWE-119")
    severity: str = Field("HIGH")
    cvss_v31_score: float = Field(7.5)
    cvss_vector: str = Field("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:H")
    affected_products: List[str] = Field(default_factory=list)
    remediation_guidance: str = Field(...)
    patch_available: bool = Field(True)
    active_exploit_observed: bool = Field(False)
    compliance_tags: List[str] = Field(default_factory=list)


class AssetScanRequest(BaseModel):
    device_id: Optional[str] = Field(None, description="Target specific device ID")
    subnet_id: Optional[str] = Field(None, description="Scan all devices in subnet")


class UpdateAssetVulnStatusRequest(BaseModel):
    status: str = Field(..., description="DISCOVERED, CONFIRMED, IN_REMEDIATION, VERIFIED, CLOSED, FALSE_POSITIVE")
    analyst_notes: Optional[str] = Field(None, description="Remediation comment or patch ticket reference")


class VulnerabilityKPIResponse(BaseModel):
    total_cves: int
    critical_cves: int
    high_cves: int
    total_vulnerable_assets: int
    unpatched_critical_assets: int
    avg_patch_priority: float
    compliance_breakdown: Dict[str, int]


class EPSSRequest(BaseModel):
    cve_id: str
    cvss_base_score: Optional[float] = 5.0
    attack_vector: Optional[str] = "NETWORK"
    user_interaction: Optional[str] = "NONE"
    privileges_required: Optional[str] = "NONE"
    has_public_exploit: Optional[bool] = False
    is_cisa_kev: Optional[bool] = False


class EPSSResponse(BaseModel):
    cve_id: str
    epss_score: float
    percentile: float
    is_actively_exploited: bool
    rationale: str


class SBOMScanRequest(BaseModel):
    sbom_raw: str = Field(..., description="CycloneDX or SPDX or Generic JSON string")

