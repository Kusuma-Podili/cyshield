"""
CyberShield Enterprise - CI/CD Pipeline & Supply Chain Poisoning Sentinel Schemas
Provides data models for SBOM inspection, CI/CD workflow security, typosquatting detection,
and SLSA-compliant build attestation verification.
"""

from typing import List, Dict, Optional, Any
from pydantic import BaseModel, Field
from datetime import datetime
from enum import Enum


class PackageEcosystem(str, Enum):
    PYPI = "pypi"
    NPM = "npm"
    MAVEN = "maven"
    CARGO = "cargo"
    GOLANG = "golang"
    RUBYGEMS = "rubygems"
    DOCKER = "docker"


class PipelinePlatform(str, Enum):
    GITHUB_ACTIONS = "github_actions"
    GITLAB_CI = "gitlab_ci"
    JENKINS = "jenkins"
    AZURE_PIPELINES = "azure_pipelines"
    CIRCLE_CI = "circleci"


class SLSALevel(str, Enum):
    LEVEL_0 = "LEVEL_0"
    LEVEL_1 = "LEVEL_1"
    LEVEL_2 = "LEVEL_2"
    LEVEL_3 = "LEVEL_3"
    LEVEL_4 = "LEVEL_4"


class FindingSeverity(str, Enum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class AttestationStatus(str, Enum):
    VERIFIED = "VERIFIED"
    TAMPERED = "TAMPERED"
    UNSIGNED = "UNSIGNED"
    CORRUPTED = "CORRUPTED"


class SBOMComponent(BaseModel):
    name: str = Field(..., description="Component package name")
    version: str = Field(..., description="Component version string")
    purl: Optional[str] = Field(None, description="Package URL specification")
    ecosystem: PackageEcosystem = Field(PackageEcosystem.PYPI, description="Package manager ecosystem")
    licenses: List[str] = Field(default_factory=list, description="Declared component licenses")
    direct_dependency: bool = Field(True, description="Whether this is a direct or transitive dependency")
    hashes: Dict[str, str] = Field(default_factory=dict, description="Cryptographic digests (sha256, sha512)")
    is_pinned: bool = Field(True, description="Whether version is pinned to exact release")


class SBOMDocument(BaseModel):
    format: str = Field("cyclonedx", description="SBOM standard format ('cyclonedx' or 'spdx')")
    spec_version: str = Field("1.5", description="Specification version")
    application_name: str = Field("unnamed-application", description="Application or artifact target")
    total_components: int = Field(0, description="Total components in SBOM")
    components: List[SBOMComponent] = Field(default_factory=list, description="Parsed components")
    dependency_graph: Dict[str, List[str]] = Field(default_factory=dict, description="Parent -> child dependencies")


class PipelineTamperFinding(BaseModel):
    finding_type: str = Field(..., description="Finding classification (e.g. CURL_PIPE_BASH, SECRET_LEAK)")
    severity: FindingSeverity = Field(FindingSeverity.HIGH, description="Risk severity level")
    line_number: Optional[int] = Field(None, description="Approximate line number in workflow file")
    evidence: str = Field(..., description="Code or configuration snippet matching rule")
    description: str = Field(..., description="Detailed threat impact explanation")
    recommendation: str = Field(..., description="Hardening or remediation guidance")


class TypoSquatFinding(BaseModel):
    target_package: str = Field(..., description="Legitimate popular reference package")
    suspicious_package: str = Field(..., description="Suspicious candidate package name")
    ecosystem: PackageEcosystem = Field(PackageEcosystem.PYPI, description="Package ecosystem")
    distance: int = Field(..., description="Levenshtein distance")
    similarity_score: float = Field(..., description="Similarity ratio from 0.0 to 1.0")
    attack_vector: str = Field(..., description="e.g. Typosquatting, Homoglyph, Omission, Transposition")
    risk_level: FindingSeverity = Field(FindingSeverity.HIGH, description="Severity rating")


class ArtifactAttestation(BaseModel):
    artifact_path: str = Field(..., description="Relative or absolute path of build artifact")
    source_commit_sha: Optional[str] = Field(None, description="Git commit hash of source repo")
    expected_sha256: str = Field(..., description="Expected pre-build or ledger cryptographic digest")
    calculated_sha256: str = Field(..., description="Actual calculated SHA-256 of candidate binary")
    attestation_status: AttestationStatus = Field(AttestationStatus.VERIFIED, description="Verification outcome")
    signature_valid: bool = Field(False, description="Whether cryptographic signature verified cleanly")
    slsa_level: SLSALevel = Field(SLSALevel.LEVEL_2, description="SLSA compliance tier achieved")
    verification_details: str = Field("Artifact matches reproducible build ledger digest", description="Audit note")


class WorkflowAuditRequest(BaseModel):
    workflow_name: str = Field("ci.yml", description="Workflow file identifier")
    workflow_content: str = Field(..., description="Raw YAML/text workflow specification")
    platform: PipelinePlatform = Field(PipelinePlatform.GITHUB_ACTIONS, description="CI/CD orchestrator")


class SBOMAuditRequest(BaseModel):
    sbom_content: str = Field(..., description="JSON or string content of SBOM")
    format: str = Field("cyclonedx", description="SBOM standard ('cyclonedx' or 'spdx')")


class TypoSquatCheckRequest(BaseModel):
    packages: List[str] = Field(..., description="List of package names to check")
    ecosystem: PackageEcosystem = Field(PackageEcosystem.PYPI, description="Ecosystem to audit against")


class AttestationVerifyRequest(BaseModel):
    artifact_name: str = Field(..., description="Name of the artifact")
    artifact_content_base64: str = Field(..., description="Base64-encoded binary content")
    expected_sha256: str = Field(..., description="Expected SHA-256 hash")
    signature: Optional[str] = Field(None, description="Optional hex or base64 cryptographic signature")


class PipelineAuditReport(BaseModel):
    audit_id: str = Field(..., description="Unique UUID for audit run")
    timestamp: datetime = Field(default_factory=datetime.utcnow, description="Timestamp of evaluation")
    workflow_name: str = Field("ci.yml", description="Evaluated workflow identifier")
    security_score: float = Field(..., description="Postured score from 0 to 100")
    tamper_findings: List[PipelineTamperFinding] = Field(default_factory=list, description="Security violations detected")
    typosquat_findings: List[TypoSquatFinding] = Field(default_factory=list, description="Typosquatted packages detected")
    unpinned_dependencies_count: int = Field(0, description="Count of unpinned dependencies")
    slsa_assessment: SLSALevel = Field(SLSALevel.LEVEL_1, description="Assessed SLSA build integrity tier")
    is_deployable: bool = Field(True, description="Whether pipeline meets minimum security gates")
    recommendations: List[str] = Field(default_factory=list, description="Actionable remediation steps")
