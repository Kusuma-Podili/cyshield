"""
CyberShield Enterprise - CI/CD Pipeline & Supply Chain Poisoning Sentinel REST Routes
Provides endpoints for workflow tampering analysis, SBOM evaluation, typosquatting checks,
and SLSA-compliant build attestation.
"""

import base64
from fastapi import APIRouter, HTTPException, Depends
from typing import Dict, Any, List

from cybershield.cicd.schemas import (
    WorkflowAuditRequest,
    SBOMAuditRequest,
    TypoSquatCheckRequest,
    AttestationVerifyRequest,
    PipelineTamperFinding,
    SBOMDocument,
    TypoSquatFinding,
    ArtifactAttestation,
    PipelineAuditReport,
)
from cybershield.cicd.sentinel import CICDPipelineSentinel

router = APIRouter(prefix="/api/v1/cicd", tags=["CI/CD Pipeline Sentinel"])

# Global sentinel instance
_sentinel = CICDPipelineSentinel()


def get_sentinel() -> CICDPipelineSentinel:
    return _sentinel


@router.post("/audit/workflow", response_model=List[PipelineTamperFinding])
def audit_workflow(req: WorkflowAuditRequest, sentinel: CICDPipelineSentinel = Depends(get_sentinel)):
    """Statically audit a CI/CD workflow definition for tampering and vulnerability vectors."""
    try:
        findings = sentinel.audit_workflow_script(req.workflow_content, platform=req.platform)
        return findings
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Failed to audit workflow: {str(e)}")


@router.post("/audit/sbom", response_model=SBOMDocument)
def audit_sbom(req: SBOMAuditRequest, sentinel: CICDPipelineSentinel = Depends(get_sentinel)):
    """Parse and audit a CycloneDX or SPDX SBOM document."""
    try:
        if req.format.lower() == "spdx":
            sbom = sentinel.parse_spdx_sbom(req.sbom_content)
        else:
            sbom = sentinel.parse_cyclonedx_sbom(req.sbom_content)
        return sbom
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Failed to parse SBOM: {str(e)}")


@router.post("/detect/typosquat", response_model=List[TypoSquatFinding])
def detect_typosquatting(req: TypoSquatCheckRequest, sentinel: CICDPipelineSentinel = Depends(get_sentinel)):
    """Check a list of package names for typosquatting against popular reference repositories."""
    results: List[TypoSquatFinding] = []
    for pkg in req.packages:
        findings = sentinel.detect_typosquatting(pkg, ecosystem=req.ecosystem)
        results.extend(findings)
    return results


@router.post("/verify/attestation", response_model=ArtifactAttestation)
def verify_attestation(req: AttestationVerifyRequest, sentinel: CICDPipelineSentinel = Depends(get_sentinel)):
    """Verify cryptographic hash and provenance signature of build artifacts."""
    try:
        artifact_bytes = base64.b64decode(req.artifact_content_base64)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid base64 encoding for artifact content")

    attestation = sentinel.verify_build_attestation(
        artifact_bytes=artifact_bytes,
        expected_sha256=req.expected_sha256,
        signature=req.signature,
    )
    return attestation


@router.post("/evaluate/pipeline", response_model=PipelineAuditReport)
def evaluate_pipeline_posture(
    req: WorkflowAuditRequest, sentinel: CICDPipelineSentinel = Depends(get_sentinel)
):
    """Aggregate all CI/CD threat dimensions into a comprehensive posture score."""
    try:
        report = sentinel.evaluate_pipeline_posture(
            workflow_content=req.workflow_content,
            workflow_name=req.workflow_name,
            platform=req.platform,
        )
        return report
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Pipeline evaluation failed: {str(e)}")


@router.get("/posture/summary")
def get_posture_summary(sentinel: CICDPipelineSentinel = Depends(get_sentinel)) -> Dict[str, Any]:
    """Retrieve overall CI/CD pipeline supply chain security summary."""
    return {
        "status": "active",
        "supported_platforms": ["github_actions", "gitlab_ci", "jenkins", "azure_pipelines"],
        "supported_sboms": ["cyclonedx_1.4_1.5", "spdx_2.2_2.3"],
        "slsa_verification_ready": True,
        "reference_packages_tracked": sum(len(pkgs) for pkgs in sentinel.POPULAR_PACKAGES.values()),
    }


@router.get("/health")
def health():
    return {"status": "healthy", "service": "cicd-sentinel", "version": "1.0.0"}
