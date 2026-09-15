"""
CyberShield Enterprise - Vulnerability Management REST API Endpoints
Provides endpoints for CVSS scoring, CVE querying, vulnerability scanning,
asset remediation tracking, and security compliance postures.
"""

from __future__ import annotations

from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.ext.asyncio import AsyncSession

from cybershield.database.session import get_db
from cybershield.database.models.user import User
from cybershield.database.models.role import Permission
from cybershield.auth.dependencies import get_current_user, require_permission
from cybershield.audit.service import AuditService
from cybershield.vulnerabilities.cvss import CVSSv31Engine
from cybershield.vulnerabilities.cwe_kb import CWEKnowledgeBase
from cybershield.vulnerabilities.epss import EPSSCalculator
from cybershield.vulnerabilities.offline_cve_db import OfflineCVEDatabase
from cybershield.vulnerabilities.sbom_analyzer import SBOMAnalyzer
from cybershield.vulnerabilities.service import vulnerability_service
from cybershield.vulnerabilities.schemas import (
    CVSSCalculationRequest,
    CVSSCalculationResponse,
    CreateVulnerabilityRequest,
    AssetScanRequest,
    UpdateAssetVulnStatusRequest,
    VulnerabilityKPIResponse,
    EPSSRequest,
    EPSSResponse,
    SBOMScanRequest,
)

router = APIRouter(prefix="/api/vulnerabilities", tags=["Vulnerability Management"])


@router.get("", summary="List CVE Catalog Entries")
async def list_vulnerabilities(
    search: Optional[str] = Query(None, description="Search by CVE code, title, or description"),
    severity: Optional[str] = Query(None, description="Filter by severity: CRITICAL, HIGH, MEDIUM, LOW"),
    min_cvss: Optional[float] = Query(None, description="Minimum CVSS v3.1 score"),
    page: int = Query(1, ge=1),
    page_size: int = Query(20, ge=1, le=100),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.VULN_VIEW)),
):
    """Retrieve paginated and filtered CVE vulnerabilities."""
    return await vulnerability_service.list_vulnerabilities(
        session=db,
        search=search,
        severity=severity,
        min_cvss=min_cvss,
        page=page,
        page_size=page_size,
    )


@router.get("/kpis", summary="Vulnerability Posture KPIs", response_model=VulnerabilityKPIResponse)
async def get_vulnerability_kpis(
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.VULN_VIEW)),
):
    """Retrieve executive vulnerability metrics and compliance distribution."""
    return await vulnerability_service.get_vulnerability_kpis(db)


@router.post("/cvss/calculate", summary="Calculate CVSS v3.1 Score", response_model=CVSSCalculationResponse)
async def calculate_cvss_score(
    req: CVSSCalculationRequest,
    current_user: User = Depends(require_permission(Permission.VULN_VIEW)),
):
    """Calculate official FIRST CVSS v3.1 Base, Temporal, and Environmental scores."""
    result = CVSSv31Engine.calculate_scores(
        av=req.attack_vector,
        ac=req.attack_complexity,
        pr=req.privileges_required,
        ui=req.user_interaction,
        scope=req.scope,
        conf=req.confidentiality_impact,
        integ=req.integrity_impact,
        avail=req.availability_impact,
        e=req.exploit_code_maturity,
        rl=req.remediation_level,
        rc=req.report_confidence,
    )
    return result


@router.post("", status_code=status.HTTP_201_CREATED, summary="Create or Ingest CVE Record")
async def create_vulnerability(
    req: CreateVulnerabilityRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.VULN_MANAGE)),
):
    """Register a new CVE definition in the enterprise catalog."""
    try:
        vuln = await vulnerability_service.create_vulnerability(
            session=db,
            cve_id=req.cve_id,
            title=req.title,
            description=req.description,
            cwe_id=req.cwe_id,
            severity=req.severity,
            cvss_v31_score=req.cvss_v31_score,
            cvss_vector=req.cvss_vector,
            affected_products=req.affected_products,
            remediation_guidance=req.remediation_guidance,
            patch_available=req.patch_available,
            active_exploit_observed=req.active_exploit_observed,
            compliance_tags=req.compliance_tags,
        )

        await AuditService.log_event(
            db=db,
            action="CREATE_CVE_RECORD",
            resource=f"cve:{vuln.cve_id}",
            username=current_user.username,
            user_id=current_user.id,
            details={"cve_id": vuln.cve_id, "score": vuln.cvss_v31_score, "severity": vuln.severity},
            status="SUCCESS",
        )
        return vuln.to_dict()
    except ValueError as e:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(e))


@router.get("/assets", summary="List Asset Vulnerability Associations")
async def list_asset_vulnerabilities(
    device_id: Optional[str] = Query(None, description="Filter by device ID"),
    cve_id: Optional[str] = Query(None, description="Filter by CVE ID"),
    status_filter: Optional[str] = Query(None, alias="status", description="Filter by status"),
    page: int = Query(1, ge=1),
    page_size: int = Query(25, ge=1, le=100),
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.VULN_VIEW)),
):
    """Query discovered asset vulnerabilities with patch priority rankings."""
    return await vulnerability_service.list_asset_vulnerabilities(
        session=db,
        device_id=device_id,
        cve_id=cve_id,
        status=status_filter,
        page=page,
        page_size=page_size,
    )


@router.post("/scan", summary="Trigger Asset Vulnerability Scan")
async def scan_assets(
    req: AssetScanRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.VULN_SCAN)),
):
    """Execute vulnerability scan against network devices to detect CVE exposures."""
    results = await vulnerability_service.scan_assets_for_vulnerabilities(
        session=db,
        device_id=req.device_id,
        subnet_id=req.subnet_id,
    )

    await AuditService.log_event(
        db=db,
        action="VULNERABILITY_SCAN_EXECUTED",
        resource=req.device_id or req.subnet_id or "ALL_ASSETS",
        username=current_user.username,
        user_id=current_user.id,
        details={"scanned_devices": results["scanned_devices"], "findings": results["findings_generated"]},
        status="SUCCESS",
    )
    return results


@router.patch("/assets/{binding_id}/status", summary="Update Vulnerability Remediation Status")
async def update_remediation_status(
    binding_id: str,
    req: UpdateAssetVulnStatusRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.VULN_MANAGE)),
):
    """Advance an asset vulnerability through the remediation lifecycle."""
    updated = await vulnerability_service.update_asset_vuln_status(
        session=db,
        binding_id=binding_id,
        new_status=req.status,
        analyst_notes=req.analyst_notes,
    )
    if not updated:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Asset vulnerability record '{binding_id}' not found",
        )

    await AuditService.log_event(
        db=db,
        action="UPDATE_VULN_STATUS",
        resource=f"asset_vuln:{binding_id}",
        username=current_user.username,
        user_id=current_user.id,
        details={"new_status": req.status, "notes": req.analyst_notes},
        status="SUCCESS",
    )
    return updated.to_dict()


# --- Offline CWE, EPSS, SBOM & KEV Knowledge Base Endpoints ---

@router.get("/cwe/catalog", summary="List CWE Knowledge Base")
async def list_cwe_catalog(
    search: Optional[str] = Query(None, description="Search term in CWE names/descriptions"),
    current_user: User = Depends(require_permission(Permission.VULN_VIEW)),
):
    """Retrieve full or filtered offline Common Weakness Enumeration catalog."""
    if search:
        return [c.__dict__ for c in CWEKnowledgeBase.search(search)]
    return [c.__dict__ for c in CWEKnowledgeBase.list_all()]


@router.get("/cwe/{cwe_id}", summary="Get CWE Definition Detail")
async def get_cwe_detail(
    cwe_id: str,
    current_user: User = Depends(require_permission(Permission.VULN_VIEW)),
):
    """Retrieve structured CWE definition, consequences, and mitigations."""
    cwe = CWEKnowledgeBase.get(cwe_id)
    if not cwe:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"CWE '{cwe_id}' not found")
    return cwe.__dict__


@router.post("/epss/calculate", response_model=EPSSResponse, summary="Calculate Offline EPSS Score")
async def calculate_epss_score(
    req: EPSSRequest,
    current_user: User = Depends(require_permission(Permission.VULN_VIEW)),
):
    """Compute offline EPSS exploitation probability and percentile without cloud APIs."""
    score = EPSSCalculator.calculate_epss(
        cve_id=req.cve_id,
        cvss_base_score=req.cvss_base_score or 5.0,
        attack_vector=req.attack_vector or "NETWORK",
        user_interaction=req.user_interaction or "NONE",
        privileges_required=req.privileges_required or "NONE",
        has_public_exploit=req.has_public_exploit or False,
        is_cisa_kev=req.is_cisa_kev or False,
    )
    return EPSSResponse(
        cve_id=score.cve_id,
        epss_score=score.epss_score,
        percentile=score.percentile,
        is_actively_exploited=score.is_actively_exploited,
        rationale=score.rationale,
    )


@router.post("/sbom/scan", summary="Scan Software Bill of Materials (SBOM)")
async def scan_sbom(
    req: SBOMScanRequest,
    current_user: User = Depends(require_permission(Permission.VULN_SCAN)),
):
    """Ingest CycloneDX or SPDX JSON SBOM and correlate components against offline CVE database."""
    report = SBOMAnalyzer.scan_sbom(req.sbom_raw)
    return {
        "format_type": report.format_type,
        "total_components": report.total_components,
        "vulnerable_components_count": report.vulnerable_components_count,
        "total_cves_found": report.total_cves_found,
        "critical_cves": report.critical_cves,
        "high_cves": report.high_cves,
        "findings": [f.__dict__ for f in report.findings],
    }


@router.get("/offline/catalog", summary="List Offline Landmark CVEs & KEV")
async def list_offline_cves(
    severity: Optional[str] = Query(None),
    is_kev_only: bool = Query(False),
    current_user: User = Depends(require_permission(Permission.VULN_VIEW)),
):
    """Retrieve offline catalog of landmark enterprise CVEs and CISA KEV."""
    entries = OfflineCVEDatabase.list_cves(severity=severity, is_kev_only=is_kev_only)
    return [e.__dict__ for e in entries]


@router.get("/{cve_id}", summary="Get CVE Detail Dossier")
async def get_vulnerability_detail(
    cve_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_permission(Permission.VULN_VIEW)),
):
    """Retrieve full CVE vulnerability dossier with impacted asset list."""
    vuln = await vulnerability_service.get_vulnerability_by_cve(db, cve_id)
    if not vuln:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"CVE '{cve_id}' not found")
    return vuln
