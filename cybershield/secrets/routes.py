"""CyberShield Enterprise - Autonomous Secret Sprawl & Token Entropy Scanner Routes.
Exposes endpoints for code/text scanning, file auditing, finding triage, and sprawl metrics.
"""

from typing import Dict, List, Optional, Any
from fastapi import APIRouter, HTTPException, Query, status

from .schemas import (
    SecretFinding,
    ScanTextRequest,
    ScanFileRequest,
    SecretScanSummary,
    SecretStatsResponse,
)
from .scanner import SecretEntropyScanner

router = APIRouter(prefix="/api/v1/secrets", tags=["Secret Sprawl & Token Entropy Scanner"])

# Singleton scanner engine instance
_SECRET_SCANNER = SecretEntropyScanner()


@router.post("/scan/text", response_model=SecretScanSummary, status_code=status.HTTP_200_OK)
def scan_inline_text(request: ScanTextRequest):
    """Scan raw text buffer, source code snippet, or log entry for leaked secrets."""
    return _SECRET_SCANNER.scan_text(
        text=request.content,
        source_label=request.source_label,
        entropy_threshold=request.entropy_threshold,
    )


@router.post("/scan/file", response_model=SecretScanSummary, status_code=status.HTTP_200_OK)
def scan_file_path(request: ScanFileRequest):
    """Scan a target file on local filesystem for exposed credentials."""
    return _SECRET_SCANNER.scan_file(
        file_path=request.file_path,
        entropy_threshold=request.entropy_threshold,
    )


@router.get("/findings", response_model=List[SecretFinding])
def list_secret_findings(
    unresolved_only: bool = Query(default=False, description="Filter only unresolved findings")
):
    """List historical detected secret exposures."""
    all_findings = list(_SECRET_SCANNER.findings_store.values())
    if unresolved_only:
        return [f for f in all_findings if not f.is_remediated]
    return all_findings


@router.post("/remediate/{finding_id}", response_model=SecretFinding)
def remediate_secret_finding(finding_id: str):
    """Mark a secret finding as remediated / rotated."""
    finding = _SECRET_SCANNER.remediate_finding(finding_id)
    if not finding:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Secret finding {finding_id} not found."
        )
    return finding


@router.get("/stats", response_model=SecretStatsResponse)
def get_secret_sprawl_statistics():
    """Retrieve platform-wide credential exposure posture and metrics."""
    return _SECRET_SCANNER.get_statistics()
