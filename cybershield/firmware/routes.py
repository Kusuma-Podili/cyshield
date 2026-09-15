"""
Firmware and Embedded Binary Analysis REST API routes.
"""

from typing import List, Dict, Any, Optional
from fastapi import APIRouter, HTTPException

from cybershield.firmware.schemas import (
    FirmwareScanRequest,
    FirmwareScanResult,
    FirmwareArchitecture,
    FilesystemType,
)
from cybershield.firmware.analyzer import FirmwareAnalyzer

firmware_router = APIRouter(prefix="/api/firmware", tags=["Firmware Analysis"])

_analyzer = FirmwareAnalyzer()
_scan_store: Dict[str, FirmwareScanResult] = {}


@firmware_router.post("/analyze", response_model=FirmwareScanResult)
def analyze_firmware_binary(request: FirmwareScanRequest):
    """
    Submits a firmware image or binary blob for static security analysis.
    Inspects ELF headers, filesystems, Shannon entropy, and hardcoded secrets.
    """
    result = _analyzer.analyze(request)
    _scan_store[result.scan_id] = result
    return result


@firmware_router.get("/scans", response_model=List[FirmwareScanResult])
def list_firmware_scans():
    """List all completed firmware security scans."""
    return list(_scan_store.values())


@firmware_router.get("/scans/{scan_id}", response_model=FirmwareScanResult)
def get_firmware_scan(scan_id: str):
    """Fetch details of a specific firmware scan result."""
    if scan_id not in _scan_store:
        raise HTTPException(status_code=404, detail="Firmware scan not found")
    return _scan_store[scan_id]


@firmware_router.get("/summary")
def get_firmware_summary():
    """Aggregated firmware posture summary across scanned IoT/embedded binaries."""
    total_scans = len(_scan_store)
    if total_scans == 0:
        return {
            "total_scans": 0,
            "mean_risk_score": 0.0,
            "architecture_distribution": {},
            "findings_by_severity": {
                "CRITICAL": 0,
                "HIGH": 0,
                "MEDIUM": 0,
                "LOW": 0
            },
        }

    arch_counts: Dict[str, int] = {}
    sev_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    total_risk = 0.0

    for scan in _scan_store.values():
        total_risk += scan.risk_score
        arch = scan.detected_architecture.value
        arch_counts[arch] = arch_counts.get(arch, 0) + 1
        for finding in scan.findings:
            sev = finding.severity.value
            if sev in sev_counts:
                sev_counts[sev] += 1

    return {
        "total_scans": total_scans,
        "mean_risk_score": round(total_risk / total_scans, 1),
        "architecture_distribution": arch_counts,
        "findings_by_severity": sev_counts,
    }
