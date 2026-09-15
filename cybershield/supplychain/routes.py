"""
Software Supply Chain Security REST API routes.
"""

from typing import Any, Dict, List, Optional
from fastapi import APIRouter, HTTPException, status

from cybershield.supplychain.scanner import SupplyChainScanner
from cybershield.supplychain.schemas import (
    PackageEcosystem,
    SupplyChainScanRequest,
    SupplyChainScanResult,
)

supplychain_router = APIRouter(prefix="/api/supplychain", tags=["Software Supply Chain & Dependency Security"])
_scanner = SupplyChainScanner()
_scans_store: Dict[str, SupplyChainScanResult] = {}


@supplychain_router.post("/scan", response_model=SupplyChainScanResult)
async def scan_dependency_manifest(request: SupplyChainScanRequest):
    """
    Scans project dependency manifests (requirements.txt, package.json)
    for typosquatting, malicious install hooks, and poisoned packages.
    """
    result = _scanner.scan_manifest(request)
    _scans_store[result.scan_id] = result
    return result


@supplychain_router.get("/scans", response_model=List[SupplyChainScanResult])
async def list_supplychain_scans():
    """List completed supply chain scans."""
    return list(_scans_store.values())


@supplychain_router.get("/scans/{scan_id}", response_model=SupplyChainScanResult)
async def get_supplychain_scan(scan_id: str):
    """Retrieve details of a specific supply chain scan report."""
    if scan_id not in _scans_store:
        raise HTTPException(status_code=404, detail=f"Supply chain scan '{scan_id}' not found")
    return _scans_store[scan_id]


@supplychain_router.get("/poisoned-catalog")
async def get_poisoned_package_catalog():
    """Retrieve database of known poisoned open-source packages across PyPI and npm."""
    return _scanner.KNOWN_POISONED_PACKAGES


@supplychain_router.get("/overview")
async def get_supplychain_overview():
    """Executive metrics on supply chain scans, blocked builds, and top vulnerability types."""
    total_scans = len(_scans_store)
    if total_scans == 0:
        return {
            "total_scans": 0,
            "blocked_builds": 0,
            "mean_risk_score": 0.0,
            "threats_by_type": {},
        }

    blocked = sum(1 for s in _scans_store.values() if s.is_build_blocked)
    total_risk = sum(s.risk_score for s in _scans_store.values())
    threat_counts: Dict[str, int] = {}

    for s in _scans_store.values():
        for f in s.findings:
            t = f.threat_type.value
            threat_counts[t] = threat_counts.get(t, 0) + 1

    return {
        "total_scans": total_scans,
        "blocked_builds": blocked,
        "mean_risk_score": round(total_risk / total_scans, 1),
        "threats_by_type": threat_counts,
    }
