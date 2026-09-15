"""Threat Intelligence, MITRE ATT&CK & CVE REST API Endpoints."""

from __future__ import annotations

from typing import List, Optional, Dict, Any
from fastapi import APIRouter, HTTPException, Query
from pydantic import BaseModel

from cybershield.core.models import IoCEntry, CVECatalogEntry, CVSSMetrics
from cybershield.intel.ioc_database import ioc_database
from cybershield.intel.mitre_attack import mitre_matrix
from cybershield.intel.cve_catalog import cve_catalog, CVSSv31Calculator
from cybershield.ingestion.collector import collector

router = APIRouter(prefix="/api/v1/intel", tags=["Threat Intelligence"])


class CVSSCalcRequest(BaseModel):
    attack_vector: str = "NETWORK"
    attack_complexity: str = "LOW"
    privileges_required: str = "NONE"
    user_interaction: str = "NONE"
    scope: str = "UNCHANGED"
    confidentiality: str = "HIGH"
    integrity: str = "HIGH"
    availability: str = "HIGH"


@router.get("/mitre/tactics")
async def get_mitre_tactics():
    """Retrieve full list of 14 MITRE ATT&CK tactics."""
    return mitre_matrix.get_all_tactics()


@router.get("/mitre/heatmap")
async def get_mitre_heatmap():
    """Compute real-time MITRE matrix heatmap from active alert telemetry."""
    alerts = collector.get_recent_alerts(limit=5000)
    return mitre_matrix.calculate_heatmap(alerts)


@router.get("/ioc/lookup")
async def lookup_ioc(value: str = Query(..., description="IP, Domain, or SHA256 hash")):
    """Sub-millisecond IoC lookup using in-memory Bloom filter and exact table."""
    hit = ioc_database.lookup(value)
    if not hit:
        return {"matched": False, "query": value}
    return {"matched": True, "entry": hit}


@router.get("/ioc/all", response_model=List[IoCEntry])
async def list_all_iocs():
    """Retrieve all local threat intelligence IoCs."""
    return ioc_database.get_all_entries()


@router.get("/cve", response_model=List[CVECatalogEntry])
async def list_cves():
    """List local enterprise vulnerability CVE catalog."""
    return cve_catalog.get_all_cves()


@router.post("/cvss/calculate", response_model=CVSSMetrics)
async def calculate_cvss(payload: CVSSCalcRequest):
    """Compute official CVSS v3.1 score from vector metrics."""
    return CVSSv31Calculator.calculate(
        av=payload.attack_vector,
        ac=payload.attack_complexity,
        pr=payload.privileges_required,
        ui=payload.user_interaction,
        scope=payload.scope,
        conf=payload.confidentiality,
        integ=payload.integrity,
        avail=payload.availability,
    )
