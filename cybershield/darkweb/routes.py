"""CyberShield Enterprise - Autonomous Dark Web & Leaked Credential Sentinel Routes.
Exposes endpoints for breach dump ingestion, k-anonymity hash prefix searching,
corporate email checking, threat alerts, and dark web metrics.
"""

from typing import Dict, List, Optional, Any
from fastapi import APIRouter, HTTPException, Query, status

from .schemas import (
    IngestBreachRecordRequest,
    HashPrefixLookupRequest,
    HashPrefixLookupResponse,
    CorporateEmailCheckRequest,
    DarkWebExposureAlert,
    DarkWebSentinelMetrics,
)
from .sentinel import DarkWebCredentialSentinel

router = APIRouter(prefix="/api/v1/darkweb", tags=["Dark Web & Leaked Credential Sentinel"])

# Singleton sentinel instance
_DARKWEB_SENTINEL = DarkWebCredentialSentinel()


@router.post("/ingest/breach", response_model=Dict[str, Any], status_code=status.HTTP_201_CREATED)
def ingest_breach_record(request: IngestBreachRecordRequest):
    """Ingest a credential record from dark web breach feeds or stealer logs."""
    alert = _DARKWEB_SENTINEL.ingest_breach_record(request)
    return {
        "status": "ingested",
        "email": request.email,
        "is_corporate_compromise": alert is not None,
        "alert": alert,
    }


@router.post("/check/hash/prefix", response_model=HashPrefixLookupResponse, status_code=status.HTTP_200_OK)
def lookup_hash_prefix(request: HashPrefixLookupRequest):
    """Query 5-character hash prefix under NIST SP 800-63B k-anonymity to detect exposed passwords."""
    return _DARKWEB_SENTINEL.lookup_hash_prefix(request)


@router.post("/check/email", response_model=List[DarkWebExposureAlert], status_code=status.HTTP_200_OK)
def check_corporate_email(request: CorporateEmailCheckRequest):
    """Check if a corporate employee email has known dark web breach exposures."""
    return _DARKWEB_SENTINEL.check_corporate_email(request.email)


@router.get("/threats", response_model=List[DarkWebExposureAlert])
def list_darkweb_threats():
    """Retrieve all corporate credential exposures detected on the dark web."""
    return _DARKWEB_SENTINEL.alerts


@router.get("/status", response_model=DarkWebSentinelMetrics)
def get_darkweb_monitoring_status():
    """Query dark web surveillance coverage and compromised account metrics."""
    return _DARKWEB_SENTINEL.get_metrics()
