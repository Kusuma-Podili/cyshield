"""CyberShield Enterprise - Autonomous Active Directory & Kerberos Attack Sentinel Routes.
Exposes endpoints for Kerberos ticket auditing, DC security event inspection,
Active Directory threat tracking, and Domain hygiene posture reports.
"""

from typing import Dict, List, Optional, Any
from fastapi import APIRouter, HTTPException, Query, status

from .schemas import (
    KerberosTicketInspectionRequest,
    DCSecurityEvent,
    ADThreatAlert,
    ADDomainPostureReport,
)
from .sentinel import ActiveDirectorySentinel

router = APIRouter(prefix="/api/v1/ad", tags=["Active Directory & Kerberos Sentinel"])

# Singleton sentinel instance
_AD_SENTINEL = ActiveDirectorySentinel()


@router.post("/tickets/inspect", response_model=Dict[str, Any], status_code=status.HTTP_200_OK)
def inspect_kerberos_ticket(request: KerberosTicketInspectionRequest):
    """Audit Kerberos authentication ticket for Golden/Silver ticket forgery or AS-REP roasting."""
    alert = _AD_SENTINEL.inspect_kerberos_ticket(request)
    return {
        "status": "ticket_inspected",
        "ticket_id": request.ticket_id,
        "is_threat": alert is not None,
        "threat_technique": alert.threat_technique.value if alert else None,
        "alert": alert,
    }


@router.post("/events/inspect", response_model=Dict[str, Any], status_code=status.HTTP_200_OK)
def inspect_domain_controller_event(event: DCSecurityEvent):
    """Audit Domain Controller event for DCSync replication or Kerberoasting attack patterns."""
    alert = _AD_SENTINEL.inspect_dc_event(event)
    return {
        "status": "event_processed",
        "event_id": event.event_id,
        "is_threat": alert is not None,
        "threat_technique": alert.threat_technique.value if alert else None,
        "alert": alert,
    }


@router.get("/threats", response_model=List[ADThreatAlert])
def list_active_directory_threats():
    """Retrieve all detected Active Directory / Kerberos compromise security alerts."""
    return _AD_SENTINEL.alerts


@router.get("/posture", response_model=ADDomainPostureReport)
def get_domain_hygiene_posture(
    krbtgt_age_days: int = Query(default=45, ge=0),
    unconstrained_delegation_count: int = Query(default=2, ge=0),
    preauth_disabled_count: int = Query(default=1, ge=0),
):
    """Calculate and return Active Directory hygiene score and domain posture."""
    return _AD_SENTINEL.evaluate_domain_posture(
        krbtgt_age_days=krbtgt_age_days,
        unconstrained_delegation_count=unconstrained_delegation_count,
        preauth_disabled_count=preauth_disabled_count,
    )
