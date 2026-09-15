"""CyberShield Enterprise - Deception Orchestrator API Routes.
Exposes endpoints for honeytoken creation, endpoint lure deployment,
service emulation interactions, tripwire verification, and deception alerts.
"""

from typing import Dict, List, Optional, Any
from fastapi import APIRouter, HTTPException, Query, status

from .schemas import (
    HoneytokenType,
    EmulatedServiceType,
    Honeytoken,
    DeceptionLure,
    DeceptionAlert,
    ServiceEmulatorStatus,
)
from .orchestrator import DeceptionOrchestrator

router = APIRouter(prefix="/api/v1/honey", tags=["Threat Deception & High-Interaction Emulators"])

# Active singleton orchestrator
_ORCHESTRATOR = DeceptionOrchestrator()


@router.post("/tokens", response_model=Honeytoken, status_code=status.HTTP_201_CREATED)
def create_honeytoken(
    token_type: HoneytokenType = Query(...),
    decoy_username: str = Query(...),
    target_service: str = Query(...),
):
    """Generate a cryptographically signed canary honeytoken."""
    return _ORCHESTRATOR.generate_honeytoken(
        token_type=token_type,
        decoy_username=decoy_username,
        target_service=target_service,
    )


@router.get("/tokens", response_model=List[Honeytoken])
def list_honeytokens():
    """Retrieve all active canary tokens."""
    return list(_ORCHESTRATOR.honeytokens.values())


@router.post("/lures", response_model=DeceptionLure, status_code=status.HTTP_201_CREATED)
def deploy_lure(
    deployed_host_id: str = Query(...),
    honeytoken_id: str = Query(...),
    file_path_or_location: str = Query(...),
):
    """Place a decoy lure on an endpoint host."""
    try:
        return _ORCHESTRATOR.deploy_lure(
            deployed_host_id=deployed_host_id,
            honeytoken_id=honeytoken_id,
            file_path_or_location=file_path_or_location,
        )
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.get("/lures", response_model=List[DeceptionLure])
def list_lures():
    """Retrieve all deployed deception lures."""
    return list(_ORCHESTRATOR.lures.values())


@router.post("/interact", response_model=Dict[str, Any])
def interact_with_service(
    service: EmulatedServiceType = Query(...),
    source_ip: str = Query("198.51.100.77"),
    source_port: int = Query(49152),
    command_or_query: str = Query(...),
    raw_payload: Optional[str] = Query(None),
):
    """Send an adversary interaction to an emulated honeypot service."""
    response, alert = _ORCHESTRATOR.handle_service_interaction(
        service=service,
        source_ip=source_ip,
        source_port=source_port,
        command_or_query=command_or_query,
        raw_payload=raw_payload,
    )
    return {
        "service_response": response,
        "alert_triggered": alert is not None,
        "alert_id": alert.alert_id if alert else None,
        "adversary_action": alert.adversary_action if alert else None,
    }


@router.post("/tripwire", response_model=Dict[str, Any])
def test_honeytoken_tripwire(
    token_value: str = Query(..., description="Observed credential value to check"),
    source_ip: str = Query("10.0.5.15"),
):
    """Check if an observed token in network or process telemetry is a canary honeytoken."""
    alert = _ORCHESTRATOR.verify_and_trigger_honeytoken(
        token_value=token_value,
        source_ip=source_ip,
    )
    return {
        "is_canary": alert is not None,
        "alert_triggered": alert is not None,
        "alert_id": alert.alert_id if alert else None,
    }


@router.get("/alerts", response_model=List[DeceptionAlert])
def get_deception_alerts(limit: int = Query(50, ge=1, le=500)):
    """Retrieve zero-false-positive deterministic deception alerts."""
    return _ORCHESTRATOR.alerts[-limit:]


@router.get("/emulators", response_model=List[ServiceEmulatorStatus])
def get_emulator_status():
    """Get status and connection metrics for all decoy service emulators."""
    return _ORCHESTRATOR.get_service_status()
