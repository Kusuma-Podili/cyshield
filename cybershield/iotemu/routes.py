"""CyberShield Enterprise - Autonomous Firmware Emulation & IoT Sandbox Routes.
Exposes endpoints for headless daemon emulation, dynamic CGI fuzzing,
backdoor credential scanning, and IoT vulnerability intelligence.
"""

from typing import Dict, List, Optional, Any
from fastapi import APIRouter, HTTPException, Query, status

from .schemas import (
    EmulateDaemonRequest,
    FuzzEndpointRequest,
    IoTVulnerabilityAlert,
    EmulationSessionReport,
    IoTPlatformStatus,
)
from .sandbox import FirmwareDynamicSandbox

router = APIRouter(prefix="/api/v1/iotemu", tags=["Firmware Emulation & IoT Dynamic Sandbox"])

# Singleton sandbox instance
_IOT_SANDBOX = FirmwareDynamicSandbox()


@router.post("/emulate/daemon", response_model=EmulationSessionReport, status_code=status.HTTP_201_CREATED)
def start_daemon_emulation(request: EmulateDaemonRequest):
    """Launch headless virtual emulation of an embedded IoT daemon."""
    return _IOT_SANDBOX.start_emulation_session(request)


@router.post("/fuzz/{session_id}", response_model=Dict[str, Any], status_code=status.HTTP_200_OK)
def fuzz_daemon_endpoint(session_id: str, request: FuzzEndpointRequest):
    """Dynamically test an emulated CGI endpoint for command injection or buffer overflows."""
    alert = _IOT_SANDBOX.fuzz_endpoint(session_id, request)
    return {
        "session_id": session_id,
        "endpoint": request.endpoint_path,
        "vulnerability_detected": alert is not None,
        "alert": alert,
    }


@router.post("/backdoors/{session_id}", response_model=List[IoTVulnerabilityAlert], status_code=status.HTTP_200_OK)
def scan_daemon_backdoors(session_id: str):
    """Audit emulated daemon for factory default hardcoded credentials."""
    return _IOT_SANDBOX.audit_backdoors(session_id)


@router.get("/vulnerabilities", response_model=List[IoTVulnerabilityAlert])
def list_iot_vulnerabilities():
    """Retrieve all zero-day and n-day vulnerabilities discovered in firmware binaries."""
    return _IOT_SANDBOX.vulnerabilities


@router.get("/status", response_model=IoTPlatformStatus)
def get_iot_sandbox_status():
    """Query IoT emulation lab capacity and discovered vulnerability metrics."""
    return _IOT_SANDBOX.get_platform_status()
