"""
CyberShield Enterprise - SCADA / Modbus & Industrial DNP3 Deep Packet Inspector REST Routes
Provides endpoints for ICS wire traffic dissection, Purdue zone enforcement,
and automated cyber-sabotage command interception.
"""

from fastapi import APIRouter, HTTPException, Depends
from typing import Dict, Any, List

from cybershield.scadadpi.schemas import (
    IndustrialProtocol,
    PurdueLevel,
    PacketInspectionRequest,
    SCADADecision,
    ModbusFrame,
    DNP3Frame,
    S7CommFrame,
)
from cybershield.scadadpi.inspector import SCADADeepPacketInspector

router = APIRouter(prefix="/api/v1/scadadpi", tags=["SCADA & Industrial DPI"])

_inspector = SCADADeepPacketInspector(allow_plc_writes=False, enforce_sbo=True)


def get_inspector() -> SCADADeepPacketInspector:
    return _inspector


@router.post("/inspect/packet", response_model=SCADADecision)
def inspect_packet(req: PacketInspectionRequest, inspector: SCADADeepPacketInspector = Depends(get_inspector)):
    """Deep inspect raw industrial packet bytes, enforce Purdue boundaries, and render policy decision."""
    try:
        raw_bytes = bytes.fromhex(req.raw_packet_hex.replace(" ", "").replace("0x", ""))
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid hex representation for raw_packet_hex")

    return inspector.inspect_packet(
        raw_bytes=raw_bytes,
        protocol_hint=req.protocol_hint,
        source_ip=req.source_ip,
        dest_ip=req.dest_ip,
        source_level=req.source_purdue_level,
        dest_level=req.dest_purdue_level,
    )


@router.post("/inspect/modbus", response_model=Dict[str, Any])
def inspect_modbus(raw_packet_hex: str, inspector: SCADADeepPacketInspector = Depends(get_inspector)):
    """Dissect Modbus TCP frame and check for unauthorized coil force commands."""
    try:
        raw_bytes = bytes.fromhex(raw_packet_hex.replace(" ", "").replace("0x", ""))
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid hex string")

    frame, alerts = inspector.dissect_modbus_tcp(raw_bytes)
    return {
        "frame": frame.model_dump() if frame else None,
        "alerts": [a.model_dump() for a in alerts],
    }


@router.post("/inspect/dnp3", response_model=Dict[str, Any])
def inspect_dnp3(raw_packet_hex: str, inspector: SCADADeepPacketInspector = Depends(get_inspector)):
    """Dissect DNP3 frame and check for cold restart or SBO bypass."""
    try:
        raw_bytes = bytes.fromhex(raw_packet_hex.replace(" ", "").replace("0x", ""))
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid hex string")

    frame, alerts = inspector.dissect_dnp3(raw_bytes)
    return {
        "frame": frame.model_dump() if frame else None,
        "alerts": [a.model_dump() for a in alerts],
    }


@router.post("/inspect/s7", response_model=Dict[str, Any])
def inspect_s7(raw_packet_hex: str, inspector: SCADADeepPacketInspector = Depends(get_inspector)):
    """Dissect Siemens S7comm frame and detect PLC CPU stop commands."""
    try:
        raw_bytes = bytes.fromhex(raw_packet_hex.replace(" ", "").replace("0x", ""))
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid hex string")

    frame, alerts = inspector.dissect_s7comm(raw_bytes)
    return {
        "frame": frame.model_dump() if frame else None,
        "alerts": [a.model_dump() for a in alerts],
    }


@router.get("/stats/summary")
def get_stats_summary(inspector: SCADADeepPacketInspector = Depends(get_inspector)) -> Dict[str, Any]:
    """Retrieve SCADA deep packet inspection capabilities and configuration."""
    return {
        "status": "active",
        "allow_plc_writes": inspector.allow_plc_writes,
        "enforce_sbo": inspector.enforce_sbo,
        "supported_protocols": ["modbus_tcp", "dnp3", "siemens_s7comm"],
        "purdue_model_enforcement": "strict_level_1_airgap",
    }


@router.get("/health")
def health():
    return {"status": "healthy", "service": "scada-dpi-inspector", "version": "1.0.0"}
