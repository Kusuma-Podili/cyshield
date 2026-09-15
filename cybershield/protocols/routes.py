"""REST API Endpoints for Deep Network Protocol Dissection & DPI."""

from __future__ import annotations

from typing import Any, Dict, List
from fastapi import APIRouter, Depends, HTTPException, status

from cybershield.auth.dependencies import get_current_user
from cybershield.database.models.user import User
from cybershield.database.models.role import Permission, has_permission
from cybershield.protocols.schemas import (
    ProtocolType,
    DissectionRequest,
    ProtocolDissectionResult,
    BatchDissectionRequest,
    BatchDissectionResponse,
    ProtocolStatsResponse,
)
from cybershield.protocols.dissector_engine import ProtocolDissectorEngine

router = APIRouter(prefix="/api/protocols", tags=["Network Protocol Dissectors & DPI"])


@router.post("/dissect", response_model=ProtocolDissectionResult)
async def dissect_network_packet(
    request: DissectionRequest,
    current_user: User = Depends(get_current_user),
):
    """Dissect a raw binary or textual packet payload and extract security threat telemetry."""
    return ProtocolDissectorEngine.dissect_packet(request)


@router.post("/dissect/batch", response_model=BatchDissectionResponse)
async def dissect_network_batch(
    batch: BatchDissectionRequest,
    current_user: User = Depends(get_current_user),
):
    """Dissect multiple network packets in high-throughput batch mode."""
    return ProtocolDissectorEngine.dissect_batch(batch)


@router.get("/stats", response_model=ProtocolStatsResponse)
async def get_protocol_dpi_statistics(
    current_user: User = Depends(get_current_user),
):
    """Retrieve runtime DPI operational metrics, protocol breakdown, and top threat anomalies."""
    return ProtocolDissectorEngine.get_stats()


@router.get("/supported")
async def list_supported_protocols(
    current_user: User = Depends(get_current_user),
):
    """List all supported enterprise IT and OT/SCADA protocol decoders and security rules."""
    return {
        "supported_protocols": [p.value for p in ProtocolType if p != ProtocolType.UNKNOWN],
        "categories": {
            "Enterprise IT & Internet": ["DNS", "HTTP1", "HTTP2", "TLS", "SMB", "KERBEROS", "RDP"],
            "Industrial SCADA & IoT": ["MODBUS", "DNP3", "BACNET", "MQTT"],
        },
        "capabilities": [
            "Binary Wire-Format Dissection",
            "RFC 1035 DNS Tunneling & DGA Entropy Detection",
            "HTTP Request Smuggling (CL.TE) & Web Attack Signatures",
            "HTTP/2 Rapid Reset DDoS (CVE-2023-44487) Detection",
            "TLS 1.3 Handshake & JA3 / JA4 Malicious C2 Fingerprinting",
            "SMBv1 EternalBlue (MS17-010) & PsExec Named Pipe Traversal",
            "Active Directory Kerberoasting (RC4-HMAC) & AS-REP Roasting",
            "RDP Insecure Protocol & BlueKeep (CVE-2019-0708) Channel Binding",
            "Modbus TCP PLC Ladder Reprogram & Coil Forcing Anomaly Detection",
            "DNP3 Substation Breaker Trip & Industroyer Unsolicited Suppression",
            "BACnet/IP Smart Facility HVAC / Fire Safety Reboot Sabotage",
            "MQTT IoT Anonymous Access & Root Wildcard Eavesdropping",
        ],
    }
