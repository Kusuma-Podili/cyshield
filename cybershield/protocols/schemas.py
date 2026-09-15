"""Pydantic v2 Schemas for Deep Protocol Decoders & Network Dissectors."""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class ProtocolType(str, Enum):
    DNS = "DNS"
    HTTP1 = "HTTP1"
    HTTP2 = "HTTP2"
    TLS = "TLS"
    SMB = "SMB"
    KERBEROS = "KERBEROS"
    RDP = "RDP"
    MODBUS = "MODBUS"
    DNP3 = "DNP3"
    BACNET = "BACNET"
    MQTT = "MQTT"
    UNKNOWN = "UNKNOWN"


class AnomalySeverity(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class ProtocolAnomaly(BaseModel):
    rule_id: str = Field(..., description="Unique anomaly identification code (e.g. DNS-TUNNEL-001)")
    severity: AnomalySeverity = Field(..., description="Risk impact severity")
    title: str = Field(..., description="Concise anomaly title")
    description: str = Field(..., description="Detailed technical rationale of the detected threat pattern")
    mitre_technique: Optional[str] = Field(None, description="Mapped MITRE ATT&CK technique code (e.g. T1071.004)")
    mitigation: Optional[str] = Field(None, description="Recommended SOC containment action")


class DecodedPacket(BaseModel):
    protocol: ProtocolType
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    src_ip: str = "0.0.0.0"
    dst_ip: str = "0.0.0.0"
    src_port: int = 0
    dst_port: int = 0
    raw_length_bytes: int = 0
    headers: Dict[str, Any] = Field(default_factory=dict)
    payload_fields: Dict[str, Any] = Field(default_factory=dict)
    fingerprint: Optional[str] = Field(None, description="Protocol-specific cryptographic or structural fingerprint (e.g. JA3, JA4, CTPH)")
    is_suspicious: bool = False
    anomalies: List[ProtocolAnomaly] = Field(default_factory=list)


class ProtocolDissectionResult(BaseModel):
    success: bool = True
    protocol: ProtocolType
    raw_length_bytes: int
    decoded_packet: DecodedPacket
    anomalies_count: int = 0
    execution_time_ms: float = 0.0
    error_message: Optional[str] = None


class DissectionRequest(BaseModel):
    protocol_hint: Optional[ProtocolType] = Field(default=None, description="Optional hint for faster decoder routing")
    payload_hex: Optional[str] = Field(default=None, description="Hexadecimal-encoded packet byte stream")
    payload_base64: Optional[str] = Field(default=None, description="Base64-encoded packet byte stream")
    payload_text: Optional[str] = Field(default=None, description="Plaintext payload (e.g. HTTP/1.1 or SIP)")
    src_ip: str = Field(default="10.0.0.100", description="Source IP address")
    dst_ip: str = Field(default="10.0.0.1", description="Destination IP address")
    src_port: int = Field(default=49152, description="Source port number")
    dst_port: int = Field(default=80, description="Destination port number")


class BatchDissectionRequest(BaseModel):
    packets: List[DissectionRequest]


class BatchDissectionResponse(BaseModel):
    total_processed: int
    anomalies_detected: int
    results: List[ProtocolDissectionResult]


class ProtocolStatsResponse(BaseModel):
    total_dissected: int
    protocols_active: Dict[str, int]
    anomalies_detected: int
    top_anomalies: List[Dict[str, Any]]
