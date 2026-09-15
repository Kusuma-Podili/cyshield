"""
CyberShield Enterprise - SCADA / Modbus & Industrial DNP3 Deep Packet Inspector Schemas
Provides data models for OT/ICS deep packet dissection, stateful protocol tracking,
and industrial sabotage command detection (Modbus TCP, DNP3, Siemens S7comm).
"""

from typing import List, Dict, Optional, Any
from pydantic import BaseModel, Field
from datetime import datetime
from enum import Enum


class IndustrialProtocol(str, Enum):
    MODBUS_TCP = "modbus_tcp"
    DNP3 = "dnp3"
    SIEMENS_S7 = "s7comm"
    ETHERNET_IP = "ethernet_ip"
    BACNET = "bacnet"


class SCADASeverity(str, Enum):
    INFO = "INFO"
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class PurdueLevel(int, Enum):
    LEVEL_0_FIELD = 0
    LEVEL_1_CONTROLLERS = 1
    LEVEL_2_SUPERVISORY = 2
    LEVEL_3_OPERATIONS = 3
    LEVEL_4_ENTERPRISE = 4
    INTERNET = 5


class ModbusFrame(BaseModel):
    transaction_id: int = Field(..., description="Modbus TCP transaction identifier")
    protocol_id: int = Field(0, description="Protocol identifier, 0 for Modbus TCP")
    unit_id: int = Field(..., description="Slave / Unit device address")
    function_code: int = Field(..., description="Modbus function code (e.g. 0x01, 0x05, 0x10)")
    function_name: str = Field(..., description="Human-readable function description")
    is_write_operation: bool = Field(False, description="Whether command alters PLC coil or register state")
    target_address: Optional[int] = Field(None, description="Coil or register memory address")
    register_count: Optional[int] = Field(None, description="Number of coils/registers affected")
    payload_hex: str = Field(..., description="Raw hex data payload")


class DNP3Frame(BaseModel):
    source_address: int = Field(..., description="DNP3 master or outstation source address")
    destination_address: int = Field(..., description="DNP3 master or outstation destination address")
    function_code: int = Field(..., description="DNP3 Application Layer function code")
    function_name: str = Field(..., description="Decoded function (e.g. READ, DIRECT_OPERATE, COLD_RESTART)")
    is_control_operation: bool = Field(False, description="Whether command triggers physical actuator or restart")
    sequence_number: int = Field(..., description="Application sequence number")
    payload_hex: str = Field(..., description="Raw DNP3 application PDU in hex")


class S7CommFrame(BaseModel):
    pdu_type: int = Field(..., description="S7 PDU type (1=Job, 2=Ack, 3=Ack_Data, 7=UserData)")
    function_code: int = Field(..., description="S7comm function code (e.g. 0x04 Read, 0x05 Write, 0x28 PLC Control)")
    function_name: str = Field(..., description="Decoded S7 function description")
    subfunction: Optional[str] = Field(None, description="e.g. 'PLC_STOP', 'PLC_START', 'MEM_UPLOAD'")
    payload_hex: str = Field(..., description="Raw S7 payload in hex")


class SCADAThreatAlert(BaseModel):
    alert_id: str = Field(..., description="Unique alert UUID")
    timestamp: datetime = Field(default_factory=datetime.utcnow, description="Detection timestamp")
    protocol: IndustrialProtocol = Field(..., description="Affected SCADA/ICS protocol")
    severity: SCADASeverity = Field(..., description="Risk severity level")
    threat_category: str = Field(..., description="e.g. UNAUTHORIZED_FORCE_COIL, PLC_CPU_STOP, SBO_VIOLATION")
    source_ip: str = Field(..., description="Client or attacker IP")
    destination_ip: str = Field(..., description="PLC or RTU IP")
    device_id: Optional[str] = Field(None, description="PLC station name or ID")
    title: str = Field(..., description="Alert title")
    details: str = Field(..., description="Forensic context and command analysis")
    purdue_violation: bool = Field(False, description="Whether command traversed Purdue model boundaries directly")
    mitigation_action: str = Field(..., description="Recommended defensive action")


class PacketInspectionRequest(BaseModel):
    raw_packet_hex: str = Field(..., description="Hex string of packet bytes")
    protocol_hint: IndustrialProtocol = Field(IndustrialProtocol.MODBUS_TCP, description="Protocol hint")
    source_ip: str = Field("192.168.1.100", description="Source IP address")
    dest_ip: str = Field("192.168.1.50", description="Destination PLC IP address")
    source_purdue_level: PurdueLevel = Field(PurdueLevel.LEVEL_4_ENTERPRISE, description="Purdue level of source")
    dest_purdue_level: PurdueLevel = Field(PurdueLevel.LEVEL_1_CONTROLLERS, description="Purdue level of destination")


class SCADADecision(BaseModel):
    is_authorized: bool = Field(True, description="Whether command is permitted by ICS security policy")
    action: str = Field("ALLOW", description="'ALLOW', 'BLOCK', 'ISOLATE_PLC'")
    protocol: IndustrialProtocol = Field(..., description="Decoded protocol")
    decoded_summary: str = Field(..., description="Summary of parsed packet")
    threat_alerts: List[SCADAThreatAlert] = Field(default_factory=list, description="Triggered security alerts")
