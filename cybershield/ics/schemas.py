"""
Industrial Control Systems (ICS) and Operational Technology (OT) Schemas and Models.
Defines Purdue model hierarchy, PLC states, protocol anomalies, and critical infrastructure telemetry.
"""

from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class ICSProtocol(str, Enum):
    MODBUS_TCP = "MODBUS_TCP"
    DNP3 = "DNP3"
    S7COMM = "S7COMM"
    ETHERNET_IP = "ETHERNET_IP"
    BACNET = "BACNET"


class PurdueLevel(str, Enum):
    LEVEL_0_FIELD = "LEVEL_0_FIELD"               # Sensors, Actuators, Valves
    LEVEL_1_CONTROL = "LEVEL_1_CONTROL"           # PLCs, RTUs, IEDs
    LEVEL_2_SUPERVISORY = "LEVEL_2_SUPERVISORY"   # HMI, SCADA Servers
    LEVEL_3_OPERATIONS = "LEVEL_3_OPERATIONS"     # Plant Operations, Historian
    LEVEL_4_ENTERPRISE = "LEVEL_4_ENTERPRISE"     # Corporate IT Network


class ICSAnomalyType(str, Enum):
    UNAUTHORIZED_WRITE = "UNAUTHORIZED_WRITE"
    PLC_CPU_STOP = "PLC_CPU_STOP"
    SETPOINT_OUT_OF_BOUNDS = "SETPOINT_OUT_OF_BOUNDS"
    PURDUE_ZONE_VIOLATION = "PURDUE_ZONE_VIOLATION"
    FIRMWARE_MODIFICATION = "FIRMWARE_MODIFICATION"
    DNP3_RESTART_COMMAND = "DNP3_RESTART_COMMAND"


class ICSSeverity(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class ICSAsset(BaseModel):
    """An Industrial Control System asset mapped to Purdue hierarchy."""
    asset_id: str
    name: str
    ip_address: str
    purdue_level: PurdueLevel
    protocol: ICSProtocol
    vendor: str  # Siemens, Schneider Electric, Rockwell Automation, Honeywell
    model: str
    is_safety_system: bool = False  # Safety Instrumented System (SIS) - Crown Jewel
    firmware_version: str = "1.0.4"
    monitored_registers: Dict[str, Dict[str, float]] = Field(default_factory=dict)  # "reg_40001": {"min": 0, "max": 100}


class ModbusTelemetry(BaseModel):
    """Captured Modbus TCP frame telemetry."""
    transaction_id: int
    unit_id: int
    function_code: int
    function_name: str
    src_ip: str
    dst_ip: str
    register_address: Optional[int] = None
    register_value: Optional[float] = None
    timestamp: datetime = Field(default_factory=datetime.utcnow)


class S7CommTelemetry(BaseModel):
    """Captured Siemens S7comm control protocol frame."""
    pdu_type: int
    function_code: int
    function_name: str  # e.g., "PLC_STOP", "READ_VAR", "WRITE_VAR", "UPLOAD"
    src_ip: str
    dst_ip: str
    db_number: Optional[int] = None
    timestamp: datetime = Field(default_factory=datetime.utcnow)


class ICSAlert(BaseModel):
    """Alert for industrial process anomalies and physical safety threats."""
    alert_id: str
    timestamp: datetime = Field(default_factory=datetime.utcnow)
    protocol: ICSProtocol
    anomaly_type: ICSAnomalyType
    severity: ICSSeverity
    target_asset_id: str
    target_asset_name: str
    src_ip: str
    dst_ip: str
    title: str
    description: str
    mitre_attack_ics_id: str  # e.g., T0855 (Unauthorized Command Message), T0816 (Device Restart/Shutdown)
    safety_impact: str
    remediation_steps: List[str] = Field(default_factory=list)
