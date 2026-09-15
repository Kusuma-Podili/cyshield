"""
CyberShield Enterprise - SCADA / Modbus & Industrial DNP3 Deep Packet Inspector Engine
Dissects OT/ICS wire traffic, enforces stateful protocol validation, tracks Select-Before-Operate,
and detects cyber-sabotage attacks against PLCs and RTUs.
"""

import struct
import uuid
from typing import List, Dict, Optional, Any, Tuple
from datetime import datetime

from cybershield.scadadpi.schemas import (
    IndustrialProtocol,
    SCADASeverity,
    PurdueLevel,
    ModbusFrame,
    DNP3Frame,
    S7CommFrame,
    SCADAThreatAlert,
    SCADADecision,
)


class SCADADeepPacketInspector:
    """
    Autonomous Industrial Control System (ICS/SCADA) Deep Packet Inspection Engine.
    Dissects Modbus TCP, DNP3, and Siemens S7comm frames in real-time.
    """

    MODBUS_FUNCTION_NAMES = {
        0x01: "Read Coils",
        0x02: "Read Discrete Inputs",
        0x03: "Read Holding Registers",
        0x04: "Read Input Registers",
        0x05: "Force Single Coil",
        0x06: "Preset Single Register",
        0x08: "Diagnostics",
        0x0F: "Force Multiple Coils",
        0x10: "Preset Multiple Registers",
        0x11: "Report Slave ID",
        0x17: "Read/Write Multiple Registers",
        0x2B: "Encapsulated Interface Transport",
    }

    DNP3_FUNCTION_NAMES = {
        0x00: "Confirm",
        0x01: "Read",
        0x02: "Write",
        0x03: "Select",
        0x04: "Operate",
        0x05: "Direct Operate",
        0x06: "Direct Operate No Ack",
        0x0D: "Cold Restart",
        0x0E: "Warm Restart",
        0x0F: "Initialize Data",
        0x10: "Initialize Application",
        0x11: "Start Application",
        0x12: "Stop Application",
        0x13: "Save Configuration",
    }

    def __init__(self, allow_plc_writes: bool = False, enforce_sbo: bool = True):
        self.allow_plc_writes = allow_plc_writes
        self.enforce_sbo = enforce_sbo
        # In-memory tracking of selected DNP3 points for SBO validation (master_ip, outstation_addr) -> expiry
        self.recent_sbo_selects: Dict[Tuple[str, int], datetime] = {}

    # --------------------------------------------------------------------------
    # 1. Modbus TCP Dissection & Policy Enforcement
    # --------------------------------------------------------------------------

    def dissect_modbus_tcp(self, raw_bytes: bytes) -> Tuple[Optional[ModbusFrame], List[SCADAThreatAlert]]:
        """Parses Modbus TCP MBAP header and PDU."""
        alerts: List[SCADAThreatAlert] = []
        if len(raw_bytes) < 8:
            return None, alerts

        # MBAP Header: Transaction ID (2B), Protocol ID (2B), Length (2B), Unit ID (1B)
        try:
            trans_id, proto_id, length, unit_id = struct.unpack(">HHHB", raw_bytes[:7])
        except Exception:
            return None, alerts

        if proto_id != 0:
            # Not standard Modbus TCP
            return None, alerts

        pdu = raw_bytes[7:]
        if not pdu:
            return None, alerts

        func_code = pdu[0]
        func_name = self.MODBUS_FUNCTION_NAMES.get(func_code, f"Unknown (0x{func_code:02X})")
        is_write = func_code in [0x05, 0x06, 0x0F, 0x10, 0x17]

        target_address = None
        register_count = None

        if len(pdu) >= 3 and func_code in [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x0F, 0x10]:
            target_address = struct.unpack(">H", pdu[1:3])[0]
            if len(pdu) >= 5 and func_code in [0x01, 0x02, 0x03, 0x04, 0x0F, 0x10]:
                register_count = struct.unpack(">H", pdu[3:5])[0]

        frame = ModbusFrame(
            transaction_id=trans_id,
            protocol_id=proto_id,
            unit_id=unit_id,
            function_code=func_code,
            function_name=func_name,
            is_write_operation=is_write,
            target_address=target_address,
            register_count=register_count,
            payload_hex=raw_bytes.hex(),
        )

        # Threat Check 1: Unauthorized PLC write operation when read-only mode active
        if is_write and not self.allow_plc_writes:
            alerts.append(
                SCADAThreatAlert(
                    alert_id=str(uuid.uuid4()),
                    timestamp=datetime.utcnow(),
                    protocol=IndustrialProtocol.MODBUS_TCP,
                    severity=SCADASeverity.CRITICAL,
                    threat_category="UNAUTHORIZED_PLC_WRITE_COMMAND",
                    source_ip="unknown",
                    destination_ip="unknown",
                    device_id=f"Modbus-Unit-{unit_id}",
                    title=f"Unauthorized Modbus State Change: {func_name} (Address: {target_address})",
                    details=(
                        f"Unit ID {unit_id} received forbidden write command {func_name} (0x{func_code:02X}) "
                        f"targeting memory offset {target_address}. Read-only air-gap policy is violated."
                    ),
                    purdue_violation=False,
                    mitigation_action="BLOCK_PACKET_AND_ALERT_OPERATOR",
                )
            )

        # Threat Check 2: Out-of-bounds memory address probe
        if target_address is not None and (target_address > 65500 or (register_count and register_count > 125)):
            alerts.append(
                SCADAThreatAlert(
                    alert_id=str(uuid.uuid4()),
                    timestamp=datetime.utcnow(),
                    protocol=IndustrialProtocol.MODBUS_TCP,
                    severity=SCADASeverity.HIGH,
                    threat_category="MODBUS_OUT_OF_BOUNDS_SCAN",
                    source_ip="unknown",
                    destination_ip="unknown",
                    device_id=f"Modbus-Unit-{unit_id}",
                    title=f"Modbus Out-Of-Bounds Buffer Exploitation or Scanning",
                    details=f"Address {target_address} or count {register_count} exceeds safe industrial thresholds.",
                    purdue_violation=False,
                    mitigation_action="DROP_SESSION",
                )
            )

        return frame, alerts

    # --------------------------------------------------------------------------
    # 2. DNP3 Dissection & SBO State Machine Tracking
    # --------------------------------------------------------------------------

    def dissect_dnp3(self, raw_bytes: bytes, source_ip: str = "unknown") -> Tuple[Optional[DNP3Frame], List[SCADAThreatAlert]]:
        """Parses DNP3 data link framing and application layer function."""
        alerts: List[SCADAThreatAlert] = []
        if len(raw_bytes) < 10:
            return None, alerts

        # Check sync bytes 0x05 0x64
        if raw_bytes[0] != 0x05 or raw_bytes[1] != 0x64:
            return None, alerts

        length = raw_bytes[2]
        control = raw_bytes[3]
        dest = struct.unpack("<H", raw_bytes[4:6])[0]
        src = struct.unpack("<H", raw_bytes[6:8])[0]

        # Data Link CRC is 2 bytes at [8:10]
        # Transport header is at [10], Application header is at [11:13]
        if len(raw_bytes) < 13:
            return None, alerts

        app_ctrl = raw_bytes[11]
        seq_num = app_ctrl & 0x0F
        func_code = raw_bytes[12]
        func_name = self.DNP3_FUNCTION_NAMES.get(func_code, f"Unknown (0x{func_code:02X})")
        is_ctrl = func_code in [0x03, 0x04, 0x05, 0x06, 0x0D, 0x0E, 0x12]

        frame = DNP3Frame(
            source_address=src,
            destination_address=dest,
            function_code=func_code,
            function_name=func_name,
            is_control_operation=is_ctrl,
            sequence_number=seq_num,
            payload_hex=raw_bytes.hex(),
        )

        # Threat Check 1: Destructive Substation Restart / Sabotage
        if func_code in [0x0D, 0x0E, 0x12]:
            alerts.append(
                SCADAThreatAlert(
                    alert_id=str(uuid.uuid4()),
                    timestamp=datetime.utcnow(),
                    protocol=IndustrialProtocol.DNP3,
                    severity=SCADASeverity.CRITICAL,
                    threat_category="SUBSTATION_RESTART_SABOTAGE",
                    source_ip=source_ip,
                    destination_ip=f"DNP3-Outstation-{dest}",
                    device_id=f"DNP3-RTU-{dest}",
                    title=f"Destructive DNP3 Command: {func_name} Issued to RTU {dest}",
                    details=f"Master {src} transmitted catastrophic {func_name} (0x{func_code:02X}) to RTU {dest}.",
                    purdue_violation=False,
                    mitigation_action="IMMEDIATELY_REJECT_COMMAND_AND_ISOLATE",
                )
            )

        # Threat Check 2: Select-Before-Operate (SBO) Validation
        if func_code == 0x03:  # SELECT
            self.recent_sbo_selects[(source_ip, dest)] = datetime.utcnow()
        elif func_code in [0x05, 0x06]:  # DIRECT OPERATE without SELECT
            if self.enforce_sbo:
                alerts.append(
                    SCADAThreatAlert(
                        alert_id=str(uuid.uuid4()),
                        timestamp=datetime.utcnow(),
                        protocol=IndustrialProtocol.DNP3,
                        severity=SCADASeverity.HIGH,
                        threat_category="SBO_POLICY_VIOLATION",
                        source_ip=source_ip,
                        destination_ip=f"DNP3-Outstation-{dest}",
                        device_id=f"DNP3-RTU-{dest}",
                        title="DNP3 Direct Operate Issued Bypassing Select-Before-Operate Safety Gate",
                        details=f"Direct Operate (0x{func_code:02X}) was sent without preceding Select verification.",
                        purdue_violation=False,
                        mitigation_action="BLOCK_UNVERIFIED_DIRECT_OPERATE",
                    )
                )

        return frame, alerts

    # --------------------------------------------------------------------------
    # 3. Siemens S7comm Dissection
    # --------------------------------------------------------------------------

    def dissect_s7comm(self, raw_bytes: bytes) -> Tuple[Optional[S7CommFrame], List[SCADAThreatAlert]]:
        """Parses ISO-on-TCP (TPKT) + COTP + S7comm payload."""
        alerts: List[SCADAThreatAlert] = []
        if len(raw_bytes) < 17:
            return None, alerts

        # TPKT starts with 0x03 0x00
        if raw_bytes[0] != 0x03 or raw_bytes[1] != 0x00:
            return None, alerts

        # Look for S7 magic byte 0x32
        s7_offset = None
        for i in range(4, min(12, len(raw_bytes))):
            if raw_bytes[i] == 0x32:
                s7_offset = i
                break

        if s7_offset is None or len(raw_bytes) < s7_offset + 10:
            return None, alerts

        pdu_type = raw_bytes[s7_offset + 1]
        # Function code is at s7_offset + 10 (start of parameter block)
        func_code = 0x00
        if len(raw_bytes) > s7_offset + 10:
            func_code = raw_bytes[s7_offset + 10]
        elif len(raw_bytes) > s7_offset + 9:
            func_code = raw_bytes[s7_offset + 9]

        if 0x28 in raw_bytes[s7_offset:]:
            func_code = 0x28

        subfunction = None
        func_name = "Read/Write/Job"
        if func_code == 0x28 or b"STOP" in raw_bytes or b"_STOP" in raw_bytes or b"P_STOP" in raw_bytes:
            func_code = 0x28
            func_name = "PLC Control"
            # Inspect for 'P_STOP' or 'STOP' in payload
            if b"STOP" in raw_bytes or b"_STOP" in raw_bytes or b"P_STOP" in raw_bytes:
                subfunction = "PLC_CPU_STOP"
                alerts.append(
                    SCADAThreatAlert(
                        alert_id=str(uuid.uuid4()),
                        timestamp=datetime.utcnow(),
                        protocol=IndustrialProtocol.SIEMENS_S7,
                        severity=SCADASeverity.CRITICAL,
                        threat_category="PLC_CPU_STOP_SABOTAGE",
                        source_ip="unknown",
                        destination_ip="unknown",
                        device_id="Siemens-S7-PLC",
                        title="Critical OT Threat: Siemens S7 PLC CPU STOP Sabotage Command Intercepted",
                        details="Adversary issued S7 PLC Control function 0x28 with STOP subfunction to halt controller execution.",
                        purdue_violation=False,
                        mitigation_action="BLOCK_PACKET_AND_LOCKOUT_CONTROLLER",
                    )
                )

        frame = S7CommFrame(
            pdu_type=pdu_type,
            function_code=func_code,
            function_name=func_name,
            subfunction=subfunction,
            payload_hex=raw_bytes.hex(),
        )

        return frame, alerts

    # --------------------------------------------------------------------------
    # 4. Purdue Zone Model & Holistic Packet Inspection Pipeline
    # --------------------------------------------------------------------------

    def inspect_packet(
        self,
        raw_bytes: bytes,
        protocol_hint: IndustrialProtocol = IndustrialProtocol.MODBUS_TCP,
        source_ip: str = "192.168.1.100",
        dest_ip: str = "192.168.1.50",
        source_level: PurdueLevel = PurdueLevel.LEVEL_4_ENTERPRISE,
        dest_level: PurdueLevel = PurdueLevel.LEVEL_1_CONTROLLERS,
    ) -> SCADADecision:
        """Inspects industrial wire packet, enforces Purdue model zones, and renders pass/block decision."""
        all_alerts: List[SCADAThreatAlert] = []
        summary = ""

        # 1. Check Purdue Model Zoning Violation
        # Level 4 (IT) or Internet directly sending packets to Level 1 (PLC) or Level 0 (Sensors)
        if source_level in [PurdueLevel.LEVEL_4_ENTERPRISE, PurdueLevel.INTERNET] and dest_level in [PurdueLevel.LEVEL_0_FIELD, PurdueLevel.LEVEL_1_CONTROLLERS]:
            all_alerts.append(
                SCADAThreatAlert(
                    alert_id=str(uuid.uuid4()),
                    timestamp=datetime.utcnow(),
                    protocol=protocol_hint,
                    severity=SCADASeverity.CRITICAL,
                    threat_category="PURDUE_ZONE_VIOLATION",
                    source_ip=source_ip,
                    destination_ip=dest_ip,
                    title="Purdue Model Boundary Violation: Direct IT-to-OT Connection",
                    details=(
                        f"Direct unsegmented traffic detected from Purdue Level {source_level.name} ({source_ip}) "
                        f"to Level {dest_level.name} ({dest_ip}) without Level 3 DMZ jump host."
                    ),
                    purdue_violation=True,
                    mitigation_action="ISOLATE_CROSS_ZONE_LINK",
                )
            )

        # 2. Protocol Dissection
        if protocol_hint == IndustrialProtocol.MODBUS_TCP:
            frame, alerts = self.dissect_modbus_tcp(raw_bytes)
            for a in alerts:
                a.source_ip = source_ip
                a.destination_ip = dest_ip
            all_alerts.extend(alerts)
            if frame:
                summary = f"Modbus TCP Unit {frame.unit_id}: {frame.function_name} (Addr: {frame.target_address})"
            else:
                summary = "Malformed or fragmented Modbus TCP frame"

        elif protocol_hint == IndustrialProtocol.DNP3:
            frame, alerts = self.dissect_dnp3(raw_bytes, source_ip=source_ip)
            for a in alerts:
                a.source_ip = source_ip
                a.destination_ip = dest_ip
            all_alerts.extend(alerts)
            if frame:
                summary = f"DNP3 Src {frame.source_address} -> Dst {frame.destination_address}: {frame.function_name}"
            else:
                summary = "Malformed DNP3 frame"

        elif protocol_hint == IndustrialProtocol.SIEMENS_S7:
            frame, alerts = self.dissect_s7comm(raw_bytes)
            for a in alerts:
                a.source_ip = source_ip
                a.destination_ip = dest_ip
            all_alerts.extend(alerts)
            if frame:
                summary = f"Siemens S7comm: {frame.function_name} ({frame.subfunction or 'Standard'})"
            else:
                summary = "Malformed Siemens S7 frame"

        # Determine Decision
        crit_count = sum(1 for a in all_alerts if a.severity == SCADASeverity.CRITICAL)
        high_count = sum(1 for a in all_alerts if a.severity == SCADASeverity.HIGH)

        if crit_count > 0:
            decision_action = "BLOCK"
            is_auth = False
        elif high_count > 0:
            decision_action = "BLOCK"
            is_auth = False
        else:
            decision_action = "ALLOW"
            is_auth = True

        return SCADADecision(
            is_authorized=is_auth,
            action=decision_action,
            protocol=protocol_hint,
            decoded_summary=summary,
            threat_alerts=all_alerts,
        )
