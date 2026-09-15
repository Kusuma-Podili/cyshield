"""Deep Modbus TCP / SCADA Industrial Protocol Dissector (Modbus-IDA Specification).

Dissects MBAP headers, Modbus PDUs, function codes, coils, holding registers,
and detects unauthorized PLC stop/reprogram commands, industrial sabotage, and OT reconnaissance.
"""

from __future__ import annotations

import struct
from typing import Any, Dict, List, Optional

from cybershield.protocols.schemas import (
    ProtocolType,
    DecodedPacket,
    ProtocolAnomaly,
    AnomalySeverity,
)

MODBUS_FUNCTIONS: Dict[int, str] = {
    0x01: "Read Coils",
    0x02: "Read Discrete Inputs",
    0x03: "Read Holding Registers",
    0x04: "Read Input Registers",
    0x05: "Write Single Coil",
    0x06: "Write Single Register",
    0x07: "Read Exception Status",
    0x08: "Diagnostics",
    0x0B: "Get Comm Event Counter",
    0x0C: "Get Comm Event Log",
    0x0F: "Write Multiple Coils",
    0x10: "Write Multiple Registers",
    0x11: "Report Server ID",
    0x14: "Read File Record",
    0x15: "Write File Record",
    0x16: "Mask Write Register",
    0x17: "Read/Write Multiple Registers",
    0x2B: "Encapsulated Interface (Device ID)",
    0x5A: "Vendor Specific PLC Firmware / Execution",
}


class ModbusDecoder:
    """Dissects binary Modbus TCP packets for operational technology (OT) monitoring."""

    @classmethod
    def decode(
        cls,
        raw_bytes: bytes,
        src_ip: str = "172.16.10.50",
        dst_ip: str = "172.16.10.1",
        src_port: int = 40500,
        dst_port: int = 502,
    ) -> DecodedPacket:
        """Dissect Modbus Application Protocol (MBAP) header and Function Codes."""
        anomalies: List[ProtocolAnomaly] = []
        headers: Dict[str, Any] = {}
        payload: Dict[str, Any] = {}

        if len(raw_bytes) < 8:
            return DecodedPacket(
                protocol=ProtocolType.MODBUS,
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=src_port,
                dst_port=dst_port,
                raw_length_bytes=len(raw_bytes),
                headers={"error": "Malformed Modbus: Less than 8 bytes for MBAP + FC"},
                is_suspicious=True,
            )

        # MBAP Header: Transaction ID (2B), Protocol ID (2B, 0=Modbus), Length (2B), Unit ID (1B)
        tx_id, proto_id, pdu_len, unit_id = struct.unpack("!HHHB", raw_bytes[:7])
        function_code = raw_bytes[7]

        fn_name = MODBUS_FUNCTIONS.get(function_code, f"CUSTOM_0x{function_code:02x}")

        headers.update({
            "transaction_id": hex(tx_id),
            "protocol_id": proto_id,
            "pdu_length": pdu_len,
            "unit_id": unit_id,
            "function_code": function_code,
            "function_name": fn_name,
        })

        data_payload = raw_bytes[8:]

        # --- SCADA / ICS Threat Heuristics ---

        # 1. Non-standard Modbus Protocol ID
        if proto_id != 0:
            anomalies.append(
                ProtocolAnomaly(
                    rule_id="MODBUS-PROTO-ID-001",
                    severity=AnomalySeverity.HIGH,
                    title="Invalid Modbus Protocol Identifier",
                    description=f"MBAP Protocol ID is {proto_id} (standard Modbus requires 0). Possible tunneling or protocol fuzzing.",
                    mitre_technique="T0855",
                )
            )

        # 2. Critical PLC Firmware / Vendor Specific Execution (e.g. Schneider UMAS 0x5A)
        if function_code in (0x5A, 0x5B, 0x15):
            anomalies.append(
                ProtocolAnomaly(
                    rule_id="MODBUS-PLC-PROGRAM-001",
                    severity=AnomalySeverity.CRITICAL,
                    title="PLC Firmware / Ladder Logic Modification Attempt",
                    description=(
                        f"Modbus function code 0x{function_code:02x} ({fn_name}) detected. "
                        "Used for PLC logic reprogram, memory manipulation, or firmware uploads."
                    ),
                    mitre_technique="T0843",
                    mitigation="Verify engineering change order and enforce hardware-level key-switch protection on PLC.",
                )
            )

        # 3. Device Identification Reconnaissance (Function 0x11 or 0x2B)
        if function_code in (0x11, 0x2B):
            anomalies.append(
                ProtocolAnomaly(
                    rule_id="MODBUS-RECON-001",
                    severity=AnomalySeverity.MEDIUM,
                    title="OT Asset Device Fingerprinting & Discovery",
                    description=f"Modbus function {fn_name} requested PLC vendor model, firmware version, and device identification strings.",
                    mitre_technique="T0846",
                )
            )

        # 4. Dangerous Coil Override (Function 0x05 or 0x0F)
        if function_code in (0x05, 0x0F) and len(data_payload) >= 4:
            coil_addr, coil_val = struct.unpack("!HH", data_payload[:4])
            payload["coil_address"] = coil_addr
            payload["coil_value"] = hex(coil_val)

            # 0xFF00 = Force ON, 0x0000 = Force OFF
            if coil_val == 0xFF00:
                anomalies.append(
                    ProtocolAnomaly(
                        rule_id="MODBUS-COIL-FORCE-001",
                        severity=AnomalySeverity.HIGH,
                        title="Unauthorized Actuator Force ON Command",
                        description=f"Direct command forcing coil address {coil_addr} to ON state (0xFF00) from IP {src_ip}.",
                        mitre_technique="T0855",
                    )
                )

        return DecodedPacket(
            protocol=ProtocolType.MODBUS,
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=dst_port,
            raw_length_bytes=len(raw_bytes),
            headers=headers,
            payload_fields=payload,
            is_suspicious=len(anomalies) > 0,
            anomalies=anomalies,
        )
