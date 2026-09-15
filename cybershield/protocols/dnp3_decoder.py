"""Deep DNP3 (Distributed Network Protocol 3 / IEEE 1815) Utility SCADA Dissector.

Dissects DNP3 Data Link, Transport, and Application layers, Function Codes,
and detects Industroyer/CrashOverride electrical grid sabotage, RTU cold restart, and breaker trip commands.
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

DNP3_FUNCTION_NAMES: Dict[int, str] = {
    0x00: "CONFIRM",
    0x01: "READ",
    0x02: "WRITE",
    0x03: "SELECT",
    0x04: "OPERATE",
    0x05: "DIRECT_OPERATE",
    0x06: "DIRECT_OPERATE_NO_ACK",
    0x07: "IMMEDIATE_FREEZE",
    0x08: "IMMEDIATE_FREEZE_NO_ACK",
    0x09: "FREEZE_CLEAR",
    0x0A: "FREEZE_CLEAR_NO_ACK",
    0x0B: "FREEZE_AT_TIME",
    0x0C: "FREEZE_AT_TIME_NO_ACK",
    0x0D: "COLD_RESTART",
    0x0E: "WARM_RESTART",
    0x0F: "INITIALIZE_DATA",
    0x10: "INITIALIZE_APPLICATION",
    0x11: "START_APPLICATION",
    0x12: "STOP_APPLICATION",
    0x13: "SAVE_CONFIGURATION",
    0x14: "ENABLE_UNSOLICITED",
    0x15: "DISABLE_UNSOLICITED",
    0x16: "ASSIGN_CLASS",
    0x17: "DELAY_MEASURE",
    0x81: "RESPONSE",
    0x82: "UNSOLICITED_RESPONSE",
}


class DNP3Decoder:
    """Dissects DNP3 electric utility and water management protocol packets."""

    @classmethod
    def decode(
        cls,
        raw_bytes: bytes,
        src_ip: str = "10.20.30.100",
        dst_ip: str = "10.20.30.1",
        src_port: int = 45100,
        dst_port: int = 20000,
    ) -> DecodedPacket:
        """Dissect IEEE 1815 DNP3 wire-format frames."""
        anomalies: List[ProtocolAnomaly] = []
        headers: Dict[str, Any] = {}
        payload: Dict[str, Any] = {}

        if len(raw_bytes) < 10:
            return DecodedPacket(
                protocol=ProtocolType.DNP3,
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=src_port,
                dst_port=dst_port,
                raw_length_bytes=len(raw_bytes),
                headers={"error": "DNP3 packet too short (<10 bytes)"},
                is_suspicious=True,
            )

        # 1. Data Link Layer (10 bytes): Start (2B: 0x05 0x64), Length (1B), Control (1B), Dest (2B), Source (2B), CRC (2B)
        start_magic = raw_bytes[:2]
        if start_magic != b"\x05\x64":
            return DecodedPacket(
                protocol=ProtocolType.DNP3,
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=src_port,
                dst_port=dst_port,
                raw_length_bytes=len(raw_bytes),
                headers={"error": f"Invalid DNP3 sync bytes: {start_magic.hex()}"},
                is_suspicious=True,
            )

        dl_len, dl_ctrl, dst_addr, src_addr, dl_crc = struct.unpack("<BBHHH", raw_bytes[2:10])

        headers.update({
            "sync": "0x0564",
            "length": dl_len,
            "control": hex(dl_ctrl),
            "dest_address": dst_addr,
            "src_address": src_addr,
            "crc": hex(dl_crc),
        })

        # Parse Transport and Application Layers (after 10-byte data link header)
        if len(raw_bytes) >= 12:
            tr_ctrl = raw_bytes[10]
            headers["transport_control"] = hex(tr_ctrl)

            app_ctrl = raw_bytes[11]
            headers["app_control"] = hex(app_ctrl)

            if len(raw_bytes) >= 13:
                app_fn = raw_bytes[12]
                fn_name = DNP3_FUNCTION_NAMES.get(app_fn, f"CUSTOM_0x{app_fn:02x}")
                headers["application_function"] = fn_name
                headers["function_code"] = app_fn

                # --- Electrical Grid / SCADA Sabotage Heuristics ---

                # 1. Cold Restart of Substation RTU (Function 0x0D)
                if app_fn == 0x0D:
                    anomalies.append(
                        ProtocolAnomaly(
                            rule_id="DNP3-COLD-RESTART-001",
                            severity=AnomalySeverity.CRITICAL,
                            title="Substation RTU Cold Restart Command Dispatched",
                            description=(
                                f"DNP3 Cold Restart (0x0D) command dispatched to RTU address {dst_addr}. "
                                "Forces remote terminal unit shutdown, potentially dropping grid telemetry."
                            ),
                            mitre_technique="T0814",
                            mitigation="Verify dispatch authority from Energy Management System (EMS) control center.",
                        )
                    )

                # 2. Disable Unsolicited Responses (Function 0x15 - Industroyer / CrashOverride signature)
                if app_fn == 0x15:
                    anomalies.append(
                        ProtocolAnomaly(
                            rule_id="DNP3-DISABLE-UNSOLICITED-001",
                            severity=AnomalySeverity.CRITICAL,
                            title="DNP3 Disable Unsolicited Telemetry (Industroyer Pattern)",
                            description=(
                                "Command 0x15 (Disable Unsolicited) sent to RTU. Blinds grid operators "
                                "from autonomous change-of-state notifications during an attack."
                            ),
                            mitre_technique="T0815",
                            mitigation="Investigate source IP immediately and verify RTU event reporting status.",
                        )
                    )

                # 3. Direct Operate breaker open/close without Select (Function 0x05 or 0x06)
                if app_fn in (0x05, 0x06):
                    anomalies.append(
                        ProtocolAnomaly(
                            rule_id="DNP3-DIRECT-OPERATE-001",
                            severity=AnomalySeverity.HIGH,
                            title="Direct Operate Actuator Command (Bypassed SBO)",
                            description=f"Direct Operate function {fn_name} dispatched without Select-Before-Operate confirmation sequence.",
                            mitre_technique="T0855",
                        )
                    )

                # 4. Broadcast Address Destination (0xFFFF)
                if dst_addr == 0xFFFF:
                    anomalies.append(
                        ProtocolAnomaly(
                            rule_id="DNP3-BROADCAST-WRITE-001",
                            severity=AnomalySeverity.HIGH,
                            title="DNP3 Substation Broadcast Command",
                            description="DNP3 command directed to global broadcast address 0xFFFF targeting all field devices.",
                            mitre_technique="T0846",
                        )
                    )

        return DecodedPacket(
            protocol=ProtocolType.DNP3,
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
