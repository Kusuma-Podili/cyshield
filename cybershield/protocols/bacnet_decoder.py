"""Deep BACnet/IP (Building Automation & Control Networks / ASHRAE 135) Dissector.

Dissects BVLC, NPDU, and APDU layers, BACnet services, and detects
HVAC shutdown, facility physical security disruption, and building automation sabotage.
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

BVLC_FUNCTIONS: Dict[int, str] = {
    0x00: "BVLC-Result",
    0x01: "Write-BDT",
    0x02: "Read-BDT",
    0x04: "Forwarded-NPDU",
    0x09: "Original-Broadcast-NPDU",
    0x0A: "Original-Unicast-NPDU",
}

BACNET_APDU_TYPES: Dict[int, str] = {
    0: "Confirmed-Request",
    1: "Unconfirmed-Request",
    2: "Simple-ACK",
    3: "Complex-ACK",
    4: "Segment-ACK",
    5: "Error",
    6: "Reject",
    7: "Abort",
}

BACNET_SERVICES: Dict[int, str] = {
    0x0C: "ReadProperty",
    0x0E: "ReadPropertyMultiple",
    0x0F: "WriteProperty",
    0x10: "WritePropertyMultiple",
    0x14: "DeviceCommunicationControl",
    0x1A: "ReinitializeDevice",
    0x08: "Who-Is",
    0x00: "I-Am",
}


class BACnetDecoder:
    """Dissects binary BACnet/IP frames for smart building and facility security monitoring."""

    @classmethod
    def decode(
        cls,
        raw_bytes: bytes,
        src_ip: str = "192.168.20.15",
        dst_ip: str = "192.168.20.255",
        src_port: int = 47808,
        dst_port: int = 47808,
    ) -> DecodedPacket:
        """Dissect BACnet Virtual Link Control (BVLC) and application services."""
        anomalies: List[ProtocolAnomaly] = []
        headers: Dict[str, Any] = {}
        payload: Dict[str, Any] = {}

        if len(raw_bytes) < 4:
            return DecodedPacket(
                protocol=ProtocolType.BACNET,
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=src_port,
                dst_port=dst_port,
                raw_length_bytes=len(raw_bytes),
                headers={"error": "BACnet packet too short (<4 bytes)"},
                is_suspicious=True,
            )

        # BVLC Header (4 bytes): Type (0x81), Function (1B), Length (2B)
        bvlc_type, bvlc_fn, bvlc_len = struct.unpack("!BBH", raw_bytes[:4])

        if bvlc_type != 0x81:
            return DecodedPacket(
                protocol=ProtocolType.BACNET,
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=src_port,
                dst_port=dst_port,
                raw_length_bytes=len(raw_bytes),
                headers={"error": f"Invalid BACnet/IP BVLC magic: 0x{bvlc_type:02x}"},
                is_suspicious=True,
            )

        fn_name = BVLC_FUNCTIONS.get(bvlc_fn, f"CUSTOM_0x{bvlc_fn:02x}")
        headers.update({
            "bvlc_type": "BACnet/IP (0x81)",
            "bvlc_function": fn_name,
            "bvlc_length": bvlc_len,
        })

        offset = 4
        if bvlc_fn == 0x04:  # Forwarded-NPDU contains 6-byte originating IP/Port
            offset += 6

        # NPDU (Network Protocol Data Unit)
        if len(raw_bytes) >= offset + 2:
            npdu_ver = raw_bytes[offset]
            npdu_ctrl = raw_bytes[offset + 1]
            headers["npdu_version"] = npdu_ver
            headers["npdu_control"] = hex(npdu_ctrl)
            offset += 2

            # Check DNET / SNET presence in control byte
            if npdu_ctrl & 0x20:  # Destination specifier
                offset += 5  # DNET (2B), DLEN (1B), DADR
            if npdu_ctrl & 0x08:  # Source specifier
                offset += 5

            # APDU (Application Protocol Data Unit)
            if len(raw_bytes) > offset:
                apdu_byte0 = raw_bytes[offset]
                apdu_type = (apdu_byte0 >> 4) & 0x0F
                apdu_name = BACNET_APDU_TYPES.get(apdu_type, f"TYPE_{apdu_type}")
                headers["apdu_type"] = apdu_name

                service_choice = None
                if apdu_type == 0 and len(raw_bytes) >= offset + 4:  # Confirmed-Request
                    # Byte 1: Max Segs/Max Resp, Byte 2: Invoke ID, Byte 3: Service Choice
                    service_choice = raw_bytes[offset + 3]
                elif apdu_type == 1 and len(raw_bytes) >= offset + 2:  # Unconfirmed-Request
                    service_choice = raw_bytes[offset + 1]

                if service_choice is not None:
                    svc_name = BACNET_SERVICES.get(service_choice, f"SERVICE_0x{service_choice:02x}")
                    headers["service_choice"] = svc_name
                    headers["service_code"] = service_choice

                    # --- Smart Facility / Physical Infrastructure Threat Heuristics ---

                    # 1. Device Communication Control (Silence Controllers)
                    if service_choice == 0x14:
                        anomalies.append(
                            ProtocolAnomaly(
                                rule_id="BACNET-COMM-DISABLE-001",
                                severity=AnomalySeverity.CRITICAL,
                                title="Building Controller Silence Command (DeviceCommControl)",
                                description=(
                                    f"BACnet service 0x14 (DeviceCommunicationControl) sent to facility controller. "
                                    "Disables communication, isolating HVAC, fire safety, or power monitors."
                                ),
                                mitre_technique="T0815",
                                mitigation="Block external BACnet traffic and verify physical building management credentials.",
                            )
                        )

                    # 2. Reinitialize Device (Reboot Facility Hardware)
                    if service_choice == 0x1A:
                        anomalies.append(
                            ProtocolAnomaly(
                                rule_id="BACNET-REBOOT-001",
                                severity=AnomalySeverity.CRITICAL,
                                title="Unauthorized Facility Controller Reboot / Reinitialize",
                                description="BACnet ReinitializeDevice (0x1A) service requested cold reboot of building controller.",
                                mitre_technique="T0814",
                                mitigation="Investigate IP immediately and review physical facility operations.",
                            )
                        )

                    # 3. Write Property Multiple to Actuators
                    if service_choice in (0x0F, 0x10):
                        payload["write_target"] = "Actuator / Setpoint Parameter Modification"

        return DecodedPacket(
            protocol=ProtocolType.BACNET,
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
