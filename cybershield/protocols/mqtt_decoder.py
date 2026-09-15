"""Deep MQTT (Message Queuing Telemetry Transport / ISO/IEC 20922) IoT Dissector.

Dissects MQTT Fixed Header, Variable Header, and Payload for IoT & Industrial gateways.
Detects anonymous broker access, wildcard reconnaissance subscriptions (#, +), and unauthorized command injection.
"""

from __future__ import annotations

import struct
from typing import Any, Dict, List, Optional, Tuple

from cybershield.protocols.schemas import (
    ProtocolType,
    DecodedPacket,
    ProtocolAnomaly,
    AnomalySeverity,
)

MQTT_CONTROL_PACKETS: Dict[int, str] = {
    1: "CONNECT",
    2: "CONNACK",
    3: "PUBLISH",
    4: "PUBACK",
    5: "PUBREC",
    6: "PUBREL",
    7: "PUBCOMP",
    8: "SUBSCRIBE",
    9: "SUBACK",
    10: "UNSUBSCRIBE",
    11: "UNSUBACK",
    12: "PINGREQ",
    13: "PINGRESP",
    14: "DISCONNECT",
    15: "AUTH",
}


class MQTTDecoder:
    """Dissects binary MQTT packets for IoT and SCADA perimeter defense."""

    @staticmethod
    def _read_remaining_length(raw: bytes, offset: int) -> Tuple[int, int]:
        """Decode MQTT variable-byte remaining length field (1-4 bytes)."""
        multiplier = 1
        value = 0
        consumed = 0
        while offset < len(raw) and consumed < 4:
            encoded_byte = raw[offset]
            offset += 1
            consumed += 1
            value += (encoded_byte & 0x7F) * multiplier
            multiplier *= 128
            if (encoded_byte & 0x80) == 0:
                break
        return value, consumed

    @staticmethod
    def _read_utf8_string(raw: bytes, offset: int) -> Tuple[str, int]:
        """Read 2-byte length-prefixed UTF-8 string."""
        if offset + 2 > len(raw):
            return "", 0
        str_len = struct.unpack("!H", raw[offset : offset + 2])[0]
        offset += 2
        if offset + str_len > len(raw):
            return "", 2
        s = raw[offset : offset + str_len].decode("utf-8", errors="replace")
        return s, 2 + str_len

    @classmethod
    def decode(
        cls,
        raw_bytes: bytes,
        src_ip: str = "10.0.50.22",
        dst_ip: str = "10.0.50.1",
        src_port: int = 59001,
        dst_port: int = 1883,
    ) -> DecodedPacket:
        """Dissect binary MQTT stream."""
        anomalies: List[ProtocolAnomaly] = []
        headers: Dict[str, Any] = {}
        payload: Dict[str, Any] = {}

        if len(raw_bytes) < 2:
            return DecodedPacket(
                protocol=ProtocolType.MQTT,
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=src_port,
                dst_port=dst_port,
                raw_length_bytes=len(raw_bytes),
                headers={"error": "Malformed MQTT: Under 2 bytes"},
                is_suspicious=True,
            )

        # Byte 1: Packet Type (4b), DUP (1b), QoS (2b), RETAIN (1b)
        byte0 = raw_bytes[0]
        packet_type = (byte0 >> 4) & 0x0F
        dup = bool((byte0 >> 3) & 0x01)
        qos = (byte0 >> 1) & 0x03
        retain = bool(byte0 & 0x01)

        pkt_name = MQTT_CONTROL_PACKETS.get(packet_type, f"TYPE_{packet_type}")
        rem_len, len_consumed = cls._read_remaining_length(raw_bytes, 1)
        offset = 1 + len_consumed

        headers.update({
            "packet_type": pkt_name,
            "packet_type_id": packet_type,
            "qos": qos,
            "dup": dup,
            "retain": retain,
            "remaining_length": rem_len,
        })

        # Parse CONNECT Packet
        if packet_type == 1 and len(raw_bytes) > offset + 6:
            proto_name, p_consumed = cls._read_utf8_string(raw_bytes, offset)
            offset += p_consumed
            if offset + 4 <= len(raw_bytes):
                proto_level = raw_bytes[offset]
                connect_flags = raw_bytes[offset + 1]
                keep_alive = struct.unpack("!H", raw_bytes[offset + 2 : offset + 4])[0]
                offset += 4

                has_username = bool(connect_flags & 0x80)
                has_password = bool(connect_flags & 0x40)
                has_will = bool(connect_flags & 0x04)
                clean_session = bool(connect_flags & 0x02)

                headers.update({
                    "protocol_name": proto_name,
                    "protocol_level": proto_level,
                    "keep_alive_seconds": keep_alive,
                    "clean_session": clean_session,
                    "has_username": has_username,
                    "has_password": has_password,
                })

                # Client ID
                client_id, c_consumed = cls._read_utf8_string(raw_bytes, offset)
                offset += c_consumed
                payload["client_id"] = client_id

                # Threat Heuristic: Anonymous Connection
                if not has_username and not has_password:
                    anomalies.append(
                        ProtocolAnomaly(
                            rule_id="MQTT-ANON-CONNECT-001",
                            severity=AnomalySeverity.MEDIUM,
                            title="Unauthenticated Anonymous MQTT Session",
                            description=f"Client '{client_id or 'anonymous'}' established an unauthenticated MQTT broker connection without username/password flags.",
                            mitre_technique="T1078.001",
                            mitigation="Enforce mandatory client certificate (mTLS) or TLS username/token authentication on port 8883.",
                        )
                    )

        # Parse SUBSCRIBE Packet
        elif packet_type == 8 and len(raw_bytes) > offset + 2:
            packet_id = struct.unpack("!H", raw_bytes[offset : offset + 2])[0]
            offset += 2
            topics = []
            while offset < len(raw_bytes):
                topic_filter, t_consumed = cls._read_utf8_string(raw_bytes, offset)
                if not topic_filter:
                    break
                offset += t_consumed
                req_qos = raw_bytes[offset] if offset < len(raw_bytes) else 0
                offset += 1
                topics.append({"topic": topic_filter, "requested_qos": req_qos})

            payload["subscribed_topics"] = topics

            # Threat Heuristic: Wildcard Eavesdropping
            for t in topics:
                tf = t["topic"]
                if tf in ("#", "+", "factory/#", "telemetry/#", "sensor/#"):
                    anomalies.append(
                        ProtocolAnomaly(
                            rule_id="MQTT-WILDCARD-RECON-001",
                            severity=AnomalySeverity.HIGH,
                            title="MQTT Root Wildcard Subscription (Eavesdropping)",
                            description=f"Subscription filter '{tf}' captures all sub-topic traffic across the broker, indicating automated data harvesting.",
                            mitre_technique="T1040",
                            mitigation="Configure topic-level Access Control Lists (ACLs) to restrict wildcard subscription permissions.",
                        )
                    )

        # Parse PUBLISH Packet
        elif packet_type == 3 and len(raw_bytes) > offset + 2:
            topic, t_consumed = cls._read_utf8_string(raw_bytes, offset)
            offset += t_consumed
            if qos > 0 and offset + 2 <= len(raw_bytes):
                pkt_id = struct.unpack("!H", raw_bytes[offset : offset + 2])[0]
                offset += 2
                payload["packet_id"] = pkt_id

            msg_bytes = raw_bytes[offset:]
            msg_snippet = msg_bytes[:200].decode("utf-8", errors="replace")
            payload["topic"] = topic
            payload["message_snippet"] = msg_snippet
            payload["message_length"] = len(msg_bytes)

            # Threat Heuristic: Critical Control Topic Injection
            if any(crit in topic.lower() for crit in ("reboot", "firmware", "kill", "override", "actuator/force")):
                anomalies.append(
                    ProtocolAnomaly(
                        rule_id="MQTT-COMMAND-INJECT-001",
                        severity=AnomalySeverity.CRITICAL,
                        title="Critical IoT Command Topic Publication",
                        description=f"Publish event targeted critical operational topic '{topic}' with message payload: '{msg_snippet[:64]}'.",
                        mitre_technique="T0855",
                    )
                )

        return DecodedPacket(
            protocol=ProtocolType.MQTT,
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
