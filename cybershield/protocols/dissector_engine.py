"""Central Network Protocol Dissector & Threat Classification Engine.

Automatically routes incoming network telemetry and raw packets to specialized
binary dissectors based on port mappings and deep packet inspection (DPI) magic-byte heuristics.
"""

from __future__ import annotations

import base64
import binascii
import time
from collections import defaultdict
from typing import Any, Dict, List, Optional, Tuple

from cybershield.protocols.schemas import (
    ProtocolType,
    DecodedPacket,
    ProtocolDissectionResult,
    DissectionRequest,
    BatchDissectionRequest,
    BatchDissectionResponse,
    ProtocolStatsResponse,
)
from cybershield.protocols.dns_decoder import DNSDecoder
from cybershield.protocols.http2_decoder import HTTPDecoder
from cybershield.protocols.tls_decoder import TLSDecoder
from cybershield.protocols.smb_decoder import SMBDecoder
from cybershield.protocols.kerberos_decoder import KerberosDecoder
from cybershield.protocols.rdp_decoder import RDPDecoder
from cybershield.protocols.modbus_decoder import ModbusDecoder
from cybershield.protocols.dnp3_decoder import DNP3Decoder
from cybershield.protocols.bacnet_decoder import BACnetDecoder
from cybershield.protocols.mqtt_decoder import MQTTDecoder


class ProtocolDissectorEngine:
    """Enterprise multi-protocol DPI and security dissector engine."""

    # Operational Telemetry Accumulators
    _total_dissected: int = 0
    _protocol_counts: Dict[str, int] = defaultdict(int)
    _anomalies_detected: int = 0
    _recent_anomalies: List[Dict[str, Any]] = []

    @classmethod
    def identify_protocol(
        cls,
        raw_bytes: bytes,
        src_port: int = 0,
        dst_port: int = 0,
        hint: Optional[ProtocolType] = None,
    ) -> ProtocolType:
        """DPI heuristic protocol classifier combining transport ports and payload signatures."""
        if hint and hint != ProtocolType.UNKNOWN:
            return hint

        ports = {src_port, dst_port}

        # 1. Signature-based magic byte checks
        if raw_bytes.startswith(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"):
            return ProtocolType.HTTP2
        if raw_bytes.startswith(b"\x05\x64"):
            return ProtocolType.DNP3
        if raw_bytes.startswith(b"\x81") and 47808 in ports:
            return ProtocolType.BACNET
        if raw_bytes.startswith(b"\xffSMB") or raw_bytes.startswith(b"\xfeSMB"):
            return ProtocolType.SMB
        if len(raw_bytes) >= 4 and raw_bytes[0] == 0x00 and raw_bytes[4:8] in (b"\xffSMB", b"\xfeSMB"):
            return ProtocolType.SMB
        if len(raw_bytes) >= 3 and raw_bytes[0] == 0x16 and raw_bytes[1] == 0x03:
            return ProtocolType.TLS
        if len(raw_bytes) >= 4 and raw_bytes[0] == 0x03 and raw_bytes[1] == 0x00:
            return ProtocolType.RDP

        # Check HTTP/1.x Textual Verbs
        for verb in (b"GET ", b"POST ", b"PUT ", b"DELETE ", b"HEAD ", b"OPTIONS ", b"HTTP/1."):
            if raw_bytes.startswith(verb):
                return ProtocolType.HTTP1

        # Check Kerberos Application Tags
        if raw_bytes and raw_bytes[0] in (0x6A, 0x6B, 0x6C, 0x6D, 0x6E, 0x6F, 0x7E):
            return ProtocolType.KERBEROS

        # 2. Port-based fallback routing
        if 53 in ports:
            return ProtocolType.DNS
        if 80 in ports or 8080 in ports:
            return ProtocolType.HTTP1
        if 443 in ports or 8443 in ports:
            return ProtocolType.TLS
        if 445 in ports or 139 in ports:
            return ProtocolType.SMB
        if 88 in ports:
            return ProtocolType.KERBEROS
        if 3389 in ports:
            return ProtocolType.RDP
        if 502 in ports:
            return ProtocolType.MODBUS
        if 20000 in ports:
            return ProtocolType.DNP3
        if 47808 in ports:
            return ProtocolType.BACNET
        if 1883 in ports or 8883 in ports:
            return ProtocolType.MQTT

        return ProtocolType.UNKNOWN

    @classmethod
    def _parse_payload_bytes(cls, req: DissectionRequest) -> bytes:
        """Convert input hex, base64, or text payload into raw bytes."""
        if req.payload_hex:
            clean_hex = "".join(req.payload_hex.split())
            return binascii.unhexlify(clean_hex)
        elif req.payload_base64:
            return base64.b64decode(req.payload_base64)
        elif req.payload_text:
            return req.payload_text.encode("utf-8")
        return b""

    @classmethod
    def dissect_packet(cls, req: DissectionRequest) -> ProtocolDissectionResult:
        """Execute high-precision protocol dissection against a network packet payload."""
        t0 = time.perf_counter()

        try:
            raw_bytes = cls._parse_payload_bytes(req)
        except Exception as e:
            return ProtocolDissectionResult(
                success=False,
                protocol=ProtocolType.UNKNOWN,
                raw_length_bytes=0,
                decoded_packet=DecodedPacket(
                    protocol=ProtocolType.UNKNOWN,
                    headers={"error": f"Failed to decode payload bytes: {str(e)}"},
                ),
                error_message=str(e),
                execution_time_ms=round((time.perf_counter() - t0) * 1000.0, 3),
            )

        proto = cls.identify_protocol(
            raw_bytes,
            src_port=req.src_port,
            dst_port=req.dst_port,
            hint=req.protocol_hint,
        )

        decoded: DecodedPacket

        try:
            if proto == ProtocolType.DNS:
                decoded = DNSDecoder.decode(raw_bytes, req.src_ip, req.dst_ip, req.src_port, req.dst_port)
            elif proto == ProtocolType.HTTP1:
                # Textual decoder
                text_content = req.payload_text or raw_bytes.decode("utf-8", errors="replace")
                decoded = HTTPDecoder.decode_text_http1(text_content, req.src_ip, req.dst_ip, req.src_port, req.dst_port)
            elif proto == ProtocolType.HTTP2:
                decoded = HTTPDecoder.decode_binary_http2(raw_bytes, req.src_ip, req.dst_ip, req.src_port, req.dst_port)
            elif proto == ProtocolType.TLS:
                decoded = TLSDecoder.decode_client_hello(raw_bytes, req.src_ip, req.dst_ip, req.src_port, req.dst_port)
            elif proto == ProtocolType.SMB:
                decoded = SMBDecoder.decode(raw_bytes, req.src_ip, req.dst_ip, req.src_port, req.dst_port)
            elif proto == ProtocolType.KERBEROS:
                decoded = KerberosDecoder.decode(raw_bytes, req.src_ip, req.dst_ip, req.src_port, req.dst_port)
            elif proto == ProtocolType.RDP:
                decoded = RDPDecoder.decode(raw_bytes, req.src_ip, req.dst_ip, req.src_port, req.dst_port)
            elif proto == ProtocolType.MODBUS:
                decoded = ModbusDecoder.decode(raw_bytes, req.src_ip, req.dst_ip, req.src_port, req.dst_port)
            elif proto == ProtocolType.DNP3:
                decoded = DNP3Decoder.decode(raw_bytes, req.src_ip, req.dst_ip, req.src_port, req.dst_port)
            elif proto == ProtocolType.BACNET:
                decoded = BACnetDecoder.decode(raw_bytes, req.src_ip, req.dst_ip, req.src_port, req.dst_port)
            elif proto == ProtocolType.MQTT:
                decoded = MQTTDecoder.decode(raw_bytes, req.src_ip, req.dst_ip, req.src_port, req.dst_port)
            else:
                decoded = DecodedPacket(
                    protocol=ProtocolType.UNKNOWN,
                    src_ip=req.src_ip,
                    dst_ip=req.dst_ip,
                    src_port=req.src_port,
                    dst_port=req.dst_port,
                    raw_length_bytes=len(raw_bytes),
                    headers={"info": "Unrecognized protocol stream"},
                    payload_fields={"raw_hex_preview": raw_bytes[:64].hex()},
                )
        except Exception as ex:
            decoded = DecodedPacket(
                protocol=proto,
                src_ip=req.src_ip,
                dst_ip=req.dst_ip,
                src_port=req.src_port,
                dst_port=req.dst_port,
                raw_length_bytes=len(raw_bytes),
                headers={"error": f"Dissector exception: {str(ex)}"},
                is_suspicious=True,
            )

        duration_ms = round((time.perf_counter() - t0) * 1000.0, 3)

        # Update Telemetry Metrics
        cls._total_dissected += 1
        cls._protocol_counts[proto.value] += 1
        anom_cnt = len(decoded.anomalies)
        if anom_cnt > 0:
            cls._anomalies_detected += anom_cnt
            for a in decoded.anomalies:
                cls._recent_anomalies.append({
                    "rule_id": a.rule_id,
                    "severity": a.severity.value,
                    "title": a.title,
                    "protocol": proto.value,
                    "src_ip": req.src_ip,
                    "dst_ip": req.dst_ip,
                    "mitre_technique": a.mitre_technique,
                })
            # Trim telemetry history
            if len(cls._recent_anomalies) > 100:
                cls._recent_anomalies = cls._recent_anomalies[-100:]

        return ProtocolDissectionResult(
            success=True,
            protocol=proto,
            raw_length_bytes=len(raw_bytes),
            decoded_packet=decoded,
            anomalies_count=anom_cnt,
            execution_time_ms=duration_ms,
        )

    @classmethod
    def dissect_batch(cls, batch: BatchDissectionRequest) -> BatchDissectionResponse:
        """Dissect multiple network packets concurrently."""
        results = [cls.dissect_packet(p) for p in batch.packets]
        total_anoms = sum(r.anomalies_count for r in results)
        return BatchDissectionResponse(
            total_processed=len(results),
            anomalies_detected=total_anoms,
            results=results,
        )

    @classmethod
    def get_stats(cls) -> ProtocolStatsResponse:
        """Return operational DPI statistics and threat breakdown."""
        return ProtocolStatsResponse(
            total_dissected=cls._total_dissected,
            protocols_active=dict(cls._protocol_counts),
            anomalies_detected=cls._anomalies_detected,
            top_anomalies=cls._recent_anomalies[-10:],
        )
