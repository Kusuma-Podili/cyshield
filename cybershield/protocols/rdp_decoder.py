"""Deep RDP (Remote Desktop Protocol) Dissector & BlueKeep Threat Analyzer (MS-RDPBCGR).

Parses binary TPKT, X.224 Connection Requests, RDP Negotiation Requests,
and detects Insecure RDP (No NLA), BlueKeep (CVE-2019-0708), and CredSSP bypasses.
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

X224_PDU_NAMES: Dict[int, str] = {
    0xE0: "Connection Request (CR)",
    0xD0: "Connection Confirm (CC)",
    0xF0: "Data (DT)",
    0x80: "Disconnect Request (DR)",
    0x70: "Error (ER)",
}

RDP_SECURITY_PROTOCOLS: Dict[int, str] = {
    0x00000000: "PROTOCOL_RDP (Legacy Insecure)",
    0x00000001: "PROTOCOL_SSL (TLS Encryption)",
    0x00000002: "PROTOCOL_HYBRID (NLA CredSSP)",
    0x00000004: "PROTOCOL_RDSTLS",
    0x00000008: "PROTOCOL_HYBRID_EX",
}


class RDPDecoder:
    """Dissects binary RDP wire-format connection sequences."""

    @classmethod
    def decode(
        cls,
        raw_bytes: bytes,
        src_ip: str = "192.168.1.120",
        dst_ip: str = "192.168.1.10",
        src_port: int = 50123,
        dst_port: int = 3389,
    ) -> DecodedPacket:
        """Dissect TPKT and X.224 RDP connection requests."""
        anomalies: List[ProtocolAnomaly] = []
        headers: Dict[str, Any] = {}
        payload: Dict[str, Any] = {}

        if len(raw_bytes) < 4:
            return DecodedPacket(
                protocol=ProtocolType.RDP,
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=src_port,
                dst_port=dst_port,
                raw_length_bytes=len(raw_bytes),
                headers={"error": "Malformed RDP: Less than 4 bytes"},
                is_suspicious=True,
            )

        # 1. TPKT Header (4 bytes): Version (1B), Reserved (1B), Length (2B)
        tpkt_ver, tpkt_res, tpkt_len = struct.unpack("!BBH", raw_bytes[:4])
        headers["tpkt_version"] = tpkt_ver
        headers["tpkt_length"] = tpkt_len

        offset = 4

        # 2. X.224 Header
        if len(raw_bytes) >= offset + 3:
            x224_len = raw_bytes[offset]
            x224_type = raw_bytes[offset + 1]
            pdu_name = X224_PDU_NAMES.get(x224_type, f"PDU_0x{x224_type:02x}")
            headers["x224_type"] = pdu_name
            offset += 2

            # Inspect Connection Request
            if x224_type == 0xE0 and len(raw_bytes) > offset + 5:
                # Cookie / Routing token check (e.g. "Cookie: mstshash=user\r\n")
                cookie_str = None
                cookie_idx = raw_bytes.find(b"Cookie: mstshash=", offset)
                if cookie_idx != -1:
                    c_end = raw_bytes.find(b"\r\n", cookie_idx)
                    if c_end != -1:
                        cookie_str = raw_bytes[cookie_idx:c_end].decode("ascii", errors="replace")
                        payload["routing_cookie"] = cookie_str

                # RDP Negotiation Request: Type (0x01), Flags, Length (8), requestedProtocols (4B)
                neg_idx = raw_bytes.find(b"\x01\x00\x08\x00", offset)
                if neg_idx != -1 and len(raw_bytes) >= neg_idx + 8:
                    req_proto = struct.unpack("<I", raw_bytes[neg_idx + 4 : neg_idx + 8])[0]
                    proto_name = RDP_SECURITY_PROTOCOLS.get(req_proto, f"CUSTOM_0x{req_proto:08x}")
                    headers["requested_security_protocol"] = proto_name
                    headers["security_protocol_flags"] = hex(req_proto)

                    # Security Anomaly: Legacy insecure RDP without NLA
                    if req_proto == 0x00000000:
                        anomalies.append(
                            ProtocolAnomaly(
                                rule_id="RDP-NO-NLA-001",
                                severity=AnomalySeverity.HIGH,
                                title="Insecure RDP Connection (NLA Disabled)",
                                description="Client requested legacy standard RDP encryption without Network Level Authentication (NLA) or TLS.",
                                mitre_technique="T1021.001",
                                mitigation="Enforce 'Require Network Level Authentication for remote connections' in Windows Group Policy.",
                            )
                        )

                # BlueKeep Exploit Heuristic (CVE-2019-0708)
                # Exploits bind to MS_T120 static virtual channel before authentication
                if b"MS_T120" in raw_bytes and req_proto == 0:
                    anomalies.append(
                        ProtocolAnomaly(
                            rule_id="RDP-BLUEKEEP-001",
                            severity=AnomalySeverity.CRITICAL,
                            title="Potential BlueKeep Exploitation Attempt (CVE-2019-0708)",
                            description="RDP connection request combined legacy security with virtual channel binding for MS_T120, signature of BlueKeep exploit kits.",
                            mitre_technique="T1210",
                            mitigation="Immediately block external 3389 access and verify MS Security Update for CVE-2019-0708.",
                        )
                    )

        return DecodedPacket(
            protocol=ProtocolType.RDP,
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
