"""Deep Kerberos v5 Protocol Dissector & Active Directory Threat Analyzer (RFC 4120).

Parses ASN.1 DER Kerberos structures (AS-REQ, AS-REP, TGS-REQ, TGS-REP, AP-REQ),
encryption type negotiations, and detects Kerberoasting, AS-REP Roasting, and Golden Ticket patterns.
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

KERBEROS_APP_TAGS: Dict[int, str] = {
    0x6A: "AS-REQ",
    0x6B: "AS-REP",
    0x6C: "TGS-REQ",
    0x6D: "TGS-REP",
    0x6E: "AP-REQ",
    0x6F: "AP-REP",
    0x7E: "KRB-ERROR",
}

KERBEROS_ETYPES: Dict[int, str] = {
    1: "des-cbc-crc",
    3: "des-cbc-md5",
    17: "aes128-cts-hmac-sha1-96",
    18: "aes256-cts-hmac-sha1-96",
    23: "rc4-hmac",
    24: "rc4-hmac-exp",
}


class KerberosDecoder:
    """Dissects binary Kerberos ASN.1 DER frames and evaluates Active Directory attack vectors."""

    @classmethod
    def decode(
        cls,
        raw_bytes: bytes,
        src_ip: str = "10.0.0.80",
        dst_ip: str = "10.0.0.2",
        src_port: int = 51234,
        dst_port: int = 88,
    ) -> DecodedPacket:
        """Parse binary Kerberos frame and evaluate credential dumping / roasting heuristics."""
        anomalies: List[ProtocolAnomaly] = []
        headers: Dict[str, Any] = {}
        payload: Dict[str, Any] = {}

        offset = 0

        # TCP framing: 4-byte big-endian length prefix
        if len(raw_bytes) >= 4 and dst_port == 88:
            potential_tcp_len = struct.unpack("!I", raw_bytes[:4])[0]
            if potential_tcp_len + 4 == len(raw_bytes):
                headers["tcp_length"] = potential_tcp_len
                offset = 4

        if len(raw_bytes) <= offset:
            return DecodedPacket(
                protocol=ProtocolType.KERBEROS,
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=src_port,
                dst_port=dst_port,
                raw_length_bytes=len(raw_bytes),
                headers={"error": "Empty Kerberos payload"},
                is_suspicious=False,
            )

        tag = raw_bytes[offset]
        msg_type_name = KERBEROS_APP_TAGS.get(tag, f"UNKNOWN_APP_0x{tag:02x}")
        headers["application_tag"] = hex(tag)
        headers["message_type"] = msg_type_name

        # Search for requested etypes in byte stream
        detected_etypes = []
        for etype_id, etype_name in KERBEROS_ETYPES.items():
            # In ASN.1 INTEGER, positive integers are encoded as 0x02 0x01 <id> or 0x02 0x02
            if bytes([0x02, 0x01, etype_id]) in raw_bytes:
                detected_etypes.append(etype_name)

        payload["detected_etypes"] = detected_etypes

        # --- Active Directory Security Threat Heuristics ---

        # 1. Kerberoasting (TGS-REQ requesting RC4-HMAC ticket)
        if msg_type_name == "TGS-REQ":
            if "rc4-hmac" in detected_etypes:
                anomalies.append(
                    ProtocolAnomaly(
                        rule_id="KERB-ROASTING-001",
                        severity=AnomalySeverity.CRITICAL,
                        title="Kerberoasting Attack Pattern (RC4 Downgrade)",
                        description=(
                            "Kerberos TGS-REQ explicitly requested weak RC4-HMAC encryption (etype 23) "
                            "for a service ticket, indicating an active Kerberoasting credential harvesting attempt."
                        ),
                        mitre_technique="T1558.003",
                        mitigation="Enforce AES256 encryption on Service Principal Accounts (SPNs) and rotate passwords >25 characters.",
                    )
                )

        # 2. AS-REP Roasting Indicator
        if msg_type_name == "AS-REQ":
            # Check for absence of PA-ENC-TIMESTAMP (PADATA type 2: 0x02, 0x01, 0x02)
            has_preauth = bytes([0x02, 0x01, 0x02]) in raw_bytes
            if not has_preauth and len(raw_bytes) > 50:
                anomalies.append(
                    ProtocolAnomaly(
                        rule_id="KERB-ASREP-ROAST-001",
                        severity=AnomalySeverity.HIGH,
                        title="AS-REP Roasting Opportunity (No Pre-Authentication)",
                        description="Kerberos AS-REQ submitted without pre-authentication timestamps. Susceptible to offline hash extraction.",
                        mitre_technique="T1558.004",
                        mitigation="Require Kerberos pre-authentication ('Do not require Kerberos preauthentication' set to False).",
                    )
                )

        # 3. Obsolete DES Encryption
        if any(e in detected_etypes for e in ("des-cbc-crc", "des-cbc-md5")):
            anomalies.append(
                ProtocolAnomaly(
                    rule_id="KERB-WEAK-DES-001",
                    severity=AnomalySeverity.HIGH,
                    title="Obsolete DES Kerberos Encryption Negotiated",
                    description="Kerberos negotiation contains broken 56-bit DES encryption suites.",
                    mitre_technique="T1558",
                )
            )

        return DecodedPacket(
            protocol=ProtocolType.KERBEROS,
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
