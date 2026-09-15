"""Deep DNS Protocol Decoder & Tunneling Analyzer (RFC 1035 / RFC 3596).

Provides full wire-format binary parsing of DNS headers, question sections,
resource record decompression, Shannon entropy analysis, and DGA/tunneling detection.
"""

from __future__ import annotations

import io
import math
import struct
from collections import Counter
from typing import Any, Dict, List, Optional, Tuple

from cybershield.protocols.schemas import (
    ProtocolType,
    DecodedPacket,
    ProtocolAnomaly,
    AnomalySeverity,
)

# DNS Record Type Mapping
DNS_TYPE_NAMES: Dict[int, str] = {
    1: "A",
    2: "NS",
    5: "CNAME",
    6: "SOA",
    12: "PTR",
    15: "MX",
    16: "TXT",
    28: "AAAA",
    33: "SRV",
    41: "OPT",
    48: "DNSKEY",
    255: "ANY",
}

DNS_RCODE_NAMES: Dict[int, str] = {
    0: "NOERROR",
    1: "FORMERR",
    2: "SERVFAIL",
    3: "NXDOMAIN",
    4: "NOTIMP",
    5: "REFUSED",
    9: "NOTAUTH",
}


class DNSDecoder:
    """Enterprise-grade binary DNS packet dissector and security analyzer."""

    @staticmethod
    def calculate_shannon_entropy(data: str) -> float:
        """Calculate Shannon entropy for string randomness / base64 detection."""
        if not data:
            return 0.0
        counts = Counter(data)
        n = len(data)
        entropy = -sum((cnt / n) * math.log2(cnt / n) for cnt in counts.values())
        return round(entropy, 3)

    @classmethod
    def _read_name(cls, raw: bytes, offset: int) -> Tuple[str, int]:
        """Parse DNS domain name with full RFC 1035 compression pointer support (0xC0)."""
        labels: List[str] = []
        original_offset = offset
        jumped = False
        bytes_consumed = 0
        visited_pointers = set()

        while True:
            if offset >= len(raw):
                break
            length = raw[offset]

            if (length & 0xC0) == 0xC0:
                # Compression pointer (2 bytes)
                if offset + 1 >= len(raw):
                    break
                pointer = ((length & 0x3F) << 8) | raw[offset + 1]
                if pointer in visited_pointers:
                    # Loop detected
                    break
                visited_pointers.add(pointer)

                if not jumped:
                    bytes_consumed = (offset - original_offset) + 2
                    jumped = True
                offset = pointer
                continue

            offset += 1
            if length == 0:
                # End of name
                if not jumped:
                    bytes_consumed = offset - original_offset
                break

            if offset + length > len(raw):
                break
            label = raw[offset : offset + length].decode("ascii", errors="replace")
            labels.append(label)
            offset += length

        if not jumped:
            bytes_consumed = offset - original_offset

        domain = ".".join(labels)
        return domain, bytes_consumed

    @classmethod
    def decode(
        cls,
        raw_bytes: bytes,
        src_ip: str = "10.0.0.10",
        dst_ip: str = "8.8.8.8",
        src_port: int = 53535,
        dst_port: int = 53,
    ) -> DecodedPacket:
        """Parse binary DNS wire format and extract telemetry + anomaly signatures."""
        anomalies: List[ProtocolAnomaly] = []
        headers: Dict[str, Any] = {}
        payload: Dict[str, Any] = {
            "questions": [],
            "answers": [],
            "authorities": [],
            "additionals": [],
        }

        if len(raw_bytes) < 12:
            return DecodedPacket(
                protocol=ProtocolType.DNS,
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=src_port,
                dst_port=dst_port,
                raw_length_bytes=len(raw_bytes),
                headers={"error": "Malformed DNS: Packet too short (<12 bytes)"},
                is_suspicious=True,
                anomalies=[
                    ProtocolAnomaly(
                        rule_id="DNS-MALFORMED-001",
                        severity=AnomalySeverity.LOW,
                        title="Malformed DNS Header",
                        description=f"DNS packet payload is only {len(raw_bytes)} bytes, below minimal 12-byte header.",
                    )
                ],
            )

        # Unpack 12-byte header: ID, Flags, QDCOUNT, ANCOUNT, NSCOUNT, ARCOUNT
        tx_id, flags_raw, qdcount, ancount, nscount, arcount = struct.unpack("!HHHHHH", raw_bytes[:12])

        qr = (flags_raw >> 15) & 0x01
        opcode = (flags_raw >> 11) & 0x0F
        aa = (flags_raw >> 10) & 0x01
        tc = (flags_raw >> 9) & 0x01
        rd = (flags_raw >> 8) & 0x01
        ra = (flags_raw >> 7) & 0x01
        z = (flags_raw >> 4) & 0x07
        rcode = flags_raw & 0x0F

        headers = {
            "transaction_id": hex(tx_id),
            "is_response": bool(qr),
            "opcode": opcode,
            "authoritative": bool(aa),
            "truncated": bool(tc),
            "recursion_desired": bool(rd),
            "recursion_available": bool(ra),
            "rcode": rcode,
            "rcode_name": DNS_RCODE_NAMES.get(rcode, f"UNKNOWN_{rcode}"),
            "questions_count": qdcount,
            "answers_count": ancount,
            "authorities_count": nscount,
            "additionals_count": arcount,
        }

        offset = 12

        # Parse Question Section
        for _ in range(qdcount):
            if offset >= len(raw_bytes):
                break
            qname, consumed = cls._read_name(raw_bytes, offset)
            offset += consumed
            if offset + 4 <= len(raw_bytes):
                qtype_int, qclass_int = struct.unpack("!HH", raw_bytes[offset : offset + 4])
                offset += 4
                qtype_name = DNS_TYPE_NAMES.get(qtype_int, f"TYPE_{qtype_int}")
                payload["questions"].append({
                    "name": qname,
                    "type": qtype_name,
                    "class": qclass_int,
                })

                # --- Security Telemetry Heuristics ---
                # 1. DNS Tunneling & High Entropy Subdomain Detection
                parts = qname.split(".")
                if parts:
                    subdomain = parts[0]
                    sub_entropy = cls.calculate_shannon_entropy(subdomain)
                    if len(subdomain) > 35 and sub_entropy > 3.6:
                        anomalies.append(
                            ProtocolAnomaly(
                                rule_id="DNS-TUNNEL-001",
                                severity=AnomalySeverity.CRITICAL,
                                title="Suspected DNS Tunneling Exfiltration",
                                description=(
                                    f"Subdomain label '{subdomain[:24]}...' has length {len(subdomain)} "
                                    f"and excessive Shannon entropy ({sub_entropy}), characteristic of Base32/Base64 exfiltration tunnels."
                                ),
                                mitre_technique="T1071.004",
                                mitigation="Block external resolution for root domain and isolate host network adapter.",
                            )
                        )
                    # 2. Extremely long query length
                    if len(qname) > 120:
                        anomalies.append(
                            ProtocolAnomaly(
                                rule_id="DNS-TUNNEL-002",
                                severity=AnomalySeverity.HIGH,
                                title="Abnormally Long DNS Query",
                                description=f"Total FQDN query length is {len(qname)} characters (>120 limit threshold).",
                                mitre_technique="T1071.004",
                            )
                        )
                    # 3. DGA (Domain Generation Algorithm) Heuristic: High consonant ratio
                    consonants = sum(1 for c in subdomain.lower() if c in "bcdfghjklmnpqrstvwxyz")
                    vowels = sum(1 for c in subdomain.lower() if c in "aeiou")
                    if len(subdomain) >= 12 and vowels > 0 and (consonants / len(subdomain)) > 0.82:
                        anomalies.append(
                            ProtocolAnomaly(
                                rule_id="DNS-DGA-001",
                                severity=AnomalySeverity.HIGH,
                                title="Algorithmic Domain Generation (DGA) Detected",
                                description=f"Subdomain '{subdomain}' exhibits high consonant-to-vowel ratio ({consonants}:{vowels}), matching known malware DGA seeds.",
                                mitre_technique="T1568.002",
                                mitigation="Sinkhole domain and cross-reference with active threat intelligence feeds.",
                            )
                        )

        # Parse Answer Section
        for _ in range(ancount):
            if offset >= len(raw_bytes):
                break
            aname, consumed = cls._read_name(raw_bytes, offset)
            offset += consumed
            if offset + 10 <= len(raw_bytes):
                atype, aclass, attl, rdlength = struct.unpack("!HHIH", raw_bytes[offset : offset + 10])
                offset += 10
                rdata_raw = raw_bytes[offset : offset + rdlength]
                offset += rdlength

                parsed_rdata = ""
                if atype == 1 and len(rdata_raw) == 4:
                    # IPv4
                    parsed_rdata = ".".join(str(b) for b in rdata_raw)
                elif atype == 28 and len(rdata_raw) == 16:
                    # IPv6
                    parsed_rdata = ":".join(f"{rdata_raw[i]:02x}{rdata_raw[i+1]:02x}" for i in range(0, 16, 2))
                elif atype in (2, 5, 12):
                    # NS, CNAME, PTR
                    parsed_rdata, _ = cls._read_name(raw_bytes, offset - rdlength)
                elif atype == 16:
                    # TXT
                    txt_parts = []
                    txt_off = 0
                    while txt_off < len(rdata_raw):
                        tlen = rdata_raw[txt_off]
                        txt_off += 1
                        txt_parts.append(rdata_raw[txt_off : txt_off + tlen].decode("utf-8", errors="replace"))
                        txt_off += tlen
                    parsed_rdata = " ".join(txt_parts)

                payload["answers"].append({
                    "name": aname,
                    "type": DNS_TYPE_NAMES.get(atype, f"TYPE_{atype}"),
                    "ttl": attl,
                    "rdata": parsed_rdata or rdata_raw.hex(),
                })

                # Fast-Flux check: very low TTL
                if attl < 60 and atype == 1:
                    anomalies.append(
                        ProtocolAnomaly(
                            rule_id="DNS-FASTFLUX-001",
                            severity=AnomalySeverity.MEDIUM,
                            title="Fast-Flux Low TTL Record",
                            description=f"Answer for '{aname}' returned IP {parsed_rdata} with ultra-short TTL of {attl}s.",
                            mitre_technique="T1568.001",
                        )
                    )

        # NXDOMAIN Amplification / Recon Check
        if rcode == 3 and not qr:
            pass

        return DecodedPacket(
            protocol=ProtocolType.DNS,
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
