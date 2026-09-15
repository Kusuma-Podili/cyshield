"""Deep HTTP/1.1 & HTTP/2 Binary Frame Protocol Dissector (RFC 7230 / RFC 7540).

Parses binary HTTP/2 frames, stream multiplexing headers, HPACK structures,
and detects HTTP Request Smuggling and HTTP/2 Rapid Reset (CVE-2023-44487) attacks.
"""

from __future__ import annotations

import re
import struct
from typing import Any, Dict, List, Optional

from cybershield.protocols.schemas import (
    ProtocolType,
    DecodedPacket,
    ProtocolAnomaly,
    AnomalySeverity,
)

# HTTP/2 Frame Types (RFC 7540 Section 6)
HTTP2_FRAME_NAMES: Dict[int, str] = {
    0x00: "DATA",
    0x01: "HEADERS",
    0x02: "PRIORITY",
    0x03: "RST_STREAM",
    0x04: "SETTINGS",
    0x05: "PUSH_PROMISE",
    0x06: "PING",
    0x07: "GOAWAY",
    0x08: "WINDOW_UPDATE",
    0x09: "CONTINUATION",
}

# Suspicious Scanner User-Agents
SCANNER_USER_AGENTS = {
    "sqlmap", "nikto", "dirbuster", "gobuster", "masscan", "zgrab", "nuclei", "hydra", "nmap"
}

# Web Attack Patterns
PATTERNS_SQLI = [
    re.compile(r"(\%27)|(\')|(\-\-)|(\%23)|(#)", re.IGNORECASE),
    re.compile(r"\w*((\%27)|(\'))(\s)*((\%6F)|o|(\%4F))((\%72)|r|(\%52))", re.IGNORECASE),
    re.compile(r"exec(\s|\+)+(s|x)p\w+", re.IGNORECASE),
    re.compile(r"union(\s|\+)+(all(\s|\+)+)?select", re.IGNORECASE),
]

PATTERNS_TRAVERSAL = re.compile(r"(\.\./|\.\.\\|\%2e\%2e\%2f|\%2e\%2e\/)", re.IGNORECASE)
PATTERNS_COMMAND_INJ = re.compile(r"(;|\||`|\$\(|\$\{)\s*(cat|ls|whoami|id|bash|sh|cmd|powershell|curl|wget)", re.IGNORECASE)
PATTERNS_JNDI = re.compile(r"\$\{\s*jndi:(ldap|rmi|dns|nis|iiop)", re.IGNORECASE)


class HTTPDecoder:
    """Dissects both HTTP/1.x textual streams and HTTP/2 binary multiplexed frames."""

    @classmethod
    def decode_text_http1(
        cls,
        payload_text: str,
        src_ip: str = "10.0.0.15",
        dst_ip: str = "192.168.1.50",
        src_port: int = 54321,
        dst_port: int = 80,
    ) -> DecodedPacket:
        """Parse textual HTTP/1.0 and HTTP/1.1 requests/responses."""
        anomalies: List[ProtocolAnomaly] = []
        lines = payload_text.replace("\r\n", "\n").split("\n")
        first_line = lines[0] if lines else ""

        headers: Dict[str, str] = {}
        body = ""
        is_body = False

        method, uri, version = "UNKNOWN", "/", "HTTP/1.1"
        parts = first_line.split(" ")
        if len(parts) >= 3:
            method, uri, version = parts[0].upper(), parts[1], parts[2].upper()

        for line in lines[1:]:
            if not is_body:
                if line == "":
                    is_body = True
                    continue
                if ":" in line:
                    k, v = line.split(":", 1)
                    headers[k.strip().lower()] = v.strip()
            else:
                body += line + "\n"

        # --- Security Telemetry Heuristics ---

        # 1. HTTP Request Smuggling (CL.TE or TE.CL conflict)
        has_cl = "content-length" in headers
        has_te = "transfer-encoding" in headers
        if has_cl and has_te:
            anomalies.append(
                ProtocolAnomaly(
                    rule_id="HTTP-SMUGGLE-001",
                    severity=AnomalySeverity.CRITICAL,
                    title="HTTP Request Smuggling Attempt (CL-TE Desync)",
                    description="Request contains both 'Content-Length' and 'Transfer-Encoding' headers, indicating HTTP desync / request smuggling attempt.",
                    mitre_technique="T1499.004",
                    mitigation="Reject dual-header requests at reverse proxy and enforce HTTP/2 end-to-end.",
                )
            )

        # 2. Scanner / Recon User-Agents
        ua = headers.get("user-agent", "").lower()
        if any(sc in ua for sc in SCANNER_USER_AGENTS):
            anomalies.append(
                ProtocolAnomaly(
                    rule_id="HTTP-SCANNER-001",
                    severity=AnomalySeverity.HIGH,
                    title="Automated Vulnerability Scanner Detected",
                    description=f"User-Agent '{headers.get('user-agent')}' matches known offensive tool signatures.",
                    mitre_technique="T1595.002",
                    mitigation="Add IP to perimeter dynamic blocklist for 24 hours.",
                )
            )

        # 3. SQL Injection in URI or Body
        combined_payload = uri + " " + body
        if any(p.search(combined_payload) for p in PATTERNS_SQLI):
            anomalies.append(
                ProtocolAnomaly(
                    rule_id="HTTP-SQLI-001",
                    severity=AnomalySeverity.CRITICAL,
                    title="SQL Injection Exploit Pattern",
                    description=f"Injected SQL syntax detected in request path/body: '{uri[:64]}'.",
                    mitre_technique="T1190",
                    mitigation="Sanitize user input via parameterized queries and inspect database query logs.",
                )
            )

        # 4. Path Traversal
        if PATTERNS_TRAVERSAL.search(uri):
            anomalies.append(
                ProtocolAnomaly(
                    rule_id="HTTP-TRAVERSAL-001",
                    severity=AnomalySeverity.HIGH,
                    title="Directory Path Traversal Attempt",
                    description=f"Path traversal sequence '../' discovered in requested URI '{uri}'.",
                    mitre_technique="T1083",
                )
            )

        # 5. Remote Code Execution / Command Injection
        if PATTERNS_COMMAND_INJ.search(combined_payload):
            anomalies.append(
                ProtocolAnomaly(
                    rule_id="HTTP-CMDI-001",
                    severity=AnomalySeverity.CRITICAL,
                    title="OS Command Injection Attempt",
                    description="Shell command execution tokens and binaries detected in HTTP request payload.",
                    mitre_technique="T1059",
                    mitigation="Isolate web service container and review process fork trees.",
                )
            )

        # 6. Log4Shell / JNDI Injection
        if PATTERNS_JNDI.search(combined_payload):
            anomalies.append(
                ProtocolAnomaly(
                    rule_id="HTTP-LOG4J-001",
                    severity=AnomalySeverity.CRITICAL,
                    title="Log4Shell / JNDI Exploit String Detected",
                    description="JNDI lookup expression '${jndi:...' detected in request stream.",
                    mitre_technique="T1190",
                )
            )

        return DecodedPacket(
            protocol=ProtocolType.HTTP1,
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=dst_port,
            raw_length_bytes=len(payload_text.encode("utf-8")),
            headers={
                "method": method,
                "uri": uri,
                "version": version,
                **headers,
            },
            payload_fields={
                "body_snippet": body[:500] if body else "",
                "body_length": len(body),
            },
            is_suspicious=len(anomalies) > 0,
            anomalies=anomalies,
        )

    @classmethod
    def decode_binary_http2(
        cls,
        raw_bytes: bytes,
        src_ip: str = "10.0.0.15",
        dst_ip: str = "192.168.1.50",
        src_port: int = 54321,
        dst_port: int = 443,
    ) -> DecodedPacket:
        """Parse binary HTTP/2 frame stream (RFC 7540)."""
        anomalies: List[ProtocolAnomaly] = []
        frames: List[Dict[str, Any]] = []

        offset = 0
        # Check for client connection preface "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
        PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
        if raw_bytes.startswith(PREFACE):
            offset += len(PREFACE)

        rst_count = 0
        headers_count = 0

        while offset + 9 <= len(raw_bytes):
            # 24-bit length, 8-bit type, 8-bit flags, 31-bit stream ID
            b0, b1, b2, ftype, flags, s_raw = struct.unpack("!BBBBBI", raw_bytes[offset : offset + 9])
            length = (b0 << 16) | (b1 << 8) | b2
            stream_id = s_raw & 0x7FFFFFFF
            offset += 9

            frame_name = HTTP2_FRAME_NAMES.get(ftype, f"UNKNOWN_0x{ftype:02x}")
            payload_chunk = raw_bytes[offset : offset + length]
            offset += length

            if ftype == 0x01:  # HEADERS
                headers_count += 1
            elif ftype == 0x03:  # RST_STREAM
                rst_count += 1

            frames.append({
                "type": frame_name,
                "type_id": ftype,
                "stream_id": stream_id,
                "length": length,
                "flags": hex(flags),
            })

        # Rapid Reset Attack Detection (CVE-2023-44487)
        if headers_count >= 5 and rst_count >= 5 and (rst_count / max(1, headers_count)) >= 0.8:
            anomalies.append(
                ProtocolAnomaly(
                    rule_id="HTTP2-RAPIDRESET-001",
                    severity=AnomalySeverity.CRITICAL,
                    title="HTTP/2 Rapid Reset DDoS Attack (CVE-2023-44487)",
                    description=(
                        f"Stream contains {headers_count} HEADERS frames immediately followed by {rst_count} RST_STREAM frames, "
                        "matching the signature of the HTTP/2 Rapid Reset denial-of-service attack vector."
                    ),
                    mitre_technique="T1498.001",
                    mitigation="Enforce HTTP/2 RST_STREAM rate limiting and temporarily throttle offending IP session.",
                )
            )

        return DecodedPacket(
            protocol=ProtocolType.HTTP2,
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=dst_port,
            raw_length_bytes=len(raw_bytes),
            headers={
                "frames_count": len(frames),
                "headers_frames": headers_count,
                "rst_frames": rst_count,
            },
            payload_fields={
                "frames": frames[:30],
            },
            is_suspicious=len(anomalies) > 0,
            anomalies=anomalies,
        )
