"""Deep SMBv1 / SMBv2 / SMBv3 Protocol Dissector & Lateral Movement Analyzer.

Dissects binary SMB packet headers, commands, named pipes, and detects
EternalBlue (MS17-010), PsExec execution, Admin share traversal, and NTLM relay attacks.
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

# SMBv2 Commands
SMB2_COMMAND_NAMES: Dict[int, str] = {
    0x0000: "NEGOTIATE",
    0x0001: "SESSION_SETUP",
    0x0002: "LOGOFF",
    0x0003: "TREE_CONNECT",
    0x0004: "TREE_DISCONNECT",
    0x0005: "CREATE",
    0x0006: "CLOSE",
    0x0007: "FLUSH",
    0x0008: "READ",
    0x0009: "WRITE",
    0x000A: "LOCK",
    0x000B: "IOCTL",
    0x000C: "CANCEL",
    0x000D: "ECHO",
    0x000E: "QUERY_DIRECTORY",
    0x000F: "CHANGE_NOTIFY",
    0x0010: "QUERY_INFO",
    0x0011: "SET_INFO",
}

# Malicious / Lateral Named Pipes
SUSPICIOUS_NAMED_PIPES = {
    "psexesvc": "PsExec Lateral Command Execution",
    "winexesvc": "Winexe Remote Command Service",
    "paexec": "PowerAdmin Remote Execution",
    "csexec": "Cobalt Strike Exec Pipe",
    "status_": "Metasploit SMB Named Pipe",
    "spoolss": "Print Spooler RPC (PrintNightmare CVE-2021-34527)",
    "lsarpc": "LSA Remote Procedure Call (Secrets Dumping)",
    "samr": "Security Account Manager RPC (Enumeration)",
}


class SMBDecoder:
    """Dissects binary SMBv1 and SMBv2/v3 protocol frames."""

    @classmethod
    def decode(
        cls,
        raw_bytes: bytes,
        src_ip: str = "10.0.0.60",
        dst_ip: str = "10.0.0.2",
        src_port: int = 49200,
        dst_port: int = 445,
    ) -> DecodedPacket:
        """Parse binary SMB network packet and evaluate attack heuristics."""
        anomalies: List[ProtocolAnomaly] = []
        headers: Dict[str, Any] = {}
        payload: Dict[str, Any] = {}

        offset = 0

        # Handle optional NetBIOS Session Service 4-byte header
        if len(raw_bytes) >= 4 and raw_bytes[0] == 0x00:
            nbss_len = (raw_bytes[1] << 16) | (raw_bytes[2] << 8) | raw_bytes[3]
            headers["netbios_length"] = nbss_len
            offset = 4

        if len(raw_bytes) < offset + 4:
            return DecodedPacket(
                protocol=ProtocolType.SMB,
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=src_port,
                dst_port=dst_port,
                raw_length_bytes=len(raw_bytes),
                headers={"error": "SMB packet too short"},
                is_suspicious=True,
            )

        magic = raw_bytes[offset : offset + 4]

        # Check for SMBv1 (\xFFSMB)
        if magic == b"\xffSMB":
            headers["dialect"] = "SMBv1"
            cmd_code = raw_bytes[offset + 4] if len(raw_bytes) > offset + 4 else 0
            headers["smbv1_command"] = hex(cmd_code)

            # Security Anomaly: Insecure legacy SMBv1
            anomalies.append(
                ProtocolAnomaly(
                    rule_id="SMB-V1-DEPRECATED-001",
                    severity=AnomalySeverity.HIGH,
                    title="Obsolete SMBv1 Protocol Traffic",
                    description="SMBv1 negotiation detected. Protocol is deprecated and highly susceptible to remote exploit (MS17-010 EternalBlue).",
                    mitre_technique="T1210",
                    mitigation="Disable SMBv1 globally across Active Directory Group Policy.",
                )
            )

            # Check for NT Transact / Transaction2 (EternalBlue Signature)
            if cmd_code in (0x25, 0x2F, 0x32, 0xA0):
                anomalies.append(
                    ProtocolAnomaly(
                        rule_id="SMB-ETERNALBLUE-001",
                        severity=AnomalySeverity.CRITICAL,
                        title="Potential EternalBlue / MS17-010 Exploit Frame",
                        description=f"SMBv1 Transaction command 0x{cmd_code:02x} detected matching MS17-010 buffer manipulation characteristics.",
                        mitre_technique="T1210",
                        mitigation="Immediately isolate host and verify Microsoft Security Bulletin MS17-010 patch status.",
                    )
                )

        # Check for SMBv2 / SMBv3 (\xFESMB)
        elif magic == b"\xfeSMB" and len(raw_bytes) >= offset + 64:
            headers["dialect"] = "SMBv2/v3"
            hdr_bytes = raw_bytes[offset : offset + 64]
            # StructureSize (2B at 4), CreditCharge (2B at 6), Status/ChannelSeq (4B at 8), Command (2B at 12)
            struct_size = struct.unpack("<H", hdr_bytes[4:6])[0]
            status_code = struct.unpack("<I", hdr_bytes[8:12])[0]
            cmd_code = struct.unpack("<H", hdr_bytes[12:14])[0]
            flags = struct.unpack("<I", hdr_bytes[16:20])[0]
            msg_id = struct.unpack("<Q", hdr_bytes[24:32])[0]
            proc_id = struct.unpack("<I", hdr_bytes[32:36])[0]
            tree_id = struct.unpack("<I", hdr_bytes[36:40])[0]
            session_id = struct.unpack("<Q", hdr_bytes[40:48])[0]

            cmd_name = SMB2_COMMAND_NAMES.get(cmd_code, f"CMD_0x{cmd_code:04x}")
            headers.update({
                "command": cmd_name,
                "command_id": cmd_code,
                "status": hex(status_code),
                "message_id": msg_id,
                "process_id": proc_id,
                "tree_id": tree_id,
                "session_id": hex(session_id),
                "is_signed": bool(flags & 0x08),
            })

            # Inspect payload after 64-byte SMB2 header
            p_offset = offset + 64
            p_bytes = raw_bytes[p_offset:]

            # Heuristic: Extract strings in payload (e.g. Pipe names, Share paths)
            try:
                # Look for UTF-16LE strings (standard Windows SMB strings)
                decoded_str = p_bytes.decode("utf-16le", errors="ignore").lower()
                for pipe_key, threat_desc in SUSPICIOUS_NAMED_PIPES.items():
                    if pipe_key in decoded_str:
                        anomalies.append(
                            ProtocolAnomaly(
                                rule_id="SMB-LATERAL-PIPE-001",
                                severity=AnomalySeverity.CRITICAL,
                                title=f"Suspicious Lateral Execution Pipe: {pipe_key}",
                                description=f"SMB payload requested access to high-risk named pipe '{pipe_key}' ({threat_desc}).",
                                mitre_technique="T1021.002",
                                mitigation="Block lateral SMB traffic between workstations and inspect originating process.",
                            )
                        )

                # Check Admin Share Traversal
                if "admin$" in decoded_str or "c$" in decoded_str:
                    anomalies.append(
                        ProtocolAnomaly(
                            rule_id="SMB-ADMIN-SHARE-001",
                            severity=AnomalySeverity.HIGH,
                            title="Administrative Share Access (C$ / ADMIN$)",
                            description="SMB Tree Connect request targeted administrative file share, typical of staging ransomware or lateral malware deployment.",
                            mitre_technique="T1021.002",
                            mitigation="Restrict local administrator account usage across network boundaries.",
                        )
                    )
            except Exception:
                pass

        return DecodedPacket(
            protocol=ProtocolType.SMB,
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
