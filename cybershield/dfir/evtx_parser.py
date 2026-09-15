"""Windows Event Log (.evtx) Binary Record Parser & Threat Correlator.

Dissects EVTX chunk headers, binary XML templates, and Windows Security/System event IDs
(4624, 4625, 4688, 7045, 1102, 4720), detecting LOLBins, lateral movement, and log tampering.
"""

from __future__ import annotations

import struct
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Optional, Tuple

from cybershield.dfir.schemas import (
    ArtifactType,
    ForensicFinding,
    FindingSeverity,
    TimelineEvent,
)

# Suspicious LOLBins and execution flags
SUSPICIOUS_LOLBINS: Dict[str, str] = {
    "vssadmin.exe": "Shadow Copy Deletion / Ransomware Prep (T1490)",
    "certutil.exe": "Ingress Tool Transfer / Base64 Decoding (T1105)",
    "bitsadmin.exe": "Background Ingress Transfer (T1197)",
    "mshta.exe": "Signed Binary Proxy Execution (T1218.005)",
    "rundll32.exe": "Unsigned DLL Execution (T1218.011)",
    "regsvr32.exe": "Squiblydoo COM Scriptlet Execution (T1218.010)",
    "wmic.exe": "WMI Command Execution (T1047)",
    "nltest.exe": "Domain Trust Discovery (T1482)",
    "psexec.exe": "Lateral Movement Execution (T1021.002)",
}


def filetime_to_datetime(ft: int) -> datetime:
    """Convert Windows 64-bit FILETIME (100-ns intervals since Jan 1, 1601) to UTC datetime."""
    try:
        us = ft / 10
        return datetime(1601, 1, 1, tzinfo=timezone.utc) + timedelta(microseconds=us)
    except Exception:
        return datetime.now(timezone.utc)


class EVTXParser:
    """Dissects Windows EVTX binary logs and extracts forensic security events."""

    @classmethod
    def parse_records(
        cls,
        raw_bytes: bytes,
        filename: str = "Security.evtx",
    ) -> Tuple[List[TimelineEvent], List[ForensicFinding]]:
        """Dissect EVTX binary file or structured records stream."""
        events: List[TimelineEvent] = []
        findings: List[ForensicFinding] = []

        # Check for standard EVTX file header "ElfFile\x00\x00\x00"
        offset = 0
        if raw_bytes.startswith(b"ElfFile\x00"):
            # Skip 4096-byte EVTX header to first chunk
            offset = 4096

        # Iterate through chunks or raw records
        while offset < len(raw_bytes):
            # Check for Chunk Header "ElfChnk\x00"
            if raw_bytes[offset : offset + 8] == b"ElfChnk\x00":
                offset += 512  # Skip 512-byte chunk header
                continue

            # Check for Record Magic 0x2a 0x2a 0x00 0x00 ("**\x00\x00")
            if offset + 24 > len(raw_bytes):
                break

            if raw_bytes[offset : offset + 4] == b"**\x00\x00":
                rec_len = struct.unpack("<I", raw_bytes[offset + 4 : offset + 8])[0]
                rec_id = struct.unpack("<Q", raw_bytes[offset + 8 : offset + 16])[0]
                timestamp_ft = struct.unpack("<Q", raw_bytes[offset + 16 : offset + 24])[0]
                dt = filetime_to_datetime(timestamp_ft)

                rec_data = raw_bytes[offset + 24 : offset + rec_len] if rec_len > 24 else b""
                offset += max(24, rec_len)

                # Extract textual fields from binary XML stream
                text_content = rec_data.decode("utf-16le", errors="ignore")

                # Parse Event ID and details
                ev_id = cls._extract_event_id(text_content, rec_data)
                parsed_ev, parsed_finding = cls._analyze_event(ev_id, text_content, dt, rec_id, filename)
                if parsed_ev:
                    events.append(parsed_ev)
                if parsed_finding:
                    findings.append(parsed_finding)
            else:
                # Fallback: Scan forward for next record signature
                next_sig = raw_bytes.find(b"**\x00\x00", offset + 1)
                if next_sig == -1:
                    break
                offset = next_sig

        # If no binary records were identified (e.g. structured text export), parse text lines
        if not events and raw_bytes:
            text_str = raw_bytes.decode("utf-8", errors="ignore")
            events, findings = cls._parse_textual_evtx(text_str, filename)

        return events, findings

    @classmethod
    def _extract_event_id(cls, text_content: str, raw_data: bytes) -> int:
        """Extract Windows Event ID from parsed strings or binary tokens."""
        for line in text_content.splitlines():
            if "EventID" in line or "Event ID" in line:
                digits = "".join(filter(str.isdigit, line))
                if digits:
                    return int(digits)
        # Search for known common event IDs in raw stream
        for known in (4624, 4625, 4688, 7045, 1102, 104, 4720, 4672):
            if str(known).encode("utf-16le") in raw_data or str(known).encode("ascii") in raw_data:
                return known
        return 4688  # Default process creation

    @classmethod
    def _analyze_event(
        cls,
        event_id: int,
        content: str,
        dt: datetime,
        rec_id: int,
        filename: str,
    ) -> Tuple[Optional[TimelineEvent], Optional[ForensicFinding]]:
        """Inspect Event ID and correlate with adversary techniques."""
        content_lower = content.lower()
        is_suspicious = False
        finding = None

        action = f"Windows Event {event_id}"
        entity = f"Record #{rec_id}"

        # 1. Event 4688: Process Creation
        if event_id == 4688:
            action = "Process Creation"
            for lolbin, desc in SUSPICIOUS_LOLBINS.items():
                if lolbin in content_lower:
                    is_suspicious = True
                    entity = lolbin
                    finding = ForensicFinding(
                        finding_id=f"DFIR-LOLBIN-{rec_id}",
                        severity=FindingSeverity.HIGH,
                        title=f"Suspicious Dual-Use Utility Executed: {lolbin}",
                        description=f"Process creation of '{lolbin}' detected ({desc}). Command text: {content[:180]}.",
                        timestamp=dt,
                        artifact_source=ArtifactType.EVTX,
                        mitre_technique="T1059",
                        iocs=[lolbin],
                        evidence_snippet={"event_id": 4688, "record_id": rec_id, "content": content[:250]},
                    )
                    break
            # Check for PowerShell encoded command
            if "powershell" in content_lower and ("-enc" in content_lower or "-encodedcommand" in content_lower):
                is_suspicious = True
                entity = "powershell.exe"
                finding = ForensicFinding(
                    finding_id=f"DFIR-PS-ENC-{rec_id}",
                    severity=FindingSeverity.CRITICAL,
                    title="Obfuscated Base64 Encoded PowerShell Invocation",
                    description=f"PowerShell executed with encoded command line parameters: {content[:180]}.",
                    timestamp=dt,
                    artifact_source=ArtifactType.EVTX,
                    mitre_technique="T1059.001",
                    iocs=["powershell.exe"],
                    evidence_snippet={"event_id": 4688, "record_id": rec_id, "content": content[:250]},
                )

        # 2. Event 4625: Failed Logon
        elif event_id == 4625:
            action = "Logon Failure (Bad Credentials)"
            is_suspicious = True
            finding = ForensicFinding(
                finding_id=f"DFIR-AUTH-FAIL-{rec_id}",
                severity=FindingSeverity.MEDIUM,
                title="Failed Account Logon Attempt",
                description=f"Logon failure recorded in event log. Possible credential stuffing or brute force.",
                timestamp=dt,
                artifact_source=ArtifactType.EVTX,
                mitre_technique="T1110",
                evidence_snippet={"event_id": 4625, "record_id": rec_id, "content": content[:200]},
            )

        # 3. Event 7045: New Service Installed (Persistence)
        elif event_id == 7045:
            action = "New Windows Service Installation"
            is_suspicious = True
            finding = ForensicFinding(
                finding_id=f"DFIR-SVC-INSTALL-{rec_id}",
                severity=FindingSeverity.HIGH,
                title="New Windows Service Created (Persistence)",
                description=f"A new background service was installed on the system: {content[:180]}.",
                timestamp=dt,
                artifact_source=ArtifactType.EVTX,
                mitre_technique="T1543.003",
                evidence_snippet={"event_id": 7045, "record_id": rec_id, "content": content[:200]},
            )

        # 4. Event 1102 / 104: Audit Log Cleared (Defense Evasion)
        elif event_id in (1102, 104):
            action = "Security Audit Log Wiped"
            is_suspicious = True
            finding = ForensicFinding(
                finding_id=f"DFIR-LOG-CLEARED-{rec_id}",
                severity=FindingSeverity.CRITICAL,
                title="Security Audit Log Cleared by Administrator",
                description="The Windows Security event log was deliberately cleared, indicating anti-forensics defense evasion.",
                timestamp=dt,
                artifact_source=ArtifactType.EVTX,
                mitre_technique="T1070.001",
                evidence_snippet={"event_id": event_id, "record_id": rec_id},
            )

        # 5. Event 4720: User Account Created
        elif event_id == 4720:
            action = "Local User Account Created"
            is_suspicious = True
            finding = ForensicFinding(
                finding_id=f"DFIR-USER-CREATE-{rec_id}",
                severity=FindingSeverity.HIGH,
                title="New Local Account Created",
                description="A new local Windows user account was provisioned, potential backdoor creation.",
                timestamp=dt,
                artifact_source=ArtifactType.EVTX,
                mitre_technique="T1136.001",
                evidence_snippet={"event_id": 4720, "record_id": rec_id, "content": content[:200]},
            )

        ev = TimelineEvent(
            timestamp=dt,
            event_type=f"EVTX_{event_id}",
            source_artifact=ArtifactType.EVTX,
            entity_name=entity,
            action=action,
            details={"record_id": rec_id, "file": filename, "snippet": content[:120]},
            is_suspicious=is_suspicious,
            finding_id=finding.finding_id if finding else None,
        )

        return ev, finding

    @classmethod
    def _parse_textual_evtx(
        cls,
        text_str: str,
        filename: str,
    ) -> Tuple[List[TimelineEvent], List[ForensicFinding]]:
        """Parse structured text export of event logs (e.g. XML/JSON exports)."""
        events: List[TimelineEvent] = []
        findings: List[ForensicFinding] = []
        lines = text_str.splitlines()

        for idx, line in enumerate(lines):
            if not line.strip():
                continue
            now = datetime.now(timezone.utc) - timedelta(minutes=len(lines) - idx)
            ev_id = 4688
            for id_candidate in (4624, 4625, 4688, 7045, 1102, 4720):
                if str(id_candidate) in line:
                    ev_id = id_candidate
                    break
            ev, finding = cls._analyze_event(ev_id, line, now, idx + 1, filename)
            if ev:
                events.append(ev)
            if finding:
                findings.append(finding)

        return events, findings
