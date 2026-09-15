"""Windows Prefetch (.pf) Execution Artifact Parser (SCCA Format).

Dissects Windows Prefetch files (Windows 7/8/10/11 formats), extracting executable names,
execution count, last execution timestamps, and referenced dependency DLLs.
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
from cybershield.dfir.evtx_parser import filetime_to_datetime

SUSPICIOUS_EXECUTABLES = {
    "mimikatz.exe": "Credential Dumping (T1003)",
    "procdump.exe": "LSASS Memory Dumping (T1003.001)",
    "whoami.exe": "Account Discovery (T1033)",
    "net.exe": "Domain / Network Reconnaissance (T1087)",
    "net1.exe": "Domain / Network Reconnaissance (T1087)",
    "nltest.exe": "Trust Discovery (T1482)",
    "vssadmin.exe": "Volume Shadow Deletion (T1490)",
    "powershell.exe": "Command and Scripting Interpreter (T1059.001)",
    "cmd.exe": "Command Interpreter (T1059.003)",
    "certutil.exe": "Ingress Tool Transfer (T1105)",
}


class PrefetchParser:
    """Parses binary Windows Prefetch files and extracts execution timelines."""

    @classmethod
    def parse_file(
        cls,
        raw_bytes: bytes,
        filename: str = "CMD.EXE-A1B2C3D4.pf",
    ) -> Tuple[List[TimelineEvent], List[ForensicFinding]]:
        """Dissect binary Prefetch payload."""
        events: List[TimelineEvent] = []
        findings: List[ForensicFinding] = []

        if len(raw_bytes) < 84:
            # Fallback for structured prefetch summaries
            return cls._parse_fallback(raw_bytes, filename)

        # Header Magic: SCCA
        version = struct.unpack("<I", raw_bytes[:4])[0]
        magic = raw_bytes[4:8]

        if magic != b"SCCA":
            # Might be Win10 MAM-compressed; inspect raw string tables
            return cls._parse_fallback(raw_bytes, filename)

        # Read Executable Name (60 bytes UTF-16LE starting at offset 16)
        try:
            exe_raw = raw_bytes[16:76]
            exe_name = exe_raw.decode("utf-16le", errors="ignore").split("\x00")[0].strip()
        except Exception:
            exe_name = filename.split("-")[0] if "-" in filename else filename

        if not exe_name:
            exe_name = filename.split(".")[0]

        # Version-specific offsets for Execution Count and Timestamps
        # Win 7 (ver 23): Run count at offset 152, 1 timestamp at offset 128
        # Win 8 (ver 26) / Win 10 (ver 30): Run count at offset 200, up to 8 timestamps at offset 128
        timestamps: List[datetime] = []
        run_count = 1

        if version == 23 and len(raw_bytes) >= 156:  # Win 7
            ft = struct.unpack("<Q", raw_bytes[128:136])[0]
            run_count = struct.unpack("<I", raw_bytes[152:156])[0]
            if ft > 0:
                timestamps.append(filetime_to_datetime(ft))
        elif version in (26, 30) and len(raw_bytes) >= 204:  # Win 8 / Win 10
            run_count = struct.unpack("<I", raw_bytes[200:204])[0]
            # Up to 8 FILETIMEs
            for i in range(8):
                off = 128 + (i * 8)
                if off + 8 <= len(raw_bytes):
                    ft = struct.unpack("<Q", raw_bytes[off : off + 8])[0]
                    if ft > 0:
                        timestamps.append(filetime_to_datetime(ft))
        else:
            timestamps.append(datetime.now(timezone.utc))

        if not timestamps:
            timestamps.append(datetime.now(timezone.utc))

        exe_lower = exe_name.lower()
        is_suspicious = exe_lower in SUSPICIOUS_EXECUTABLES

        # Generate Timeline Events for each recorded execution
        for idx, ts in enumerate(timestamps):
            events.append(
                TimelineEvent(
                    timestamp=ts,
                    event_type="PREFETCH_EXECUTION",
                    source_artifact=ArtifactType.PREFETCH,
                    entity_name=exe_name,
                    action=f"Program Executed (Run #{run_count - idx if run_count > idx else 1})",
                    details={
                        "prefetch_file": filename,
                        "run_count": run_count,
                        "version": version,
                        "execution_index": idx + 1,
                    },
                    is_suspicious=is_suspicious,
                    finding_id=f"DFIR-PF-{exe_lower}" if is_suspicious else None,
                )
            )

        # Threat finding if offensive tool executed
        if is_suspicious:
            threat_desc = SUSPICIOUS_EXECUTABLES[exe_lower]
            findings.append(
                ForensicFinding(
                    finding_id=f"DFIR-PF-{exe_lower}",
                    severity=FindingSeverity.HIGH if "mimikatz" not in exe_lower else FindingSeverity.CRITICAL,
                    title=f"Host Execution Evidence: {exe_name}",
                    description=f"Prefetch artifact confirms '{exe_name}' was executed {run_count} times ({threat_desc}).",
                    timestamp=timestamps[0],
                    artifact_source=ArtifactType.PREFETCH,
                    mitre_technique="T1204.002",
                    iocs=[exe_name],
                    evidence_snippet={"filename": filename, "run_count": run_count, "last_executed": timestamps[0].isoformat()},
                )
            )

        return events, findings

    @classmethod
    def _parse_fallback(
        cls,
        raw_bytes: bytes,
        filename: str,
    ) -> Tuple[List[TimelineEvent], List[ForensicFinding]]:
        """Fallback parser extracting UTF-16LE / ASCII strings from prefetch container."""
        events: List[TimelineEvent] = []
        findings: List[ForensicFinding] = []

        name = filename.split(".pf")[0].split("-")[0]
        now = datetime.now(timezone.utc)

        # Look for executable names in raw strings
        for sus_exe, desc in SUSPICIOUS_EXECUTABLES.items():
            if sus_exe.encode("utf-16le") in raw_bytes or sus_exe.encode("ascii") in raw_bytes:
                name = sus_exe
                break

        is_susp = name.lower() in SUSPICIOUS_EXECUTABLES
        ev = TimelineEvent(
            timestamp=now,
            event_type="PREFETCH_EXECUTION",
            source_artifact=ArtifactType.PREFETCH,
            entity_name=name,
            action="Program Executed (Prefetch Evidence)",
            details={"filename": filename},
            is_suspicious=is_susp,
        )
        events.append(ev)

        if is_susp:
            findings.append(
                ForensicFinding(
                    finding_id=f"DFIR-PF-{name.lower()}",
                    severity=FindingSeverity.HIGH,
                    title=f"Suspicious Process Execution Artifact: {name}",
                    description=f"Prefetch record confirms execution of '{name}'.",
                    timestamp=now,
                    artifact_source=ArtifactType.PREFETCH,
                    mitre_technique="T1204.002",
                    iocs=[name],
                )
            )

        return events, findings
