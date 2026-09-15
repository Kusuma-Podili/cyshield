"""
Autonomous Cryptographic Ransomware Canary & VSS Shadow Copy Sentinel.
Protects endpoints against rapid encryption bursts, canary file alteration,
and Volume Shadow Copy (VSS) backup deletion commands.
"""

import hashlib
import re
import uuid
from collections import defaultdict
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

from cybershield.ransomware.schemas import (
    CanaryFileType,
    CanaryTrapFile,
    FileModificationEvent,
    RansomwareAlert,
    RansomwareThreatLevel,
    VSSCommandInspectionRequest,
)


class RansomwareSentinelEngine:
    """
    Real-time defense engine detecting early-stage ransomware behavior and shadow copy attacks.
    """

    KNOWN_RANSOMWARE_EXTENSIONS = {
        ".locked", ".crypto", ".lockbit", ".blackcat", ".crypted",
        ".enc", ".wnry", ".mallox", ".conti", ".akira", ".phobos",
        ".ryuk", ".stop", ".makop", ".rhysida", ".alphv"
    }

    VSS_TAMPER_PATTERNS = [
        (
            re.compile(r"vssadmin(?:\.exe)?\s+delete\s+shadows", re.IGNORECASE),
            "Volume Shadow Copy Deletion via vssadmin",
            "T1490 - Inhibit System Recovery"
        ),
        (
            re.compile(r"wmic(?:\.exe)?\s+shadowcopy\s+delete", re.IGNORECASE),
            "WMI Shadow Copy Destruction",
            "T1490 - Inhibit System Recovery"
        ),
        (
            re.compile(r"wbadmin(?:\.exe)?\s+delete\s+(?:catalog|systemstatebackup)", re.IGNORECASE),
            "Windows Backup Catalog Purge via wbadmin",
            "T1490 - Inhibit System Recovery"
        ),
        (
            re.compile(r"bcdedit(?:\.exe)?\s+/set.*recoveryenabled\s+no", re.IGNORECASE),
            "Disabling Windows Startup Recovery via bcdedit",
            "T1490 - Inhibit System Recovery"
        ),
        (
            re.compile(r"bcdedit(?:\.exe)?\s+/set.*bootstatuspolicy\s+ignoreallfailures", re.IGNORECASE),
            "Boot Status Error Policy Tampering",
            "T1490 - Inhibit System Recovery"
        ),
    ]

    def __init__(self):
        self._canaries: Dict[str, CanaryTrapFile] = {}
        self._alerts: List[RansomwareAlert] = []
        self._host_events: Dict[str, List[FileModificationEvent]] = defaultdict(list)
        self._seed_default_canaries()

    def _seed_default_canaries(self):
        """Deploy baseline bait canary records across enterprise assets."""
        default_canaries = [
            CanaryTrapFile(
                canary_id="CANARY-001",
                host_id="SRV-FILE-01",
                file_path=r"C:\Shares\Finance\!_Q4_Audit_Confidential.docx",
                file_type=CanaryFileType.WORD,
                expected_sha256="4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945",
                watermark_token="TOKEN-CANARY-WORM-FIN-2026",
            ),
            CanaryTrapFile(
                canary_id="CANARY-002",
                host_id="SRV-FILE-01",
                file_path=r"C:\Shares\HR\!_Employees_Payroll_2026.xlsx",
                file_type=CanaryFileType.EXCEL,
                expected_sha256="8c916738f18cd9b2a758c031fc0f8d95191028308e2f89b9423b3208f4203e48",
                watermark_token="TOKEN-CANARY-WORM-HR-2026",
            ),
            CanaryTrapFile(
                canary_id="CANARY-003",
                host_id="WS-EXEC-05",
                file_path=r"C:\Users\CEO\Documents\!_Board_Strategy_2026.pdf",
                file_type=CanaryFileType.PDF,
                expected_sha256="12903bbca521948480392fa98319e64810237190f84819483920194829103948",
                watermark_token="TOKEN-CANARY-WORM-EXEC-2026",
            ),
        ]
        for c in default_canaries:
            self._canaries[c.canary_id] = c

    def deploy_host_canaries(self, host_id: str, base_directory: str) -> List[CanaryTrapFile]:
        """Generates realistic decoy bait files with alphabetical priority prefixing."""
        bait_templates = [
            ("!_Accounting_Ledger_2026.xlsx", CanaryFileType.EXCEL),
            ("!_Confidential_Contracts.docx", CanaryFileType.WORD),
            ("!_Client_Database_Backup.sql", CanaryFileType.SQL),
            ("!_Executive_Summary.pdf", CanaryFileType.PDF),
        ]
        deployed: List[CanaryTrapFile] = []
        for filename, ftype in bait_templates:
            canary_id = f"CANARY-{uuid.uuid4().hex[:6].upper()}"
            path = f"{base_directory}\\{filename}"
            token = f"CANARY-{host_id}-{uuid.uuid4().hex[:8]}"
            hash_val = hashlib.sha256(token.encode("utf-8")).hexdigest()

            canary = CanaryTrapFile(
                canary_id=canary_id,
                host_id=host_id,
                file_path=path,
                file_type=ftype,
                expected_sha256=hash_val,
                watermark_token=token,
            )
            self._canaries[canary_id] = canary
            deployed.append(canary)

        return deployed

    def inspect_vss_command(self, req: VSSCommandInspectionRequest) -> Optional[RansomwareAlert]:
        """Inspects command line executions for backup inhibition and shadow copy purging."""
        cmd = req.command_line.strip()
        for pattern, desc, mitre_ttp in self.VSS_TAMPER_PATTERNS:
            if pattern.search(cmd):
                alert = RansomwareAlert(
                    alert_id=f"RANSOM-VSS-{uuid.uuid4().hex[:6].upper()}",
                    host_id=req.host_id,
                    threat_level=RansomwareThreatLevel.CRITICAL_OUTBREAK,
                    reason=f"{desc} ({mitre_ttp}) via command: '{cmd}'",
                    process_name=req.process_name,
                    host_quarantine_recommended=True,
                )
                self._alerts.append(alert)
                return alert
        return None

    def inspect_file_modification(self, event: FileModificationEvent) -> Optional[RansomwareAlert]:
        """
        Evaluates file change telemetry for canary tampering and high-entropy encryption bursts.
        """
        now = datetime.utcnow()

        # 1. Check if modified file is a registered Canary Bait File
        for canary in self._canaries.values():
            if canary.host_id == event.host_id and canary.file_path.lower() == event.file_path.lower():
                canary.is_tampered = True
                canary.last_verified = now
                alert = RansomwareAlert(
                    alert_id=f"RANSOM-CANARY-{uuid.uuid4().hex[:6].upper()}",
                    host_id=event.host_id,
                    threat_level=RansomwareThreatLevel.CRITICAL_OUTBREAK,
                    reason=f"Decoy Canary File Tripped: '{canary.file_path}' modified by process {event.process_name} (PID {event.process_pid}) with high entropy {event.post_entropy}",
                    affected_files=[event.file_path],
                    detected_extensions=[event.new_extension],
                    process_name=event.process_name,
                    process_pid=event.process_pid,
                    host_quarantine_recommended=True,
                )
                self._alerts.append(alert)
                return alert

        # 2. Check for known ransomware extension appending
        ext = event.new_extension.lower()
        if ext in self.KNOWN_RANSOMWARE_EXTENSIONS:
            alert = RansomwareAlert(
                alert_id=f"RANSOM-EXT-{uuid.uuid4().hex[:6].upper()}",
                host_id=event.host_id,
                threat_level=RansomwareThreatLevel.CRITICAL_OUTBREAK,
                reason=f"Known ransomware extension '{ext}' appended to '{event.file_path}' by {event.process_name}",
                affected_files=[event.file_path],
                detected_extensions=[ext],
                process_name=event.process_name,
                process_pid=event.process_pid,
                host_quarantine_recommended=True,
            )
            self._alerts.append(alert)
            return alert

        # 3. Buffer sliding window event for burst analysis (last 10 seconds)
        host_queue = self._host_events[event.host_id]
        cutoff = now - timedelta(seconds=10)
        # Purge stale events
        host_queue = [e for e in host_queue if e.timestamp >= cutoff]
        host_queue.append(event)
        self._host_events[event.host_id] = host_queue

        # Check for rapid high-entropy encryption burst (>= 3 files with entropy > 7.75 in 10s)
        high_entropy_events = [e for e in host_queue if e.post_entropy >= 7.75]
        if len(high_entropy_events) >= 3:
            affected = [e.file_path for e in high_entropy_events]
            alert = RansomwareAlert(
                alert_id=f"RANSOM-BURST-{uuid.uuid4().hex[:6].upper()}",
                host_id=event.host_id,
                threat_level=RansomwareThreatLevel.HIGH,
                reason=f"Rapid cryptographic encryption burst detected: {len(high_entropy_events)} files encrypted within 10s by {event.process_name}",
                affected_files=affected,
                process_name=event.process_name,
                process_pid=event.process_pid,
                host_quarantine_recommended=True,
            )
            self._alerts.append(alert)
            return alert

        return None

    def list_canaries(self) -> List[CanaryTrapFile]:
        return list(self._canaries.values())

    def list_alerts(self) -> List[RansomwareAlert]:
        return list(reversed(self._alerts))

    def get_overview_metrics(self) -> Dict[str, Any]:
        total_canaries = len(self._canaries)
        tripped = sum(1 for c in self._canaries.values() if c.is_tampered)
        critical_alerts = sum(1 for a in self._alerts if a.threat_level == RansomwareThreatLevel.CRITICAL_OUTBREAK)

        return {
            "total_deployed_canaries": total_canaries,
            "tripped_canary_alarms": tripped,
            "total_ransomware_alerts": len(self._alerts),
            "critical_outbreaks": critical_alerts,
            "known_signature_extensions": len(self.KNOWN_RANSOMWARE_EXTENSIONS),
            "vss_tamper_patterns_active": len(self.VSS_TAMPER_PATTERNS),
        }
