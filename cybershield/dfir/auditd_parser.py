"""Linux auditd & System Journal Forensic Normalizer.

Parses Linux kernel audit events (SYSCALL, EXECVE, PROCTITLE, USER_CMD, CWD),
correlates process executions with effective user IDs (EUID/AUID), and detects privilege escalation.
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from cybershield.dfir.schemas import (
    ArtifactType,
    ForensicFinding,
    FindingSeverity,
    TimelineEvent,
)

SUSPICIOUS_LINUX_COMMANDS = {
    "useradd": "User Provisioning / Backdoor Creation (T1136.001)",
    "adduser": "User Provisioning / Backdoor Creation (T1136.001)",
    "insmod": "Kernel Module Loading / Rootkit (T1547.006)",
    "modprobe": "Kernel Module Loading / Rootkit (T1547.006)",
    "iptables": "Firewall Alteration / Defense Evasion (T1562.004)",
    "ufw": "Firewall Alteration (T1562.004)",
    "crontab": "Scheduled Task / Persistence (T1053.003)",
    "chattr": "File Attribute Modification / Immature Lock (T1222.002)",
}


class AuditdParser:
    """Dissects Linux auditd event streams and evaluates security findings."""

    @classmethod
    def parse_log(
        cls,
        text_content: str,
        filename: str = "audit.log",
    ) -> Tuple[List[TimelineEvent], List[ForensicFinding]]:
        """Parse text lines from /var/log/audit/audit.log."""
        events: List[TimelineEvent] = []
        findings: List[ForensicFinding] = []

        lines = text_content.splitlines()

        for line_num, line in enumerate(lines):
            line = line.strip()
            if not line.startswith("type="):
                continue

            # Parse msg=audit(1678901234.567:123):
            ts = datetime.now(timezone.utc)
            m_time = re.search(r"msg=audit\((\d+)(?:\.\d+)?:", line)
            if m_time:
                try:
                    epoch_s = int(m_time.group(1))
                    ts = datetime.fromtimestamp(epoch_s, tz=timezone.utc)
                except Exception:
                    pass

            # Extract key-value tokens
            tokens: Dict[str, str] = {}
            for match in re.finditer(r'([a-zA-Z0-9_]+)=("([^"]*)"|\S+)', line):
                k = match.group(1)
                v = match.group(3) if match.group(3) is not None else match.group(2)
                tokens[k] = v

            rec_type = tokens.get("type", "UNKNOWN")

            # Analyze SYSCALL or EXECVE or USER_CMD
            if rec_type in ("SYSCALL", "EXECVE", "USER_CMD"):
                comm = tokens.get("comm", tokens.get("exe", "unknown")).replace('"', '')
                cmdline = tokens.get("cmd", tokens.get("a0", comm)).replace('"', '')
                uid = tokens.get("uid", "unknown")
                euid = tokens.get("euid", "unknown")
                auid = tokens.get("auid", "unknown")
                success = tokens.get("success", "yes")

                is_suspicious = False
                finding = None

                # 1. Check Suspicious Command Binary
                comm_clean = comm.split("/")[-1].lower()
                if comm_clean in SUSPICIOUS_LINUX_COMMANDS:
                    is_suspicious = True
                    desc = SUSPICIOUS_LINUX_COMMANDS[comm_clean]
                    finding = ForensicFinding(
                        finding_id=f"DFIR-AUDITD-{line_num + 1}",
                        severity=FindingSeverity.HIGH,
                        title=f"Suspicious Linux Command Executed: {comm_clean}",
                        description=f"Command '{cmdline}' executed by UID {uid} (AUID: {auid}): {desc}.",
                        timestamp=ts,
                        artifact_source=ArtifactType.AUDITD,
                        mitre_technique="T1059.004",
                        iocs=[comm_clean],
                        evidence_snippet={"line": line_num + 1, "tokens": tokens},
                    )

                # 2. Check Sudo Privilege Escalation (USER_CMD with root EUID)
                if rec_type == "USER_CMD" or euid == "0":
                    if any(target in cmdline.lower() for target in ("/etc/shadow", "id_rsa", "sudo su", "sudo -i")):
                        is_suspicious = True
                        finding = ForensicFinding(
                            finding_id=f"DFIR-AUDITD-PRIV-{line_num + 1}",
                            severity=FindingSeverity.CRITICAL,
                            title="Sensitive Root Credential Access via Sudo",
                            description=f"Command line '{cmdline}' accessed sensitive security credentials under EUID 0.",
                            timestamp=ts,
                            artifact_source=ArtifactType.AUDITD,
                            mitre_technique="T1003.008",
                            evidence_snippet={"cmdline": cmdline, "uid": uid, "auid": auid},
                        )

                ev = TimelineEvent(
                    timestamp=ts,
                    event_type=f"AUDITD_{rec_type}",
                    source_artifact=ArtifactType.AUDITD,
                    entity_name=comm_clean,
                    action=f"Executed: {cmdline[:60]}",
                    details={
                        "uid": uid,
                        "euid": euid,
                        "auid": auid,
                        "success": success,
                        "line_number": line_num + 1,
                    },
                    is_suspicious=is_suspicious,
                    finding_id=finding.finding_id if finding else None,
                )
                events.append(ev)
                if finding:
                    findings.append(finding)

        return events, findings
