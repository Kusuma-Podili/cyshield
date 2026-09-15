"""Host-based Behavioral Heuristic Detection Engine for EDR.

Analyzes raw endpoint telemetry (process ancestry, living-off-the-land binaries,
file integrity modifications, and suspicious socket connections) to detect in-memory
injections, weaponized office macros, webshell spawns, and credential tampering.
"""

from __future__ import annotations

import logging
import re
import uuid
from typing import Any, Dict, List, Optional

from cybershield.edr.schemas import (
    EDRBehavioralAlert,
    FIMTelemetryEvent,
    NetworkSocketEvent,
    ProcessTelemetryEvent,
)

logger = logging.getLogger("cybershield.edr.behavior")

OFFICE_PROCESSES = {
    "winword.exe",
    "excel.exe",
    "powerpnt.exe",
    "outlook.exe",
    "eqnedt32.exe",
}

WEB_SERVER_PROCESSES = {
    "w3wp.exe",
    "httpd",
    "httpd.exe",
    "nginx",
    "apache2",
    "tomcat",
    "java",
}

SHELL_PROCESSES = {
    "cmd.exe",
    "powershell.exe",
    "pwsh.exe",
    "bash",
    "sh",
    "zsh",
    "wscript.exe",
    "cscript.exe",
    "mshta.exe",
}

LOLBIN_PATTERNS = [
    (r"\bcertutil(\.exe)?\b.*-(urlcache|decode|split|f)", "CertUtil Download/Decode Cradle (T1105)"),
    (r"\bmshta(\.exe)?\b.*(vbscript|javascript|http)", "Mshta Remote Script Execution (T1218.005)"),
    (r"\bbitsadmin(\.exe)?\b.*/transfer", "Bitsadmin Background File Download (T1197)"),
    (r"\bregsvr32(\.exe)?\b.*(/s\s+/u|/i:http)", "Regsvr32 Remote Scriptlet Execution / Squiblydoo (T1218.010)"),
    (r"\bwmic(\.exe)?\b.*process\s+call\s+create", "WMIC Remote Process Creation (T1047)"),
]

SENSITIVE_FIM_PATHS = [
    "/etc/shadow",
    "/etc/passwd",
    "/etc/sudoers",
    "/etc/crontab",
    "c:\\windows\\system32\\drivers\\etc\\hosts",
    "c:\\windows\\system32\\config\\sam",
    "c:\\windows\\system32\\config\\system",
]


class EDRBehaviorEngine:
    """Evaluates endpoint telemetry streams for malicious behaviors."""

    def __init__(self) -> None:
        self.lolbin_regexes = [(re.compile(p, re.IGNORECASE), name) for p, name in LOLBIN_PATTERNS]

    def analyze_processes(self, agent_id: str, hostname: str, events: List[ProcessTelemetryEvent]) -> List[EDRBehavioralAlert]:
        """Inspect process creation ancestry and LOLBins."""
        alerts: List[EDRBehavioralAlert] = []

        for p in events:
            proc_lower = p.process_name.lower()
            parent_lower = (p.parent_process_name or "").lower()
            cmd = p.command_line

            # 1. Office Application Spawning Script Interpreter / Shell
            if parent_lower in OFFICE_PROCESSES and proc_lower in SHELL_PROCESSES:
                alerts.append(
                    EDRBehavioralAlert(
                        alert_id=f"EDR-OFFICE-SHELL-{uuid.uuid4().hex[:8]}",
                        agent_id=agent_id,
                        hostname=hostname,
                        severity="CRITICAL",
                        mitre_technique="T1204.002",
                        title="Weaponized Office Document Spawned Command Shell",
                        description=(
                            f"Office process '{p.parent_process_name}' spawned scripting interpreter '{p.process_name}'. "
                            f"Command line: '{cmd}'. Classic malicious macro or exploit behavior."
                        ),
                        evidence={
                            "pid": p.pid,
                            "ppid": p.ppid,
                            "parent": p.parent_process_name,
                            "command_line": cmd,
                        },
                    )
                )

            # 2. Web Server Spawning Interactive Shell (Webshell)
            if parent_lower in WEB_SERVER_PROCESSES and proc_lower in SHELL_PROCESSES:
                alerts.append(
                    EDRBehavioralAlert(
                        alert_id=f"EDR-WEBSHELL-{uuid.uuid4().hex[:8]}",
                        agent_id=agent_id,
                        hostname=hostname,
                        severity="CRITICAL",
                        mitre_technique="T1505.003",
                        title="Web Application Server Spawned Interactive Shell (Webshell)",
                        description=(
                            f"Web server '{p.parent_process_name}' executed shell '{p.process_name}'. "
                            f"Command line: '{cmd}'. High probability of active webshell exploitation."
                        ),
                        evidence={
                            "pid": p.pid,
                            "ppid": p.ppid,
                            "parent": p.parent_process_name,
                            "command_line": cmd,
                        },
                    )
                )

            # 3. Living-Off-The-Land Binaries (LOLBins)
            for reg, attack_name in self.lolbin_regexes:
                if reg.search(cmd):
                    alerts.append(
                        EDRBehavioralAlert(
                            alert_id=f"EDR-LOLBIN-{uuid.uuid4().hex[:8]}",
                            agent_id=agent_id,
                            hostname=hostname,
                            severity="HIGH",
                            mitre_technique="T1218",
                            title=f"Living-Off-The-Land Binary Invocation: {attack_name}",
                            description=(
                                f"Suspicious LOLBin execution observed: '{cmd}'. "
                                "Adversaries leverage built-in OS utilities to evade perimeter download filters."
                            ),
                            evidence={
                                "pid": p.pid,
                                "process": p.process_name,
                                "command_line": cmd,
                                "matched_pattern": reg.pattern,
                            },
                        )
                    )
                    break

        return alerts

    def analyze_fim(self, agent_id: str, hostname: str, events: List[FIMTelemetryEvent]) -> List[EDRBehavioralAlert]:
        """Inspect File Integrity Monitoring changes."""
        alerts: List[EDRBehavioralAlert] = []

        for fim in events:
            path_lower = fim.file_path.lower()
            
            # 1. Critical System Configuration Modification
            for sensitive in SENSITIVE_FIM_PATHS:
                if path_lower == sensitive or path_lower.endswith(sensitive):
                    alerts.append(
                        EDRBehavioralAlert(
                            alert_id=f"EDR-FIM-SYS-{uuid.uuid4().hex[:8]}",
                            agent_id=agent_id,
                            hostname=hostname,
                            severity="CRITICAL",
                            mitre_technique="T1565.001",
                            title=f"Critical Security File Altered: {fim.file_path}",
                            description=(
                                f"Operation '{fim.operation}' executed on sensitive system path '{fim.file_path}'. "
                                f"Previous Hash: {fim.sha256_before or 'N/A'}, New Hash: {fim.sha256_after or 'N/A'}."
                            ),
                            evidence={
                                "file_path": fim.file_path,
                                "operation": fim.operation,
                                "user": fim.user,
                                "process_id": fim.process_id,
                            },
                        )
                    )
                    break

            # 2. Ransomware Extension Canary / Mass Renaming
            if any(path_lower.endswith(ext) for ext in [".locked", ".crypto", ".lockbit", ".wncry"]):
                alerts.append(
                    EDRBehavioralAlert(
                        alert_id=f"EDR-RANSOM-FILE-{uuid.uuid4().hex[:8]}",
                        agent_id=agent_id,
                        hostname=hostname,
                        severity="CRITICAL",
                        mitre_technique="T1486",
                        title="Ransomware Encrypted File Extension Detected",
                        description=f"File '{fim.file_path}' was renamed with a known ransomware extension pattern.",
                        evidence={"file_path": fim.file_path, "operation": fim.operation},
                    )
                )

        return alerts

    def analyze_network_sockets(self, agent_id: str, hostname: str, events: List[NetworkSocketEvent]) -> List[EDRBehavioralAlert]:
        """Inspect network sockets established by endpoint processes."""
        alerts: List[EDRBehavioralAlert] = []

        for sock in events:
            proc_lower = sock.process_name.lower()
            
            # Shell or Scripting Engine establishing outbound network socket
            if proc_lower in ("powershell.exe", "cmd.exe", "bash", "sh", "nc") and sock.state == "ESTABLISHED":
                # Check if non-private remote IP
                remote = sock.remote_ip
                is_internal = (
                    remote.startswith("10.")
                    or remote.startswith("192.168.")
                    or remote.startswith("172.16.")
                    or remote.startswith("127.")
                )
                if not is_internal:
                    alerts.append(
                        EDRBehavioralAlert(
                            alert_id=f"EDR-SHELL-C2-{uuid.uuid4().hex[:8]}",
                            agent_id=agent_id,
                            hostname=hostname,
                            severity="CRITICAL",
                            mitre_technique="T1071",
                            title=f"Command Shell Process Connected to External C2 IP ({remote})",
                            description=(
                                f"Process '{sock.process_name}' (PID {sock.pid}) established outbound connection "
                                f"to external IP '{remote}:{sock.remote_port}'. Classic reverse shell or C2 beacon."
                            ),
                            evidence={
                                "process_name": sock.process_name,
                                "pid": sock.pid,
                                "remote_ip": remote,
                                "remote_port": sock.remote_port,
                            },
                        )
                    )

        return alerts
