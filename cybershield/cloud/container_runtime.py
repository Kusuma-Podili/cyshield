"""Container Runtime Threat & Breakout Detection Engine (CWPP).

Analyzes container processes, mount topologies, Linux capabilities, and runtime behaviors
to detect container escapes, cryptomining malware, malicious execution from RAM (/dev/shm),
and Docker socket daemon abuse.
Mapped to MITRE ATT&CK Matrix for Containers.
"""

from __future__ import annotations

import logging
import re
import uuid
from typing import List

from cybershield.cloud.schemas import (
    CloudFindingSeverity,
    ContainerProcessInspectRequest,
    ContainerRuntimeAlert,
)

logger = logging.getLogger("cybershield.cloud.runtime")

DANGEROUS_HOST_MOUNTS = [
    "/var/run/docker.sock",
    "/run/containerd/containerd.sock",
    "/run/k3s/containerd/containerd.sock",
    "/proc/sysrq-trigger",
    "/etc/shadow",
    "/etc/passwd",
    "/root",
    "/",
]

CRYPTOMINING_SIGNATURES = [
    r"\bxmrig\b",
    r"\bminerd\b",
    r"\bcpuminer\b",
    r"\bstratum\+(tcp|udp|ssl)://",
    r"\bmonero\b",
    r"\bnicehash\b",
    r"\bethminer\b",
    r"\bpool\.minexmr\.com\b",
    r"\bxmr-pool\b",
]

BREAKOUT_COMMANDS = [
    (r"\bnsenter\s+--target\s+1\b", "Host namespace breakout via nsenter PID 1"),
    (r"\bnsenter\s+-t\s+1\b", "Host namespace breakout via nsenter -t 1"),
    (r"\b(insmod|modprobe)\b", "Linux Kernel module injection from container"),
    (r"\bchroot\s+/host\b", "Chroot host filesystem breakout"),
    (r"\bmknod\s+.*\bc\b", "Device file creation for raw device access"),
    (r"release_agent", "cgroup release_agent container escape vector"),
]

SUSPICIOUS_EXEC_PATHS = [
    "/dev/shm",
    "/tmp",
    "/var/tmp",
    "/run/user",
]

DANGEROUS_CAPS = {
    "CAP_SYS_ADMIN": "Full administrative kernel access, bypasses isolation barriers",
    "CAP_SYS_PTRACE": "Process trace and memory inspection across host boundary",
    "CAP_SYS_RAWIO": "Direct raw I/O port and memory access",
    "CAP_NET_ADMIN": "Network interface and firewall manipulation",
    "CAP_DAC_OVERRIDE": "Bypass file read, write, and execute permission checks",
    "ALL": "Unrestricted Linux kernel capabilities granted",
}


class ContainerRuntimeDetector:
    """Enterprise detector for CWPP container runtime threats."""

    def __init__(self) -> None:
        self.crypto_regexes = [re.compile(pat, re.IGNORECASE) for pat in CRYPTOMINING_SIGNATURES]
        self.breakout_regexes = [(re.compile(pat, re.IGNORECASE), desc) for pat, desc in BREAKOUT_COMMANDS]

    def inspect_process(self, req: ContainerProcessInspectRequest) -> List[ContainerRuntimeAlert]:
        """Inspect a running process and its execution context within a container."""
        alerts: List[ContainerRuntimeAlert] = []

        # 1. Check breakout binaries and escape patterns
        alerts.extend(self._detect_container_breakout_commands(req))

        # 2. Check cryptomining signatures
        alerts.extend(self._detect_cryptominers(req))

        # 3. Check dangerous host socket / root mounts
        alerts.extend(self._detect_dangerous_mounts(req))

        # 4. Check execution from RAM / temp paths
        alerts.extend(self._detect_suspicious_path_execution(req))

        # 5. Check excessive Linux capabilities
        alerts.extend(self._detect_dangerous_capabilities(req))

        return alerts

    def _detect_container_breakout_commands(self, req: ContainerProcessInspectRequest) -> List[ContainerRuntimeAlert]:
        alerts: List[ContainerRuntimeAlert] = []
        for reg, desc in self.breakout_regexes:
            if reg.search(req.command_line):
                alerts.append(
                    ContainerRuntimeAlert(
                        alert_id=f"CWPP-ESC-{uuid.uuid4().hex[:8]}",
                        container_id=req.container_id,
                        image_name=req.image_name,
                        pod_name=req.pod_name,
                        namespace=req.namespace,
                        severity=CloudFindingSeverity.CRITICAL,
                        title=f"Container Breakout Attempt: {desc}",
                        description=(
                            f"Process in container '{req.container_id}' executed breakout command: '{req.command_line}'. "
                            "This technique aims to escape container cgroups and access the host node."
                        ),
                        mitre_technique="T1611 - Escape to Host",
                        evidence={"command_line": req.command_line, "matched_pattern": reg.pattern},
                    )
                )
        return alerts

    def _detect_cryptominers(self, req: ContainerProcessInspectRequest) -> List[ContainerRuntimeAlert]:
        alerts: List[ContainerRuntimeAlert] = []
        for reg in self.crypto_regexes:
            if reg.search(req.command_line):
                alerts.append(
                    ContainerRuntimeAlert(
                        alert_id=f"CWPP-MINER-{uuid.uuid4().hex[:8]}",
                        container_id=req.container_id,
                        image_name=req.image_name,
                        pod_name=req.pod_name,
                        namespace=req.namespace,
                        severity=CloudFindingSeverity.CRITICAL,
                        title="Cryptomining Activity Detected in Container",
                        description=(
                            f"Process '{req.command_line}' matches cryptocurrency mining indicators. "
                            "Hijacking CPU/GPU compute resources."
                        ),
                        mitre_technique="T1496 - Resource Hijacking",
                        evidence={"command_line": req.command_line, "signature": reg.pattern},
                    )
                )
                break
        return alerts

    def _detect_dangerous_mounts(self, req: ContainerProcessInspectRequest) -> List[ContainerRuntimeAlert]:
        alerts: List[ContainerRuntimeAlert] = []
        for mount in req.mounts:
            for dangerous in DANGEROUS_HOST_MOUNTS:
                if mount == dangerous or mount.startswith(dangerous + "/"):
                    sev = (
                        CloudFindingSeverity.CRITICAL
                        if "docker.sock" in mount or "containerd.sock" in mount or mount == "/"
                        else CloudFindingSeverity.HIGH
                    )
                    alerts.append(
                        ContainerRuntimeAlert(
                            alert_id=f"CWPP-MNT-{uuid.uuid4().hex[:8]}",
                            container_id=req.container_id,
                            image_name=req.image_name,
                            pod_name=req.pod_name,
                            namespace=req.namespace,
                            severity=sev,
                            title=f"Sensitive Host Path Mounted into Container: {mount}",
                            description=(
                                f"Container '{req.container_id}' has dangerous host mount '{mount}'. "
                                "Allows full node compromise via daemon socket or host filesystem access."
                            ),
                            mitre_technique="T1611 - Escape to Host",
                            evidence={"mount": mount, "command_line": req.command_line},
                        )
                    )
        return alerts

    def _detect_suspicious_path_execution(self, req: ContainerProcessInspectRequest) -> List[ContainerRuntimeAlert]:
        alerts: List[ContainerRuntimeAlert] = []
        working_dir = req.working_dir or ""
        cmd = req.command_line

        for p in SUSPICIOUS_EXEC_PATHS:
            if working_dir.startswith(p) or f" {p}/" in cmd or cmd.startswith(f"{p}/"):
                alerts.append(
                    ContainerRuntimeAlert(
                        alert_id=f"CWPP-PATH-{uuid.uuid4().hex[:8]}",
                        container_id=req.container_id,
                        image_name=req.image_name,
                        pod_name=req.pod_name,
                        namespace=req.namespace,
                        severity=CloudFindingSeverity.HIGH,
                        title=f"Process Execution from Ephemeral/RAM Path ({p})",
                        description=(
                            f"Command '{cmd}' executed from RAM-backed directory '{p}'. "
                            "Adversaries frequently drop and execute staging payloads in memory or world-writable directories to avoid disk forensics."
                        ),
                        mitre_technique="T1059 - Command and Scripting Interpreter",
                        evidence={"working_dir": working_dir, "command_line": cmd},
                    )
                )
                break
        return alerts

    def _detect_dangerous_capabilities(self, req: ContainerProcessInspectRequest) -> List[ContainerRuntimeAlert]:
        alerts: List[ContainerRuntimeAlert] = []
        for cap in req.capabilities:
            cap_upper = cap.upper()
            if cap_upper in DANGEROUS_CAPS:
                alerts.append(
                    ContainerRuntimeAlert(
                        alert_id=f"CWPP-CAP-{uuid.uuid4().hex[:8]}",
                        container_id=req.container_id,
                        image_name=req.image_name,
                        pod_name=req.pod_name,
                        namespace=req.namespace,
                        severity=CloudFindingSeverity.HIGH,
                        title=f"Excessive Linux Capability Attached: {cap_upper}",
                        description=(
                            f"Container possesses dangerous capability '{cap_upper}'. "
                            f"{DANGEROUS_CAPS[cap_upper]}."
                        ),
                        mitre_technique="T1548 - Abuse Elevation Control Mechanism",
                        evidence={"capability": cap_upper, "user_id": req.user_id},
                    )
                )
        return alerts
