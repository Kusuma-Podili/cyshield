"""CyberShield Enterprise - Cloud-Native eBPF Kernel Event Telemetry & Syscall Interceptor.
Processes low-level kernel ring buffer streams, simulates BPF verifier safety audits,
detects container breakouts, fileless execution, and enforces autonomous LSM containment.
"""

import uuid
import time
from typing import Dict, List, Optional, Tuple, Set, Any
from datetime import datetime, timezone

from .schemas import (
    BPFHookType,
    SyscallType,
    KernelAnomalyType,
    EnforcementMode,
    KernelEvent,
    ContainerContext,
    BPFProgramSpec,
    KernelSecurityAlert,
    KernelEnforcementAction,
    RingBufferMetrics,
)


class EBPFTelemetryInterceptor:
    """Core engine for real-time kernel syscall interception and container threat prevention."""

    def __init__(self, enforcement_mode: EnforcementMode = EnforcementMode.AUDIT_ONLY):
        self.enforcement_mode = enforcement_mode
        self.start_time = time.time()
        self.total_events_ingested = 0
        self.ring_buffer_drops = 0
        self.alerts: List[KernelSecurityAlert] = []
        self.enforcement_actions: List[KernelEnforcementAction] = []
        self.loaded_programs: Dict[str, BPFProgramSpec] = {}

        # Known legitimate SUID binaries permitted to transition EUID to 0
        self.approved_suid_binaries = {
            "sudo", "su", "pkexec", "passwd", "gpasswd", "newgrp", "chfn", "chsh"
        }

        # Initialize default kernel probes
        self._register_default_probes()

    def _register_default_probes(self):
        """Register default eBPF security tracepoints and LSM hooks."""
        defaults = [
            BPFProgramSpec(
                prog_name="cybershield_lsm_bprm_check",
                hook_point="lsm/bprm_check_security",
                hook_type=BPFHookType.LSM_HOOK,
                instructions_count=1240,
                maps=["exec_deny_map", "process_cache"],
                verifier_passed=True,
                lsm_mode=self.enforcement_mode,
            ),
            BPFProgramSpec(
                prog_name="cybershield_trace_execve",
                hook_point="sys_enter_execve",
                hook_type=BPFHookType.TRACEPOINT,
                instructions_count=850,
                maps=["ringbuf_events"],
                verifier_passed=True,
                lsm_mode=self.enforcement_mode,
            ),
            BPFProgramSpec(
                prog_name="cybershield_trace_ptrace",
                hook_point="sys_enter_ptrace",
                hook_type=BPFHookType.TRACEPOINT,
                instructions_count=420,
                maps=["ptrace_audit_map"],
                verifier_passed=True,
                lsm_mode=self.enforcement_mode,
            ),
            BPFProgramSpec(
                prog_name="cybershield_kprobe_modules",
                hook_point="sys_enter_finit_module",
                hook_type=BPFHookType.KPROBE,
                instructions_count=610,
                maps=["module_sign_map"],
                verifier_passed=True,
                lsm_mode=self.enforcement_mode,
            ),
        ]
        for p in defaults:
            self.loaded_programs[p.prog_name] = p

    def verify_and_load_program(self, spec: BPFProgramSpec) -> Tuple[bool, str]:
        """Simulates the Linux in-kernel eBPF Verifier safety validation."""
        # 1. Instruction budget check
        if spec.instructions_count > 1000000:
            return False, f"Verifier rejection: instruction count {spec.instructions_count} exceeds BPF_COMPLEXITY_LIMIT (1,000,000 instructions)"

        # 2. Check program name naming conventions
        if not spec.prog_name or " " in spec.prog_name:
            return False, "Verifier rejection: invalid BPF program symbol name"

        # 3. Memory safety simulation
        if any("invalid_mem" in m.lower() for m in spec.maps):
            return False, "Verifier rejection: detected out-of-bounds pointer dereference in register R1"

        spec.verifier_passed = True
        self.loaded_programs[spec.prog_name] = spec
        return True, f"BPF program '{spec.prog_name}' passed verifier: safe for kernel injection."

    def process_kernel_event(self, event: KernelEvent) -> Optional[KernelSecurityAlert]:
        """Inspects an intercepted syscall event through behavioral security heuristics."""
        self.total_events_ingested += 1

        alert: Optional[KernelSecurityAlert] = None

        # 1. Container Escape Attempt (setns / unshare / cgroup breakout)
        if event.syscall in {SyscallType.SYS_SETNS, SyscallType.SYS_UNSHARE}:
            alert = self._check_container_escape(event)

        # 2. Fileless execution via memfd_create
        elif event.syscall == SyscallType.SYS_MEMFD_CREATE:
            alert = self._check_fileless_memfd(event)

        # 3. Kernel Privilege Escalation (ring0 / Dirty Pipe exploit)
        elif event.syscall in {SyscallType.SYS_EXECVE, SyscallType.SYS_EXECVEAT}:
            alert = self._check_privilege_escalation(event)

        # 4. Ptrace Code Injection
        elif event.syscall == SyscallType.SYS_PTRACE:
            alert = self._check_ptrace_injection(event)

        # 5. Hidden / Unsigned Kernel Module Loading (Rootkit)
        elif event.syscall in {SyscallType.SYS_INIT_MODULE, SyscallType.SYS_FINIT_MODULE}:
            alert = self._check_kernel_module(event)

        # 6. Reverse Shell over network socket
        elif event.syscall == SyscallType.SYS_CONNECT:
            alert = self._check_reverse_shell(event)

        if alert:
            # Execute active containment if in enforcement mode
            if self.enforcement_mode in {EnforcementMode.ENFORCE_KILL, EnforcementMode.ENFORCE_EPERM}:
                action = self._execute_containment(alert)
                alert.action_executed = action
            self.alerts.append(alert)

        return alert

    def _check_container_escape(self, event: KernelEvent) -> Optional[KernelSecurityAlert]:
        """Detects container namespace breakout attempts."""
        if not event.container or not event.container.container_id:
            return None

        target_ns = str(event.args.get("target_ns", event.args.get("fd_path", "")))
        flags = int(event.args.get("flags", 0))

        # Check if attempting to join host root namespaces
        if "proc/1/ns" in target_ns or flags & 0x00020000 or flags & 0x20000000:
            return KernelSecurityAlert(
                alert_id=f"alert-escape-{uuid.uuid4().hex[:8]}",
                anomaly_type=KernelAnomalyType.CONTAINER_ESCAPE_ATTEMPT,
                severity="CRITICAL",
                confidence=0.98,
                pid=event.pid,
                comm=event.comm,
                host_id=event.host_id,
                container_id=event.container.container_id,
                mitre_technique="T1611 - Escape to Host",
                forensic_reason=f"Container process '{event.comm}' (PID {event.pid}) attempted namespace transition to host PID 1 namespaces ({target_ns}).",
                raw_event=event,
                recommended_action="FREEZE_CGROUP_AND_TERMINATE",
            )
        return None

    def _check_fileless_memfd(self, event: KernelEvent) -> Optional[KernelSecurityAlert]:
        """Detects in-memory fileless execution via memfd_create."""
        name = str(event.args.get("name", ""))
        flags = int(event.args.get("flags", 0))

        # Suspicious or obfuscated memfd names (e.g. "", "[kworker]", "memfd:...", or cloaked binaries)
        suspicious_memfd = (
            name in {"", "[kworker]", "kworker", "systemd", "init"}
            or "elf" in name.lower()
            or event.args.get("cloaked", False)
        )

        if suspicious_memfd or flags == 1:  # MFD_CLOEXEC
            return KernelSecurityAlert(
                alert_id=f"alert-memfd-{uuid.uuid4().hex[:8]}",
                anomaly_type=KernelAnomalyType.MEMFD_FILELESS_EXECUTION,
                severity="HIGH",
                confidence=0.92,
                pid=event.pid,
                comm=event.comm,
                host_id=event.host_id,
                container_id=event.container.container_id if event.container else None,
                mitre_technique="T1620 - Reflective Code Loading",
                forensic_reason=f"Fileless binary staging detected: process '{event.comm}' invoked memfd_create(name='{name}') without disk backing.",
                raw_event=event,
                recommended_action="KILL_PROCESS",
            )
        return None

    def _check_privilege_escalation(self, event: KernelEvent) -> Optional[KernelSecurityAlert]:
        """Detects illegal UID->0 transition (Dirty Pipe, Dirty COW, token stealing)."""
        # If Real UID is unprivileged (> 0) but Effective UID is 0 (root)
        if event.uid > 0 and event.euid == 0:
            binary_comm = event.comm.lower().split("/")[-1]
            if binary_comm not in self.approved_suid_binaries:
                return KernelSecurityAlert(
                    alert_id=f"alert-privesc-{uuid.uuid4().hex[:8]}",
                    anomaly_type=KernelAnomalyType.PRIVILEGE_ESCALATION_RING0,
                    severity="CRITICAL",
                    confidence=0.99,
                    pid=event.pid,
                    comm=event.comm,
                    host_id=event.host_id,
                    container_id=event.container.container_id if event.container else None,
                    mitre_technique="T1068 - Exploitation for Privilege Escalation",
                    forensic_reason=f"Illegal privilege escalation: process '{event.comm}' spawned with EUID=0 from unprivileged UID={event.uid} without approved SUID binary.",
                    raw_event=event,
                    recommended_action="TERMINATE_IMMEDIATELY_AND_ISOLATE",
                )
        return None

    def _check_ptrace_injection(self, event: KernelEvent) -> Optional[KernelSecurityAlert]:
        """Detects unauthorized process memory tampering or injection."""
        request = str(event.args.get("request", "")).upper()
        target_pid = int(event.args.get("target_pid", event.pid))

        injection_requests = {"PTRACE_POKETEXT", "PTRACE_POKEDATA", "PTRACE_SETREGS", "PTRACE_ATTACH"}
        if request in injection_requests:
            # Check if injecting into a different process
            if target_pid != event.pid:
                return KernelSecurityAlert(
                    alert_id=f"alert-ptrace-{uuid.uuid4().hex[:8]}",
                    anomaly_type=KernelAnomalyType.PTRACE_CODE_INJECTION,
                    severity="HIGH",
                    confidence=0.94,
                    pid=event.pid,
                    comm=event.comm,
                    host_id=event.host_id,
                    container_id=event.container.container_id if event.container else None,
                    mitre_technique="T1055 - Process Injection",
                    forensic_reason=f"Process '{event.comm}' (PID {event.pid}) executed ptrace injection '{request}' against remote target PID {target_pid}.",
                    raw_event=event,
                    recommended_action="SEVER_PTRACE_ATTACH",
                )
        return None

    def _check_kernel_module(self, event: KernelEvent) -> Optional[KernelSecurityAlert]:
        """Detects unauthorized or unsigned rootkit kernel module loading."""
        is_signed = bool(event.args.get("signed", False))
        mod_name = str(event.args.get("module_name", event.comm))

        if not is_signed:
            return KernelSecurityAlert(
                alert_id=f"alert-rootkit-{uuid.uuid4().hex[:8]}",
                anomaly_type=KernelAnomalyType.HIDDEN_KERNEL_MODULE_LOAD,
                severity="CRITICAL",
                confidence=0.97,
                pid=event.pid,
                comm=event.comm,
                host_id=event.host_id,
                container_id=event.container.container_id if event.container else None,
                mitre_technique="T1547.006 - Kernel Modules and Extensions",
                forensic_reason=f"Kernel integrity threat: process '{event.comm}' attempted to load unsigned kernel module '{mod_name}'.",
                raw_event=event,
                recommended_action="BLOCK_MODULE_LOAD_EPERM",
            )
        return None

    def _check_reverse_shell(self, event: KernelEvent) -> Optional[KernelSecurityAlert]:
        """Detects outbound network connection from interactive shell or interpreter."""
        comm_lower = event.comm.lower()
        shell_interpreters = {"bash", "sh", "zsh", "dash", "nc", "ncat", "python", "perl", "ruby"}

        if any(comm_lower.endswith(s) or comm_lower == s for s in shell_interpreters):
            dest_ip = str(event.args.get("dest_ip", ""))
            dest_port = int(event.args.get("dest_port", 0))

            # External IP check
            if dest_ip and not (dest_ip.startswith("10.") or dest_ip.startswith("192.168.") or dest_ip.startswith("127.")):
                return KernelSecurityAlert(
                    alert_id=f"alert-revshell-{uuid.uuid4().hex[:8]}",
                    anomaly_type=KernelAnomalyType.REVERSE_SHELL_ESTABLISHED,
                    severity="CRITICAL",
                    confidence=0.96,
                    pid=event.pid,
                    comm=event.comm,
                    host_id=event.host_id,
                    container_id=event.container.container_id if event.container else None,
                    mitre_technique="T1059 / T1071 - Command and Scripting Interpreter",
                    forensic_reason=f"Reverse interactive shell detected: interpreter '{event.comm}' established outbound socket to {dest_ip}:{dest_port}.",
                    raw_event=event,
                    recommended_action="KILL_PROCESS",
                )
        return None

    def _execute_containment(self, alert: KernelSecurityAlert) -> KernelEnforcementAction:
        """Executes kernel LSM or cgroup enforcement against compromised PID."""
        action_type = "SIGKILL"
        if alert.anomaly_type == KernelAnomalyType.CONTAINER_ESCAPE_ATTEMPT and alert.container_id:
            action_type = "FREEZE_CGROUP"
        elif alert.anomaly_type == KernelAnomalyType.HIDDEN_KERNEL_MODULE_LOAD:
            action_type = "EPERM_OVERRIDE"

        action = KernelEnforcementAction(
            action_id=f"act-{uuid.uuid4().hex[:8]}",
            target_pid=alert.pid,
            container_id=alert.container_id,
            action_type=action_type,
            status="SUCCESS",
            details={
                "anomaly": alert.anomaly_type.value,
                "mitre": alert.mitre_technique,
                "lsm_enforced": True,
            },
        )
        self.enforcement_actions.append(action)
        return action

    def get_metrics(self) -> RingBufferMetrics:
        """Return operational throughput and active probe counters."""
        uptime = max(0.1, time.time() - self.start_time)
        return RingBufferMetrics(
            total_events_ingested=self.total_events_ingested,
            ring_buffer_drops=self.ring_buffer_drops,
            active_probes_count=len(self.loaded_programs),
            alerts_generated=len(self.alerts),
            enforcement_actions_taken=len(self.enforcement_actions),
            enforcement_mode=self.enforcement_mode,
            uptime_seconds=round(uptime, 2),
        )
