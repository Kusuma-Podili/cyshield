"""Tests for CyberShield Enterprise - Cloud-Native eBPF Telemetry & Syscall Interceptor.
Verifies kernel event processing, BPF verifier safety audits, container escape detection,
fileless execution tracking, privilege escalation intercepts, and REST API routes.
"""

import json
import pytest
from starlette.testclient import TestClient

from cybershield.api.server import app
from cybershield.ebpf.schemas import (
    BPFHookType,
    SyscallType,
    KernelAnomalyType,
    EnforcementMode,
    KernelEvent,
    ContainerContext,
    BPFProgramSpec,
)
from cybershield.ebpf.interceptor import EBPFTelemetryInterceptor


@pytest.fixture
def client():
    return TestClient(app)


@pytest.fixture
def interceptor():
    return EBPFTelemetryInterceptor(enforcement_mode=EnforcementMode.AUDIT_ONLY)


# =========================================================================
# Unit Tests: eBPF Verifier Simulator
# =========================================================================

def test_bpf_verifier_success(interceptor):
    valid_prog = BPFProgramSpec(
        prog_name="cybershield_xdp_drop",
        hook_point="xdp/ingress",
        hook_type=BPFHookType.XDP_INGRESS,
        instructions_count=450,
        maps=["block_ip_lpm"],
    )
    passed, msg = interceptor.verify_and_load_program(valid_prog)
    assert passed is True
    assert "safe for kernel injection" in msg
    assert "cybershield_xdp_drop" in interceptor.loaded_programs


def test_bpf_verifier_rejection_instruction_overflow(interceptor):
    huge_prog = BPFProgramSpec(
        prog_name="bad_huge_prog",
        hook_point="kprobe/sys_execve",
        hook_type=BPFHookType.KPROBE,
        instructions_count=1_500_000,
    )
    passed, msg = interceptor.verify_and_load_program(huge_prog)
    assert passed is False
    assert "exceeds BPF_COMPLEXITY_LIMIT" in msg


def test_bpf_verifier_rejection_invalid_memory(interceptor):
    bad_mem_prog = BPFProgramSpec(
        prog_name="bad_mem_prog",
        hook_point="tracepoint/sys_enter_openat",
        hook_type=BPFHookType.TRACEPOINT,
        instructions_count=120,
        maps=["invalid_mem_ref"],
    )
    passed, msg = interceptor.verify_and_load_program(bad_mem_prog)
    assert passed is False
    assert "out-of-bounds pointer" in msg


# =========================================================================
# Unit Tests: Syscall Threat Analyzers
# =========================================================================

def test_container_escape_detection(interceptor):
    container = ContainerContext(
        container_id="cgroup-k8s-pod-9941a",
        pod_name="payment-processor-pod",
        namespace="prod",
        image="company/payment:v2.1",
        is_privileged=True,
    )
    event = KernelEvent(
        event_id="evt-escape-001",
        timestamp_ns=1700000000123456,
        pid=14205,
        tid=14205,
        ppid=14000,
        uid=0,
        euid=0,
        gid=0,
        comm="nsenter",
        container=container,
        syscall=SyscallType.SYS_SETNS,
        args={"target_ns": "/proc/1/ns/mnt", "flags": 0},
    )

    alert = interceptor.process_kernel_event(event)
    assert alert is not None
    assert alert.anomaly_type == KernelAnomalyType.CONTAINER_ESCAPE_ATTEMPT
    assert alert.severity == "CRITICAL"
    assert "T1611" in alert.mitre_technique
    assert alert.container_id == "cgroup-k8s-pod-9941a"


def test_fileless_memfd_detection(interceptor):
    event = KernelEvent(
        event_id="evt-memfd-002",
        timestamp_ns=1700000000234567,
        pid=18921,
        tid=18921,
        ppid=18000,
        uid=1001,
        euid=1001,
        gid=1001,
        comm="dropper_elf",
        syscall=SyscallType.SYS_MEMFD_CREATE,
        args={"name": "[kworker]", "flags": 1},
    )

    alert = interceptor.process_kernel_event(event)
    assert alert is not None
    assert alert.anomaly_type == KernelAnomalyType.MEMFD_FILELESS_EXECUTION
    assert alert.severity == "HIGH"
    assert "T1620" in alert.mitre_technique


def test_kernel_privilege_escalation_detection(interceptor):
    # Process spawned shell with EUID=0 from regular user UID=1000 without sudo
    event = KernelEvent(
        event_id="evt-privesc-003",
        timestamp_ns=1700000000345678,
        pid=22010,
        tid=22010,
        ppid=22000,
        uid=1000,
        euid=0,
        gid=1000,
        comm="sh",
        syscall=SyscallType.SYS_EXECVE,
        args={"filename": "/bin/sh", "argv": ["sh"]},
    )

    alert = interceptor.process_kernel_event(event)
    assert alert is not None
    assert alert.anomaly_type == KernelAnomalyType.PRIVILEGE_ESCALATION_RING0
    assert alert.severity == "CRITICAL"
    assert "T1068" in alert.mitre_technique


def test_legitimate_suid_sudo_allowed(interceptor):
    # Legitimate sudo execution should NOT raise privilege escalation alert
    event = KernelEvent(
        event_id="evt-sudo-004",
        timestamp_ns=1700000000456789,
        pid=25010,
        tid=25010,
        ppid=24000,
        uid=1000,
        euid=0,
        gid=1000,
        comm="sudo",
        syscall=SyscallType.SYS_EXECVE,
        args={"filename": "/usr/bin/sudo", "argv": ["sudo", "apt", "update"]},
    )

    alert = interceptor.process_kernel_event(event)
    assert alert is None


def test_ptrace_code_injection_detection(interceptor):
    event = KernelEvent(
        event_id="evt-ptrace-005",
        timestamp_ns=1700000000567890,
        pid=29000,
        tid=29000,
        ppid=28000,
        uid=0,
        euid=0,
        gid=0,
        comm="inject_payload",
        syscall=SyscallType.SYS_PTRACE,
        args={"request": "PTRACE_POKETEXT", "target_pid": 1100, "addr": 0x7ffd0000},
    )

    alert = interceptor.process_kernel_event(event)
    assert alert is not None
    assert alert.anomaly_type == KernelAnomalyType.PTRACE_CODE_INJECTION
    assert "T1055" in alert.mitre_technique


def test_unsigned_kernel_module_detection(interceptor):
    event = KernelEvent(
        event_id="evt-mod-006",
        timestamp_ns=1700000000678901,
        pid=31000,
        tid=31000,
        ppid=30000,
        uid=0,
        euid=0,
        gid=0,
        comm="insmod",
        syscall=SyscallType.SYS_FINIT_MODULE,
        args={"module_name": "diamorphine_rootkit", "signed": False},
    )

    alert = interceptor.process_kernel_event(event)
    assert alert is not None
    assert alert.anomaly_type == KernelAnomalyType.HIDDEN_KERNEL_MODULE_LOAD
    assert "T1547.006" in alert.mitre_technique


def test_reverse_shell_detection(interceptor):
    event = KernelEvent(
        event_id="evt-rev-007",
        timestamp_ns=1700000000789012,
        pid=33000,
        tid=33000,
        ppid=32000,
        uid=1001,
        euid=1001,
        gid=1001,
        comm="bash",
        syscall=SyscallType.SYS_CONNECT,
        args={"dest_ip": "203.0.113.88", "dest_port": 4444},
    )

    alert = interceptor.process_kernel_event(event)
    assert alert is not None
    assert alert.anomaly_type == KernelAnomalyType.REVERSE_SHELL_ESTABLISHED


# =========================================================================
# Unit Tests: Autonomous LSM Containment Enforcement
# =========================================================================

def test_lsm_containment_mode_kill():
    enforcing_interceptor = EBPFTelemetryInterceptor(enforcement_mode=EnforcementMode.ENFORCE_KILL)

    container = ContainerContext(container_id="cgroup-escaped-pod", is_privileged=True)
    event = KernelEvent(
        event_id="evt-enforce-001",
        timestamp_ns=1700000000890123,
        pid=44000,
        tid=44000,
        ppid=43000,
        uid=0,
        euid=0,
        gid=0,
        comm="nsenter",
        container=container,
        syscall=SyscallType.SYS_SETNS,
        args={"target_ns": "/proc/1/ns/pid"},
    )

    alert = enforcing_interceptor.process_kernel_event(event)
    assert alert is not None
    assert alert.action_executed is not None
    assert alert.action_executed.action_type == "FREEZE_CGROUP"
    assert alert.action_executed.target_pid == 44000

    metrics = enforcing_interceptor.get_metrics()
    assert metrics.enforcement_actions_taken == 1
    assert metrics.enforcement_mode == EnforcementMode.ENFORCE_KILL


# =========================================================================
# REST API Integration Tests
# =========================================================================

def test_api_ebpf_lifecycle(client):
    # 1. Ingest normal syscall event
    benign_evt = KernelEvent(
        event_id="api-evt-001",
        timestamp_ns=1700000000999999,
        pid=55000,
        tid=55000,
        ppid=54000,
        uid=1000,
        euid=1000,
        gid=1000,
        comm="ls",
        syscall=SyscallType.SYS_OPENAT,
        args={"dirfd": -100, "pathname": "/var/log"},
    )
    resp = client.post("/api/v1/ebpf/events", json=json.loads(benign_evt.model_dump_json()))
    assert resp.status_code == 201
    assert resp.json()["alert_triggered"] is False

    # 2. Ingest malicious container breakout
    c = ContainerContext(container_id="cont-api-jail", is_privileged=True)
    breakout_evt = KernelEvent(
        event_id="api-evt-002",
        timestamp_ns=1700000001000000,
        pid=56000,
        tid=56000,
        ppid=55000,
        uid=0,
        euid=0,
        gid=0,
        comm="unshare",
        container=c,
        syscall=SyscallType.SYS_UNSHARE,
        args={"target_ns": "/proc/1/ns/mnt", "flags": 0x00020000},
    )
    resp = client.post("/api/v1/ebpf/events", json=json.loads(breakout_evt.model_dump_json()))
    assert resp.status_code == 201
    data = resp.json()
    assert data["alert_triggered"] is True
    assert data["anomaly_type"] == KernelAnomalyType.CONTAINER_ESCAPE_ATTEMPT.value

    # 3. Retrieve Kernel Alerts
    resp = client.get("/api/v1/ebpf/alerts")
    assert resp.status_code == 200
    alerts = resp.json()
    assert len(alerts) >= 1
    assert any(a["anomaly_type"] == KernelAnomalyType.CONTAINER_ESCAPE_ATTEMPT.value for a in alerts)

    # 4. Verify & Load Custom BPF Program
    prog_spec = BPFProgramSpec(
        prog_name="cybershield_sec_filter",
        hook_point="tracepoint/raw_syscalls/sys_enter",
        hook_type=BPFHookType.RAW_TRACEPOINT,
        instructions_count=650,
        maps=["audit_ring"],
    )
    resp = client.post("/api/v1/ebpf/programs/verify", json=json.loads(prog_spec.model_dump_json()))
    assert resp.status_code == 200
    assert resp.json()["status"] == "verified_and_loaded"

    # 5. List loaded programs
    resp = client.get("/api/v1/ebpf/programs")
    assert resp.status_code == 200
    progs = resp.json()
    assert len(progs) >= 4

    # 6. Manual Containment
    resp = client.post("/api/v1/ebpf/contain?target_pid=56000&action_type=SIGKILL")
    assert resp.status_code == 200
    contain_data = resp.json()
    assert contain_data["action_type"] == "SIGKILL"
    assert contain_data["target_pid"] == 56000

    # 7. Get Metrics
    resp = client.get("/api/v1/ebpf/metrics")
    assert resp.status_code == 200
    metrics = resp.json()
    assert metrics["total_events_ingested"] >= 2
    assert metrics["active_probes_count"] >= 4

    # 8. Set Enforcement Mode
    resp = client.post("/api/v1/ebpf/mode?mode=ENFORCE_KILL")
    assert resp.status_code == 200
    assert resp.json()["new_enforcement_mode"] == "ENFORCE_KILL"
