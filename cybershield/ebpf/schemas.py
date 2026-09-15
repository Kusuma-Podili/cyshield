"""CyberShield Enterprise - Cloud-Native eBPF Schemas.
Data contracts for kernel-space ring buffer events, syscall interception,
container isolation contexts, and LSM enforcement policies.
"""

from enum import Enum
from typing import Dict, List, Optional, Any
from datetime import datetime, timezone
from pydantic import BaseModel, Field


class BPFHookType(str, Enum):
    KPROBE = "KPROBE"
    KRETPROBE = "KRETPROBE"
    TRACEPOINT = "TRACEPOINT"
    RAW_TRACEPOINT = "RAW_TRACEPOINT"
    LSM_HOOK = "LSM_HOOK"
    SOCKET_FILTER = "SOCKET_FILTER"
    XDP_INGRESS = "XDP_INGRESS"


class SyscallType(str, Enum):
    SYS_EXECVE = "sys_execve"
    SYS_EXECVEAT = "sys_execveat"
    SYS_PTRACE = "sys_ptrace"
    SYS_BPF = "sys_bpf"
    SYS_CONNECT = "sys_connect"
    SYS_ACCEPT = "sys_accept"
    SYS_OPENAT = "sys_openat"
    SYS_UNSHARE = "sys_unshare"
    SYS_SETNS = "sys_setns"
    SYS_INIT_MODULE = "sys_init_module"
    SYS_FINIT_MODULE = "sys_finit_module"
    SYS_MEMFD_CREATE = "sys_memfd_create"
    SYS_SOCKET = "sys_socket"


class KernelAnomalyType(str, Enum):
    CONTAINER_ESCAPE_ATTEMPT = "CONTAINER_ESCAPE_ATTEMPT"
    MEMFD_FILELESS_EXECUTION = "MEMFD_FILELESS_EXECUTION"
    PTRACE_CODE_INJECTION = "PTRACE_CODE_INJECTION"
    PRIVILEGE_ESCALATION_RING0 = "PRIVILEGE_ESCALATION_RING0"
    HIDDEN_KERNEL_MODULE_LOAD = "HIDDEN_KERNEL_MODULE_LOAD"
    ROOTKIT_SYSCALL_HOOK = "ROOTKIT_SYSCALL_HOOK"
    REVERSE_SHELL_ESTABLISHED = "REVERSE_SHELL_ESTABLISHED"
    UNAUTHORIZED_CAPABILITY_OVERWRITE = "UNAUTHORIZED_CAPABILITY_OVERWRITE"


class EnforcementMode(str, Enum):
    AUDIT_ONLY = "AUDIT_ONLY"
    ENFORCE_KILL = "ENFORCE_KILL"
    ENFORCE_EPERM = "ENFORCE_EPERM"


class ContainerContext(BaseModel):
    """Metadata regarding container and cgroup runtime environment."""
    container_id: Optional[str] = Field(default=None, description="Container runtime ID (Docker/containerd/CRI-O)")
    pod_name: Optional[str] = Field(default=None, description="Kubernetes Pod name")
    namespace: Optional[str] = Field(default="default", description="K8s namespace")
    image: Optional[str] = Field(default=None, description="Container base image tag")
    cgroup_path: Optional[str] = Field(default=None, description="cgroup v2 hierarchy path")
    is_privileged: bool = Field(default=False, description="Container execution in privileged mode")
    capabilities: List[str] = Field(default_factory=list, description="Linux capabilities granted")


class KernelEvent(BaseModel):
    """Low-level kernel event captured via eBPF ring buffer."""
    event_id: str = Field(..., description="Unique kernel event UUID")
    timestamp_ns: int = Field(..., description="Kernel monotonic boot timestamp in nanoseconds")
    host_id: str = Field(default="host-node-01")
    pid: int = Field(..., description="Host Process ID")
    tid: int = Field(..., description="Thread ID")
    ppid: int = Field(..., description="Parent Process ID")
    uid: int = Field(..., description="Real User ID")
    euid: int = Field(..., description="Effective User ID")
    gid: int = Field(..., description="Group ID")
    comm: str = Field(..., description="Process binary command name (task_struct->comm)")
    nodename: str = Field(default="k8s-worker-prod-01")
    container: Optional[ContainerContext] = None
    syscall: SyscallType
    hook_type: BPFHookType = BPFHookType.TRACEPOINT
    args: Dict[str, Any] = Field(default_factory=dict, description="Captured syscall registers / arguments")
    ret_val: int = Field(default=0, description="Syscall return status code")
    duration_ns: int = Field(default=0, description="Syscall execution latency")
    created_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class KernelEnforcementAction(BaseModel):
    """Kernel LSM / cgroup enforcement action executed against an adversary."""
    action_id: str
    target_pid: int
    container_id: Optional[str] = None
    action_type: str = Field(..., description="SIGKILL, FREEZE_CGROUP, EPERM_OVERRIDE")
    status: str = Field(default="SUCCESS")
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    details: Dict[str, Any] = Field(default_factory=dict)


class KernelSecurityAlert(BaseModel):
    """Alert raised from kernel-space behavioral anomaly detection."""
    alert_id: str
    anomaly_type: KernelAnomalyType
    severity: str = Field(default="HIGH", description="LOW, MEDIUM, HIGH, CRITICAL")
    confidence: float = Field(default=0.95, ge=0.0, le=1.0)
    pid: int
    comm: str
    host_id: str
    container_id: Optional[str] = None
    mitre_technique: str
    forensic_reason: str
    raw_event: KernelEvent
    recommended_action: str
    action_executed: Optional[KernelEnforcementAction] = None
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class BPFProgramSpec(BaseModel):
    """Specification of an eBPF probe program loaded into kernel memory."""
    prog_name: str
    hook_point: str
    hook_type: BPFHookType
    instructions_count: int = Field(..., ge=1, le=10000000)
    maps: List[str] = Field(default_factory=list)
    verifier_passed: bool = True
    lsm_mode: EnforcementMode = EnforcementMode.AUDIT_ONLY
    loaded_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class RingBufferMetrics(BaseModel):
    """Throughput and performance metrics for the eBPF event pipeline."""
    total_events_ingested: int
    ring_buffer_drops: int
    active_probes_count: int
    alerts_generated: int
    enforcement_actions_taken: int
    enforcement_mode: EnforcementMode
    uptime_seconds: float
