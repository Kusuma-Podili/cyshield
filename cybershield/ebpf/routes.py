"""CyberShield Enterprise - Cloud-Native eBPF API Routes.
Exposes endpoints for kernel ring buffer telemetry ingestion, BPF program verifier checks,
kernel alerts, and autonomous LSM containment.
"""

from typing import Dict, List, Optional, Any
from fastapi import APIRouter, HTTPException, Query, status

from .schemas import (
    KernelEvent,
    KernelSecurityAlert,
    KernelEnforcementAction,
    BPFProgramSpec,
    RingBufferMetrics,
    EnforcementMode,
)
from .interceptor import EBPFTelemetryInterceptor

router = APIRouter(prefix="/api/v1/ebpf", tags=["eBPF Kernel Telemetry & LSM Interceptor"])

# Active singleton interceptor engine
_INTERCEPTOR = EBPFTelemetryInterceptor(enforcement_mode=EnforcementMode.AUDIT_ONLY)


@router.post("/events", response_model=Dict[str, Any], status_code=status.HTTP_201_CREATED)
def ingest_kernel_event(event: KernelEvent):
    """Ingest a raw low-level syscall or tracepoint event from the eBPF ring buffer."""
    alert = _INTERCEPTOR.process_kernel_event(event)
    return {
        "status": "ingested",
        "event_id": event.event_id,
        "alert_triggered": alert is not None,
        "alert_id": alert.alert_id if alert else None,
        "anomaly_type": alert.anomaly_type.value if alert else None,
        "containment_executed": alert.action_executed is not None if alert else False,
    }


@router.post("/programs/verify", response_model=Dict[str, Any])
def verify_bpf_program(spec: BPFProgramSpec):
    """Simulate in-kernel eBPF verifier safety checks and load program if passed."""
    passed, message = _INTERCEPTOR.verify_and_load_program(spec)
    if not passed:
        raise HTTPException(status_code=400, detail=message)
    return {
        "status": "verified_and_loaded",
        "prog_name": spec.prog_name,
        "hook_point": spec.hook_point,
        "message": message,
    }


@router.get("/programs", response_model=List[BPFProgramSpec])
def list_bpf_programs():
    """List all currently active eBPF tracepoints, kprobes, and LSM hooks."""
    return list(_INTERCEPTOR.loaded_programs.values())


@router.get("/alerts", response_model=List[KernelSecurityAlert])
def get_kernel_alerts(
    limit: int = Query(50, ge=1, le=500),
    anomaly_type: Optional[str] = None,
):
    """Retrieve all high-confidence kernel security alerts."""
    alerts = _INTERCEPTOR.alerts
    if anomaly_type:
        alerts = [a for a in alerts if a.anomaly_type.value == anomaly_type]
    return alerts[-limit:]


@router.post("/contain", response_model=KernelEnforcementAction)
def enforce_containment(
    target_pid: int = Query(..., description="Process ID to terminate"),
    container_id: Optional[str] = Query(None, description="Container ID to freeze"),
    action_type: str = Query("SIGKILL", description="SIGKILL, FREEZE_CGROUP, EPERM_OVERRIDE"),
):
    """Manually issue kernel-level containment against a compromised host PID or container."""
    action = KernelEnforcementAction(
        action_id=f"manual-{target_pid}",
        target_pid=target_pid,
        container_id=container_id,
        action_type=action_type,
        status="SUCCESS",
        details={"manual_operator_trigger": True},
    )
    _INTERCEPTOR.enforcement_actions.append(action)
    return action


@router.get("/metrics", response_model=RingBufferMetrics)
def get_ring_buffer_metrics():
    """Retrieve ring buffer ingestion rates, drops, and LSM enforcement metrics."""
    return _INTERCEPTOR.get_metrics()


@router.post("/mode")
def set_enforcement_mode(mode: EnforcementMode = Query(..., description="Target enforcement mode")):
    """Update active enforcement mode (AUDIT_ONLY, ENFORCE_KILL, ENFORCE_EPERM)."""
    _INTERCEPTOR.enforcement_mode = mode
    return {
        "status": "updated",
        "new_enforcement_mode": mode.value,
    }
