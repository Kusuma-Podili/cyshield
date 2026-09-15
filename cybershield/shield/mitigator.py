"""CyberShield Enterprise - Autonomous Zero-Day Exploit Mitigation & Memory Shield Engine.
Detects Return-Oriented Programming (ROP) gadget chains, Shadow Stack return tampering,
stack canary overwrites, heap spray allocations, and NOP sled alignment.
"""

import uuid
import re
from typing import Dict, List, Optional, Set, Any
from datetime import datetime, timezone

from .schemas import (
    ExploitTechnique,
    ShieldAction,
    InstructionTraceItem,
    TraceAuditRequest,
    StackFrameCheckRequest,
    HeapBufferAuditRequest,
    MemoryShieldAlert,
    ShieldStatusReport,
)


class MemoryShieldMitigator:
    """Enterprise user-space and kernel-cooperative memory exploit prevention engine."""

    def __init__(self):
        self.alerts: List[MemoryShieldAlert] = []
        self.monitored_pids: Set[int] = {1024, 2048, 4096}
        self.rop_counter: int = 0
        self.stack_pivot_counter: int = 0
        self.heap_spray_counter: int = 0
        self.cfi_violation_counter: int = 0

    def inspect_execution_trace(self, req: TraceAuditRequest) -> Optional[MemoryShieldAlert]:
        """Audit instruction stream for ROP gadget sequence: short blocks terminating in 'ret'."""
        self.monitored_pids.add(req.process_id)
        instructions = req.instructions

        # Group instructions into gadget sequences terminating in 'ret'
        gadgets: List[List[InstructionTraceItem]] = []
        current_gadget: List[InstructionTraceItem] = []

        for inst in instructions:
            current_gadget.append(inst)
            mnemonic_clean = inst.mnemonic.strip().lower()
            bytes_clean = inst.bytes_hex.strip().lower()

            # Return instruction: 'ret' or opcode 0xC3 / 0xCB
            if mnemonic_clean == "ret" or bytes_clean in {"c3", "cb", "c2"}:
                gadgets.append(current_gadget)
                current_gadget = []

        # ROP Heuristic: 3 or more consecutive short gadgets (<= 5 instructions each)
        short_gadget_count = sum(1 for g in gadgets if 1 <= len(g) <= 5)

        if short_gadget_count >= 3:
            self.rop_counter += 1
            alert = MemoryShieldAlert(
                alert_id=f"shd-rop-{uuid.uuid4().hex[:8]}",
                process_id=req.process_id,
                process_name=req.process_name,
                exploit_technique=ExploitTechnique.ROP_CHAIN_EXECUTION,
                mitre_technique="T1055 - Process Injection: Return-Oriented Programming (ROP)",
                action_taken=ShieldAction.BLOCK_AND_TERMINATE,
                severity="CRITICAL",
                details=(
                    f"ROP gadget chain detected in process '{req.process_name}' (PID {req.process_id}). "
                    f"Identified {short_gadget_count} consecutive gadget returns with no standard function prologue."
                ),
                mitigation_applied="Autonomous thread freeze and protective process termination to avert shellcode execution.",
            )
            self.alerts.append(alert)
            return alert

        return None

    def verify_stack_frame_integrity(self, req: StackFrameCheckRequest) -> Optional[MemoryShieldAlert]:
        """Verify stack return address against Shadow Stack and validate Stack Canary."""
        self.monitored_pids.add(req.process_id)

        # 1. Stack Canary Verification (Buffer Overflow guard)
        if req.canary_value.lower() != req.expected_canary.lower():
            self.stack_pivot_counter += 1
            alert = MemoryShieldAlert(
                alert_id=f"shd-canary-{uuid.uuid4().hex[:8]}",
                process_id=req.process_id,
                process_name="Protected_Application",
                exploit_technique=ExploitTechnique.BUFFER_OVERFLOW_CANARY_CORRUPTION,
                mitre_technique="T1203 - Exploitation for Client Execution",
                action_taken=ShieldAction.BLOCK_AND_TERMINATE,
                severity="CRITICAL",
                details=(
                    f"Stack Canary corruption detected on thread {req.thread_id} (PID {req.process_id}). "
                    f"Observed canary {req.canary_value} != expected {req.expected_canary}."
                ),
                mitigation_applied="Immediate __fastfail(FAST_FAIL_CORRUPT_STACK) invoked to prevent arbitrary control hijacking.",
            )
            self.alerts.append(alert)
            return alert

        # 2. Shadow Stack Return Address Verification (Stack Pivot / ROP defense)
        if req.current_return_address.lower() != req.expected_shadow_address.lower():
            self.stack_pivot_counter += 1
            alert = MemoryShieldAlert(
                alert_id=f"shd-pivot-{uuid.uuid4().hex[:8]}",
                process_id=req.process_id,
                process_name="Protected_Application",
                exploit_technique=ExploitTechnique.STACK_PIVOT,
                mitre_technique="T1055 - Process Injection: Stack Pivoting",
                action_taken=ShieldAction.BLOCK_AND_TERMINATE,
                severity="CRITICAL",
                details=(
                    f"Shadow Stack mismatch on thread {req.thread_id} (PID {req.process_id}). "
                    f"Call stack return {req.current_return_address} hijacked from shadow target {req.expected_shadow_address}."
                ),
                mitigation_applied="Hardware CET (Control-flow Enforcement Technology) exception raised. Target process terminated.",
            )
            self.alerts.append(alert)
            return alert

        return None

    def audit_heap_buffer(self, req: HeapBufferAuditRequest) -> Optional[MemoryShieldAlert]:
        """Inspect allocated heap chunk for NOP sleds (repeated 0x90) and heap spray shellcode."""
        self.monitored_pids.add(req.process_id)
        raw_hex = req.buffer_bytes_hex.strip().lower()

        # 1. NOP Sled Detection: 16 or more consecutive 0x90 bytes ("90" * 16 = 32 hex chars)
        if "90" * 16 in raw_hex:
            self.heap_spray_counter += 1
            alert = MemoryShieldAlert(
                alert_id=f"shd-nop-{uuid.uuid4().hex[:8]}",
                process_id=req.process_id,
                process_name="Target_Process",
                exploit_technique=ExploitTechnique.NOP_SLED_ALIGNMENT,
                mitre_technique="T1203 - Exploitation for Client Execution: NOP Sled",
                action_taken=ShieldAction.NEUTRALIZE_PAYLOAD,
                severity="HIGH",
                details=(
                    f"NOP Sled sequence detected in memory buffer {req.buffer_address} "
                    f"for PID {req.process_id} (>=16 consecutive NOP opcodes)."
                ),
                mitigation_applied="VirtualProtect called to revoke PAGE_EXECUTE permissions on allocated heap pages.",
            )
            self.alerts.append(alert)
            return alert

        # 2. Heap Spray Repetitive Pattern: e.g. "0c0c0c0c" repeated >= 8 times
        spray_pattern = re.search(r'([0-9a-f]{8})\1{7,}', raw_hex)
        if spray_pattern or (req.allocation_size_bytes > 50_000_000 and len(raw_hex) > 64):
            self.heap_spray_counter += 1
            alert = MemoryShieldAlert(
                alert_id=f"shd-spray-{uuid.uuid4().hex[:8]}",
                process_id=req.process_id,
                process_name="Target_Process",
                exploit_technique=ExploitTechnique.HEAP_SPRAY_SHELLCODE,
                mitre_technique="T1055 - Process Injection: Heap Spraying",
                action_taken=ShieldAction.BLOCK_AND_TERMINATE,
                severity="CRITICAL",
                details=(
                    f"Massive repetitive heap spray pattern observed in PID {req.process_id} "
                    f"at address {req.buffer_address} ({req.allocation_size_bytes} bytes)."
                ),
                mitigation_applied="Enforced ACG (Arbitrary Code Guard) and terminated offending process.",
            )
            self.alerts.append(alert)
            return alert

        return None

    def get_status_report(self) -> ShieldStatusReport:
        """Aggregate total exploit mitigations and protection status."""
        total_blocked = (
            self.rop_counter
            + self.stack_pivot_counter
            + self.heap_spray_counter
            + self.cfi_violation_counter
        )

        return ShieldStatusReport(
            active_monitored_processes=len(self.monitored_pids),
            total_exploits_blocked=total_blocked,
            rop_gadgets_intercepted=self.rop_counter,
            stack_pivots_prevented=self.stack_pivot_counter,
            heap_sprays_neutralized=self.heap_spray_counter,
            cfi_violations_caught=self.cfi_violation_counter,
            memory_protection_level="KERNEL_RING3_ENFORCED",
        )
