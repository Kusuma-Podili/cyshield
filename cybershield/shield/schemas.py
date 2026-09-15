"""CyberShield Enterprise - Autonomous Zero-Day Exploit Mitigation & Memory Shield Schemas.
Data contracts for ROP gadget chain detection, Shadow Stack integrity checks,
Heap Spray / NOP sled auditing, and Control-Flow Integrity (CFI) enforcement.
"""

from enum import Enum
from typing import Dict, List, Optional, Any
from datetime import datetime, timezone
from pydantic import BaseModel, Field


class ExploitTechnique(str, Enum):
    ROP_CHAIN_EXECUTION = "ROP_CHAIN_EXECUTION"
    STACK_PIVOT = "STACK_PIVOT"
    BUFFER_OVERFLOW_CANARY_CORRUPTION = "BUFFER_OVERFLOW_CANARY_CORRUPTION"
    HEAP_SPRAY_SHELLCODE = "HEAP_SPRAY_SHELLCODE"
    NOP_SLED_ALIGNMENT = "NOP_SLED_ALIGNMENT"
    CFI_BRANCH_VIOLATION = "CFI_BRANCH_VIOLATION"


class ShieldAction(str, Enum):
    BLOCK_AND_TERMINATE = "BLOCK_AND_TERMINATE"
    NEUTRALIZE_PAYLOAD = "NEUTRALIZE_PAYLOAD"
    FREEZE_THREAD = "FREEZE_THREAD"
    AUDIT_ALERT_ONLY = "AUDIT_ALERT_ONLY"


class InstructionTraceItem(BaseModel):
    """Single disassembled instruction from thread execution trace."""
    address: str = Field(..., description="Hex virtual address e.g. 0x7ffd1204")
    mnemonic: str = Field(..., description="Assembly mnemonic e.g. pop rax, ret, mov")
    op_str: Optional[str] = None
    bytes_hex: str = Field(..., description="Raw opcode bytes in hex")


class TraceAuditRequest(BaseModel):
    """Request to inspect suspicious thread instruction execution trace for ROP gadgets."""
    process_id: int
    thread_id: int
    process_name: str
    instructions: List[InstructionTraceItem]


class StackFrameCheckRequest(BaseModel):
    """Request to verify call stack return addresses and canary values against Shadow Stack."""
    process_id: int
    thread_id: int
    current_return_address: str
    expected_shadow_address: str
    canary_value: str
    expected_canary: str


class HeapBufferAuditRequest(BaseModel):
    """Request to inspect allocated memory buffer for heap spraying or NOP sleds."""
    process_id: int
    buffer_address: str
    buffer_bytes_hex: str
    allocation_size_bytes: int


class MemoryShieldAlert(BaseModel):
    """Security alert raised when a memory corruption exploit attempt is blocked."""
    alert_id: str
    process_id: int
    process_name: str
    exploit_technique: ExploitTechnique
    mitre_technique: str
    action_taken: ShieldAction
    severity: str = "CRITICAL"
    details: str
    mitigation_applied: str
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class ShieldStatusReport(BaseModel):
    """Consolidated status and statistics of memory exploit mitigations."""
    active_monitored_processes: int
    total_exploits_blocked: int
    rop_gadgets_intercepted: int
    stack_pivots_prevented: int
    heap_sprays_neutralized: int
    cfi_violations_caught: int
    memory_protection_level: str = "KERNEL_RING3_ENFORCED"
