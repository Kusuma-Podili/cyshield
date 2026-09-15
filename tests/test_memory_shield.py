"""Tests for CyberShield Enterprise - Autonomous Zero-Day Exploit Mitigation & Memory Shield.
Verifies ROP gadget chain detection, Shadow Stack return address verification,
Stack Canary integrity checks, Heap Spray / NOP sled mitigation, and REST API endpoints.
"""

import json
import pytest
from starlette.testclient import TestClient

from cybershield.api.server import app
from cybershield.shield.schemas import (
    ExploitTechnique,
    ShieldAction,
    InstructionTraceItem,
    TraceAuditRequest,
    StackFrameCheckRequest,
    HeapBufferAuditRequest,
)
from cybershield.shield.mitigator import MemoryShieldMitigator


@pytest.fixture
def client():
    return TestClient(app)


@pytest.fixture
def mitigator():
    return MemoryShieldMitigator()


# =========================================================================
# Unit Tests: Memory Exploit Mitigations
# =========================================================================

def test_detect_rop_gadget_chain(mitigator):
    # Construct 3 consecutive short gadgets terminating in 'ret' (0xc3)
    instructions = [
        # Gadget 1: pop rax; ret
        InstructionTraceItem(address="0x7ffd1000", mnemonic="pop rax", bytes_hex="58"),
        InstructionTraceItem(address="0x7ffd1001", mnemonic="ret", bytes_hex="c3"),
        # Gadget 2: pop rdi; ret
        InstructionTraceItem(address="0x7ffd1010", mnemonic="pop rdi", bytes_hex="5f"),
        InstructionTraceItem(address="0x7ffd1011", mnemonic="ret", bytes_hex="c3"),
        # Gadget 3: xchg rax, rsp; ret
        InstructionTraceItem(address="0x7ffd1020", mnemonic="xchg rax, rsp", bytes_hex="4887e0"),
        InstructionTraceItem(address="0x7ffd1023", mnemonic="ret", bytes_hex="c3"),
    ]

    req = TraceAuditRequest(
        process_id=4120,
        thread_id=1,
        process_name="vulnerable_daemon.exe",
        instructions=instructions,
    )

    alert = mitigator.inspect_execution_trace(req)
    assert alert is not None
    assert alert.exploit_technique == ExploitTechnique.ROP_CHAIN_EXECUTION
    assert alert.action_taken == ShieldAction.BLOCK_AND_TERMINATE
    assert "T1055" in alert.mitre_technique
    assert mitigator.rop_counter == 1


def test_benign_instruction_trace_no_alert(mitigator):
    # Standard function with prologue and normal execution
    instructions = [
        InstructionTraceItem(address="0x401000", mnemonic="push rbp", bytes_hex="55"),
        InstructionTraceItem(address="0x401001", mnemonic="mov rbp, rsp", bytes_hex="4889e5"),
        InstructionTraceItem(address="0x401004", mnemonic="sub rsp, 0x20", bytes_hex="4883ec20"),
        InstructionTraceItem(address="0x401008", mnemonic="mov eax, 1", bytes_hex="b801000000"),
        InstructionTraceItem(address="0x40100d", mnemonic="pop rbp", bytes_hex="5d"),
        InstructionTraceItem(address="0x40100e", mnemonic="ret", bytes_hex="c3"),
    ]

    req = TraceAuditRequest(
        process_id=2048,
        thread_id=2,
        process_name="clean_app.exe",
        instructions=instructions,
    )

    alert = mitigator.inspect_execution_trace(req)
    assert alert is None


def test_stack_canary_corruption_detection(mitigator):
    req = StackFrameCheckRequest(
        process_id=3090,
        thread_id=5,
        current_return_address="0x00401234",
        expected_shadow_address="0x00401234",
        canary_value="0xdeadbeef",
        expected_canary="0xaabbccdd",
    )

    alert = mitigator.verify_stack_frame_integrity(req)
    assert alert is not None
    assert alert.exploit_technique == ExploitTechnique.BUFFER_OVERFLOW_CANARY_CORRUPTION
    assert alert.action_taken == ShieldAction.BLOCK_AND_TERMINATE


def test_shadow_stack_mismatch_stack_pivot(mitigator):
    req = StackFrameCheckRequest(
        process_id=3090,
        thread_id=5,
        current_return_address="0x7ffe9900",  # Hijacked pointer!
        expected_shadow_address="0x00401234",  # Legitimate return
        canary_value="0xaabbccdd",
        expected_canary="0xaabbccdd",
    )

    alert = mitigator.verify_stack_frame_integrity(req)
    assert alert is not None
    assert alert.exploit_technique == ExploitTechnique.STACK_PIVOT
    assert alert.severity == "CRITICAL"


def test_heap_nop_sled_detection(mitigator):
    # 20 consecutive 0x90 bytes ("90" * 20 = 40 hex chars) followed by shellcode
    nop_sled_hex = "90" * 20 + "31c050682f2f7368"
    req = HeapBufferAuditRequest(
        process_id=5500,
        buffer_address="0x0a1b2000",
        buffer_bytes_hex=nop_sled_hex,
        allocation_size_bytes=4096,
    )

    alert = mitigator.audit_heap_buffer(req)
    assert alert is not None
    assert alert.exploit_technique == ExploitTechnique.NOP_SLED_ALIGNMENT
    assert alert.action_taken == ShieldAction.NEUTRALIZE_PAYLOAD


def test_heap_spray_pattern_detection(mitigator):
    # Repetitive pattern "0c0c0c0c" repeated 12 times
    spray_hex = "0c0c0c0c" * 12
    req = HeapBufferAuditRequest(
        process_id=6120,
        buffer_address="0x0c0c0c0c",
        buffer_bytes_hex=spray_hex,
        allocation_size_bytes=64_000_000,
    )

    alert = mitigator.audit_heap_buffer(req)
    assert alert is not None
    assert alert.exploit_technique == ExploitTechnique.HEAP_SPRAY_SHELLCODE
    assert alert.severity == "CRITICAL"


def test_shield_status_report(mitigator):
    # Trigger one ROP and one Canary alert
    mitigator.inspect_execution_trace(
        TraceAuditRequest(
            process_id=999,
            thread_id=1,
            process_name="test.exe",
            instructions=[
                InstructionTraceItem(address="0x1", mnemonic="ret", bytes_hex="c3"),
                InstructionTraceItem(address="0x2", mnemonic="ret", bytes_hex="c3"),
                InstructionTraceItem(address="0x3", mnemonic="ret", bytes_hex="c3"),
            ],
        )
    )
    mitigator.verify_stack_frame_integrity(
        StackFrameCheckRequest(
            process_id=999,
            thread_id=1,
            current_return_address="0x10",
            expected_shadow_address="0x10",
            canary_value="0xbad",
            expected_canary="0xgood",
        )
    )

    status = mitigator.get_status_report()
    assert status.total_exploits_blocked >= 2
    assert status.rop_gadgets_intercepted >= 1
    assert status.stack_pivots_prevented >= 1


# =========================================================================
# Integration Tests: FastAPI REST Endpoints
# =========================================================================

def test_api_inspect_trace(client):
    req = TraceAuditRequest(
        process_id=7777,
        thread_id=1,
        process_name="api_test.exe",
        instructions=[
            InstructionTraceItem(address="0x10", mnemonic="pop rbx", bytes_hex="5b"),
            InstructionTraceItem(address="0x11", mnemonic="ret", bytes_hex="c3"),
            InstructionTraceItem(address="0x20", mnemonic="pop rcx", bytes_hex="59"),
            InstructionTraceItem(address="0x21", mnemonic="ret", bytes_hex="c3"),
            InstructionTraceItem(address="0x30", mnemonic="pop rdx", bytes_hex="5a"),
            InstructionTraceItem(address="0x31", mnemonic="ret", bytes_hex="c3"),
        ],
    )
    resp = client.post(
        "/api/v1/shield/inspect/trace",
        json=json.loads(req.model_dump_json()),
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["status"] == "trace_analyzed"
    assert data["exploit_intercepted"] is True


def test_api_inspect_stack(client):
    req = StackFrameCheckRequest(
        process_id=7777,
        thread_id=1,
        current_return_address="0xdeadbeef",
        expected_shadow_address="0x12345678",
        canary_value="0x11223344",
        expected_canary="0x11223344",
    )
    resp = client.post(
        "/api/v1/shield/inspect/stack",
        json=json.loads(req.model_dump_json()),
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["corruption_detected"] is True


def test_api_inspect_heap_and_status(client):
    req = HeapBufferAuditRequest(
        process_id=7777,
        buffer_address="0x20000000",
        buffer_bytes_hex="90" * 32,
        allocation_size_bytes=8192,
    )
    heap_resp = client.post(
        "/api/v1/shield/inspect/heap",
        json=json.loads(req.model_dump_json()),
    )
    assert heap_resp.status_code == 200
    assert heap_resp.json()["spray_detected"] is True

    # Events endpoint
    events_resp = client.get("/api/v1/shield/events")
    assert events_resp.status_code == 200
    events = events_resp.json()
    assert len(events) >= 1

    # Status endpoint
    status_resp = client.get("/api/v1/shield/status")
    assert status_resp.status_code == 200
    status_data = status_resp.json()
    assert status_data["total_exploits_blocked"] >= 1
