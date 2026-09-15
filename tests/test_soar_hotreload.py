"""Tests for CyberShield Enterprise - SOAR Code Generator & Playbook Hot-Reload Sandbox.
Verifies Python AST security validation, restricted sandbox runtime, automated code synthesis,
zero-downtime hot-reloading with version rollback, and REST API routes.
"""

import json
import pytest
from starlette.testclient import TestClient

from cybershield.api.server import app
from cybershield.soar.hotreload.schemas import (
    PlaybookTriggerType,
    PlaybookExitStatus,
    DynamicPlaybookSpec,
)
from cybershield.soar.hotreload.sandbox import (
    PlaybookASTValidator,
    SandboxedPlaybookRuntime,
    PlaybookHotReloadManager,
)


@pytest.fixture
def client():
    return TestClient(app)


@pytest.fixture
def manager():
    return PlaybookHotReloadManager()


# =========================================================================
# Unit Tests: AST Security Validation
# =========================================================================

def test_ast_validation_valid_code():
    validator = PlaybookASTValidator()
    code = """
import json
import math

def run_playbook(context, actions):
    actions.log("Starting playbook")
    host = context.get("host_id")
    if host:
        actions.isolate_host(host)
"""
    res = validator.validate(code)
    assert res.is_safe is True
    assert len(res.detected_violations) == 0
    assert res.compiled_bytecode_hash is not None


def test_ast_validation_rejects_unapproved_imports():
    validator = PlaybookASTValidator()
    code_os = """
import os

def run_playbook(context, actions):
    os.system("rm -rf /")
"""
    res_os = validator.validate(code_os)
    assert res_os.is_safe is False
    assert any("unapproved module 'os'" in v for v in res_os.detected_violations)

    code_sub = """
from subprocess import Popen

def run_playbook(context, actions):
    pass
"""
    res_sub = validator.validate(code_sub)
    assert res_sub.is_safe is False
    assert any("unapproved module 'subprocess'" in v for v in res_sub.detected_violations)


def test_ast_validation_rejects_dangerous_calls_and_escape():
    validator = PlaybookASTValidator()
    code_eval = """
def run_playbook(context, actions):
    eval("1 + 1")
"""
    res = validator.validate(code_eval)
    assert res.is_safe is False
    assert any("eval()" in v for v in res.detected_violations)

    code_escape = """
def run_playbook(context, actions):
    x = ().__class__.__subclasses__()
"""
    res_escape = validator.validate(code_escape)
    assert res_escape.is_safe is False
    assert any("__subclasses__" in v for v in res_escape.detected_violations)


def test_ast_validation_rejects_missing_entrypoint():
    validator = PlaybookASTValidator()
    code = "x = 42"
    res = validator.validate(code)
    assert res.is_safe is False
    assert any("run_playbook" in v for v in res.detected_violations)


# =========================================================================
# Unit Tests: Sandboxed Runtime Execution
# =========================================================================

def test_sandboxed_runtime_execution_success():
    runtime = SandboxedPlaybookRuntime()
    code = """
def run_playbook(context, actions):
    host_id = context.get("host_id")
    actions.isolate_host(host_id)
    actions.block_ip(context.get("c2_ip"))
    actions.send_notification("soc-slack", "Host quarantined")
"""
    ctx = {"host_id": "ws-100", "c2_ip": "198.51.100.44"}
    status, logs, actions, err = runtime.execute(code, ctx)

    assert status == PlaybookExitStatus.SUCCESS
    assert "ISOLATE_HOST:ws-100" in actions
    assert "BLOCK_IP:198.51.100.44" in actions
    assert "NOTIFY:soc-slack" in actions
    assert err is None


def test_sandboxed_runtime_handles_exceptions():
    runtime = SandboxedPlaybookRuntime()
    code = """
def run_playbook(context, actions):
    actions.log("Starting error test")
    x = 1 / 0
"""
    status, logs, actions, err = runtime.execute(code, {})
    assert status == PlaybookExitStatus.RUNTIME_ERROR
    assert "ZeroDivisionError" in err


# =========================================================================
# Unit Tests: Code Synthesis, Hot-Reload & Rollback
# =========================================================================

def test_code_synthesis(manager):
    code = manager.synthesize_playbook_code(
        intent="When ransomware alert fires, isolate host, kill process, and block c2 ip",
        trigger_type=PlaybookTriggerType.ALERT_SEVERITY,
    )
    assert "def run_playbook" in code
    assert "isolate_host" in code
    assert "kill_process" in code
    assert "block_ip" in code

    # Synthesized code must pass AST validation!
    val = manager.validator.validate(code)
    assert val.is_safe is True


def test_hotreload_and_version_rollback(manager):
    code_v1 = """
def run_playbook(context, actions):
    actions.log("Version 1")
    actions.isolate_host(context.get("host_id"))
"""
    spec_v1 = DynamicPlaybookSpec(
        playbook_id="pb-quarantine",
        name="Quarantine Playbook",
        python_source_code=code_v1,
    )
    res1 = manager.compile_and_register(spec_v1)
    assert res1.is_safe is True
    assert manager.active_playbooks["pb-quarantine"].version == 1

    # Hot-reload update with Version 2
    code_v2 = """
def run_playbook(context, actions):
    actions.log("Version 2")
    actions.isolate_host(context.get("host_id"))
    actions.block_ip(context.get("ip"))
"""
    spec_v2 = DynamicPlaybookSpec(
        playbook_id="pb-quarantine",
        name="Quarantine Playbook Updated",
        python_source_code=code_v2,
    )
    res2 = manager.compile_and_register(spec_v2)
    assert res2.is_safe is True
    assert manager.active_playbooks["pb-quarantine"].version == 2

    # Execute Version 2
    exec_res = manager.execute_playbook("pb-quarantine", {"host_id": "ws-55", "ip": "10.0.0.1"})
    assert exec_res.playbook_version == 2
    assert "BLOCK_IP:10.0.0.1" in exec_res.actions_invoked

    # Roll back to Version 1
    rolled_back_spec = manager.rollback("pb-quarantine")
    assert rolled_back_spec.version == 1
    assert manager.active_playbooks["pb-quarantine"].version == 1

    # Execute after rollback (Version 1 does not block IP)
    exec_v1 = manager.execute_playbook("pb-quarantine", {"host_id": "ws-55", "ip": "10.0.0.1"})
    assert exec_v1.playbook_version == 1
    assert "BLOCK_IP:10.0.0.1" not in exec_v1.actions_invoked


# =========================================================================
# REST API Integration Tests
# =========================================================================

def test_api_soar_hotreload_lifecycle(client):
    # 1. Synthesize Code
    resp = client.post("/api/v1/soar/hotreload/synthesize?intent=Isolate%20host%20and%20notify%20slack")
    assert resp.status_code == 200
    synth_data = resp.json()
    assert "python_source_code" in synth_data
    code = synth_data["python_source_code"]

    # 2. Compile and Register Playbook
    spec_payload = {
        "playbook_id": "api-pb-dynamic-01",
        "name": "API Dynamic Containment",
        "version": 1,
        "trigger_type": "ALERT_SEVERITY",
        "python_source_code": code,
        "is_active": True,
        "author": "SecOps Lead",
    }
    resp = client.post("/api/v1/soar/hotreload/compile", json=spec_payload)
    assert resp.status_code == 201
    assert resp.json()["is_safe"] is True

    # 3. List Playbooks
    resp = client.get("/api/v1/soar/hotreload/playbooks")
    assert resp.status_code == 200
    pbs = resp.json()
    assert any(p["playbook_id"] == "api-pb-dynamic-01" for p in pbs)

    # 4. Execute Playbook
    context_payload = {"host_id": "ws-corp-99", "severity": "HIGH"}
    resp = client.post("/api/v1/soar/hotreload/execute/api-pb-dynamic-01", json=context_payload)
    assert resp.status_code == 200
    run_res = resp.json()
    assert run_res["exit_status"] == "SUCCESS"
    assert "ISOLATE_HOST:ws-corp-99" in run_res["actions_invoked"]

    # 5. Rejected Malicious Playbook
    bad_payload = {
        "playbook_id": "api-bad-pb",
        "name": "Exploitative Playbook",
        "version": 1,
        "trigger_type": "ALERT_SEVERITY",
        "python_source_code": "import os\ndef run_playbook(c, a):\n    os.system('id')",
        "is_active": True,
    }
    resp = client.post("/api/v1/soar/hotreload/compile", json=bad_payload)
    assert resp.status_code == 400
    assert "rejected" in resp.json()["detail"]["message"].lower()

    # 6. Retrieve Metrics
    resp = client.get("/api/v1/soar/hotreload/metrics")
    assert resp.status_code == 200
    metrics = resp.json()
    assert metrics["active_hotloaded_playbooks"] >= 1
    assert metrics["sandbox_rejections"] >= 1
