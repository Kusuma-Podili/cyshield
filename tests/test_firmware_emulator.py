"""Tests for CyberShield Enterprise - Autonomous Firmware Emulation & IoT Sandbox.
Verifies multi-architecture runtime simulation, dynamic CGI command injection fuzzing,
buffer overflow detection, default backdoor audits, and REST API endpoints.
"""

import json
from datetime import datetime, timezone
import pytest
from starlette.testclient import TestClient

from cybershield.api.server import app
from cybershield.iotemu.schemas import (
    CpuArchitecture,
    IoTVulnerabilityType,
    EmulateDaemonRequest,
    FuzzEndpointRequest,
)
from cybershield.iotemu.sandbox import FirmwareDynamicSandbox


@pytest.fixture
def client():
    return TestClient(app)


@pytest.fixture
def sandbox():
    return FirmwareDynamicSandbox()


# =========================================================================
# Unit Tests: Firmware Emulation & Dynamic Fuzzing
# =========================================================================

def test_start_emulation_session(sandbox):
    req = EmulateDaemonRequest(
        daemon_name="mini_httpd",
        architecture=CpuArchitecture.MIPS_32_EL,
        firmware_vendor="Enterprise-Gateway-MIPS",
        nvram_overrides={"http_username": "superadmin"},
        listening_port=8080,
    )

    session = sandbox.start_emulation_session(req)
    assert session.daemon_name == "mini_httpd"
    assert session.architecture == CpuArchitecture.MIPS_32_EL
    assert session.port == 8080
    assert session.session_id.startswith("iot-")
    assert session.nvram_keys_hooked >= 6


def test_fuzz_command_injection_cgi(sandbox):
    sess = sandbox.start_emulation_session(
        EmulateDaemonRequest(
            daemon_name="httpd",
            architecture=CpuArchitecture.ARM_V7_A,
        )
    )

    fuzz_req = FuzzEndpointRequest(
        endpoint_path="/cgi-bin/ping.cgi",
        http_method="POST",
        payload_input="127.0.0.1; cat /etc/shadow",
    )

    alert = sandbox.fuzz_endpoint(sess.session_id, fuzz_req)
    assert alert is not None
    assert alert.vulnerability_type == IoTVulnerabilityType.COMMAND_INJECTION_CGI
    assert alert.severity == "CRITICAL"
    assert "T1059.004" in alert.mitre_technique
    assert len(sandbox.vulnerabilities) == 1


def test_fuzz_buffer_overflow_memory_corruption(sandbox):
    sess = sandbox.start_emulation_session(
        EmulateDaemonRequest(
            daemon_name="upnpd",
            architecture=CpuArchitecture.MIPS_32_EB,
        )
    )

    oversized_payload = "A" * 1200
    fuzz_req = FuzzEndpointRequest(
        endpoint_path="/upnp/control",
        http_method="POST",
        payload_input=oversized_payload,
    )

    alert = sandbox.fuzz_endpoint(sess.session_id, fuzz_req)
    assert alert is not None
    assert alert.vulnerability_type == IoTVulnerabilityType.BUFFER_OVERFLOW_HTTP_HEADER
    assert alert.severity == "CRITICAL"


def test_fuzz_unauthenticated_nvram_dump(sandbox):
    sess = sandbox.start_emulation_session(
        EmulateDaemonRequest(
            daemon_name="httpd",
            architecture=CpuArchitecture.POWERPC_32,
        )
    )

    fuzz_req = FuzzEndpointRequest(
        endpoint_path="/system/nvram_dump.cgi",
        http_method="GET",
        payload_input="dump_all=1",
    )

    alert = sandbox.fuzz_endpoint(sess.session_id, fuzz_req)
    assert alert is not None
    assert alert.vulnerability_type == IoTVulnerabilityType.UNAUTHENTICATED_NVRAM_DUMP
    assert alert.severity == "HIGH"


def test_audit_hardcoded_backdoors(sandbox):
    sess = sandbox.start_emulation_session(
        EmulateDaemonRequest(
            daemon_name="telnetd",
            architecture=CpuArchitecture.MIPS_32_EL,
        )
    )

    backdoors = sandbox.audit_backdoors(sess.session_id)
    assert len(backdoors) >= 3
    assert all(b.vulnerability_type == IoTVulnerabilityType.HARDCODED_BACKDOOR_CREDENTIALS for b in backdoors)


# =========================================================================
# Integration Tests: FastAPI REST Endpoints
# =========================================================================

def test_api_emulate_daemon_and_fuzz(client):
    # 1. Start daemon emulation
    emu_req = {
        "daemon_name": "goahead_web",
        "architecture": "ARM_V7_A",
        "firmware_vendor": "SmartCamera-ARM",
        "listening_port": 80,
    }
    emu_resp = client.post("/api/v1/iotemu/emulate/daemon", json=emu_req)
    assert emu_resp.status_code == 201
    sess_data = emu_resp.json()
    session_id = sess_data["session_id"]

    # 2. Fuzz endpoint via API
    fuzz_req = {
        "endpoint_path": "/apply.cgi",
        "http_method": "POST",
        "payload_input": "192.168.1.1 && uname -a",
    }
    fuzz_resp = client.post(f"/api/v1/iotemu/fuzz/{session_id}", json=fuzz_req)
    assert fuzz_resp.status_code == 200
    assert fuzz_resp.json()["vulnerability_detected"] is True

    # 3. Check backdoors endpoint
    bd_resp = client.post(f"/api/v1/iotemu/backdoors/{session_id}")
    assert bd_resp.status_code == 200
    assert len(bd_resp.json()) >= 1

    # 4. Check vulnerabilities endpoint
    vuln_resp = client.get("/api/v1/iotemu/vulnerabilities")
    assert vuln_resp.status_code == 200
    assert len(vuln_resp.json()) >= 1

    # 5. Check status endpoint
    status_resp = client.get("/api/v1/iotemu/status")
    assert status_resp.status_code == 200
    status_data = status_resp.json()
    assert status_data["active_sandboxes_count"] >= 1
    assert "MIPS_32_EL" in status_data["supported_architectures"]
