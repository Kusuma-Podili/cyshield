"""
Unit and Integration Tests for OT/ICS Security Subsystem.
Verifies Modbus SIS write detection, Purdue zone violations, setpoint limits, Siemens S7 CPU Stop, and REST APIs.
"""

import pytest
from fastapi.testclient import TestClient

from cybershield.api.server import app
from cybershield.ics.inspector import ICSThreatInspector
from cybershield.ics.schemas import (
    ICSAnomalyType,
    ICSProtocol,
    ICSSeverity,
    ModbusTelemetry,
    S7CommTelemetry,
)


@pytest.fixture
def ics_inspector():
    return ICSThreatInspector()


@pytest.fixture
def client():
    return TestClient(app)


def test_seeded_ics_assets(ics_inspector):
    assets = ics_inspector.list_assets()
    assert len(assets) >= 3

    sis = next((a for a in assets if a.is_safety_system), None)
    assert sis is not None
    assert sis.ip_address == "192.168.100.10"
    assert "Triconex" in sis.vendor


def test_unauthorized_modbus_write_to_sis(ics_inspector):
    # Attacker tries to write single register to Safety Instrumented System
    telemetry = ModbusTelemetry(
        transaction_id=101,
        unit_id=1,
        function_code=6,  # Write Single Register
        function_name="Write Single Register",
        src_ip="192.168.50.99",
        dst_ip="192.168.100.10",  # SIS target
        register_address=40001,
        register_value=0.0,
    )
    alert = ics_inspector.inspect_modbus(telemetry)

    assert alert is not None
    assert alert.anomaly_type == ICSAnomalyType.UNAUTHORIZED_WRITE
    assert alert.severity == ICSSeverity.CRITICAL
    assert alert.mitre_attack_ics_id == "T0855"
    assert "Safety Instrumented System" in alert.title


def test_purdue_model_boundary_violation(ics_inspector):
    # IT/DMZ IP (10.10.1.50) connecting directly to Level 1 controller
    telemetry = ModbusTelemetry(
        transaction_id=102,
        unit_id=1,
        function_code=3,  # Read Holding Registers
        function_name="Read Holding Registers",
        src_ip="10.10.1.50",  # IT IP
        dst_ip="192.168.100.20",  # Level 1 PLC
        register_address=40001,
    )
    alert = ics_inspector.inspect_modbus(telemetry)

    assert alert is not None
    assert alert.anomaly_type == ICSAnomalyType.PURDUE_ZONE_VIOLATION
    assert alert.severity == ICSSeverity.HIGH
    assert alert.mitre_attack_ics_id == "T0886"


def test_setpoint_out_of_bounds(ics_inspector):
    # Setting steam turbine RPM to 5000 (safe max is 3600 RPM)
    telemetry = ModbusTelemetry(
        transaction_id=103,
        unit_id=1,
        function_code=16,
        function_name="Write Multiple Registers",
        src_ip="192.168.50.15",  # HMI
        dst_ip="192.168.100.20",  # Turbine PLC
        register_address=40001,
        register_value=5000.0,  # Exceeds max 3600.0!
    )
    alert = ics_inspector.inspect_modbus(telemetry)

    assert alert is not None
    assert alert.anomaly_type == ICSAnomalyType.SETPOINT_OUT_OF_BOUNDS
    assert alert.severity == ICSSeverity.CRITICAL
    assert "5000" in alert.title


def test_siemens_s7_cpu_stop_detection(ics_inspector):
    telemetry = S7CommTelemetry(
        pdu_type=1,
        function_code=0x29,
        function_name="PLC_STOP",
        src_ip="192.168.50.88",
        dst_ip="192.168.100.20",
    )
    alert = ics_inspector.inspect_s7comm(telemetry)

    assert alert is not None
    assert alert.anomaly_type == ICSAnomalyType.PLC_CPU_STOP
    assert alert.severity == ICSSeverity.CRITICAL
    assert alert.mitre_attack_ics_id == "T0816"


def test_ics_api_endpoints(client):
    # 1. List assets
    resp = client.get("/api/ics/assets")
    assert resp.status_code == 200
    assets = resp.json()
    assert len(assets) >= 3

    # 2. Inspect Modbus via API
    modbus_payload = {
        "transaction_id": 999,
        "unit_id": 1,
        "function_code": 6,
        "function_name": "Write Single Register",
        "src_ip": "192.168.50.10",
        "dst_ip": "192.168.100.10",
        "register_address": 40001,
        "register_value": 0.0,
    }
    resp = client.post("/api/ics/inspect/modbus", json=modbus_payload)
    assert resp.status_code == 200
    alert = resp.json()
    assert alert is not None
    assert alert["severity"] == "CRITICAL"

    # 3. Inspect S7comm via API
    s7_payload = {
        "pdu_type": 1,
        "function_code": 0x29,
        "function_name": "PLC_STOP",
        "src_ip": "192.168.50.5",
        "dst_ip": "192.168.100.20",
    }
    resp = client.post("/api/ics/inspect/s7comm", json=s7_payload)
    assert resp.status_code == 200
    s7_alert = resp.json()
    assert s7_alert["anomaly_type"] == "PLC_CPU_STOP"

    # 4. List alerts
    resp = client.get("/api/ics/alerts")
    assert resp.status_code == 200
    assert len(resp.json()) >= 2

    # 5. Overview
    resp = client.get("/api/ics/overview")
    assert resp.status_code == 200
    overview = resp.json()
    assert overview["total_ics_assets"] >= 3
    assert overview["safety_instrumented_systems_count"] >= 1
