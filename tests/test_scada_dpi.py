"""
CyberShield Enterprise - SCADA / Modbus & Industrial DNP3 Deep Packet Inspector Test Suite
Tests wire packet parsing for Modbus TCP, DNP3, and Siemens S7comm,
Purdue model zone enforcement, sabotage detection, and REST routes.
"""

import struct
import pytest
from starlette.testclient import TestClient

from cybershield.api.server import app
from cybershield.scadadpi.schemas import (
    IndustrialProtocol,
    SCADASeverity,
    PurdueLevel,
    PacketInspectionRequest,
)
from cybershield.scadadpi.inspector import SCADADeepPacketInspector


@pytest.fixture
def inspector():
    return SCADADeepPacketInspector(allow_plc_writes=False, enforce_sbo=True)


@pytest.fixture
def client():
    return TestClient(app)


# ------------------------------------------------------------------------------
# 1. Modbus TCP Packet Dissection Tests
# ------------------------------------------------------------------------------

def test_modbus_read_holding_registers_allowed(inspector):
    # Transaction ID: 0x0001, Protocol ID: 0x0000, Length: 0x0006, Unit ID: 0x01
    # Function Code: 0x03 (Read Holding Registers), Start Address: 0x0064 (100), Count: 0x000A (10)
    packet = struct.pack(">HHHBBHH", 1, 0, 6, 1, 3, 100, 10)
    frame, alerts = inspector.dissect_modbus_tcp(packet)

    assert frame is not None
    assert frame.transaction_id == 1
    assert frame.unit_id == 1
    assert frame.function_code == 3
    assert frame.function_name == "Read Holding Registers"
    assert frame.is_write_operation is False
    assert frame.target_address == 100
    assert frame.register_count == 10
    assert len(alerts) == 0


def test_modbus_unauthorized_force_coil_blocked(inspector):
    # Transaction ID: 0x0002, Protocol ID: 0x0000, Length: 0x0006, Unit ID: 0x01
    # Function Code: 0x05 (Force Single Coil), Address: 0x000A (10), Value: 0xFF00 (ON)
    packet = struct.pack(">HHHBBHH", 2, 0, 6, 1, 5, 10, 0xFF00)
    frame, alerts = inspector.dissect_modbus_tcp(packet)

    assert frame is not None
    assert frame.function_code == 5
    assert frame.is_write_operation is True
    assert len(alerts) == 1
    alert = alerts[0]
    assert alert.threat_category == "UNAUTHORIZED_PLC_WRITE_COMMAND"
    assert alert.severity == SCADASeverity.CRITICAL


def test_modbus_out_of_bounds_scan(inspector):
    # Address: 65520, Count: 200 (> 125 limit)
    packet = struct.pack(">HHHBBHH", 3, 0, 6, 1, 3, 65520, 200)
    frame, alerts = inspector.dissect_modbus_tcp(packet)
    assert len(alerts) >= 1
    assert alerts[0].threat_category == "MODBUS_OUT_OF_BOUNDS_SCAN"


# ------------------------------------------------------------------------------
# 2. DNP3 Dissection & SBO Violation Tests
# ------------------------------------------------------------------------------

def test_dnp3_destructive_cold_restart(inspector):
    # Sync 0x05 0x64, Length: 5, Control: 0xC4, Dest: 10, Src: 1
    # Data Link CRC: 0xAAAA (2B), Transport: 0xC0 (1B), App Control: 0xC1 (1B), Function: 0x0D (Cold Restart)
    packet = bytearray()
    packet.extend([0x05, 0x64, 0x05, 0xC4])
    packet.extend(struct.pack("<HH", 10, 1))
    packet.extend([0xAA, 0xAA, 0xC0, 0xC1, 0x0D])

    frame, alerts = inspector.dissect_dnp3(bytes(packet))
    assert frame is not None
    assert frame.destination_address == 10
    assert frame.function_code == 0x0D
    assert frame.function_name == "Cold Restart"
    assert len(alerts) == 1
    assert alerts[0].threat_category == "SUBSTATION_RESTART_SABOTAGE"
    assert alerts[0].severity == SCADASeverity.CRITICAL


def test_dnp3_direct_operate_without_select_violation(inspector):
    # Function Code 0x05: Direct Operate without prior Select
    packet = bytearray([0x05, 0x64, 0x05, 0xC4])
    packet.extend(struct.pack("<HH", 10, 1))
    packet.extend([0xAA, 0xAA, 0xC0, 0xC1, 0x05])

    frame, alerts = inspector.dissect_dnp3(bytes(packet), source_ip="192.168.1.100")
    assert frame is not None
    assert frame.function_code == 0x05
    assert len(alerts) == 1
    assert alerts[0].threat_category == "SBO_POLICY_VIOLATION"


# ------------------------------------------------------------------------------
# 3. Siemens S7comm PLC CPU Stop Tests
# ------------------------------------------------------------------------------

def test_s7comm_plc_cpu_stop_intercept(inspector):
    # TPKT (0x03 0x00 0x00 0x20) + COTP (0x02 0xF0 0x80)
    # S7 Header: Magic 0x32, PDU Type 0x01, Reserved (2B), Seq (2B), Param Len (2B), Data Len (2B)
    # Function code: 0x28 (PLC Control), Payload contains "P_STOP"
    packet = bytearray([0x03, 0x00, 0x00, 0x20, 0x02, 0xF0, 0x80])
    packet.extend([0x32, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x08, 0x00, 0x00])
    packet.extend([0x28])  # Function code 0x28
    packet.extend(b"P_STOP_TRIGGER")

    frame, alerts = inspector.dissect_s7comm(bytes(packet))
    assert frame is not None
    assert frame.function_code == 0x28
    assert frame.subfunction == "PLC_CPU_STOP"
    assert len(alerts) == 1
    assert alerts[0].threat_category == "PLC_CPU_STOP_SABOTAGE"
    assert alerts[0].severity == SCADASeverity.CRITICAL


# ------------------------------------------------------------------------------
# 4. Purdue Model & Full Packet Inspection Pipeline Tests
# ------------------------------------------------------------------------------

def test_purdue_zone_violation_and_block(inspector):
    # Modbus Read command from Enterprise Level 4 directly to Level 1 Controller
    modbus_pkt = struct.pack(">HHHBBHH", 1, 0, 6, 1, 3, 100, 10)
    decision = inspector.inspect_packet(
        raw_bytes=modbus_pkt,
        protocol_hint=IndustrialProtocol.MODBUS_TCP,
        source_ip="10.100.5.20",  # Enterprise IT
        dest_ip="192.168.1.50",   # PLC
        source_level=PurdueLevel.LEVEL_4_ENTERPRISE,
        dest_level=PurdueLevel.LEVEL_1_CONTROLLERS,
    )
    assert decision.is_authorized is False
    assert decision.action == "BLOCK"
    categories = [a.threat_category for a in decision.threat_alerts]
    assert "PURDUE_ZONE_VIOLATION" in categories


# ------------------------------------------------------------------------------
# 5. REST API Endpoints Tests
# ------------------------------------------------------------------------------

def test_api_inspect_packet(client):
    # Modbus Write Single Coil (0x05)
    packet_hex = struct.pack(">HHHBBHH", 10, 0, 6, 1, 5, 20, 0xFF00).hex()
    payload = {
        "raw_packet_hex": packet_hex,
        "protocol_hint": "modbus_tcp",
        "source_ip": "192.168.1.10",
        "dest_ip": "192.168.1.50",
        "source_purdue_level": 2,
        "dest_purdue_level": 1,
    }
    response = client.post("/api/v1/scadadpi/inspect/packet", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["is_authorized"] is False
    assert data["action"] == "BLOCK"
    assert len(data["threat_alerts"]) >= 1


def test_api_inspect_modbus(client):
    packet_hex = struct.pack(">HHHBBHH", 5, 0, 6, 1, 3, 50, 4).hex()
    response = client.post(f"/api/v1/scadadpi/inspect/modbus?raw_packet_hex={packet_hex}")
    assert response.status_code == 200
    data = response.json()
    assert data["frame"]["function_name"] == "Read Holding Registers"
    assert len(data["alerts"]) == 0


def test_api_inspect_dnp3(client):
    packet = bytearray([0x05, 0x64, 0x05, 0xC4])
    packet.extend(struct.pack("<HH", 10, 1))
    packet.extend([0xAA, 0xAA, 0xC0, 0xC1, 0x0D])
    packet_hex = packet.hex()

    response = client.post(f"/api/v1/scadadpi/inspect/dnp3?raw_packet_hex={packet_hex}")
    assert response.status_code == 200
    data = response.json()
    assert data["frame"]["function_name"] == "Cold Restart"
    assert len(data["alerts"]) == 1


def test_api_inspect_s7(client):
    packet = bytearray([0x03, 0x00, 0x00, 0x20, 0x02, 0xF0, 0x80])
    packet.extend([0x32, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x08, 0x00, 0x00, 0x28])
    packet.extend(b"STOP_TEST")
    packet_hex = packet.hex()

    response = client.post(f"/api/v1/scadadpi/inspect/s7?raw_packet_hex={packet_hex}")
    assert response.status_code == 200
    data = response.json()
    assert data["frame"]["subfunction"] == "PLC_CPU_STOP"


def test_api_stats_summary_and_health(client):
    stats = client.get("/api/v1/scadadpi/stats/summary")
    assert stats.status_code == 200
    assert stats.json()["status"] == "active"
    assert "modbus_tcp" in stats.json()["supported_protocols"]

    health = client.get("/api/v1/scadadpi/health")
    assert health.status_code == 200
    assert health.json()["service"] == "scada-dpi-inspector"
