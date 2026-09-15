"""
CyberShield Enterprise - Integration Tests for Networks, Devices, IP Management & Topology
Tests Subnet CIDR calculators, device inventory, dynamic risk scoring,
host network isolation containment, topology graph generation, and discovery sweeps.
"""

import uuid
import pytest
from starlette.testclient import TestClient
from cybershield.api.server import app
from cybershield.network.subnet_service import SubnetCalculator

client = TestClient(app)


import asyncio
from cybershield.database.session import init_db, async_session_factory
from cybershield.network.subnet_service import SubnetService
from cybershield.network.device_service import DeviceService


@pytest.fixture(scope="module", autouse=True)
def setup_database():
    """Ensure database schema is created and default enterprise assets are seeded."""
    async def _setup():
        await init_db()
        async with async_session_factory() as session:
            await SubnetService(session).seed_enterprise_subnets()
            await DeviceService(session).seed_enterprise_devices()
    asyncio.run(_setup())


@pytest.fixture(scope="module")
def admin_token():
    """Authenticate as default superadmin and return JWT token."""
    login_resp = client.post("/api/auth/login", json={
        "username_or_email": "superadmin",
        "password": "CyberShield2026!"
    })
    assert login_resp.status_code == 200
    return login_resp.json()["access_token"]


def test_subnet_cidr_mathematics():
    """Verify SubnetCalculator accurately computes RFC 1878 / 4632 geometry."""
    # Test standard /24 subnet
    c24 = SubnetCalculator.inspect_cidr("10.0.1.0/24")
    assert c24["network_address"] == "10.0.1.0"
    assert c24["broadcast_address"] == "10.0.1.255"
    assert c24["netmask"] == "255.255.255.0"
    assert c24["total_usable_hosts"] == 254
    assert c24["gateway_ip"] == "10.0.1.1"

    # Test /23 subnet (510 usable hosts)
    c23 = SubnetCalculator.inspect_cidr("172.16.0.0/23")
    assert c23["total_usable_hosts"] == 510
    assert c23["netmask"] == "255.255.254.0"

    # Test IP in subnet
    assert SubnetCalculator.is_ip_in_subnet("10.0.1.45", "10.0.1.0/24") is True
    assert SubnetCalculator.is_ip_in_subnet("10.0.2.45", "10.0.1.0/24") is False

    # Test next available IP calculation
    used = ["10.0.1.1", "10.0.1.2", "10.0.1.3"]
    next_ip = SubnetCalculator.find_next_available_ip("10.0.1.0/24", used)
    assert next_ip == "10.0.1.4"


def test_list_and_seed_subnets(admin_token):
    """Verify default enterprise subnets are seeded and returned with live stats."""
    headers = {"Authorization": f"Bearer {admin_token}"}
    resp = client.get("/api/networks", headers=headers)
    assert resp.status_code == 200
    data = resp.json()
    assert data["total"] >= 4
    subnets = {s["id"]: s for s in data["items"]}

    assert "sub-corp-01" in subnets
    assert "sub-dmz-01" in subnets
    assert "sub-dc-01" in subnets
    assert "sub-mgmt-01" in subnets

    corp = subnets["sub-corp-01"]
    assert corp["cidr"] == "10.0.1.0/24"
    assert corp["gateway_ip"] == "10.0.1.1"
    assert corp["zone_type"] == "CORP_LAN"
    assert corp["total_ips"] == 254


def test_create_custom_subnet(admin_token):
    """Verify creating a custom subnet generates geometry and registers gateway."""
    headers = {"Authorization": f"Bearer {admin_token}"}
    import random
    uid = uuid.uuid4().hex[:6]
    name = f"OT ICS Factory Floor {uid}"
    cidr = f"10.{random.randint(150, 240)}.{random.randint(1, 250)}.0/24"

    payload = {
        "name": name,
        "cidr": cidr,
        "vlan_id": 210,
        "zone_type": "OT_ICS",
        "description": "Industrial control systems and SCADA telemetry.",
        "risk_level": "HIGH",
        "dns_servers": ["10.0.3.10"]
    }
    resp = client.post("/api/networks", json=payload, headers=headers)
    assert resp.status_code == 201
    created = resp.json()
    assert created["name"] == name
    assert created["cidr"] == cidr
    assert created["total_ips"] == 254
    assert created["gateway_ip"].endswith(".1")


def test_list_devices_and_risk_scoring(admin_token):
    """Verify inventory of seeded devices and risk score computation."""
    headers = {"Authorization": f"Bearer {admin_token}"}
    resp = client.get("/api/devices", headers=headers)
    assert resp.status_code == 200
    data = resp.json()
    assert data["total"] >= 7
    devices = {d["id"]: d for d in data["items"]}

    # Verify Domain Controller attributes
    assert "dev-dc-01" in devices
    dc = devices["dev-dc-01"]
    assert dc["hostname"] == "dc-primary.corp"
    assert dc["ip_address"] == "10.0.3.10"
    assert dc["is_critical_asset"] is True
    assert dc["risk_score"] > 0.0
    assert 88 in dc["open_ports"]  # Kerberos port

    # Verify Perimeter Firewall
    assert "dev-fw-01" in devices
    fw = devices["dev-fw-01"]
    assert fw["device_type"] == "FIREWALL"


def test_register_new_device(admin_token):
    """Verify registering a new server and automatic IP record allocation."""
    headers = {"Authorization": f"Bearer {admin_token}"}
    uid = uuid.uuid4().hex[:6]
    hostname = f"app-api-srv-{uid}.corp"
    mac = f"00:50:56:B9:{uid[:2]}:{uid[2:4]}".upper()

    payload = {
        "hostname": hostname,
        "ip_address": f"10.0.2.{100 + int(uid[:2], 16) % 100}",
        "mac_address": mac,
        "device_type": "SERVER",
        "os_family": "LINUX",
        "os_version": "Debian 12 Bookworm",
        "subnet_id": "sub-dmz-01",
        "location": "DMZ Cluster C",
        "is_critical_asset": False,
        "open_ports": [22, 443, 8000],
        "tags": ["api", "microservice"]
    }
    resp = client.post("/api/devices", json=payload, headers=headers)
    assert resp.status_code == 201
    created = resp.json()
    assert created["hostname"] == hostname
    assert created["mac_address"] == mac
    assert created["status"] == "ONLINE"
    assert created["risk_score"] >= 0.0

    # Retrieve individual device
    get_resp = client.get(f"/api/devices/{created['id']}", headers=headers)
    assert get_resp.status_code == 200
    assert get_resp.json()["id"] == created["id"]


def test_device_isolation_and_unquarantine(admin_token):
    """Verify host network quarantine containment and subsequent restoration."""
    headers = {"Authorization": f"Bearer {admin_token}"}

    # Target the finance workstation
    target_id = "dev-ws-fin"
    iso_resp = client.post(
        f"/api/devices/{target_id}/isolate",
        json={"reason": "Active Ransomware lateral movement detected by CyberShield AI engine."},
        headers=headers
    )
    assert iso_resp.status_code == 200
    iso_data = iso_resp.json()
    assert iso_data["device_id"] == target_id
    assert iso_data["current_status"] == "ISOLATED"
    assert "ACL-QUARANTINE" in iso_data["containment_rule_id"]

    # Verify status in device details
    dev_resp = client.get(f"/api/devices/{target_id}", headers=headers)
    assert dev_resp.json()["status"] == "ISOLATED"
    assert dev_resp.json()["risk_score"] >= 85.0

    # Lift quarantine
    unq_resp = client.post(f"/api/devices/{target_id}/unquarantine", headers=headers)
    assert unq_resp.status_code == 200
    assert unq_resp.json()["status"] == "ONLINE"


def test_network_topology_graph(admin_token):
    """Verify topology graph endpoint outputs nodes, edges, coordinates, and link health."""
    headers = {"Authorization": f"Bearer {admin_token}"}
    resp = client.get("/api/network/topology", headers=headers)
    assert resp.status_code == 200
    graph = resp.json()

    assert "nodes" in graph
    assert "edges" in graph
    assert graph["total_nodes"] >= 7
    assert graph["total_edges"] >= 4
    assert graph["healthy_links_pct"] > 50.0

    # Verify node coordinate geometry
    node = graph["nodes"][0]
    assert "x" in node and "y" in node
    assert node["x"] > 0 and node["y"] > 0

    # Verify edge schema
    edge = graph["edges"][0]
    assert "source" in edge
    assert "target" in edge
    assert "bandwidth_mbps" in edge
    assert edge["status"] == "UP"


def test_network_discovery_scan(admin_token):
    """Verify automated network sweep finds hosts, detects rogue devices, and checks conflicts."""
    headers = {"Authorization": f"Bearer {admin_token}"}
    payload = {
        "subnet_id": "sub-corp-01",
        "ping_timeout_ms": 200,
        "port_scan_depth": "STANDARD"
    }
    resp = client.post("/api/network/discovery/scan", json=payload, headers=headers)
    assert resp.status_code == 200
    result = resp.json()

    assert result["subnet_id"] == "sub-corp-01"
    assert result["scanned_ips"] == 254
    assert result["active_hosts_found"] >= 2
    assert result["scan_duration_sec"] > 0.0
    assert len(result["hosts"]) >= 2

    # Check rogue device detection in sub-corp-01
    rogue_hosts = [h for h in result["hosts"] if not h["is_known"]]
    assert len(rogue_hosts) >= 1
    assert "rogue" in rogue_hosts[0]["hostname"].lower() or "raspberry" in rogue_hosts[0]["os_fingerprint"].lower()


def test_network_summary_kpis(admin_token):
    """Verify aggregated network inventory metrics endpoint."""
    headers = {"Authorization": f"Bearer {admin_token}"}
    resp = client.get("/api/network/summary", headers=headers)
    assert resp.status_code == 200
    summary = resp.json()

    assert summary["total_devices"] >= 7
    assert summary["subnets_count"] >= 4
    assert summary["total_allocated_ips"] >= 4
    assert summary["network_health_pct"] > 0.0
    assert summary["total_bandwidth_capacity_gbps"] > 0.0
