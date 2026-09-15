"""Automated Tests for Wave 3: Deception Technology, Canaries & Honeypots."""

import pytest
from httpx import AsyncClient, ASGITransport

from cybershield.api.server import app
from cybershield.deception.schemas import CanaryType, CanaryGenerateRequest
from cybershield.deception.canary import CanaryManager
from cybershield.deception.engine import DeceptionEngine
from cybershield.deception.traps.service_traps import (
    SSHTrap,
    SMBShareTrap,
    HTTPAdminTrap,
    DatabaseTrap,
)


def test_canary_generation_and_tripwire():
    """Verify honeytoken generation and tripwire alerting."""
    # 1. API Key Canary
    req = CanaryGenerateRequest(
        canary_type=CanaryType.API_KEY,
        name="Production CI/CD AWS Secret",
    )
    token = CanaryManager.generate_canary(req)
    assert token.token_id.startswith("cny-")
    assert token.is_tripped is False
    assert "AKIA" in token.canary_value

    # Trip the canary
    key_id = token.metadata["key_id"]
    alert = CanaryManager.check_value_trip(f"Connecting using {key_id} and secret", "192.168.1.55")
    assert alert is not None
    assert alert.trap_or_canary_id == token.token_id
    assert alert.severity == "CRITICAL"
    assert token.is_tripped is True
    assert token.trip_count == 1
    assert token.trip_source_ip == "192.168.1.55"

    # 2. Honeyfile Canary
    req_file = CanaryGenerateRequest(
        canary_type=CanaryType.HONEYFILE,
        name="Confidential Salaries",
        target_path_or_host="Salaries_2026.xlsx",
    )
    file_token = CanaryManager.generate_canary(req_file)
    alert_file = CanaryManager.check_value_trip(f"Downloaded file: Salaries_2026.xlsx from share", "10.10.10.20")
    assert alert_file is not None
    assert alert_file.trap_or_canary_id == file_token.token_id


def test_decoy_traps_execution():
    """Verify all 4 decoy trap emulators."""
    # 1. SSH Trap
    ssh = SSHTrap()
    alert_ssh = ssh.handle_auth_attempt("root", "toor123", "172.16.0.40")
    assert alert_ssh.severity == "CRITICAL"
    assert "root" in alert_ssh.title

    # 2. SMB Trap
    smb = SMBShareTrap()
    alert_smb = smb.handle_share_access("FINANCE_ARCHIVE$", "READ_FILE", "172.16.0.40", "analyst")
    assert alert_smb.severity == "CRITICAL"
    assert "FINANCE_ARCHIVE$" in alert_smb.title

    # 3. HTTP Admin Trap
    http = HTTPAdminTrap()
    alert_http = http.handle_http_probe("/phpmyadmin", "GET", "172.16.0.40")
    assert alert_http.severity == "HIGH"
    assert "/phpmyadmin" in alert_http.title

    # 4. Database Trap
    db = DatabaseTrap()
    alert_db = db.handle_command("KEYS *", "172.16.0.40")
    assert alert_db.severity == "CRITICAL"
    assert "KEYS *" in alert_db.title


def test_deception_engine_orchestration():
    """Verify master DeceptionEngine coordinates traps and canary history."""
    DeceptionEngine.initialize_default_decoys()
    traps = DeceptionEngine.list_traps()
    assert len(traps) >= 4
    trap_types = [t.trap_type.value for t in traps]
    assert "SSH" in trap_types
    assert "SMB" in trap_types
    assert "HTTP_ADMIN" in trap_types
    assert "DATABASE" in trap_types

    stats = DeceptionEngine.get_stats()
    assert stats.total_traps >= 4
    assert stats.total_canaries >= 2


@pytest.mark.asyncio
async def test_deception_rest_api():
    """Verify Deception REST API endpoints."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        # Login
        login_resp = await ac.post("/api/auth/login", json={"username_or_email": "superadmin", "password": "CyberShield2026!"})
        assert login_resp.status_code == 200
        token = login_resp.json()["access_token"]
        headers = {"Authorization": f"Bearer {token}"}

        # 1. List Decoys
        res_traps = await ac.get("/api/deception/traps", headers=headers)
        assert res_traps.status_code == 200
        assert len(res_traps.json()) >= 4

        # 2. List Canaries
        res_canaries = await ac.get("/api/deception/canaries", headers=headers)
        assert res_canaries.status_code == 200
        assert len(res_canaries.json()) >= 1

        # 3. Generate Canary
        gen_payload = {
            "canary_type": "DATABASE_RECORD",
            "name": "Decoy Customer Card Table",
            "target_path_or_host": "cust_credit_cards_v1",
        }
        res_gen = await ac.post("/api/deception/canaries/generate", json=gen_payload, headers=headers)
        assert res_gen.status_code == 200
        canary_data = res_gen.json()
        assert canary_data["canary_type"] == "DATABASE_RECORD"

        # 4. Verify / Trip Token
        res_trip = await ac.post(
            "/api/deception/canaries/verify",
            json={"input_text": f"SELECT * FROM {canary_data['canary_value']}", "source_ip": "10.0.99.1"},
            headers=headers,
        )
        assert res_trip.status_code == 200
        assert res_trip.json()["tripped"] is True

        # 5. Simulate Trap
        sim_payload = {
            "trap_type": "SSH",
            "source_ip": "192.168.100.20",
            "payload": {"username": "deploy_agent", "password": "compromised_password"},
        }
        res_sim = await ac.post("/api/deception/traps/simulate", json=sim_payload, headers=headers)
        assert res_sim.status_code == 200
        assert "deploy_agent" in res_sim.json()["title"]

        # 6. Deception Stats
        res_stats = await ac.get("/api/deception/stats", headers=headers)
        assert res_stats.status_code == 200
        assert res_stats.json()["total_tripwire_alerts"] >= 1
