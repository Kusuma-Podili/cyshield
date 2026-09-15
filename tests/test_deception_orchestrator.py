"""Tests for CyberShield Enterprise - Threat Deception Orchestrator & High-Interaction Emulators.
Verifies canary honeytoken generation, endpoint lure deployment, high-interaction service emulation
(Redis, PostgreSQL, Docker API), tripwire detection, and REST API routes.
"""

import json
import pytest
from starlette.testclient import TestClient

from cybershield.api.server import app
from cybershield.honey.schemas import (
    HoneytokenType,
    EmulatedServiceType,
)
from cybershield.honey.orchestrator import DeceptionOrchestrator


@pytest.fixture
def client():
    return TestClient(app)


@pytest.fixture
def orchestrator():
    return DeceptionOrchestrator()


# =========================================================================
# Unit Tests: Honeytokens & Lures
# =========================================================================

def test_generate_honeytokens(orchestrator):
    # AWS Key
    t_aws = orchestrator.generate_honeytoken(
        token_type=HoneytokenType.AWS_KEY,
        decoy_username="svc_backup_aws",
        target_service="Amazon S3 Cold Storage",
    )
    assert t_aws.token_id in orchestrator.honeytokens
    assert t_aws.token_value.startswith("AKIA")
    assert len(t_aws.signature_hash) == 64

    # API Bearer
    t_api = orchestrator.generate_honeytoken(
        token_type=HoneytokenType.API_BEARER_TOKEN,
        decoy_username="api_payment_worker",
        target_service="Stripe Webhook Gateway",
    )
    assert t_api.token_value.startswith("cs_live_")

    # SSH Key
    t_ssh = orchestrator.generate_honeytoken(
        token_type=HoneytokenType.SSH_PRIVATE_KEY,
        decoy_username="root",
        target_service="Bastion Host",
    )
    assert "BEGIN OPENSSH PRIVATE KEY" in t_ssh.token_value


def test_deploy_lure(orchestrator):
    token = orchestrator.generate_honeytoken(
        token_type=HoneytokenType.AWS_KEY,
        decoy_username="dev_test",
        target_service="AWS",
    )
    lure = orchestrator.deploy_lure(
        deployed_host_id="ws-engineer-01",
        honeytoken_id=token.token_id,
        file_path_or_location="C:\\Users\\engineer\\.aws\\credentials",
    )
    assert lure.lure_id in orchestrator.lures
    assert lure.deployed_host_id == "ws-engineer-01"
    assert lure.is_active is True

    # Error on non-existent token
    with pytest.raises(ValueError):
        orchestrator.deploy_lure("host-01", "non-existent-token", "/tmp/token")


# =========================================================================
# Unit Tests: High-Interaction Service Emulators
# =========================================================================

def test_redis_emulator_benign_and_attack(orchestrator):
    # Benign PING
    res, alert = orchestrator.handle_service_interaction(
        service=EmulatedServiceType.REDIS_CACHE,
        source_ip="10.0.1.10",
        source_port=51200,
        command_or_query="PING",
    )
    assert res["message"] == "PONG"
    assert alert is None

    # Rogue CONFIG SET attack (MITRE T1059)
    res_atk, alert_atk = orchestrator.handle_service_interaction(
        service=EmulatedServiceType.REDIS_CACHE,
        source_ip="198.51.100.88",
        source_port=44111,
        command_or_query="CONFIG SET dir /root/.ssh",
    )
    assert alert_atk is not None
    assert alert_atk.adversary_action == "UNAUTHORIZED_REDIS_ROGUE_WRITE"
    assert alert_atk.severity == "CRITICAL"
    assert "T1059" in alert_atk.mitre_technique


def test_postgres_emulator_benign_and_sqli(orchestrator):
    # Benign SELECT
    res, alert = orchestrator.handle_service_interaction(
        service=EmulatedServiceType.POSTGRES_DB,
        source_ip="10.0.2.15",
        source_port=33900,
        command_or_query="SELECT * FROM payment_cards",
    )
    assert res["status"] == "ok"
    assert res["rows_returned"] == 2
    assert alert is None

    # Malicious SQL Injection UNION SELECT
    res_sqli, alert_sqli = orchestrator.handle_service_interaction(
        service=EmulatedServiceType.POSTGRES_DB,
        source_ip="203.0.113.4",
        source_port=55122,
        command_or_query="SELECT * FROM customers WHERE id = 1 UNION SELECT user, password_hash FROM admin_users",
    )
    assert alert_sqli is not None
    assert alert_sqli.adversary_action == "MALICIOUS_SQL_INJECTION_AGAINST_HONEYPOT"
    assert "T1190" in alert_sqli.mitre_technique


def test_docker_emulator_container_breakout(orchestrator):
    # Breakout attempt mounting host root filesystem /
    res, alert = orchestrator.handle_service_interaction(
        service=EmulatedServiceType.DOCKER_DAEMON_API,
        source_ip="10.0.50.2",
        source_port=42100,
        command_or_query="POST /v1.40/containers/create",
        raw_payload='{"Binds": ["/:/host_root:rw"], "Privileged": true}',
    )
    assert alert is not None
    assert alert.adversary_action == "DOCKER_CONTAINER_BREAKOUT_ATTEMPT"
    assert "T1611" in alert.mitre_technique


# =========================================================================
# Unit Tests: Honeytoken Tripwire Sentinel
# =========================================================================

def test_honeytoken_tripwire_verification(orchestrator):
    token = orchestrator.generate_honeytoken(
        token_type=HoneytokenType.AWS_KEY,
        decoy_username="fake_admin",
        target_service="AWS STS",
    )

    # Trigger tripwire with valid canary value
    alert = orchestrator.verify_and_trigger_honeytoken(
        token_value=token.token_value,
        source_ip="198.51.100.99",
        context={"user_agent": "aws-cli/2.0"},
    )
    assert alert is not None
    assert alert.token_id == token.token_id
    assert alert.confidence == 1.0
    assert token.alerts_triggered_count == 1

    # Non-canary token check
    alert_none = orchestrator.verify_and_trigger_honeytoken(
        token_value="AKIA_LEGITIMATE_NON_HONEYTOKEN",
        source_ip="10.0.1.1",
    )
    assert alert_none is None


def test_service_emulator_status_metrics(orchestrator):
    orchestrator.handle_service_interaction(
        service=EmulatedServiceType.REDIS_CACHE,
        source_ip="192.168.1.5",
        source_port=50000,
        command_or_query="PING",
    )
    statuses = orchestrator.get_service_status()
    assert len(statuses) >= 4
    redis_st = [s for s in statuses if s.service_type == EmulatedServiceType.REDIS_CACHE][0]
    assert redis_st.port == 6379
    assert redis_st.interactions_count >= 1


# =========================================================================
# REST API Integration Tests
# =========================================================================

def test_api_deception_lifecycle(client):
    # 1. Create Honeytoken
    resp = client.post("/api/v1/honey/tokens?token_type=AWS_KEY&decoy_username=api_decoy&target_service=AWS_IAM")
    assert resp.status_code == 201
    tok = resp.json()
    assert tok["token_type"] == "AWS_KEY"
    tok_id = tok["token_id"]
    tok_val = tok["token_value"]

    # 2. List Tokens
    resp = client.get("/api/v1/honey/tokens")
    assert resp.status_code == 200
    assert len(resp.json()) >= 1

    # 3. Deploy Lure
    resp = client.post(f"/api/v1/honey/lures?deployed_host_id=srv-app-01&honeytoken_id={tok_id}&file_path_or_location=%2Fetc%2Faws.conf")
    assert resp.status_code == 201
    assert resp.json()["deployed_host_id"] == "srv-app-01"

    # 4. List Lures
    resp = client.get("/api/v1/honey/lures")
    assert resp.status_code == 200
    assert len(resp.json()) >= 1

    # 5. Interact with Service Emulator (Redis rogue write)
    resp = client.post("/api/v1/honey/interact?service=REDIS_CACHE&source_ip=198.51.100.22&source_port=55100&command_or_query=CONFIG%20SET%20dir%20%2Froot")
    assert resp.status_code == 200
    interact_data = resp.json()
    assert interact_data["alert_triggered"] is True
    assert interact_data["adversary_action"] == "UNAUTHORIZED_REDIS_ROGUE_WRITE"

    # 6. Tripwire Verification
    resp = client.post(f"/api/v1/honey/tripwire?token_value={tok_val}&source_ip=198.51.100.33")
    assert resp.status_code == 200
    trip_data = resp.json()
    assert trip_data["is_canary"] is True
    assert trip_data["alert_triggered"] is True

    # 7. Get Deception Alerts
    resp = client.get("/api/v1/honey/alerts")
    assert resp.status_code == 200
    alerts = resp.json()
    assert len(alerts) >= 2

    # 8. Get Emulator Status
    resp = client.get("/api/v1/honey/emulators")
    assert resp.status_code == 200
    assert len(resp.json()) >= 4
