"""Unit tests for SOAR Automation Actions and Playbooks."""

import pytest
from cybershield.soar.actions import SOARActionRegistry
from cybershield.soar.playbook import soar_engine


@pytest.mark.asyncio
async def test_soar_containment_actions():
    """Verify atomic actions execute and register state correctly."""
    # Test Host Isolation
    ok, msg, details = await SOARActionRegistry.execute("ISOLATE_HOST", "ws-target-12.corp", {"reason": "Test Quarantine"})
    assert ok is True
    assert "ws-target-12.corp" in SOARActionRegistry.ISOLATED_HOSTS

    # Test IP Block
    ok, msg, details = await SOARActionRegistry.execute("BLOCK_IP", "198.51.100.99", {"direction": "EGRESS"})
    assert ok is True
    assert "198.51.100.99" in SOARActionRegistry.BLOCKED_IPS

    # Test Credential Revocation
    ok, msg, details = await SOARActionRegistry.execute("REVOKE_USER_CREDENTIALS", "compromised_user", {})
    assert ok is True
    assert "compromised_user" in SOARActionRegistry.REVOKED_USERS

    # Test Forensic Snapshot
    ok, msg, details = await SOARActionRegistry.execute("CAPTURE_FORENSIC_SNAPSHOT", "ws-target-12.corp", {})
    assert ok is True
    assert "sha256" in details


@pytest.mark.asyncio
async def test_extended_soar_actions():
    """Verify extended SOAR action handlers: sinkhole, quarantine, disable AD, deception, VM revert."""
    # Test Domain Sinkhole
    ok, msg, details = await SOARActionRegistry.execute("SINKHOLE_DOMAIN", "evil-c2-beacon.ru", {"sinkhole_ip": "127.0.0.1"})
    assert ok is True
    assert details["sinkhole_ip"] == "127.0.0.1"

    # Test File Quarantine
    ok, msg, details = await SOARActionRegistry.execute("QUARANTINE_FILE", "/tmp/xmrig_miner", {})
    assert ok is True
    assert "quarantine" in details["quarantine_location"]

    # Test Disable AD Account
    ok, msg, details = await SOARActionRegistry.execute("DISABLE_AD_ACCOUNT", "svc_backup_user", {})
    assert ok is True
    assert details["status"] == "DISABLED"

    # Test Deception Tripwire
    ok, msg, details = await SOARActionRegistry.execute("TRIGGER_DECEPTION_TRIPWIRE", "10.0.4.0/24", {"trap_type": "SSH_DECOY"})
    assert ok is True
    assert details["trap_type"] == "SSH_DECOY"

    # Test Revert VM Snapshot
    ok, msg, details = await SOARActionRegistry.execute("REVERT_VM_SNAPSHOT", "vm-workload-01", {"snapshot": "clean_golden_image"})
    assert ok is True
    assert details["snapshot"] == "clean_golden_image"


@pytest.mark.asyncio
async def test_soar_ransomware_playbook_execution():
    """Verify multi-step ransomware containment playbook completes."""
    execution = await soar_engine.execute_playbook(
        playbook_id="PB-RANSOMWARE-01",
        target_entity="ws-finance-08.corp",
        context_vars={
            "host": "ws-finance-08.corp",
            "source_ip": "45.33.32.156",
            "user": "mscott"
        }
    )
    assert execution.status == "COMPLETED"
    assert len(execution.steps) >= 4
    for step in execution.steps:
        assert step.status == "COMPLETED"
        assert step.duration_ms >= 0.0


@pytest.mark.asyncio
async def test_bec_wire_fraud_playbook_execution():
    """Verify multi-step Business Email Compromise playbook completes."""
    execution = await soar_engine.execute_playbook(
        playbook_id="PB-BEC-FRAUD-01",
        target_entity="ceo@corp.com",
        context_vars={
            "user": "ceo@corp.com",
            "source_ip": "198.51.100.44",
        }
    )
    assert execution.status == "COMPLETED"
    assert len(execution.steps) == 5
    for step in execution.steps:
        assert step.status == "COMPLETED"


@pytest.mark.asyncio
async def test_kerberoasting_playbook_execution():
    """Verify Kerberoasting containment playbook executes deception and forensic captures."""
    execution = await soar_engine.execute_playbook(
        playbook_id="PB-KERBEROAST-01",
        target_entity="ws-eng-03.corp",
        context_vars={
            "host": "ws-eng-03.corp",
        }
    )
    assert execution.status == "COMPLETED"
    assert len(execution.steps) == 4


@pytest.mark.asyncio
async def test_cryptomining_playbook_execution():
    """Verify CWPP cryptomining kill and VM revert playbook completes."""
    execution = await soar_engine.execute_playbook(
        playbook_id="PB-MINER-KILL-01",
        target_entity="node-worker-k8s-02",
        context_vars={
            "host": "node-worker-k8s-02",
            "destination_ip": "185.220.101.5",
        }
    )
    assert execution.status == "COMPLETED"
    assert len(execution.steps) == 5


@pytest.mark.asyncio
async def test_zeroday_shield_playbook_execution():
    """Verify Zero-Day Isolation Shield playbook isolates, dumps RAM, and arms decoys."""
    execution = await soar_engine.execute_playbook(
        playbook_id="PB-ZERODAY-01",
        target_entity="srv-public-web-01.corp",
        context_vars={
            "host": "srv-public-web-01.corp",
            "source_ip": "203.0.113.88",
        }
    )
    assert execution.status == "COMPLETED"
    assert len(execution.steps) == 5
