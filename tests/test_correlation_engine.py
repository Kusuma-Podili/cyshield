"""
Unit and Integration Tests for Complex Event Processing (CEP) and Temporal Correlation.
Verifies sliding window buffering, sequence chain detection, aggregation rules, and REST APIs.
"""

from datetime import datetime, timedelta
import pytest
from fastapi.testclient import TestClient

from cybershield.api.server import app
from cybershield.correlation.engine import TemporalCorrelationEngine
from cybershield.correlation.rules_catalog import DEFAULT_CORRELATION_RULES
from cybershield.correlation.schemas import (
    AggregationFunction,
    ConditionOperator,
    CorrelationRule,
    CorrelationWindowType,
    EventFilter,
    SequenceStep,
)
from cybershield.correlation.window_buffer import TemporalEventBuffer


@pytest.fixture
def cep_engine():
    return TemporalCorrelationEngine(buffer_retention_seconds=600)


@pytest.fixture
def client():
    return TestClient(app)


def test_temporal_event_buffer_sliding_window():
    buf = TemporalEventBuffer(max_retention_seconds=300)
    base_time = datetime(2026, 9, 12, 12, 0, 0)

    # Add events at t=0, t=10s, t=20s
    buf.add_event({"id": "e1", "username": "alice", "timestamp": base_time})
    buf.add_event({"id": "e2", "username": "alice", "timestamp": base_time + timedelta(seconds=10)})
    buf.add_event({"id": "e3", "username": "bob", "timestamp": base_time + timedelta(seconds=20)})

    assert buf.total_events() == 3

    # Query 15-second window ending at t=25s
    win = buf.get_window(window_seconds=15, as_of_time=base_time + timedelta(seconds=25))
    # Should contain e2 (t=10) and e3 (t=20)
    assert len(win) == 2
    event_ids = [e["id"] for e in win]
    assert "e2" in event_ids
    assert "e3" in event_ids

    # Query grouped by username=alice
    alice_win = buf.get_window(
        window_seconds=30, group_by_field="username", group_by_value="alice", as_of_time=base_time + timedelta(seconds=25)
    )
    assert len(alice_win) == 2
    assert all(e["username"] == "alice" for e in alice_win)


def test_sequence_correlation_brute_force_success(cep_engine):
    base_time = datetime.utcnow()

    # Step 1: 3 failed logins for victim_user
    events = [
        {"id": "f1", "username": "victim_user", "event_type": "AUTH_FAILURE", "timestamp": base_time},
        {"id": "f2", "username": "victim_user", "event_type": "AUTH_FAILURE", "timestamp": base_time + timedelta(seconds=10)},
        {"id": "f3", "username": "victim_user", "event_type": "AUTH_FAILURE", "timestamp": base_time + timedelta(seconds=20)},
    ]
    alerts = cep_engine.process_batch(events)
    assert len(alerts) == 0  # Sequence not complete yet

    # Step 2: 1 successful login for victim_user
    success_evt = {"id": "s1", "username": "victim_user", "event_type": "AUTH_SUCCESS", "timestamp": base_time + timedelta(seconds=30)}
    alerts = cep_engine.process_event(success_evt)
    
    assert len(alerts) >= 1
    bf_alert = next((a for a in alerts if a.rule_id == "CORR-BRUTE-FORCE-SUCCESS"), None)
    assert bf_alert is not None
    assert bf_alert.severity == "CRITICAL"
    assert bf_alert.matched_events_count == 4
    assert bf_alert.mitre_technique_id == "T1110.001"


def test_aggregation_correlation_password_spray(cep_engine):
    base_time = datetime.utcnow()
    attacker_ip = "185.220.101.9"

    events = [
        {"id": f"spray-{i}", "src_ip": attacker_ip, "username": f"user_{i}", "event_type": "AUTH_FAILURE", "timestamp": base_time + timedelta(seconds=i * 5)}
        for i in range(6)
    ]

    alerts = cep_engine.process_batch(events)
    spray_alert = next((a for a in alerts if a.rule_id == "CORR-PASSWORD-SPRAY"), None)
    assert spray_alert is not None
    assert spray_alert.severity == "HIGH"
    assert spray_alert.group_key == f"src_ip:{attacker_ip}"


def test_aggregation_correlation_ransomware_burst(cep_engine):
    base_time = datetime.utcnow()
    host = "WORKSTATION-FIN-09"

    events = [
        {"id": f"rw-{i}", "host_id": host, "event_type": "FILE_MODIFIED", "path": f"C:\\Docs\\file_{i}.enc", "timestamp": base_time + timedelta(seconds=i * 0.5)}
        for i in range(25)
    ]

    alerts = cep_engine.process_batch(events)
    rw_alert = next((a for a in alerts if a.rule_id == "CORR-RANSOMWARE-BURST"), None)
    assert rw_alert is not None
    assert rw_alert.severity == "CRITICAL"
    assert rw_alert.mitre_technique_id == "T1486"


def test_cooldown_tracker_suppression(cep_engine):
    base_time = datetime.utcnow()
    host = "SERVER-DB-01"

    events1 = [
        {"id": f"rw1-{i}", "host_id": host, "event_type": "FILE_MODIFIED", "timestamp": base_time}
        for i in range(22)
    ]
    alerts1 = cep_engine.process_batch(events1)
    assert len(alerts1) == 1

    # Immediate second batch within cooldown period should be suppressed
    events2 = [
        {"id": f"rw2-{i}", "host_id": host, "event_type": "FILE_MODIFIED", "timestamp": base_time + timedelta(seconds=5)}
        for i in range(22)
    ]
    alerts2 = cep_engine.process_batch(events2)
    assert len(alerts2) == 0


def test_correlation_api_endpoints(client):
    # 1. List rules
    resp = client.get("/api/correlation/rules")
    assert resp.status_code == 200
    rules = resp.json()
    assert len(rules) >= 4

    # 2. Ingest stream of events via API
    payload = {
        "events": [
            {"id": "api-1", "username": "admin", "event_type": "AUTH_FAILURE", "timestamp": "2026-09-12T12:00:00Z"},
            {"id": "api-2", "username": "admin", "event_type": "AUTH_FAILURE", "timestamp": "2026-09-12T12:00:05Z"},
            {"id": "api-3", "username": "admin", "event_type": "AUTH_FAILURE", "timestamp": "2026-09-12T12:00:10Z"},
            {"id": "api-4", "username": "admin", "event_type": "AUTH_SUCCESS", "timestamp": "2026-09-12T12:00:15Z"},
        ]
    }
    resp = client.post("/api/correlation/process", json=payload)
    assert resp.status_code == 200
    alerts = resp.json()
    assert len(alerts) >= 1
    assert alerts[0]["rule_id"] == "CORR-BRUTE-FORCE-SUCCESS"

    # 3. Retrieve alerts
    resp = client.get("/api/correlation/alerts")
    assert resp.status_code == 200
    assert len(resp.json()) >= 1

    # 4. Check stats
    resp = client.get("/api/correlation/stats")
    assert resp.status_code == 200
    stats = resp.json()
    assert stats["total_rules"] >= 5
    assert stats["total_correlated_alerts"] >= 1
