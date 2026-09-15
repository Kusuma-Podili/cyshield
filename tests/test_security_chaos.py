"""
Unit and integration tests for Security Chaos Engineering & Fault Injection Engine.
"""

import pytest
from fastapi.testclient import TestClient

from cybershield.api.server import app
from cybershield.chaos.engine import SecurityChaosEngine
from cybershield.chaos.schemas import (
    ChaosExperimentCreateRequest,
    ChaosExperimentStatus,
    ChaosFaultType,
    HypothesisVerdict,
)


@pytest.fixture
def engine():
    return SecurityChaosEngine()


@pytest.fixture
def client():
    return TestClient(app)


def test_seeded_chaos_experiments(engine):
    experiments = engine.list_experiments()
    assert len(experiments) >= 2
    e_ids = [e.experiment_id for e in experiments]
    assert "EXP-CHAOS-001" in e_ids
    assert "EXP-CHAOS-002" in e_ids

    e1 = engine.get_experiment("EXP-CHAOS-001")
    assert e1 is not None
    assert e1.verdict == HypothesisVerdict.HYPOTHESIS_CONFIRMED
    assert e1.blast_radius_contained is True


def test_create_and_run_chaos_experiment(engine):
    req = ChaosExperimentCreateRequest(
        name="Ingestion Pipeline Latency Degradation Test",
        target_subsystem="SyslogIngestor",
        fault_type=ChaosFaultType.LATENCY_SPIKE,
        parameters={"delay_ms": 2000},
        hypothesis_statement="System buffers events without dropping messages when pipeline latency increases by 2000ms."
    )
    exp = engine.create_experiment(req)
    assert exp.status == ChaosExperimentStatus.SCHEDULED
    exp_id = exp.experiment_id

    # Run experiment
    executed = engine.run_experiment(exp_id)
    assert executed.status == ChaosExperimentStatus.COMPLETED
    assert executed.verdict == HypothesisVerdict.HYPOTHESIS_CONFIRMED
    assert executed.duration_seconds > 0.0
    assert executed.blast_radius_contained is True
    assert "injected_latency_ms" in executed.steady_state_after


def test_abort_chaos_experiment_circuit_breaker(engine):
    req = ChaosExperimentCreateRequest(
        name="Worker Crash Test",
        target_subsystem="WorkerPool",
        fault_type=ChaosFaultType.WORKER_PROCESS_CRASH,
        parameters={},
        hypothesis_statement="Supervisor revives crashed workers within 1 second."
    )
    exp = engine.create_experiment(req)
    aborted = engine.abort_experiment(exp.experiment_id)
    assert aborted.status == ChaosExperimentStatus.ABORTED
    assert aborted.verdict == HypothesisVerdict.INCONCLUSIVE


def test_chaos_overview_metrics(engine):
    metrics = engine.get_overview_metrics()
    assert metrics["total_chaos_experiments"] >= 2
    assert metrics["completed_experiments"] >= 2
    assert metrics["resilience_confidence_percentage"] >= 90.0
    assert len(metrics["supported_fault_types"]) >= 5


def test_chaos_api_lifecycle(client):
    # 1. List experiments
    list_res = client.get("/api/chaos/experiments")
    assert list_res.status_code == 200
    assert len(list_res.json()) >= 2

    # 2. Create experiment via API
    create_payload = {
        "name": "API Rate Limiter Backpressure Test",
        "target_subsystem": "APIGateway",
        "fault_type": "CORRUPTED_PAYLOAD",
        "parameters": {"corrupted_packet_count": 25},
        "hypothesis_statement": "API gateway returns 400 Bad Request without crashing internal workers."
    }
    create_res = client.post("/api/chaos/experiments", json=create_payload)
    assert create_res.status_code == 201
    exp_id = create_res.json()["experiment_id"]

    # 3. Get experiment details
    get_res = client.get(f"/api/chaos/experiments/{exp_id}")
    assert get_res.status_code == 200
    assert get_res.json()["status"] == "SCHEDULED"

    # 4. Run experiment via API
    run_res = client.post(f"/api/chaos/experiments/{exp_id}/run")
    assert run_res.status_code == 200
    assert run_res.json()["status"] == "COMPLETED"
    assert run_res.json()["verdict"] == "HYPOTHESIS_CONFIRMED"

    # 5. Get overview
    ovr_res = client.get("/api/chaos/overview")
    assert ovr_res.status_code == 200
    assert ovr_res.json()["completed_experiments"] >= 3
