"""
Unit and Integration Tests for Breach and Attack Simulation (BAS) Subsystem.
Verifies atomic test catalog, attack technique simulation, cross-engine detection validation, and REST APIs.
"""

import pytest
from fastapi.testclient import TestClient

from cybershield.api.server import app
from cybershield.bas.atomic_tests import ATOMIC_TEST_CATALOG, get_atomic_test
from cybershield.bas.runner import AttackSimulationRunner
from cybershield.bas.schemas import SimulationExecutionMode, SimulationRunRequest


@pytest.fixture
def runner():
    return AttackSimulationRunner()


@pytest.fixture
def client():
    return TestClient(app)


def test_atomic_test_catalog():
    tests = ATOMIC_TEST_CATALOG
    assert len(tests) >= 6
    techniques = [t.mitre_technique_id for t in tests]
    assert "T1059.001" in techniques
    assert "T1003.001" in techniques
    assert "T1110.001" in techniques
    assert "T1486" in techniques

    # Verify retrieval by ID
    ps_test = get_atomic_test("BAS-T1059-001")
    assert ps_test is not None
    assert ps_test.name == "PowerShell Encoded Script Execution"


def test_single_atomic_simulation_powershell(runner):
    test = get_atomic_test("BAS-T1059-001")
    assert test is not None
    res = runner.run_atomic_test(test, SimulationExecutionMode.SYNTHETIC_INJECTION)

    assert res.test_id == "BAS-T1059-001"
    assert res.detected is True
    assert len(res.matched_rules) >= 1
    assert res.detecting_engine is not None


def test_single_atomic_simulation_lsass(runner):
    test = get_atomic_test("BAS-T1003-001")
    assert test is not None
    res = runner.run_atomic_test(test, SimulationExecutionMode.SYNTHETIC_INJECTION)

    assert res.detected is True
    assert any("T1003" in r or "LSASS" in r for r in res.matched_rules)


def test_single_atomic_simulation_brute_force(runner):
    test = get_atomic_test("BAS-T1110-001")
    assert test is not None
    res = runner.run_atomic_test(test, SimulationExecutionMode.SYNTHETIC_INJECTION)

    assert res.detected is True
    assert any("CEP" in r or "BRUTE" in r for r in res.matched_rules)


def test_execute_simulation_suite_coverage(runner):
    req = SimulationRunRequest(execution_mode=SimulationExecutionMode.SYNTHETIC_INJECTION)
    report = runner.execute_simulation_suite(req)

    assert report.total_tests_run == len(ATOMIC_TEST_CATALOG)
    assert report.detected_count >= 4
    assert report.detection_coverage_pct >= 50.0
    assert len(report.test_results) == len(ATOMIC_TEST_CATALOG)
    assert report.completed_at >= report.started_at


def test_bas_api_endpoints(client):
    # 1. List tests
    resp = client.get("/api/bas/tests")
    assert resp.status_code == 200
    tests = resp.json()
    assert len(tests) >= 6

    # 2. Get test detail
    resp = client.get("/api/bas/tests/BAS-T1059-001")
    assert resp.status_code == 200
    assert resp.json()["test_id"] == "BAS-T1059-001"

    # 3. Run selective simulation via API
    run_payload = {
        "test_ids": ["BAS-T1059-001", "BAS-T1003-001"],
        "execution_mode": "SYNTHETIC_INJECTION",
    }
    resp = client.post("/api/bas/run", json=run_payload)
    assert resp.status_code == 201
    report = resp.json()
    assert report["total_tests_run"] == 2
    assert report["detected_count"] == 2
    assert report["detection_coverage_pct"] == 100.0
    run_id = report["run_id"]

    # 4. Get report
    resp = client.get(f"/api/bas/reports/{run_id}")
    assert resp.status_code == 200
    assert resp.json()["run_id"] == run_id

    # 5. List reports
    resp = client.get("/api/bas/reports")
    assert resp.status_code == 200
    assert len(resp.json()) >= 1

    # 6. Summary metrics
    resp = client.get("/api/bas/summary")
    assert resp.status_code == 200
    summary = resp.json()
    assert summary["catalog_size"] >= 6
    assert summary["total_simulations_executed"] >= 1
