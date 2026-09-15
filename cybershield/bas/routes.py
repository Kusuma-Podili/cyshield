"""
Breach and Attack Simulation (BAS) REST API Routes.
Exposes endpoints for listing atomic tests, executing simulations, and querying coverage reports.
"""

from typing import Any, Dict, List, Optional
from fastapi import APIRouter, HTTPException, Query, status

from cybershield.bas.atomic_tests import ATOMIC_TEST_CATALOG, get_atomic_test
from cybershield.bas.runner import AttackSimulationRunner
from cybershield.bas.schemas import (
    AtomicTest,
    SimulationReport,
    SimulationRunRequest,
)

bas_router = APIRouter(prefix="/api/bas", tags=["Breach and Attack Simulation (BAS)"])
bas_runner = AttackSimulationRunner()


@bas_router.get("/tests", response_model=List[AtomicTest])
async def list_tests():
    """List all available atomic attack simulation tests mapped to MITRE ATT&CK."""
    return bas_runner.list_available_tests()


@bas_router.get("/tests/{test_id}", response_model=AtomicTest)
async def get_test(test_id: str):
    """Retrieve details of a specific atomic simulation test."""
    t = get_atomic_test(test_id)
    if not t:
        raise HTTPException(status_code=404, detail=f"Test {test_id} not found")
    return t


@bas_router.post("/run", response_model=SimulationReport, status_code=status.HTTP_201_CREATED)
async def run_simulation(request: SimulationRunRequest):
    """Launch atomic breach simulation suite and evaluate real-time detection efficacy."""
    return bas_runner.execute_simulation_suite(request)


@bas_router.get("/reports", response_model=List[SimulationReport])
async def list_reports():
    """List historical breach simulation validation reports."""
    return bas_runner.list_reports()


@bas_router.get("/reports/{run_id}", response_model=SimulationReport)
async def get_report(run_id: str):
    """Retrieve a specific breach simulation report by ID."""
    rep = bas_runner.get_report(run_id)
    if not rep:
        raise HTTPException(status_code=404, detail=f"Simulation report {run_id} not found")
    return rep


@bas_router.get("/summary")
async def get_summary():
    """Get overall BAS summary metrics and defense posture."""
    reports = bas_runner.list_reports()
    total_runs = len(reports)
    avg_coverage = sum(r.detection_coverage_pct for r in reports) / total_runs if total_runs else 0.0

    return {
        "catalog_size": len(ATOMIC_TEST_CATALOG),
        "total_simulations_executed": total_runs,
        "average_detection_coverage_pct": round(avg_coverage, 1),
        "available_tactics": list({t.tactic for t in ATOMIC_TEST_CATALOG}),
    }
