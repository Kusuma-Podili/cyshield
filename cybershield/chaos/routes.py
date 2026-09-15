"""
Security Chaos Engineering REST API routes.
"""

from typing import Any, Dict, List, Optional
from fastapi import APIRouter, HTTPException, Query, status

from cybershield.chaos.engine import SecurityChaosEngine
from cybershield.chaos.schemas import (
    ChaosExperiment,
    ChaosExperimentCreateRequest,
)

chaos_router = APIRouter(prefix="/api/chaos", tags=["Security Chaos Engineering & Fault Injection"])
_chaos_engine = SecurityChaosEngine()


@chaos_router.get("/experiments", response_model=List[ChaosExperiment])
async def list_chaos_experiments():
    """List all scheduled and completed security chaos experiments."""
    return _chaos_engine.list_experiments()


@chaos_router.post("/experiments", response_model=ChaosExperiment, status_code=status.HTTP_201_CREATED)
async def create_chaos_experiment(req: ChaosExperimentCreateRequest):
    """Define and schedule a new controlled security fault injection experiment."""
    return _chaos_engine.create_experiment(req)


@chaos_router.post("/experiments/{experiment_id}/run", response_model=ChaosExperiment)
async def run_chaos_experiment(experiment_id: str):
    """Execute a scheduled chaos experiment with automatic blast-radius containment."""
    try:
        return _chaos_engine.run_experiment(experiment_id)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


@chaos_router.post("/experiments/{experiment_id}/abort", response_model=ChaosExperiment)
async def abort_chaos_experiment(experiment_id: str):
    """Trigger safety circuit-breaker to instantly abort an active experiment."""
    try:
        return _chaos_engine.abort_experiment(experiment_id)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


@chaos_router.get("/experiments/{experiment_id}", response_model=ChaosExperiment)
async def get_chaos_experiment(experiment_id: str):
    """Retrieve detailed steady-state metrics and hypothesis outcome for a chaos experiment."""
    exp = _chaos_engine.get_experiment(experiment_id)
    if not exp:
        raise HTTPException(status_code=404, detail=f"Chaos experiment '{experiment_id}' not found")
    return exp


@chaos_router.get("/overview")
async def get_chaos_overview():
    """Executive metrics on platform resilience confidence, confirmed hypotheses, and blindspots."""
    return _chaos_engine.get_overview_metrics()
