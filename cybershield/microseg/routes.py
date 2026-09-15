"""
Enterprise Network Microsegmentation REST API Routes.
Exposes endpoints for policy management, firewall code generation, and lateral flow drift evaluation.
"""

from typing import Any, Dict, List, Optional
from fastapi import APIRouter, HTTPException, Query, status

from cybershield.microseg.compiler import MicrosegmentationCompiler
from cybershield.microseg.schemas import (
    CompileRequest,
    CompiledFirewallRuleset,
    FlowEvaluationRequest,
    FlowViolationEvent,
    MicrosegmentationRule,
)

microseg_router = APIRouter(prefix="/api/microseg", tags=["Network Microsegmentation"])
microseg_compiler = MicrosegmentationCompiler()


@microseg_router.get("/rules", response_model=List[MicrosegmentationRule])
async def list_rules():
    """List declarative east-west microsegmentation security policies."""
    return microseg_compiler.list_rules()


@microseg_router.post("/rules", response_model=MicrosegmentationRule, status_code=status.HTTP_201_CREATED)
async def create_rule(rule: MicrosegmentationRule):
    """Define a new microsegmentation policy between workload tiers."""
    return microseg_compiler.add_rule(rule)


@microseg_router.post("/compile", response_model=CompiledFirewallRuleset)
async def compile_ruleset(request: CompileRequest):
    """Compile declarative policies into target syntax (nftables, iptables, Windows Firewall, Kubernetes NetworkPolicy, AWS SG)."""
    try:
        return microseg_compiler.compile_ruleset(request.target_format, request.rule_ids)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@microseg_router.post("/evaluate-flow", response_model=Optional[FlowViolationEvent])
async def evaluate_flow(flow: FlowEvaluationRequest):
    """Evaluate observed network flow telemetry against microsegmentation boundaries."""
    return microseg_compiler.evaluate_flow(flow)


@microseg_router.get("/violations", response_model=List[FlowViolationEvent])
async def list_violations(limit: int = Query(50, ge=1, le=500)):
    """List detected lateral movement microsegmentation boundary violations."""
    return microseg_compiler.list_violations(limit=limit)
