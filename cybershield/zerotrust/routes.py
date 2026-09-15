"""
Zero Trust Architecture REST API Routes.
Exposes endpoints for continuous posture evaluation, access decisioning, and policy management.
"""

from typing import Any, Dict, List, Optional
from fastapi import APIRouter, HTTPException, Query, status

from cybershield.zerotrust.policy_engine import ZeroTrustPolicyEngine
from cybershield.zerotrust.schemas import (
    AccessContext,
    TrustEvaluation,
    ZeroTrustPolicy,
)

zerotrust_router = APIRouter(prefix="/api/zerotrust", tags=["Zero Trust Architecture"])
zt_engine = ZeroTrustPolicyEngine()


@zerotrust_router.post("/evaluate", response_model=TrustEvaluation)
async def evaluate_access_request(context: AccessContext):
    """Evaluate an endpoint access request in real-time against ZTA policy."""
    return zt_engine.evaluate_access(context)


@zerotrust_router.get("/policies", response_model=List[ZeroTrustPolicy])
async def list_policies():
    """List configured Zero Trust access policies across sensitivity tiers."""
    return zt_engine.list_policies()


@zerotrust_router.post("/policies", response_model=ZeroTrustPolicy, status_code=status.HTTP_201_CREATED)
async def create_or_update_policy(policy: ZeroTrustPolicy):
    """Create or update a Zero Trust policy."""
    return zt_engine.create_or_update_policy(policy)


@zerotrust_router.get("/history", response_model=List[TrustEvaluation])
async def get_evaluation_history(
    device_id: Optional[str] = Query(None),
    user_id: Optional[str] = Query(None),
    limit: int = Query(50, ge=1, le=500),
):
    """Retrieve historical access evaluations and decisions."""
    return zt_engine.get_evaluations_history(device_id=device_id, user_id=user_id, limit=limit)


@zerotrust_router.get("/overview")
async def get_overview():
    """Get aggregate Zero Trust access statistics and health telemetry."""
    return zt_engine.get_overview_statistics()
