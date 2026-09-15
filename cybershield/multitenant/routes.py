"""
Multi-Tenant Architecture & Virtual SOC REST API routes.
"""

from typing import Any, Dict, List, Optional
from fastapi import APIRouter, HTTPException, Query, status

from cybershield.multitenant.schemas import (
    TenantCreateRequest,
    TenantProfile,
    TenantRole,
    TenantUsageMetrics,
    TenantUserMapping,
)
from cybershield.multitenant.service import TenantManager

multitenant_router = APIRouter(prefix="/api/tenants", tags=["Multi-Tenant & Virtual SOC (vSOC)"])
_tenant_manager = TenantManager()


@multitenant_router.get("", response_model=List[TenantProfile])
async def list_tenants():
    """List all registered enterprise tenant organizations."""
    return _tenant_manager.list_tenants()


@multitenant_router.post("", response_model=TenantProfile, status_code=status.HTTP_201_CREATED)
async def create_tenant(req: TenantCreateRequest):
    """Provision a new isolated tenant boundary with custom quotas."""
    return _tenant_manager.create_tenant(req)


@multitenant_router.get("/overview")
async def get_multitenant_overview():
    """Consolidated metrics across all virtual SOC tenant boundaries."""
    return _tenant_manager.get_overview_metrics()


@multitenant_router.get("/{tenant_id}", response_model=TenantProfile)
async def get_tenant(tenant_id: str):
    """Retrieve tenant profile by ID."""
    tenant = _tenant_manager.get_tenant(tenant_id)
    if not tenant:
        raise HTTPException(status_code=404, detail=f"Tenant '{tenant_id}' not found")
    return tenant


@multitenant_router.get("/{tenant_id}/usage", response_model=TenantUsageMetrics)
async def get_tenant_usage(tenant_id: str):
    """Retrieve real-time capacity and quota consumption metrics."""
    usage = _tenant_manager.get_tenant_usage(tenant_id)
    if not usage:
        raise HTTPException(status_code=404, detail=f"Tenant '{tenant_id}' not found")
    return usage


@multitenant_router.post("/{tenant_id}/users", response_model=TenantUserMapping, status_code=status.HTTP_201_CREATED)
async def assign_user_to_tenant(tenant_id: str, user_id: str = Query(...), role: TenantRole = TenantRole.SOC_ANALYST):
    """Assign a user account to a specific tenant with scoped RBAC permissions."""
    try:
        return _tenant_manager.assign_user_to_tenant(user_id=user_id, tenant_id=tenant_id, role=role)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@multitenant_router.get("/{tenant_id}/users", response_model=List[TenantUserMapping])
async def list_tenant_users(tenant_id: str):
    """List all users assigned to an enterprise tenant organization."""
    return _tenant_manager.get_tenant_users(tenant_id)
