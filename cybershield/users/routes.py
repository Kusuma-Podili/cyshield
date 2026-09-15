"""User Administration & Role Management REST API Endpoints."""

from __future__ import annotations

from typing import List, Optional
from fastapi import APIRouter, Depends, Query, Request, status
from sqlalchemy.ext.asyncio import AsyncSession

from cybershield.database.session import get_db
from cybershield.database.models import User, UserRole, Permission, get_role_permissions
from cybershield.auth.dependencies import get_current_user, require_permission
from cybershield.auth.schemas import UserProfileResponse
from cybershield.users.schemas import (
    UserCreateAdminRequest,
    UserUpdateRequest,
    UserListResponse,
    RoleDefinitionResponse,
)
from cybershield.users.service import UserService

router = APIRouter(tags=["User Management"])

ROLE_DESCRIPTIONS = {
    "SUPER_ADMIN": "Unrestricted administrative authority across all platform systems.",
    "SECURITY_ADMIN": "Manages users, permissions, alert rules, and security configurations.",
    "SECURITY_ANALYST": "Monitors alerts, investigates threats, seals forensic evidence, and reviews MITRE matrix.",
    "NETWORK_ANALYST": "Monitors network topologies, bandwidth, port traffic, and device flows.",
    "INCIDENT_RESPONDER": "Coordinates incident lifecycles, executes automated SOAR containment playbooks.",
    "VIEWER": "Read-only access to dashboards, threat intel, and compliance reports.",
}


@router.get("/api/users", response_model=UserListResponse)
async def list_users(
    role: Optional[str] = None,
    search: Optional[str] = None,
    is_active: Optional[bool] = None,
    page: int = Query(default=1, ge=1),
    page_size: int = Query(default=20, ge=1, le=100),
    current_user: User = Depends(require_permission(Permission.USERS_VIEW)),
    db: AsyncSession = Depends(get_db),
):
    """Retrieve paginated list of enterprise users with role and search filters."""
    items, total = await UserService.list_users(
        db, role=role, search=search, is_active=is_active, page=page, page_size=page_size
    )
    return UserListResponse(items=items, total=total, page=page, page_size=page_size)


@router.post("/api/users", response_model=UserProfileResponse, status_code=status.HTTP_201_CREATED)
async def create_user(
    payload: UserCreateAdminRequest,
    request: Request,
    current_user: User = Depends(require_permission(Permission.USERS_CREATE)),
    db: AsyncSession = Depends(get_db),
):
    """Administrator onboarding of a new user account with designated role."""
    ip = request.client.host if request.client else "127.0.0.1"
    return await UserService.create_user_admin(
        db, payload, admin_username=current_user.username, ip_address=ip
    )


@router.get("/api/users/{user_id}", response_model=UserProfileResponse)
async def get_user_detail(
    user_id: int,
    current_user: User = Depends(require_permission(Permission.USERS_VIEW)),
    db: AsyncSession = Depends(get_db),
):
    """Fetch profile and permissions for a specific user ID."""
    u = await UserService.get_user_by_id(db, user_id)
    resp = UserProfileResponse.model_validate(u)
    resp.permissions = get_role_permissions(u.role)
    return resp


@router.patch("/api/users/{user_id}", response_model=UserProfileResponse)
async def update_user(
    user_id: int,
    payload: UserUpdateRequest,
    request: Request,
    current_user: User = Depends(require_permission(Permission.USERS_EDIT)),
    db: AsyncSession = Depends(get_db),
):
    """Update profile attributes, role assignments, or active status."""
    ip = request.client.host if request.client else "127.0.0.1"
    return await UserService.update_user(
        db, user_id, payload, admin_username=current_user.username, ip_address=ip
    )


@router.post("/api/users/{user_id}/unlock", response_model=UserProfileResponse)
async def unlock_user_account(
    user_id: int,
    request: Request,
    current_user: User = Depends(require_permission(Permission.USERS_EDIT)),
    db: AsyncSession = Depends(get_db),
):
    """Manually clear failed login lockout on a user account."""
    ip = request.client.host if request.client else "127.0.0.1"
    return await UserService.unlock_user(
        db, user_id, admin_username=current_user.username, ip_address=ip
    )


@router.get("/api/roles", response_model=List[RoleDefinitionResponse])
async def list_roles(current_user: User = Depends(get_current_user)):
    """Retrieve catalog of all 6 enterprise roles and their permission matrices."""
    results = []
    for r in UserRole:
        results.append(
            RoleDefinitionResponse(
                role=r.value,
                description=ROLE_DESCRIPTIONS.get(r.value, "Enterprise user role"),
                permissions=get_role_permissions(r),
            )
        )
    return results
