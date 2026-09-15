"""FastAPI Security Dependencies for Authentication and Authorization."""

from __future__ import annotations

from typing import List, Optional, Callable
from fastapi import Depends, HTTPException, status
from fastapi.security import OAuth2PasswordBearer
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from cybershield.database.session import get_db
from cybershield.database.models import User, UserRole, Permission, has_permission
from cybershield.auth.security import decode_token

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/auth/login", auto_error=False)


async def get_current_user(
    token: Optional[str] = Depends(oauth2_scheme),
    db: AsyncSession = Depends(get_db),
) -> User:
    """Validate bearer token and resolve authenticated User from database."""
    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication credentials were not provided",
            headers={"WWW-Authenticate": "Bearer"},
        )

    try:
        payload = decode_token(token)
        if payload.get("token_type") != "access":
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token type, access token required",
                headers={"WWW-Authenticate": "Bearer"},
            )
        user_id = payload.get("sub")
        if not user_id:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Malformed token payload",
                headers={"WWW-Authenticate": "Bearer"},
            )
    except Exception as ex:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Token validation failed: {str(ex)}",
            headers={"WWW-Authenticate": "Bearer"},
        )

    result = await db.execute(select(User).where(User.id == int(user_id)))
    user = result.scalar_one_or_none()

    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authenticated user account does not exist",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account is deactivated. Contact security administrator.",
        )

    if user.is_temporarily_locked():
        raise HTTPException(
            status_code=status.HTTP_423_LOCKED,
            detail="Account is temporarily locked due to repeated authentication failures.",
        )

    return user


def require_role(allowed_roles: List[str | UserRole]) -> Callable:
    """Dependency factory ensuring current user belongs to one of the specified roles."""
    normalized = [r.value if isinstance(r, UserRole) else str(r).upper() for r in allowed_roles]

    async def _role_checker(user: User = Depends(get_current_user)) -> User:
        # SUPER_ADMIN always satisfies any role requirement
        if user.role.upper() == UserRole.SUPER_ADMIN.value:
            return user
        if user.role.upper() not in normalized:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Access denied. Requires one of roles: {', '.join(normalized)}",
            )
        return user

    return _role_checker


def require_permission(required_perm: str | Permission) -> Callable:
    """Dependency factory ensuring current user possesses a specific RBAC permission."""
    perm_val = required_perm.value if isinstance(required_perm, Permission) else str(required_perm)

    async def _perm_checker(user: User = Depends(get_current_user)) -> User:
        if user.role.upper() == UserRole.SUPER_ADMIN.value:
            return user
        if not has_permission(user.role, perm_val):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Forbidden. Missing required security permission: '{perm_val}'",
            )
        return user

    return _perm_checker
