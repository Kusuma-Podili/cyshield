"""User Administration Business Logic Service."""

from __future__ import annotations

from typing import List, Tuple, Optional
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, desc, or_
from fastapi import HTTPException, status

from cybershield.database.models import User, UserRole, get_role_permissions
from cybershield.auth.security import get_password_hash
from cybershield.auth.schemas import UserProfileResponse
from cybershield.users.schemas import UserCreateAdminRequest, UserUpdateRequest
from cybershield.audit.service import AuditService


class UserService:
    """Enterprise user account lifecycle operations."""

    @classmethod
    async def list_users(
        cls,
        db: AsyncSession,
        role: Optional[str] = None,
        search: Optional[str] = None,
        is_active: Optional[bool] = None,
        page: int = 1,
        page_size: int = 20,
    ) -> Tuple[List[UserProfileResponse], int]:
        """Fetch paginated, filtered user accounts."""
        query = select(User)

        if role:
            query = query.where(User.role == role.upper())
        if is_active is not None:
            query = query.where(User.is_active == is_active)
        if search:
            s = f"%{search}%"
            query = query.where(or_(User.username.ilike(s), User.email.ilike(s), User.full_name.ilike(s)))

        # Count total
        count_q = select(func.count()).select_from(query.subquery())
        total = (await db.execute(count_q)).scalar_one()

        offset = (page - 1) * page_size
        query = query.order_by(desc(User.created_at)).offset(offset).limit(page_size)

        result = await db.execute(query)
        users = result.scalars().all()

        profiles = []
        for u in users:
            p = UserProfileResponse.model_validate(u)
            p.permissions = get_role_permissions(u.role)
            profiles.append(p)

        return profiles, total

    @classmethod
    async def get_user_by_id(cls, db: AsyncSession, user_id: int) -> User:
        """Fetch user by ID or raise 404."""
        result = await db.execute(select(User).where(User.id == user_id))
        user = result.scalar_one_or_none()
        if not user:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=f"User #{user_id} not found")
        return user

    @classmethod
    async def create_user_admin(
        cls,
        db: AsyncSession,
        payload: UserCreateAdminRequest,
        admin_username: str,
        ip_address: str = "127.0.0.1",
    ) -> UserProfileResponse:
        """Admin creates a new user account with assigned role."""
        query = select(User).where(or_(User.username == payload.username.lower(), User.email == payload.email.lower()))
        if (await db.execute(query)).scalar_one_or_none():
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Username or email already in use")

        # Validate role
        role_upper = payload.role.upper()
        if role_upper not in UserRole.__members__:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"Invalid role '{payload.role}'")

        new_user = User(
            username=payload.username.lower(),
            email=payload.email.lower(),
            full_name=payload.full_name,
            hashed_password=get_password_hash(payload.password),
            role=role_upper,
            is_active=payload.is_active,
            is_verified=True,
        )
        db.add(new_user)
        await db.commit()
        await db.refresh(new_user)

        await AuditService.log_event(
            db,
            action="ADMIN_CREATE_USER",
            username=admin_username,
            resource=f"users/{new_user.id}",
            ip_address=ip_address,
            details={"created_user": new_user.username, "role": new_user.role},
        )

        resp = UserProfileResponse.model_validate(new_user)
        resp.permissions = get_role_permissions(new_user.role)
        return resp

    @classmethod
    async def update_user(
        cls,
        db: AsyncSession,
        user_id: int,
        payload: UserUpdateRequest,
        admin_username: str,
        ip_address: str = "127.0.0.1",
    ) -> UserProfileResponse:
        """Update existing user properties (role, active, locked)."""
        user = await cls.get_user_by_id(db, user_id)

        changes = {}
        if payload.full_name is not None:
            changes["full_name"] = payload.full_name
            user.full_name = payload.full_name
        if payload.email is not None:
            changes["email"] = payload.email.lower()
            user.email = payload.email.lower()
        if payload.role is not None:
            r = payload.role.upper()
            if r not in UserRole.__members__:
                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"Invalid role '{payload.role}'")
            changes["role"] = r
            user.role = r
        if payload.is_active is not None:
            changes["is_active"] = payload.is_active
            user.is_active = payload.is_active
        if payload.is_locked is not None:
            changes["is_locked"] = payload.is_locked
            user.is_locked = payload.is_locked
            if not payload.is_locked:
                user.failed_login_attempts = 0
                user.lockout_until = None

        await db.commit()
        await db.refresh(user)

        await AuditService.log_event(
            db,
            action="ADMIN_UPDATE_USER",
            username=admin_username,
            resource=f"users/{user.id}",
            ip_address=ip_address,
            details={"target_user": user.username, "modifications": changes},
        )

        resp = UserProfileResponse.model_validate(user)
        resp.permissions = get_role_permissions(user.role)
        return resp

    @classmethod
    async def unlock_user(
        cls,
        db: AsyncSession,
        user_id: int,
        admin_username: str,
        ip_address: str = "127.0.0.1",
    ) -> UserProfileResponse:
        """Unlock an account and clear failed attempt counters."""
        user = await cls.get_user_by_id(db, user_id)
        user.is_locked = False
        user.lockout_until = None
        user.failed_login_attempts = 0

        await db.commit()
        await db.refresh(user)

        await AuditService.log_event(
            db,
            action="ADMIN_UNLOCK_ACCOUNT",
            username=admin_username,
            resource=f"users/{user.id}",
            ip_address=ip_address,
            details={"unlocked_user": user.username},
        )

        resp = UserProfileResponse.model_validate(user)
        resp.permissions = get_role_permissions(user.role)
        return resp
