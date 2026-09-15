"""Pydantic Schemas for User Management & Role Administration."""

from __future__ import annotations

from typing import List, Optional, Dict, Any
from pydantic import BaseModel, EmailStr, Field
from cybershield.auth.schemas import UserProfileResponse


class UserCreateAdminRequest(BaseModel):
    """Payload for administrator creating a new user with specific role."""
    username: str = Field(min_length=3, max_length=32, pattern="^[a-zA-Z0-9_-]+$")
    email: EmailStr
    password: str = Field(min_length=8, max_length=128)
    full_name: str = Field(min_length=1, max_length=128)
    role: str = "SECURITY_ANALYST"
    is_active: bool = True


class UserUpdateRequest(BaseModel):
    """Payload for updating an existing user account."""
    full_name: Optional[str] = None
    email: Optional[EmailStr] = None
    role: Optional[str] = None
    is_active: Optional[bool] = None
    is_locked: Optional[bool] = None


class UserListResponse(BaseModel):
    """Paginated list of user accounts."""
    items: List[UserProfileResponse]
    total: int
    page: int
    page_size: int


class RoleDefinitionResponse(BaseModel):
    """Metadata describing a role and its permission matrix."""
    role: str
    description: str
    permissions: List[str]
