"""Pydantic Schemas for Authentication & Identity Management."""

from __future__ import annotations

from datetime import datetime
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, EmailStr, Field, ConfigDict


class LoginRequest(BaseModel):
    """User credentials submitted for authentication."""
    username_or_email: str
    password: str


class UserProfileResponse(BaseModel):
    """Sanitized user profile data returned to client."""
    model_config = ConfigDict(from_attributes=True)

    id: int
    username: str
    email: str
    full_name: str
    role: str
    permissions: List[str] = []
    is_active: bool
    is_locked: bool
    last_login_at: Optional[datetime] = None
    created_at: datetime


class TokenResponse(BaseModel):
    """OAuth2-compatible JWT token response."""
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in_seconds: int
    user: UserProfileResponse


class RefreshTokenRequest(BaseModel):
    """Refresh token submission."""
    refresh_token: str


class UserRegisterRequest(BaseModel):
    """New user registration payload."""
    username: str = Field(min_length=3, max_length=32, pattern="^[a-zA-Z0-9_-]+$")
    email: EmailStr
    password: str = Field(min_length=8, max_length=128)
    full_name: str = Field(min_length=1, max_length=128)
    role: Optional[str] = "VIEWER"


class PasswordResetRequest(BaseModel):
    """Password reset request payload."""
    email: EmailStr


class PasswordResetConfirmRequest(BaseModel):
    """Password reset confirmation with token."""
    token: str
    new_password: str = Field(min_length=8, max_length=128)


class LoginHistoryItem(BaseModel):
    """Login history audit entry."""
    model_config = ConfigDict(from_attributes=True)

    id: int
    username: str
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    success: bool
    failure_reason: Optional[str] = None
    timestamp: datetime
