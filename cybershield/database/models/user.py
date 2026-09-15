"""SQLAlchemy ORM User Model for CyberShield Enterprise."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Optional, Dict, Any
from sqlalchemy import (
    Column,
    Integer,
    String,
    Boolean,
    DateTime,
    JSON,
    Index,
)
from cybershield.database.session import Base
from cybershield.database.models.role import UserRole


def now_utc() -> datetime:
    return datetime.now(timezone.utc)


class User(Base):
    """Enterprise user account model with security lockout and audit attributes."""
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    username = Column(String(64), unique=True, nullable=False, index=True)
    email = Column(String(255), unique=True, nullable=False, index=True)
    full_name = Column(String(128), nullable=False, default="")
    hashed_password = Column(String(255), nullable=False)
    role = Column(String(32), nullable=False, default=UserRole.VIEWER.value)

    # Status Flags
    is_active = Column(Boolean, default=True, nullable=False)
    is_verified = Column(Boolean, default=True, nullable=False)
    is_locked = Column(Boolean, default=False, nullable=False)

    # Brute-force & Security Lockout
    failed_login_attempts = Column(Integer, default=0, nullable=False)
    lockout_until = Column(DateTime(timezone=True), nullable=True)
    last_login_at = Column(DateTime(timezone=True), nullable=True)
    last_login_ip = Column(String(45), nullable=True)

    # Timestamps
    created_at = Column(DateTime(timezone=True), default=now_utc, nullable=False)
    updated_at = Column(DateTime(timezone=True), default=now_utc, onupdate=now_utc, nullable=False)

    # Security Preferences (MFA, Sessions)
    security_settings = Column(JSON, default=dict, nullable=False)

    __table_args__ = (
        Index("ix_users_role_active", "role", "is_active"),
    )

    def is_temporarily_locked(self) -> bool:
        """Check if account is locked either permanently or by temporary timeout."""
        if not self.is_locked:
            return False
        if self.lockout_until is None:
            return True
        # Check if lockout period has expired
        return datetime.now(timezone.utc) < self.lockout_until.replace(tzinfo=timezone.utc)
