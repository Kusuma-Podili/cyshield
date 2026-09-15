"""SQLAlchemy ORM LoginHistory Model for Identity Protection & UEBA Profiling."""

from __future__ import annotations

from datetime import datetime, timezone
from sqlalchemy import (
    Column,
    Integer,
    String,
    Boolean,
    DateTime,
    Index,
)
from cybershield.database.session import Base


def now_utc() -> datetime:
    return datetime.now(timezone.utc)


class LoginHistory(Base):
    """Detailed record of all authentication attempts with IP, user-agent, and status."""
    __tablename__ = "login_history"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    user_id = Column(Integer, nullable=True, index=True)
    username = Column(String(64), nullable=False, index=True)
    ip_address = Column(String(45), nullable=True)
    user_agent = Column(String(255), nullable=True)
    success = Column(Boolean, nullable=False)
    failure_reason = Column(String(128), nullable=True)
    timestamp = Column(DateTime(timezone=True), default=now_utc, nullable=False, index=True)

    __table_args__ = (
        Index("ix_login_history_user_ts", "username", "timestamp"),
    )
