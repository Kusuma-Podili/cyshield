"""SQLAlchemy ORM AuditLog Model for Compliance & Security Operations."""

from __future__ import annotations

from datetime import datetime, timezone
from sqlalchemy import (
    Column,
    Integer,
    String,
    DateTime,
    JSON,
    Index,
)
from cybershield.database.session import Base


def now_utc() -> datetime:
    return datetime.now(timezone.utc)


class AuditLog(Base):
    """Immutable audit trail of all security operations, administrative actions, and logins."""
    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    user_id = Column(Integer, nullable=True, index=True)
    username = Column(String(64), nullable=False, default="ANONYMOUS", index=True)
    action = Column(String(64), nullable=False, index=True)  # e.g., "LOGIN", "USER_CREATE", "ROLE_CHANGE"
    resource = Column(String(128), nullable=False, default="SYSTEM")
    ip_address = Column(String(45), nullable=True)
    user_agent = Column(String(255), nullable=True)
    status = Column(String(16), nullable=False, default="SUCCESS")  # SUCCESS, FAILED, BLOCKED
    request_id = Column(String(36), nullable=True)
    details = Column(JSON, default=dict, nullable=False)
    timestamp = Column(DateTime(timezone=True), default=now_utc, nullable=False, index=True)

    __table_args__ = (
        Index("ix_audit_action_timestamp", "action", "timestamp"),
    )
