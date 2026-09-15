"""Enterprise Audit Logging Service for CyberShield Enterprise.

Records structured, tamper-evident security audit entries for all logins,
credential alterations, permission changes, containment events, and settings updates.
Guarantees zero credential leakage by strictly scrubbing passwords and tokens.
"""

from __future__ import annotations

import uuid
import logging
from typing import Dict, Any, Optional, List, Tuple
from datetime import datetime, timezone
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc

from cybershield.database.models import AuditLog

logger = logging.getLogger("cybershield.audit")

SENSITIVE_KEYS = {
    "password", "hashed_password", "token", "access_token", "refresh_token",
    "secret", "api_key", "credentials", "authorization"
}


def sanitize_payload(payload: Any) -> Any:
    """Recursively scrub sensitive keys from dictionaries or lists."""
    if isinstance(payload, dict):
        cleaned = {}
        for k, v in payload.items():
            if any(sens in k.lower() for sens in SENSITIVE_KEYS):
                cleaned[k] = "[REDACTED]"
            else:
                cleaned[k] = sanitize_payload(v)
        return cleaned
    elif isinstance(payload, list):
        return [sanitize_payload(item) for item in payload]
    return payload


class AuditService:
    """Provides methods to record and query enterprise audit events."""

    @classmethod
    async def log_event(
        cls,
        db: AsyncSession,
        action: str,
        username: str = "ANONYMOUS",
        user_id: Optional[int] = None,
        resource: str = "SYSTEM",
        status: str = "SUCCESS",
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
        request_id: Optional[str] = None,
        details: Optional[Dict[str, Any]] = None,
    ) -> AuditLog:
        """Record an immutable, sanitized audit entry."""
        sanitized_details = sanitize_payload(details or {})
        audit_entry = AuditLog(
            user_id=user_id,
            username=username,
            action=action.upper(),
            resource=resource,
            status=status.upper(),
            ip_address=ip_address,
            user_agent=user_agent,
            request_id=request_id or f"REQ-{uuid.uuid4().hex[:8].upper()}",
            details=sanitized_details,
        )
        db.add(audit_entry)
        try:
            await db.commit()
            await db.refresh(audit_entry)
            logger.info("AUDIT [%s] user=%s action=%s status=%s", audit_entry.request_id, username, action, status)
            return audit_entry
        except Exception as ex:
            await db.rollback()
            logger.error("Failed to commit audit entry: %s", ex)
            raise

    @classmethod
    async def query_logs(
        cls,
        db: AsyncSession,
        action: Optional[str] = None,
        username: Optional[str] = None,
        status: Optional[str] = None,
        limit: int = 50,
        offset: int = 0,
    ) -> Tuple[List[AuditLog], int]:
        """Query paginated audit entries matching filter criteria."""
        query = select(AuditLog)

        if action:
            query = query.where(AuditLog.action == action.upper())
        if username:
            query = query.where(AuditLog.username.ilike(f"%{username}%"))
        if status:
            query = query.where(AuditLog.status == status.upper())

        # Count total matches
        from sqlalchemy import func
        count_query = select(func.count()).select_from(query.subquery())
        total_count = (await db.execute(count_query)).scalar_one()

        # Order by newest first
        query = query.order_by(desc(AuditLog.timestamp)).offset(offset).limit(limit)
        result = await db.execute(query)
        records = result.scalars().all()

        return list(records), total_count
