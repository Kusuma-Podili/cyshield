"""
CyberShield Enterprise - Alert Deduplication & Noise Suppression Engine
Generates deterministic correlation hashes to deduplicate identical alert streams
and evaluates suppression policies to prevent alert fatigue.
"""

import hashlib
import re
from datetime import datetime, timedelta
from typing import Optional, Tuple, List
from sqlalchemy import select, and_
from sqlalchemy.ext.asyncio import AsyncSession

from cybershield.database.models.events_and_alerts import (
    AlertModel,
    AlertSuppressionRuleModel,
    AlertStatus,
)
from cybershield.core.logging import get_logger

logger = get_logger("cybershield.alerts.deduplicator")


class AlertDeduplicator:
    """Evaluates deduplication hashes and suppression conditions."""

    DEDUP_WINDOW_MINUTES = 15

    @staticmethod
    def compute_hash(
        rule_id: str,
        host_name: Optional[str] = None,
        user_name: Optional[str] = None,
        host_ip: Optional[str] = None,
    ) -> str:
        """Calculate deterministic SHA-256 fingerprint for grouping duplicate telemetry."""
        raw_key = f"{rule_id.strip()}|{(host_name or '').strip().lower()}|{(user_name or '').strip().lower()}|{(host_ip or '').strip()}"
        return hashlib.sha256(raw_key.encode("utf-8")).hexdigest()

    @classmethod
    async def find_duplicate(
        cls,
        session: AsyncSession,
        dedup_hash: str
    ) -> Optional[AlertModel]:
        """Check if an open alert with identical hash exists within the sliding window."""
        cutoff = datetime.utcnow() - timedelta(minutes=cls.DEDUP_WINDOW_MINUTES)
        stmt = select(AlertModel).where(
            and_(
                AlertModel.deduplication_hash == dedup_hash,
                AlertModel.status.in_([AlertStatus.NEW, AlertStatus.ASSIGNED, AlertStatus.UNDER_INVESTIGATION]),
                AlertModel.last_seen >= cutoff
            )
        ).order_by(AlertModel.last_seen.desc())

        result = await session.execute(stmt)
        return result.scalar_one_or_none()

    @staticmethod
    async def check_suppression(
        session: AsyncSession,
        rule_name: str,
        host_name: Optional[str] = None,
        user_name: Optional[str] = None,
    ) -> Tuple[bool, Optional[str]]:
        """Evaluate if alert matches any active suppression rules."""
        stmt = select(AlertSuppressionRuleModel).where(AlertSuppressionRuleModel.is_active == True)
        result = await session.execute(stmt)
        active_rules = result.scalars().all()

        for rule in active_rules:
            # Check expiration
            if rule.expires_at and rule.expires_at < datetime.utcnow():
                continue

            matched = True
            if rule.rule_name_pattern:
                if not re.search(rule.rule_name_pattern, rule_name, re.IGNORECASE):
                    matched = False

            if matched and rule.host_pattern and host_name:
                if not re.search(rule.host_pattern, host_name, re.IGNORECASE):
                    matched = False

            if matched and rule.user_pattern and user_name:
                if not re.search(rule.user_pattern, user_name, re.IGNORECASE):
                    matched = False

            if matched:
                logger.info(
                    "SUPPRESSED ALERT: '%s' on '%s' matched suppression rule '%s' (Reason: %s)",
                    rule_name, host_name, rule.name, rule.reason
                )
                return True, f"Matched rule '{rule.name}': {rule.reason}"

        return False, None
