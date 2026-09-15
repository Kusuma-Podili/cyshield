"""Enterprise Configuration & Settings Manager for CyberShield Enterprise.

Provides dynamic, database-backed platform runtime parameters with cryptographic audit
trailing and validation against schema constraints.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Dict, Any, List, Optional
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from cybershield.database.models.platform_settings import PlatformSettingModel
from cybershield.audit.vault import AuditVault


DEFAULT_SETTINGS: List[Dict[str, Any]] = [
    # --- SECURITY POLICY ---
    {
        "key": "security.password_min_length",
        "category": "SECURITY_POLICY",
        "display_name": "Minimum Password Length",
        "description": "Enforce minimum character count for local user credentials.",
        "value_type": "INTEGER",
        "value_str": "12",
        "default_value": "12",
        "is_secret": False,
        "requires_restart": False,
    },
    {
        "key": "security.mfa_enforced",
        "category": "SECURITY_POLICY",
        "display_name": "Enforce Multi-Factor Authentication (MFA)",
        "description": "Require MFA verification for administrative privilege tiers.",
        "value_type": "BOOLEAN",
        "value_str": "true",
        "default_value": "true",
        "is_secret": False,
        "requires_restart": False,
    },
    {
        "key": "security.session_timeout_minutes",
        "category": "SECURITY_POLICY",
        "display_name": "SOC Analyst Inactivity Timeout (Minutes)",
        "description": "Idle session timeout before re-authentication is required.",
        "value_type": "INTEGER",
        "value_str": "30",
        "default_value": "30",
        "is_secret": False,
        "requires_restart": False,
    },
    {
        "key": "security.jwt_expiry_hours",
        "category": "SECURITY_POLICY",
        "display_name": "JWT Token Lifetime (Hours)",
        "description": "Validity period for issued JWT bearer tokens.",
        "value_type": "INTEGER",
        "value_str": "8",
        "default_value": "8",
        "is_secret": False,
        "requires_restart": True,
    },

    # --- DETECTION & SOAR ---
    {
        "key": "soar.auto_quarantine_enabled",
        "category": "DETECTION_SOAR",
        "display_name": "Autonomous Endpoint Quarantine",
        "description": "Automatically isolate compromised endpoints when threat score exceeds threshold.",
        "value_type": "BOOLEAN",
        "value_str": "true",
        "default_value": "true",
        "is_secret": False,
        "requires_restart": False,
    },
    {
        "key": "soar.auto_quarantine_risk_cutoff",
        "category": "DETECTION_SOAR",
        "display_name": "Auto-Quarantine Risk Cutoff Score",
        "description": "Risk score (0-100) above which autonomous containment triggers.",
        "value_type": "FLOAT",
        "value_str": "85.0",
        "default_value": "85.0",
        "is_secret": False,
        "requires_restart": False,
    },
    {
        "key": "detection.alert_throttling_window_seconds",
        "category": "DETECTION_SOAR",
        "display_name": "Alert De-duplication Window (Seconds)",
        "description": "Time window to suppress duplicate alerts from identical host/signature pairs.",
        "value_type": "INTEGER",
        "value_str": "60",
        "default_value": "60",
        "is_secret": False,
        "requires_restart": False,
    },

    # --- RETENTION & STORAGE ---
    {
        "key": "retention.events_days",
        "category": "RETENTION_STORAGE",
        "display_name": "SIEM Raw Events Retention (Days)",
        "description": "Retention window for normalized security telemetry in database.",
        "value_type": "INTEGER",
        "value_str": "90",
        "default_value": "90",
        "is_secret": False,
        "requires_restart": False,
    },
    {
        "key": "retention.alerts_days",
        "category": "RETENTION_STORAGE",
        "display_name": "Security Alerts Retention (Days)",
        "description": "Retention window for triage alerts and incident associations.",
        "value_type": "INTEGER",
        "value_str": "180",
        "default_value": "180",
        "is_secret": False,
        "requires_restart": False,
    },
    {
        "key": "retention.worm_vault_retention_days",
        "category": "RETENTION_STORAGE",
        "display_name": "WORM Cryptographic Ledger Minimum Retention (Days)",
        "description": "Compliance mandate for immutable audit trail preservation.",
        "value_type": "INTEGER",
        "value_str": "365",
        "default_value": "365",
        "is_secret": False,
        "requires_restart": False,
    },

    # --- ML & ANALYTICS ---
    {
        "key": "ml.anomaly_contamination_rate",
        "category": "ML_ANALYTICS",
        "display_name": "Isolation Forest Contamination Rate",
        "description": "Expected proportion of anomalies in training telemetry distribution.",
        "value_type": "FLOAT",
        "value_str": "0.05",
        "default_value": "0.05",
        "is_secret": False,
        "requires_restart": False,
    },
    {
        "key": "ml.retraining_interval_hours",
        "category": "ML_ANALYTICS",
        "display_name": "Automated Model Retraining Cadence (Hours)",
        "description": "Frequency of background retraining for behavioral baselines.",
        "value_type": "INTEGER",
        "value_str": "24",
        "default_value": "24",
        "is_secret": False,
        "requires_restart": False,
    },
]


class SettingsManager:
    """Provides methods to read, update, and manage dynamic platform settings."""

    @classmethod
    async def seed_defaults_if_empty(cls, db: AsyncSession) -> None:
        """Seed default configuration settings into the database if not present."""
        for s_def in DEFAULT_SETTINGS:
            existing = await db.execute(
                select(PlatformSettingModel).where(PlatformSettingModel.key == s_def["key"])
            )
            if not existing.scalar_one_or_none():
                setting = PlatformSettingModel(
                    key=s_def["key"],
                    category=s_def["category"],
                    display_name=s_def["display_name"],
                    description=s_def["description"],
                    value_type=s_def["value_type"],
                    value_str=s_def["value_str"],
                    default_value=s_def["default_value"],
                    is_secret=s_def["is_secret"],
                    requires_restart=s_def["requires_restart"],
                    updated_by="SYSTEM_BOOTSTRAP",
                    updated_at=datetime.now(timezone.utc),
                )
                db.add(setting)
        await db.commit()

    @classmethod
    async def list_settings(
        cls,
        db: AsyncSession,
        category: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List platform settings with optional category filter."""
        await cls.seed_defaults_if_empty(db)
        query = select(PlatformSettingModel)
        if category:
            query = query.where(PlatformSettingModel.category == category.upper())
        query = query.order_by(PlatformSettingModel.category, PlatformSettingModel.key)
        res = await db.execute(query)
        return [s.to_dict() for s in res.scalars().all()]

    @classmethod
    async def get_setting(cls, db: AsyncSession, key: str) -> Optional[Dict[str, Any]]:
        """Retrieve a specific platform configuration setting."""
        await cls.seed_defaults_if_empty(db)
        res = await db.execute(select(PlatformSettingModel).where(PlatformSettingModel.key == key))
        s = res.scalar_one_or_none()
        return s.to_dict() if s else None

    @classmethod
    async def update_setting(
        cls,
        db: AsyncSession,
        key: str,
        value_str: str,
        actor: str = "SYSTEM",
    ) -> Optional[Dict[str, Any]]:
        """Update setting value, validate format, and write an immutable audit block."""
        await cls.seed_defaults_if_empty(db)
        res = await db.execute(select(PlatformSettingModel).where(PlatformSettingModel.key == key))
        setting = res.scalar_one_or_none()
        if not setting:
            return None

        # Type validation
        old_val = setting.value_str
        try:
            if setting.value_type == "INTEGER":
                int(value_str)
            elif setting.value_type == "FLOAT":
                float(value_str)
            elif setting.value_type == "BOOLEAN":
                if value_str.lower() not in ("true", "false", "1", "0"):
                    raise ValueError("Must be a valid boolean (true/false)")
        except ValueError as ex:
            raise ValueError(f"Invalid value for type {setting.value_type}: {ex}")

        setting.value_str = value_str
        setting.updated_by = actor
        setting.updated_at = datetime.now(timezone.utc)
        await db.commit()
        await db.refresh(setting)

        # Cryptographically record change in WORM ledger
        await AuditVault.record_block(
            db=db,
            action="SETTING_UPDATED",
            actor_id=actor,
            actor_role="ADMINISTRATOR",
            entity_type="PLATFORM_SETTING",
            entity_id=key,
            payload_data={"key": key, "old_value": old_val, "new_value": value_str},
        )

        return setting.to_dict()

    @classmethod
    async def reset_setting(cls, db: AsyncSession, key: str, actor: str = "SYSTEM") -> Optional[Dict[str, Any]]:
        """Reset setting back to its factory default value."""
        await cls.seed_defaults_if_empty(db)
        res = await db.execute(select(PlatformSettingModel).where(PlatformSettingModel.key == key))
        setting = res.scalar_one_or_none()
        if not setting:
            return None

        return await cls.update_setting(db, key, setting.default_value, actor=actor)
