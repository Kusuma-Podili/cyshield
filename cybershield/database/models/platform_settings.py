"""Platform Settings Database Models for CyberShield Enterprise.

Enables runtime dynamic configuration for security policies, SOAR execution thresholds,
event data retention, ML anomaly sensitivity, and alert throttling.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Optional, Dict, Any
from sqlalchemy import (
    Column,
    String,
    Boolean,
    DateTime,
    Text,
)

from cybershield.database.session import Base


class PlatformSettingModel(Base):
    """Dynamic runtime platform configuration setting."""

    __tablename__ = "platform_settings"

    key = Column(String(64), primary_key=True, index=True)
    category = Column(String(64), nullable=False, index=True)  # SECURITY_POLICY, DETECTION_SOAR, etc.
    display_name = Column(String(128), nullable=False)
    description = Column(Text, nullable=False)
    value_type = Column(String(32), default="STRING", nullable=False)  # STRING, INTEGER, FLOAT, BOOLEAN, JSON
    value_str = Column(Text, nullable=False)
    default_value = Column(Text, nullable=False)
    is_secret = Column(Boolean, default=False, nullable=False)
    requires_restart = Column(Boolean, default=False, nullable=False)
    updated_by = Column(String(128), default="SYSTEM", nullable=False)
    updated_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)

    def get_typed_value(self) -> Any:
        """Parse value_str into its typed Python equivalent."""
        v = self.value_str
        if self.value_type == "INTEGER":
            return int(v)
        elif self.value_type == "FLOAT":
            return float(v)
        elif self.value_type == "BOOLEAN":
            return v.strip().lower() in ("true", "1", "yes", "on")
        elif self.value_type == "JSON":
            try:
                return json.loads(v)
            except Exception:
                return {}
        return v

    def to_dict(self) -> Dict[str, Any]:
        return {
            "key": self.key,
            "category": self.category,
            "display_name": self.display_name,
            "description": self.description,
            "value_type": self.value_type,
            "value": "[REDACTED]" if self.is_secret else self.get_typed_value(),
            "raw_value": "[REDACTED]" if self.is_secret else self.value_str,
            "default_value": "[REDACTED]" if self.is_secret else self.default_value,
            "is_secret": self.is_secret,
            "requires_restart": self.requires_restart,
            "updated_by": self.updated_by,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }
