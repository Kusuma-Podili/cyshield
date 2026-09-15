"""
CyberShield Enterprise - Data Pipelines, Feature Store & Analytics Database Models
Provides persistent relational models for scheduled ETL workflows,
online/offline feature store vectors, and aggregated security metrics rollups.
"""

from __future__ import annotations

import enum
from datetime import datetime
from typing import Dict, Any, Optional, List

from sqlalchemy import (
    Column,
    String,
    Integer,
    Float,
    Boolean,
    DateTime,
    Text,
    JSON,
    Index,
)

from cybershield.database.session import Base


class PipelineStatus(str, enum.Enum):
    """Execution status of scheduled ETL data pipelines."""
    IDLE = "IDLE"
    RUNNING = "RUNNING"
    SUCCESS = "SUCCESS"
    FAILED = "FAILED"


class PipelineType(str, enum.Enum):
    """Functional categories for analytical data pipelines."""
    METRICS_ROLLUP = "METRICS_ROLLUP"
    FEATURE_STORE_UPDATE = "FEATURE_STORE_UPDATE"
    ASSET_RISK_RECALCULATION = "ASSET_RISK_RECALCULATION"
    MITRE_HEATMAP_COMPILATION = "MITRE_HEATMAP_COMPILATION"


class ETLPipelineModel(Base):
    """
    Enterprise Data Pipeline configuration and execution ledger.
    Tracks recurring schedules, batch transformation states, and throughput telemetry.
    """
    __tablename__ = "etl_pipelines"

    id = Column(String(64), primary_key=True)  # e.g. "ETL-SECURITY-METRICS-HOURLY"
    name = Column(String(128), nullable=False)
    schedule_cron = Column(String(64), nullable=False)  # e.g. "*/15 * * * *"
    pipeline_type = Column(String(64), nullable=False, index=True)
    status = Column(String(32), default=PipelineStatus.IDLE.value, nullable=False, index=True)
    last_run_at = Column(DateTime, nullable=True)
    next_run_at = Column(DateTime, nullable=True)
    duration_sec = Column(Float, default=0.0)
    records_processed = Column(Integer, default=0)
    error_message = Column(Text, nullable=True)
    is_enabled = Column(Boolean, default=True, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)

    __table_args__ = (
        Index("idx_etl_status_type", "status", "pipeline_type"),
    )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "schedule_cron": self.schedule_cron,
            "pipeline_type": self.pipeline_type,
            "status": self.status,
            "last_run_at": self.last_run_at.isoformat() if self.last_run_at else None,
            "next_run_at": self.next_run_at.isoformat() if self.next_run_at else None,
            "duration_sec": round(self.duration_sec or 0.0, 3),
            "records_processed": self.records_processed or 0,
            "error_message": self.error_message,
            "is_enabled": self.is_enabled,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
        }


class FeatureStoreRecordModel(Base):
    """
    Online & Offline Feature Store Vector.
    Stores engineered, temporal behavioral features for entities (IP, Host, User)
    ready for sub-millisecond retrieval by inference models and retraining jobs.
    """
    __tablename__ = "feature_store_records"

    id = Column(String(128), primary_key=True)  # e.g. "FEAT-IP-10.0.20.55-20260315-12"
    feature_group = Column(String(64), nullable=False, index=True)  # "DEVICE_HOURLY", "USER_DAILY"
    entity_id = Column(String(128), nullable=False, index=True)      # IP address, hostname, username
    feature_vector = Column(JSON, default=dict)                     # dictionary of numerical features
    computed_at = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)

    __table_args__ = (
        Index("idx_feat_entity_group", "entity_id", "feature_group"),
    )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "feature_group": self.feature_group,
            "entity_id": self.entity_id,
            "feature_vector": self.feature_vector or {},
            "computed_at": self.computed_at.isoformat() if self.computed_at else None,
        }


class SecurityMetricsRollupModel(Base):
    """
    Historical Aggregated Security Metrics Rollup.
    Provides pre-computed hourly and daily time-series statistics for
    executive dashboards, MTTD/MTTR analytics, and trend visualization.
    """
    __tablename__ = "security_metrics_rollups"

    id = Column(String(64), primary_key=True)  # e.g. "ROLLUP-HOURLY-20260315-12"
    period_type = Column(String(32), default="HOURLY", nullable=False, index=True)  # HOURLY, DAILY
    timestamp = Column(DateTime, nullable=False, index=True)
    total_events = Column(Integer, default=0)
    total_alerts = Column(Integer, default=0)
    critical_alerts = Column(Integer, default=0)
    high_alerts = Column(Integer, default=0)
    blocked_threats = Column(Integer, default=0)
    quarantined_hosts = Column(Integer, default=0)
    mttd_seconds = Column(Float, default=180.0)
    mttr_seconds = Column(Float, default=450.0)
    attack_surface_score = Column(Float, default=85.0)  # 0 to 100 Posture Health
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    __table_args__ = (
        Index("idx_rollup_period_time", "period_type", "timestamp"),
    )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "period_type": self.period_type,
            "timestamp": self.timestamp.isoformat() if self.timestamp else None,
            "total_events": self.total_events or 0,
            "total_alerts": self.total_alerts or 0,
            "critical_alerts": self.critical_alerts or 0,
            "high_alerts": self.high_alerts or 0,
            "blocked_threats": self.blocked_threats or 0,
            "quarantined_hosts": self.quarantined_hosts or 0,
            "mttd_seconds": round(self.mttd_seconds or 0.0, 1),
            "mttr_seconds": round(self.mttr_seconds or 0.0, 1),
            "attack_surface_score": round(self.attack_surface_score or 0.0, 1),
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }
