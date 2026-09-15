"""
CyberShield Enterprise - Machine Learning & UEBA Database Models
Provides persistent relational models for registered AI/ML models,
user behavioral baselines, anomaly thresholds, and inference audit logs.
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
    ForeignKey,
    Index,
)
from sqlalchemy.orm import relationship

from cybershield.database.session import Base


class MLTaskType(str, enum.Enum):
    """Supported Machine Learning Task Categories."""
    ANOMALY_DETECTION = "ANOMALY_DETECTION"
    PAYLOAD_CLASSIFICATION = "PAYLOAD_CLASSIFICATION"
    RISK_PREDICTION = "RISK_PREDICTION"
    UEBA_SCORING = "UEBA_SCORING"


class MLModelStatus(str, enum.Enum):
    """Lifecycle status of registered AI/ML models."""
    ACTIVE = "ACTIVE"
    TRAINING = "TRAINING"
    CANDIDATE = "CANDIDATE"
    ARCHIVED = "ARCHIVED"


class MLModelRecord(Base):
    """
    Enterprise Model Registry record tracking algorithm metadata,
    hyperparameters, performance metrics, and serialized artifact paths.
    """
    __tablename__ = "ml_models"

    id = Column(String(64), primary_key=True)  # e.g. "ML-IFOREST-v1"
    name = Column(String(128), nullable=False, index=True)
    version = Column(String(32), nullable=False, index=True)
    algorithm = Column(String(64), nullable=False)
    task_type = Column(String(64), nullable=False, index=True)
    status = Column(String(32), default=MLModelStatus.CANDIDATE.value, nullable=False, index=True)
    metrics = Column(JSON, default=dict)  # accuracy, precision, recall, f1, roc_auc, confusion_matrix
    hyperparameters = Column(JSON, default=dict)
    artifact_path = Column(String(256), nullable=True)
    dataset_name = Column(String(128), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)
    trained_at = Column(DateTime, nullable=True)

    __table_args__ = (
        Index("idx_ml_task_status", "task_type", "status"),
        Index("idx_ml_name_version", "name", "version", unique=True),
    )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "version": self.version,
            "algorithm": self.algorithm,
            "task_type": self.task_type,
            "status": self.status,
            "metrics": self.metrics or {},
            "hyperparameters": self.hyperparameters or {},
            "artifact_path": self.artifact_path,
            "dataset_name": self.dataset_name,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "updated_at": self.updated_at.isoformat() if self.updated_at else None,
            "trained_at": self.trained_at.isoformat() if self.trained_at else None,
        }


class UserBehaviorBaselineModel(Base):
    """
    User & Entity Behavior Analytics (UEBA) baseline profile.
    Stores rolling behavioral statistics, typical access distributions,
    and statistical standard deviations for real-time anomaly detection.
    """
    __tablename__ = "user_behavior_baselines"

    id = Column(String(64), primary_key=True)  # e.g. "UEBA-USER-admin"
    user_id = Column(Integer, nullable=True, index=True)
    username = Column(String(64), nullable=False, unique=True, index=True)
    typical_login_hours = Column(JSON, default=list)  # list of ints [8, 9, 10, 11, 12, 13, 14, 15, 16, 17]
    typical_ip_ranges = Column(JSON, default=list)  # list of CIDR strings or IP locations
    typical_locations = Column(JSON, default=list)  # list of {"country": "US", "city": "New York", "lat": 40.71, "lon": -74.00}
    avg_daily_events = Column(Float, default=50.0)
    avg_bytes_transferred = Column(Float, default=1048576.0)  # 1 MB
    std_dev_bytes = Column(Float, default=524288.0)  # 512 KB
    accessed_resources = Column(JSON, default=list)  # list of endpoints or hosts typically accessed
    risk_score = Column(Float, default=10.0, index=True)  # 0 to 100 continuous risk
    peer_group = Column(String(64), default="STANDARD_EMPLOYEE", index=True)
    last_calculated_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)

    __table_args__ = (
        Index("idx_ueba_user_risk", "username", "risk_score"),
    )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "user_id": self.user_id,
            "username": self.username,
            "typical_login_hours": self.typical_login_hours or [],
            "typical_ip_ranges": self.typical_ip_ranges or [],
            "typical_locations": self.typical_locations or [],
            "avg_daily_events": round(self.avg_daily_events or 0.0, 1),
            "avg_bytes_transferred": round(self.avg_bytes_transferred or 0.0, 1),
            "std_dev_bytes": round(self.std_dev_bytes or 0.0, 1),
            "accessed_resources": self.accessed_resources or [],
            "risk_score": round(self.risk_score or 0.0, 1),
            "peer_group": self.peer_group,
            "last_calculated_at": self.last_calculated_at.isoformat() if self.last_calculated_at else None,
        }


class MLInferenceLogModel(Base):
    """
    Audit log of real-time machine learning inferences,
    providing telemetry on prediction throughput, latency, and drift.
    """
    __tablename__ = "ml_inference_logs"

    id = Column(String(64), primary_key=True)  # UUID
    model_id = Column(String(64), nullable=False, index=True)
    task_type = Column(String(64), nullable=False, index=True)
    input_summary = Column(Text, nullable=True)
    prediction = Column(String(128), nullable=False)
    confidence_score = Column(Float, default=1.0)
    anomaly_score = Column(Float, nullable=True)
    latency_ms = Column(Float, default=0.0)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False, index=True)

    __table_args__ = (
        Index("idx_infer_task_created", "task_type", "created_at"),
    )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "model_id": self.model_id,
            "task_type": self.task_type,
            "input_summary": self.input_summary,
            "prediction": self.prediction,
            "confidence_score": round(self.confidence_score or 0.0, 4),
            "anomaly_score": round(self.anomaly_score, 4) if self.anomaly_score is not None else None,
            "latency_ms": round(self.latency_ms or 0.0, 3),
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }
