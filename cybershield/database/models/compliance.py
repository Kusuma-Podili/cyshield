"""Regulatory Compliance Database Models for CyberShield Enterprise.

Supports multi-standard governance across SOC 2 Type II, ISO/IEC 27001:2022,
NIST CSF 2.0, PCI-DSS v4.0, HIPAA Security Rule, and GDPR.
"""

from __future__ import annotations

import enum
from datetime import datetime, timezone
from typing import Optional, Dict, Any, List
from sqlalchemy import (
    Column,
    String,
    Integer,
    Float,
    Boolean,
    DateTime,
    Enum as SQLEnum,
    Text,
    ForeignKey,
    JSON,
)
from sqlalchemy.orm import relationship

from cybershield.database.session import Base


class ComplianceStatus(str, enum.Enum):
    COMPLIANT = "COMPLIANT"
    PARTIALLY_COMPLIANT = "PARTIALLY_COMPLIANT"
    NON_COMPLIANT = "NON_COMPLIANT"
    NOT_APPLICABLE = "NOT_APPLICABLE"


class ControlSeverity(str, enum.Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class ComplianceFrameworkModel(Base):
    """Represents a regulatory or industry security compliance framework."""

    __tablename__ = "compliance_frameworks"

    id = Column(String(32), primary_key=True, index=True)  # e.g., 'SOC2', 'ISO27001'
    name = Column(String(128), nullable=False)
    version = Column(String(32), default="2024.1")
    description = Column(Text, nullable=False)
    category = Column(String(64), default="SECURITY_AND_GOVERNANCE")
    is_active = Column(Boolean, default=True, nullable=False)

    total_controls = Column(Integer, default=0, nullable=False)
    compliant_controls = Column(Integer, default=0, nullable=False)
    partial_controls = Column(Integer, default=0, nullable=False)
    non_compliant_controls = Column(Integer, default=0, nullable=False)
    overall_score = Column(Float, default=0.0, nullable=False)  # 0.0 to 100.0

    last_assessed_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)

    # Relationships
    controls = relationship(
        "ComplianceControlModel",
        back_populates="framework",
        cascade="all, delete-orphan",
        lazy="selectin",
    )
    assessments = relationship(
        "ComplianceAssessmentModel",
        back_populates="framework",
        cascade="all, delete-orphan",
        lazy="selectin",
    )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "version": self.version,
            "description": self.description,
            "category": self.category,
            "is_active": self.is_active,
            "total_controls": self.total_controls,
            "compliant_controls": self.compliant_controls,
            "partial_controls": self.partial_controls,
            "non_compliant_controls": self.non_compliant_controls,
            "overall_score": round(self.overall_score, 1),
            "last_assessed_at": self.last_assessed_at.isoformat() if self.last_assessed_at else None,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


class ComplianceControlModel(Base):
    """An individual security requirement / control within a compliance framework."""

    __tablename__ = "compliance_controls"

    id = Column(String(64), primary_key=True, index=True)  # e.g., 'SOC2-CC6.1'
    framework_id = Column(String(32), ForeignKey("compliance_frameworks.id"), nullable=False, index=True)
    control_code = Column(String(32), nullable=False, index=True)
    title = Column(String(255), nullable=False)
    domain = Column(String(128), nullable=False, index=True)
    description = Column(Text, nullable=False)
    remediation_guidance = Column(Text, nullable=False)
    severity = Column(SQLEnum(ControlSeverity), default=ControlSeverity.HIGH, nullable=False)
    status = Column(SQLEnum(ComplianceStatus), default=ComplianceStatus.PARTIALLY_COMPLIANT, nullable=False)
    score = Column(Float, default=50.0, nullable=False)  # 0.0 to 100.0

    evaluator_key = Column(String(64), nullable=True)  # Logic function identifier
    evidence_summary = Column(Text, nullable=True)
    evidence_json = Column(JSON, nullable=True)
    last_evaluated_at = Column(DateTime, nullable=True)

    framework = relationship("ComplianceFrameworkModel", back_populates="controls")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "framework_id": self.framework_id,
            "control_code": self.control_code,
            "title": self.title,
            "domain": self.domain,
            "description": self.description,
            "remediation_guidance": self.remediation_guidance,
            "severity": self.severity.value if self.severity else None,
            "status": self.status.value if self.status else None,
            "score": round(self.score, 1),
            "evaluator_key": self.evaluator_key,
            "evidence_summary": self.evidence_summary,
            "evidence_json": self.evidence_json or {},
            "last_evaluated_at": self.last_evaluated_at.isoformat() if self.last_evaluated_at else None,
        }


class ComplianceAssessmentModel(Base):
    """Historical audit snapshot capturing compliance state across time."""

    __tablename__ = "compliance_assessments"

    id = Column(String(64), primary_key=True, index=True)  # e.g., 'ASM-2026-...'
    framework_id = Column(String(32), ForeignKey("compliance_frameworks.id"), nullable=False, index=True)
    assessed_by = Column(String(128), default="SYSTEM", nullable=False)
    overall_score = Column(Float, nullable=False)
    status_counts = Column(JSON, nullable=False)
    findings_json = Column(JSON, nullable=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)

    framework = relationship("ComplianceFrameworkModel", back_populates="assessments")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "framework_id": self.framework_id,
            "assessed_by": self.assessed_by,
            "overall_score": round(self.overall_score, 1),
            "status_counts": self.status_counts or {},
            "findings_count": len(self.findings_json) if self.findings_json else 0,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }
