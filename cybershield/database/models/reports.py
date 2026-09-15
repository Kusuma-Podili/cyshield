"""Report Generation Database Models for CyberShield Enterprise.

Persists generated executive, compliance, vulnerability, and incident reports.
"""

from __future__ import annotations

import enum
from datetime import datetime, timezone
from typing import Optional, Dict, Any
from sqlalchemy import (
    Column,
    String,
    Integer,
    DateTime,
    Enum as SQLEnum,
    Text,
    JSON,
)

from cybershield.database.session import Base


class ReportType(str, enum.Enum):
    EXECUTIVE_POSTURE = "EXECUTIVE_POSTURE"
    COMPLIANCE_ATTESTATION = "COMPLIANCE_ATTESTATION"
    VULNERABILITY_ASSESSMENT = "VULNERABILITY_ASSESSMENT"
    INCIDENT_DOSSIER = "INCIDENT_DOSSIER"


class ReportFormat(str, enum.Enum):
    HTML = "HTML"
    JSON = "JSON"
    CSV = "CSV"


class GeneratedReportModel(Base):
    """Archived generated security intelligence and compliance report."""

    __tablename__ = "generated_reports"

    id = Column(String(64), primary_key=True, index=True)  # e.g., 'RPT-2026-...'
    title = Column(String(255), nullable=False)
    report_type = Column(SQLEnum(ReportType), default=ReportType.EXECUTIVE_POSTURE, nullable=False, index=True)
    format = Column(SQLEnum(ReportFormat), default=ReportFormat.HTML, nullable=False)
    parameters = Column(JSON, nullable=True)
    summary = Column(Text, nullable=False)
    content_html = Column(Text, nullable=True)
    raw_data = Column(JSON, nullable=True)
    file_size_bytes = Column(Integer, default=0, nullable=False)
    generated_by = Column(String(128), default="SYSTEM", nullable=False)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False, index=True)

    def to_dict(self, include_content: bool = False) -> Dict[str, Any]:
        data = {
            "id": self.id,
            "title": self.title,
            "report_type": self.report_type.value if self.report_type else None,
            "format": self.format.value if self.format else None,
            "parameters": self.parameters or {},
            "summary": self.summary,
            "file_size_bytes": self.file_size_bytes,
            "generated_by": self.generated_by,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }
        if include_content:
            data["content_html"] = self.content_html
            data["raw_data"] = self.raw_data
        return data
