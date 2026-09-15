"""Pydantic Schemas for Automated Report Generation."""

from __future__ import annotations

from typing import Optional, Dict, Any, List
from pydantic import BaseModel, Field


class ReportGenerateRequest(BaseModel):
    title: Optional[str] = Field(None, description="Optional custom title for report")
    report_type: str = Field("EXECUTIVE_POSTURE", description="EXECUTIVE_POSTURE, COMPLIANCE_ATTESTATION, VULNERABILITY_ASSESSMENT, INCIDENT_DOSSIER")
    format: str = Field("HTML", description="HTML, JSON, or CSV")
    parameters: Optional[Dict[str, Any]] = Field(default_factory=dict, description="Filter parameters like date_from, target_framework, etc.")


class ReportSummaryResponse(BaseModel):
    id: str
    title: str
    report_type: str
    format: str
    parameters: Dict[str, Any] = {}
    summary: str
    file_size_bytes: int
    generated_by: str
    created_at: Optional[str] = None


class ReportDetailResponse(ReportSummaryResponse):
    content_html: Optional[str] = None
    raw_data: Optional[Dict[str, Any]] = None
