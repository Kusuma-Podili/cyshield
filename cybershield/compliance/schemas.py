"""Pydantic Schemas for Regulatory Compliance Subsystem."""

from __future__ import annotations

from typing import Optional, List, Dict, Any
from pydantic import BaseModel, Field


class ControlResponse(BaseModel):
    id: str
    framework_id: str
    control_code: str
    title: str
    domain: str
    description: str
    remediation_guidance: str
    severity: str
    status: str
    score: float
    evaluator_key: Optional[str] = None
    evidence_summary: Optional[str] = None
    evidence_json: Optional[Dict[str, Any]] = None
    last_evaluated_at: Optional[str] = None


class FrameworkResponse(BaseModel):
    id: str
    name: str
    version: str
    description: str
    category: str
    is_active: bool
    total_controls: int
    compliant_controls: int
    partial_controls: int
    non_compliant_controls: int
    overall_score: float
    last_assessed_at: Optional[str] = None
    created_at: Optional[str] = None


class AssessmentResponse(BaseModel):
    id: str
    framework_id: str
    assessed_by: str
    overall_score: float
    status_counts: Dict[str, int]
    findings_count: int
    created_at: Optional[str] = None


class AssessmentDetailResponse(AssessmentResponse):
    findings: List[Dict[str, Any]] = []


class ComplianceOverviewResponse(BaseModel):
    global_compliance_score: float
    letter_grade: str
    frameworks: List[FrameworkResponse]
    total_controls: int
    compliant_controls: int
    partial_controls: int
    non_compliant_controls: int
    critical_gaps: List[Dict[str, Any]]
