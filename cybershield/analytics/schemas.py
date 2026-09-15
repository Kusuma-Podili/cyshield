"""
CyberShield Enterprise - Analytics & Data Pipelines Pydantic Schemas
Defines request and response models for scheduled ETL workflows,
Feature Store lookups, Security Posture Index, and MITRE ATT&CK coverage matrices.
"""

from __future__ import annotations

from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field


class ETLPipelineResponse(BaseModel):
    id: str
    name: str
    schedule_cron: str
    pipeline_type: str
    status: str
    last_run_at: Optional[str] = None
    next_run_at: Optional[str] = None
    duration_sec: float = 0.0
    records_processed: int = 0
    error_message: Optional[str] = None
    is_enabled: bool = True
    created_at: Optional[str] = None
    updated_at: Optional[str] = None


class PipelineRunResponse(BaseModel):
    pipeline_id: str
    name: str
    status: str
    duration_sec: float
    records_processed: int
    message: str


class FeatureVectorResponse(BaseModel):
    entity_id: str
    feature_group: str
    feature_vector: Dict[str, Any] = Field(default_factory=dict)
    computed_at: Optional[str] = None


class SecurityMetricsRollupResponse(BaseModel):
    id: str
    period_type: str
    timestamp: str
    total_events: int
    total_alerts: int
    critical_alerts: int
    high_alerts: int
    blocked_threats: int
    quarantined_hosts: int
    mttd_seconds: float
    mttr_seconds: float
    attack_surface_score: float


class SecurityPostureResponse(BaseModel):
    overall_score: float = Field(..., ge=0.0, le=100.0)
    security_grade: str = Field(..., description="A+, A, B, C, D, F")
    attack_surface_score: float
    vulnerability_posture: float
    detection_coverage_score: float
    active_incidents_count: int
    critical_unpatched_assets: int
    recommendations: List[str] = Field(default_factory=list)


class MitreTacticCoverageItem(BaseModel):
    tactic_id: str
    tactic_name: str
    rules_count: int
    techniques_covered: List[str] = Field(default_factory=list)
    is_covered: bool


class MitreCoverageResponse(BaseModel):
    total_tactics: int
    covered_tactics: int
    coverage_percentage: float
    tactics: List[MitreTacticCoverageItem] = Field(default_factory=list)
