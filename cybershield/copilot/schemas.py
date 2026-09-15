"""CyberShield Enterprise - AI SOC Analyst Schemas.
Data contracts for autonomous alert triage requests, competing hypothesis evaluations,
investigation reports, and executive shift handover summaries.
"""

from enum import Enum
from typing import Dict, List, Optional, Any
from datetime import datetime, timezone
from pydantic import BaseModel, Field


class AnalystVerdict(str, Enum):
    FALSE_POSITIVE_CLOSE = "FALSE_POSITIVE_CLOSE"
    SUSPICIOUS_MONITOR = "SUSPICIOUS_MONITOR"
    CONFIRMED_TRUE_POSITIVE = "CONFIRMED_TRUE_POSITIVE"
    CRITICAL_INCIDENT_ESCALATION = "CRITICAL_INCIDENT_ESCALATION"


class ConfidenceLevel(str, Enum):
    LOW_PROBABLE = "LOW_PROBABLE"
    MEDIUM_SUBSTANTIATED = "MEDIUM_SUBSTANTIATED"
    HIGH_DEFINITIVE = "HIGH_DEFINITIVE"


class AlertTriageRequest(BaseModel):
    """Input payload for autonomous SOC analyst triage."""
    alert_id: str = Field(..., description="Unique alert UUID")
    title: str = Field(..., description="Alert signature title (e.g. Suspicious PowerShell Invocation)")
    raw_event_payload: Dict[str, Any] = Field(default_factory=dict, description="Underlying telemetry event")
    host_id: str
    user_id: Optional[str] = None
    source_ip: Optional[str] = None
    mitre_technique_hint: Optional[str] = None
    previous_alert_history: List[Dict[str, Any]] = Field(default_factory=list)


class HypothesisEvaluation(BaseModel):
    """Competing hypothesis formulated and tested by the AI analyst."""
    hypothesis_id: str
    premise: str
    supporting_evidence: List[str] = Field(default_factory=list)
    refuting_evidence: List[str] = Field(default_factory=list)
    likelihood_score: float = Field(..., ge=-1.0, le=1.0)
    is_favored: bool = False


class InvestigationReport(BaseModel):
    """Detailed forensic adjudication report produced by the autonomous SOC analyst."""
    report_id: str
    alert_id: str
    verdict: AnalystVerdict
    confidence: ConfidenceLevel
    risk_score: float = Field(..., ge=0.0, le=100.0)
    executive_summary: str
    technical_findings: List[str] = Field(default_factory=list)
    evaluated_hypotheses: List[HypothesisEvaluation] = Field(default_factory=list)
    recommended_soar_playbook: Optional[str] = None
    is_automated_adjudication: bool = True
    triaged_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class ShiftHandoverReport(BaseModel):
    """Executive shift-to-shift transition report for SOC engineering teams."""
    shift_id: str
    start_time: datetime
    end_time: datetime
    total_triaged: int
    false_positive_count: int
    escalated_count: int
    monitored_count: int
    key_threats: List[str] = Field(default_factory=list)
    executive_narrative: str
    generated_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class AnalystMetrics(BaseModel):
    """Operational efficiency counters for autonomous triage engine."""
    total_alerts_triaged: int
    false_positives_closed: int
    escalations_generated: int
    mean_triage_latency_ms: float
    auto_closure_rate: float
