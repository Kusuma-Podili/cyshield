"""CyberShield Enterprise - Privacy-Preserving Differential Privacy & Federated Telemetry Schemas.
Data contracts for Laplace/Gaussian noise mechanisms, k-anonymity verification,
and secure federated aggregation.
"""

from enum import Enum
from typing import Dict, List, Optional, Any
from datetime import datetime, timezone
from pydantic import BaseModel, Field


class NoiseMechanism(str, Enum):
    LAPLACE = "LAPLACE"
    GAUSSIAN = "GAUSSIAN"


class DifferentialPrivacyRequest(BaseModel):
    """Request to inject calibrated noise into telemetry counts or metrics."""
    metric_name: str
    true_value: float = Field(..., description="Raw sensitive aggregate count/metric")
    epsilon: float = Field(default=0.5, gt=0.0, le=10.0, description="Privacy loss budget (epsilon)")
    delta: float = Field(default=1e-5, gt=0.0, lt=1.0, description="Relaxation parameter (delta) for Gaussian mechanism")
    sensitivity: float = Field(default=1.0, gt=0.0, description="Global query sensitivity (delta f)")
    mechanism: NoiseMechanism = NoiseMechanism.LAPLACE


class DifferentialPrivacyResponse(BaseModel):
    """Differentially private noisy metric result."""
    metric_name: str
    perturbed_value: float
    epsilon_consumed: float
    noise_mechanism: NoiseMechanism
    noise_magnitude: float
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class RawIncidentRecord(BaseModel):
    """Raw incident telemetry containing sensitive internal identifiers."""
    incident_id: str
    source_ip: str
    dest_ip: str
    username: str
    department: str
    mitre_tactic: str
    alert_severity: str
    observed_time: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class AnonymizedIncidentRecord(BaseModel):
    """Sanitized incident record satisfying k-anonymity and l-diversity."""
    generalized_subnet: str
    quasi_department: str
    time_bucket: str
    mitre_tactic: str
    alert_severity: str
    cohort_size_k: int
    diversity_count_l: int


class KAnonymityBatchRequest(BaseModel):
    """Batch of incidents to anonymize with specified privacy thresholds."""
    records: List[RawIncidentRecord]
    k_threshold: int = Field(default=3, ge=2, le=50, description="Minimum cohort size for k-anonymity")
    l_threshold: int = Field(default=2, ge=1, le=10, description="Minimum diverse tactics for l-diversity")


class KAnonymityBatchResponse(BaseModel):
    """Result of k-anonymity / l-diversity sanitization."""
    total_records: int
    anonymized_records: List[AnonymizedIncidentRecord]
    suppressed_records_count: int
    k_achieved: int
    l_achieved: int
    privacy_guarantee_met: bool


class FederatedParticipantUpdate(BaseModel):
    """Local subsidiary gradient / weight vector with zero-sum mask simulation."""
    participant_id: str
    subsidiary_name: str
    vector_weights: List[float]


class FederatedAggregationRequest(BaseModel):
    """Federated secure aggregation request across multiple subsidiaries."""
    round_id: str
    model_name: str = "Enterprise-Threat-Anomaly-GNN"
    updates: List[FederatedParticipantUpdate]


class FederatedAggregationResponse(BaseModel):
    """Resulting aggregated global weights without revealing individual subsidiary data."""
    round_id: str
    model_name: str
    total_participants: int
    aggregated_vector_weights: List[float]
    aggregation_method: str = "Secure_Additive_Secret_Sharing"
    completed_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class PrivacyBudgetStatus(BaseModel):
    """Enterprise global privacy loss accounting."""
    total_budget_epsilon: float
    consumed_epsilon: float
    remaining_epsilon: float
    active_queries_count: int
    budget_exhausted: bool
