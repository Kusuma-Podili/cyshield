"""
Security Chaos Engineering & Automated Fault Injection Engine Schemas.
Models controlled fault injection, steady-state resilience hypotheses, and cyber resilience experiments.
"""

from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class ChaosFaultType(str, Enum):
    LOG_DROP_BURST = "LOG_DROP_BURST"
    LATENCY_SPIKE = "LATENCY_SPIKE"
    CORRUPTED_PAYLOAD = "CORRUPTED_PAYLOAD"
    CREDENTIAL_INVALIDATION = "CREDENTIAL_INVALIDATION"
    WORKER_PROCESS_CRASH = "WORKER_PROCESS_CRASH"


class ChaosExperimentStatus(str, Enum):
    SCHEDULED = "SCHEDULED"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    ABORTED = "ABORTED"


class HypothesisVerdict(str, Enum):
    HYPOTHESIS_CONFIRMED = "HYPOTHESIS_CONFIRMED"
    HYPOTHESIS_REFUTED = "HYPOTHESIS_REFUTED"
    INCONCLUSIVE = "INCONCLUSIVE"


class ChaosExperiment(BaseModel):
    """Controlled security resilience experiment testing detection under platform degradation."""
    experiment_id: str
    name: str
    target_subsystem: str  # e.g., "IngestionCollector", "CEP_Correlation", "ThreatIntelMatcher"
    fault_type: ChaosFaultType
    parameters: Dict[str, Any] = Field(default_factory=dict)
    hypothesis_statement: str
    status: ChaosExperimentStatus = ChaosExperimentStatus.SCHEDULED
    verdict: Optional[HypothesisVerdict] = None
    steady_state_before: Dict[str, Any] = Field(default_factory=dict)
    steady_state_after: Dict[str, Any] = Field(default_factory=dict)
    blast_radius_contained: bool = True
    executed_at: Optional[datetime] = None
    duration_seconds: float = 0.0
    created_at: datetime = Field(default_factory=datetime.utcnow)


class ChaosExperimentCreateRequest(BaseModel):
    """Payload to define and schedule a new chaos experiment."""
    name: str
    target_subsystem: str
    fault_type: ChaosFaultType
    parameters: Dict[str, Any] = Field(default_factory=dict)
    hypothesis_statement: str
