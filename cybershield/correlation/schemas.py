"""
Complex Event Processing (CEP) and Temporal Correlation Schemas.
Enables sliding-window aggregations, stateful sequence matching, and multi-event attack chain detection.
"""

from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class CorrelationWindowType(str, Enum):
    SLIDING = "SLIDING"
    TUMBLING = "TUMBLING"


class AggregationFunction(str, Enum):
    COUNT = "COUNT"
    DISTINCT_COUNT = "DISTINCT_COUNT"
    SUM = "SUM"
    AVG = "AVG"


class ConditionOperator(str, Enum):
    EQUALS = "=="
    NOT_EQUALS = "!="
    CONTAINS = "CONTAINS"
    REGEX = "REGEX"
    GREATER_THAN = ">"
    LESS_THAN = "<"
    IN = "IN"


class EventFilter(BaseModel):
    """Filter condition matching event fields."""
    field: str
    operator: ConditionOperator
    value: Any


class SequenceStep(BaseModel):
    """Step in an attack sequence chain."""
    step_id: str
    name: str
    filters: List[EventFilter] = Field(default_factory=list)
    min_count: int = 1
    max_count: Optional[int] = None


class CorrelationRule(BaseModel):
    """Stateful CEP rule evaluated over a temporal window."""
    id: str
    name: str
    description: str
    mitre_technique_id: str = "T1078"
    severity: str = "HIGH"  # LOW, MEDIUM, HIGH, CRITICAL
    enabled: bool = True
    window_type: CorrelationWindowType = CorrelationWindowType.SLIDING
    window_seconds: int = 300  # Default 5 minutes
    group_by_fields: List[str] = Field(default_factory=list)  # e.g., ["username"] or ["src_ip"]
    sequence_steps: List[SequenceStep] = Field(default_factory=list)
    aggregation: Optional[AggregationFunction] = AggregationFunction.COUNT
    aggregation_target_field: Optional[str] = None
    threshold: float = 1.0
    created_at: datetime = Field(default_factory=datetime.utcnow)


class CorrelatedIncidentAlert(BaseModel):
    """Alert emitted when a complex correlation pattern or sequence matches."""
    id: str
    rule_id: str
    rule_name: str
    severity: str
    triggered_at: datetime = Field(default_factory=datetime.utcnow)
    group_key: str
    matched_events_count: int
    matched_event_ids: List[str] = Field(default_factory=list)
    sample_events: List[Dict[str, Any]] = Field(default_factory=list)
    risk_score: float = 80.0
    mitre_technique_id: str
    summary: str
