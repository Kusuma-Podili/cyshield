"""
Threat Feed IoC Aging and Exponential Decay Engine Schemas.
Models temporal indicator half-life decay, sighting reinforcement, and automatic pruning.
"""

from datetime import datetime
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class IOCType(str, Enum):
    IPV4 = "IPV4"
    IPV6 = "IPV6"
    DOMAIN = "DOMAIN"
    URL = "URL"
    SHA256 = "SHA256"
    MD5 = "MD5"
    EMAIL = "EMAIL"
    SSL_FINGERPRINT = "SSL_FINGERPRINT"


class IOCStatus(str, Enum):
    ACTIVE = "ACTIVE"
    DECAYING = "DECAYING"
    EXPIRED = "EXPIRED"
    WHITELISTED = "WHITELISTED"


class DecayProfile(BaseModel):
    """Temporal half-life configuration per IoC indicator type."""
    ioc_type: IOCType
    half_life_days: float
    initial_confidence: float = 85.0
    min_retention_score: float = 20.0
    sighting_boost: float = 15.0


class DecayIndicator(BaseModel):
    """Threat indicator with temporal aging and confidence tracking."""
    indicator_id: str
    value: str
    ioc_type: IOCType
    initial_confidence: float = 85.0
    current_confidence: float = 85.0
    first_seen: datetime = Field(default_factory=datetime.utcnow)
    last_seen: datetime = Field(default_factory=datetime.utcnow)
    last_decay_calc: datetime = Field(default_factory=datetime.utcnow)
    sighting_count: int = 1
    status: IOCStatus = IOCStatus.ACTIVE
    source_feed: str = "Internal Intelligence"
    tags: List[str] = Field(default_factory=list)


class SightingRecordRequest(BaseModel):
    """Payload to record new telemetry observation of an existing or new indicator."""
    indicator_value: str
    ioc_type: IOCType
    sighting_source: str
    context: Optional[str] = None


class DecayEvaluationResult(BaseModel):
    """Result of evaluating decay formula over an indicator."""
    indicator_id: str
    value: str
    old_confidence: float
    new_confidence: float
    days_elapsed: float
    status: IOCStatus
    is_pruned: bool
