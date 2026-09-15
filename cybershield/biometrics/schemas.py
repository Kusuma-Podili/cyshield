"""CyberShield Enterprise - Autonomous Behavioral Biometrics & Keystroke Dynamics Schemas.
Data contracts for dwell/flight time timing, bot jitter detection,
biometric verification, and account takeover alerts.
"""

from enum import Enum
from typing import Dict, List, Optional, Any
from datetime import datetime, timezone
from pydantic import BaseModel, Field


class BiometricVerdict(str, Enum):
    AUTHENTIC_USER = "AUTHENTIC_USER"
    SUSPICIOUS_DEVIATION = "SUSPICIOUS_DEVIATION"
    AUTOMATED_BOT_SCRIPT = "AUTOMATED_BOT_SCRIPT"
    ANOMALOUS_IMPERSONATOR = "ANOMALOUS_IMPERSONATOR"


class KeystrokeTimingEvent(BaseModel):
    """Raw key down and key up event with millisecond precision."""
    key_code: str = Field(..., description="Key identifier e.g. 'a', 'Shift', 'Enter'")
    press_time_ms: float = Field(..., ge=0.0)
    release_time_ms: float = Field(..., ge=0.0)


class BiometricEnrollmentRequest(BaseModel):
    """Enrollment sample to build user's baseline typing profile."""
    user_id: str
    sample_text_length: int
    keystrokes: List[KeystrokeTimingEvent]


class BiometricVerificationRequest(BaseModel):
    """Session keystroke sequence to verify against enrolled user baseline."""
    user_id: str
    session_id: str
    keystrokes: List[KeystrokeTimingEvent]


class BiometricProfile(BaseModel):
    """Stored mathematical biometric model of user typing rhythm."""
    user_id: str
    avg_dwell_time_ms: float
    std_dwell_time_ms: float
    avg_flight_time_ms: float
    std_flight_time_ms: float
    enrolled_samples_count: int
    last_updated: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class BiometricVerificationResponse(BaseModel):
    """Evaluation verdict of behavioral biometric authenticity."""
    user_id: str
    session_id: str
    verdict: BiometricVerdict
    distance_score: float = Field(..., ge=0.0)
    jitter_variance_ms: float
    confidence: float = Field(..., ge=0.0, le=1.0)
    details: str
    recommended_action: str
    verified_at: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class BiometricThreatAlert(BaseModel):
    """Security alert raised on bot injection or account takeover."""
    alert_id: str
    user_id: str
    session_id: str
    verdict: BiometricVerdict
    mitre_technique: str
    severity: str = "HIGH"
    details: str
    countermeasure: str
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
