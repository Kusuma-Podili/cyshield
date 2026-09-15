"""CyberShield Enterprise - Autonomous Behavioral Biometrics & Keystroke Dynamics Routes.
Exposes endpoints for profile enrollment, real-time typing dynamics verification,
and behavioral impersonation / bot alerts.
"""

from typing import Dict, List, Optional, Any
from fastapi import APIRouter, HTTPException, Query, status

from .schemas import (
    BiometricEnrollmentRequest,
    BiometricVerificationRequest,
    BiometricProfile,
    BiometricVerificationResponse,
    BiometricThreatAlert,
)
from .profiler import BehavioralBiometricsEngine

router = APIRouter(prefix="/api/v1/biometrics", tags=["Behavioral Biometrics & Keystroke Dynamics"])

# Singleton biometrics engine instance
_BIOMETRICS_ENGINE = BehavioralBiometricsEngine()


@router.post("/enroll", response_model=BiometricProfile, status_code=status.HTTP_201_CREATED)
def enroll_user_keystroke_profile(request: BiometricEnrollmentRequest):
    """Enroll baseline keystroke dynamics timing profile for a corporate user."""
    return _BIOMETRICS_ENGINE.enroll_user_profile(request)


@router.post("/verify", response_model=BiometricVerificationResponse, status_code=status.HTTP_200_OK)
def verify_keystroke_session(request: BiometricVerificationRequest):
    """Verify session typing rhythm against enrolled user profile to catch account takeover or bots."""
    return _BIOMETRICS_ENGINE.verify_session(request)


@router.get("/profiles", response_model=List[BiometricProfile])
def list_enrolled_profiles():
    """Retrieve all enrolled behavioral biometric typing profiles."""
    return list(_BIOMETRICS_ENGINE.profiles.values())


@router.get("/alerts", response_model=List[BiometricThreatAlert])
def list_biometric_threat_alerts():
    """Retrieve active behavioral impersonation and robotic bot injection alerts."""
    return _BIOMETRICS_ENGINE.alerts
