"""CyberShield Enterprise - Autonomous Behavioral Biometrics & Keystroke Dynamics Engine.
Extracts dwell and flight time dynamics, detects synthetic bot jitterlessness,
computes statistical biometric distance, and raises account takeover alerts.
"""

import math
import uuid
from typing import Dict, List, Optional, Tuple, Any
from datetime import datetime, timezone

from .schemas import (
    BiometricVerdict,
    KeystrokeTimingEvent,
    BiometricEnrollmentRequest,
    BiometricVerificationRequest,
    BiometricProfile,
    BiometricVerificationResponse,
    BiometricThreatAlert,
)


class BehavioralBiometricsEngine:
    """Enterprise behavioral biometric sentinel protecting high-privilege sessions."""

    def __init__(self):
        self.profiles: Dict[str, BiometricProfile] = {}
        self.alerts: List[BiometricThreatAlert] = []

    @staticmethod
    def _extract_timing_metrics(keystrokes: List[KeystrokeTimingEvent]) -> Tuple[float, float, float, float, float]:
        """Extract average dwell time, dwell std, avg flight time, flight std, and flight variance."""
        if not keystrokes:
            return 0.0, 0.0, 0.0, 0.0, 0.0

        # Dwell times: release - press
        dwell_times = [max(0.0, k.release_time_ms - k.press_time_ms) for k in keystrokes]
        avg_dwell = sum(dwell_times) / len(dwell_times)
        var_dwell = sum((d - avg_dwell) ** 2 for d in dwell_times) / max(1, len(dwell_times))
        std_dwell = math.sqrt(var_dwell)

        # Flight times: press[i+1] - release[i]
        flight_times: List[float] = []
        for i in range(len(keystrokes) - 1):
            f_time = keystrokes[i + 1].press_time_ms - keystrokes[i].release_time_ms
            flight_times.append(f_time)

        if flight_times:
            avg_flight = sum(flight_times) / len(flight_times)
            var_flight = sum((f - avg_flight) ** 2 for f in flight_times) / max(1, len(flight_times))
            std_flight = math.sqrt(var_flight)
        else:
            avg_flight, std_flight, var_flight = 0.0, 0.0, 0.0

        return round(avg_dwell, 2), round(std_dwell, 2), round(avg_flight, 2), round(std_flight, 2), round(var_flight, 4)

    def enroll_user_profile(self, req: BiometricEnrollmentRequest) -> BiometricProfile:
        """Construct or update baseline keystroke rhythm profile for a user."""
        avg_d, std_d, avg_f, std_f, _ = self._extract_timing_metrics(req.keystrokes)

        profile = BiometricProfile(
            user_id=req.user_id,
            avg_dwell_time_ms=avg_d,
            std_dwell_time_ms=max(5.0, std_d),
            avg_flight_time_ms=avg_f,
            std_flight_time_ms=max(10.0, std_f),
            enrolled_samples_count=len(req.keystrokes),
        )
        self.profiles[req.user_id] = profile
        return profile

    def verify_session(self, req: BiometricVerificationRequest) -> BiometricVerificationResponse:
        """Verify session keystrokes against enrolled baseline profile."""
        if not req.keystrokes or len(req.keystrokes) < 3:
            return BiometricVerificationResponse(
                user_id=req.user_id,
                session_id=req.session_id,
                verdict=BiometricVerdict.SUSPICIOUS_DEVIATION,
                distance_score=99.0,
                jitter_variance_ms=0.0,
                confidence=0.1,
                details="Insufficient keystroke sample size to verify behavioral authenticity.",
                recommended_action="Request user to enter additional typing input.",
            )

        avg_d, std_d, avg_f, std_f, var_f = self._extract_timing_metrics(req.keystrokes)

        # 1. Robotic / Bot / Copy-Paste Detection
        # Machine-generated keystrokes typically exhibit virtually zero jitter variance (< 1.5ms)
        if var_f < 1.5 and len(req.keystrokes) >= 5:
            alert = BiometricThreatAlert(
                alert_id=f"bio-bot-{uuid.uuid4().hex[:8]}",
                user_id=req.user_id,
                session_id=req.session_id,
                verdict=BiometricVerdict.AUTOMATED_BOT_SCRIPT,
                mitre_technique="T1059 - Command and Scripting Interpreter: Bot Keystroke Injection",
                severity="CRITICAL",
                details=(
                    f"Automated bot or headless script detected for user '{req.user_id}' in session {req.session_id}. "
                    f"Flight time variance is unnaturally constant ({var_f:.4f} ms^2), characteristic of robotic emulation."
                ),
                countermeasure="Freeze active session and require biometric FIDO2 hardware token verification.",
            )
            self.alerts.append(alert)

            return BiometricVerificationResponse(
                user_id=req.user_id,
                session_id=req.session_id,
                verdict=BiometricVerdict.AUTOMATED_BOT_SCRIPT,
                distance_score=999.0,
                jitter_variance_ms=var_f,
                confidence=0.99,
                details="Synthetic robotic keystroke timing detected with negligible timing jitter.",
                recommended_action="TERMINATE_SESSION_IMMEDIATELY",
            )

        # Check if user has an enrolled profile
        profile = self.profiles.get(req.user_id)
        if not profile:
            # First time observation: auto-enroll baseline
            self.enroll_user_profile(
                BiometricEnrollmentRequest(
                    user_id=req.user_id,
                    sample_text_length=len(req.keystrokes),
                    keystrokes=req.keystrokes,
                )
            )
            return BiometricVerificationResponse(
                user_id=req.user_id,
                session_id=req.session_id,
                verdict=BiometricVerdict.AUTHENTIC_USER,
                distance_score=0.0,
                jitter_variance_ms=var_f,
                confidence=0.85,
                details="Baseline biometric profile initialized for user.",
                recommended_action="ALLOW_ACCESS",
            )

        # 2. Statistical Mahalanobis / Z-Score Distance Calculation
        z_dwell = abs(avg_d - profile.avg_dwell_time_ms) / profile.std_dwell_time_ms
        z_flight = abs(avg_f - profile.avg_flight_time_ms) / profile.std_flight_time_ms
        distance = round(math.sqrt(z_dwell ** 2 + z_flight ** 2), 2)

        if distance <= 2.0:
            verdict = BiometricVerdict.AUTHENTIC_USER
            conf = round(max(0.70, 1.0 - (distance / 10.0)), 2)
            details = f"Typing cadence matches enrolled user rhythm (Distance: {distance:.2f})."
            action = "ALLOW_ACCESS"
        elif distance <= 3.5:
            verdict = BiometricVerdict.SUSPICIOUS_DEVIATION
            conf = 0.60
            details = f"Moderate cadence divergence observed (Distance: {distance:.2f})."
            action = "CHALLENGE_STEP_UP_MFA"
        else:
            verdict = BiometricVerdict.ANOMALOUS_IMPERSONATOR
            conf = 0.92
            details = f"Severe typing biometric deviation (Distance: {distance:.2f}). Probable account takeover."
            action = "FREEZE_SESSION_AND_ALERT_SOC"

            alert = BiometricThreatAlert(
                alert_id=f"bio-ato-{uuid.uuid4().hex[:8]}",
                user_id=req.user_id,
                session_id=req.session_id,
                verdict=verdict,
                mitre_technique="T1078 - Valid Accounts: Behavioral Impersonation",
                severity="HIGH",
                details=(
                    f"Behavioral biometric impersonation detected for '{req.user_id}'. "
                    f"Typing speed and dwell dynamics diverge significantly from baseline (Distance: {distance:.2f})."
                ),
                countermeasure="Revoke session tokens and trigger step-up biometric verification.",
            )
            self.alerts.append(alert)

        return BiometricVerificationResponse(
            user_id=req.user_id,
            session_id=req.session_id,
            verdict=verdict,
            distance_score=distance,
            jitter_variance_ms=var_f,
            confidence=conf,
            details=details,
            recommended_action=action,
        )
