"""Tests for CyberShield Enterprise - Autonomous Behavioral Biometrics & Keystroke Dynamics Sentinel.
Verifies dwell and flight timing calculation, robotic bot detection, behavioral impersonation alerts,
and FastAPI REST endpoints.
"""

import json
from datetime import datetime, timezone
import pytest
from starlette.testclient import TestClient

from cybershield.api.server import app
from cybershield.biometrics.schemas import (
    BiometricVerdict,
    KeystrokeTimingEvent,
    BiometricEnrollmentRequest,
    BiometricVerificationRequest,
)
from cybershield.biometrics.profiler import BehavioralBiometricsEngine


@pytest.fixture
def client():
    return TestClient(app)


@pytest.fixture
def engine():
    return BehavioralBiometricsEngine()


# =========================================================================
# Unit Tests: Timing Dynamics & Impersonation Detection
# =========================================================================

def test_enroll_user_profile(engine):
    # User types 5 characters with ~100ms dwell and ~150ms flight
    keystrokes = [
        KeystrokeTimingEvent(key_code="h", press_time_ms=0, release_time_ms=100),
        KeystrokeTimingEvent(key_code="e", press_time_ms=250, release_time_ms=350),
        KeystrokeTimingEvent(key_code="l", press_time_ms=500, release_time_ms=600),
        KeystrokeTimingEvent(key_code="l", press_time_ms=750, release_time_ms=850),
        KeystrokeTimingEvent(key_code="o", press_time_ms=1000, release_time_ms=1100),
    ]

    req = BiometricEnrollmentRequest(
        user_id="alice@corp.local",
        sample_text_length=5,
        keystrokes=keystrokes,
    )

    profile = engine.enroll_user_profile(req)
    assert profile.user_id == "alice@corp.local"
    assert profile.avg_dwell_time_ms == 100.0
    assert profile.avg_flight_time_ms == 150.0
    assert profile.enrolled_samples_count == 5


def test_verify_authentic_user(engine):
    # First enroll baseline
    keystrokes_base = [
        KeystrokeTimingEvent(key_code="p", press_time_ms=0, release_time_ms=100),
        KeystrokeTimingEvent(key_code="a", press_time_ms=250, release_time_ms=350),
        KeystrokeTimingEvent(key_code="s", press_time_ms=500, release_time_ms=600),
        KeystrokeTimingEvent(key_code="s", press_time_ms=750, release_time_ms=850),
    ]
    engine.enroll_user_profile(
        BiometricEnrollmentRequest(
            user_id="bob@corp.local",
            sample_text_length=4,
            keystrokes=keystrokes_base,
        )
    )

    # Bob logs in again with very similar cadence
    keystrokes_session = [
        KeystrokeTimingEvent(key_code="p", press_time_ms=10, release_time_ms=115),
        KeystrokeTimingEvent(key_code="a", press_time_ms=260, release_time_ms=360),
        KeystrokeTimingEvent(key_code="s", press_time_ms=515, release_time_ms=620),
        KeystrokeTimingEvent(key_code="s", press_time_ms=770, release_time_ms=875),
    ]

    req = BiometricVerificationRequest(
        user_id="bob@corp.local",
        session_id="sess-bob-01",
        keystrokes=keystrokes_session,
    )

    resp = engine.verify_session(req)
    assert resp.verdict == BiometricVerdict.AUTHENTIC_USER
    assert resp.distance_score <= 2.0
    assert resp.recommended_action == "ALLOW_ACCESS"


def test_detect_automated_bot_script(engine):
    # Perfectly uniform timing simulated by script (exactly 50ms dwell and exactly 50ms flight)
    keystrokes_bot = [
        KeystrokeTimingEvent(key_code="a", press_time_ms=0, release_time_ms=50),
        KeystrokeTimingEvent(key_code="d", press_time_ms=100, release_time_ms=150),
        KeystrokeTimingEvent(key_code="m", press_time_ms=200, release_time_ms=250),
        KeystrokeTimingEvent(key_code="i", press_time_ms=300, release_time_ms=350),
        KeystrokeTimingEvent(key_code="n", press_time_ms=400, release_time_ms=450),
    ]

    req = BiometricVerificationRequest(
        user_id="admin@corp.local",
        session_id="sess-bot-99",
        keystrokes=keystrokes_bot,
    )

    resp = engine.verify_session(req)
    assert resp.verdict == BiometricVerdict.AUTOMATED_BOT_SCRIPT
    assert resp.confidence >= 0.95
    assert resp.recommended_action == "TERMINATE_SESSION_IMMEDIATELY"
    assert len(engine.alerts) == 1
    assert engine.alerts[0].verdict == BiometricVerdict.AUTOMATED_BOT_SCRIPT


def test_detect_anomalous_impersonator(engine):
    # Enrolled baseline for Carol: fast typist (~60ms dwell, ~80ms flight)
    keystrokes_fast = [
        KeystrokeTimingEvent(key_code="t", press_time_ms=0, release_time_ms=60),
        KeystrokeTimingEvent(key_code="e", press_time_ms=140, release_time_ms=200),
        KeystrokeTimingEvent(key_code="s", press_time_ms=280, release_time_ms=340),
        KeystrokeTimingEvent(key_code="t", press_time_ms=420, release_time_ms=480),
    ]
    engine.enroll_user_profile(
        BiometricEnrollmentRequest(
            user_id="carol@corp.local",
            sample_text_length=4,
            keystrokes=keystrokes_fast,
        )
    )

    # Impersonator / stranger typing very slowly with erratic ~400ms dwell and ~600ms flight
    keystrokes_slow = [
        KeystrokeTimingEvent(key_code="t", press_time_ms=0, release_time_ms=400),
        KeystrokeTimingEvent(key_code="e", press_time_ms=1000, release_time_ms=1450),
        KeystrokeTimingEvent(key_code="s", press_time_ms=2100, release_time_ms=2500),
        KeystrokeTimingEvent(key_code="t", press_time_ms=3200, release_time_ms=3650),
    ]

    req = BiometricVerificationRequest(
        user_id="carol@corp.local",
        session_id="sess-carol-hacked",
        keystrokes=keystrokes_slow,
    )

    resp = engine.verify_session(req)
    assert resp.verdict == BiometricVerdict.ANOMALOUS_IMPERSONATOR
    assert resp.distance_score > 3.5
    assert "Probable account takeover" in resp.details


# =========================================================================
# Integration Tests: FastAPI REST Endpoints
# =========================================================================

def test_api_enroll_and_verify(client):
    keystrokes = [
        {"key_code": "k", "press_time_ms": 0.0, "release_time_ms": 100.0},
        {"key_code": "e", "press_time_ms": 200.0, "release_time_ms": 300.0},
        {"key_code": "y", "press_time_ms": 400.0, "release_time_ms": 500.0},
        {"key_code": "1", "press_time_ms": 600.0, "release_time_ms": 700.0},
    ]

    # 1. Enroll via API
    enroll_req = {
        "user_id": "api_user@corp.local",
        "sample_text_length": 4,
        "keystrokes": keystrokes,
    }
    enroll_resp = client.post("/api/v1/biometrics/enroll", json=enroll_req)
    assert enroll_resp.status_code == 201
    assert enroll_resp.json()["user_id"] == "api_user@corp.local"

    # 2. Verify via API
    verify_req = {
        "user_id": "api_user@corp.local",
        "session_id": "sess-api-01",
        "keystrokes": keystrokes,
    }
    verify_resp = client.post("/api/v1/biometrics/verify", json=verify_req)
    assert verify_resp.status_code == 200
    assert "verdict" in verify_resp.json()

    # 3. Check profiles endpoint
    profiles_resp = client.get("/api/v1/biometrics/profiles")
    assert profiles_resp.status_code == 200
    assert len(profiles_resp.json()) >= 1
