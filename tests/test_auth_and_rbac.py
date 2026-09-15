"""Integration Tests for Authentication, JWT, Account Lockout & RBAC."""

import pytest
from starlette.testclient import TestClient
from cybershield.api.server import app

client = TestClient(app)


def test_superadmin_login_success():
    """Verify default seeded Super Admin can authenticate and receive JWT tokens."""
    # First ensure DB is seeded via health check
    client.get("/api/v1/system/metrics")

    response = client.post("/api/auth/login", json={
        "username_or_email": "superadmin",
        "password": "CyberShield2026!"
    })
    assert response.status_code == 200
    data = response.json()
    assert "access_token" in data
    assert "refresh_token" in data
    assert data["user"]["username"] == "superadmin"
    assert data["user"]["role"] == "SUPER_ADMIN"
    assert "users:create" in data["user"]["permissions"]


import uuid


def test_user_registration_and_login():
    """Verify new user registration and subsequent authentication."""
    uid = uuid.uuid4().hex[:6]
    username = f"analyst_{uid}"
    email = f"analyst_{uid}@enterprise.corp"
    reg_resp = client.post("/api/auth/register", json={
        "username": username,
        "email": email,
        "password": "SecurePassword123!",
        "full_name": "Test Security Analyst"
    })
    assert reg_resp.status_code == 201
    user_data = reg_resp.json()
    assert user_data["username"] == username
    assert user_data["role"] == "VIEWER"

    # Authenticate with new account
    login_resp = client.post("/api/auth/login", json={
        "username_or_email": username,
        "password": "SecurePassword123!"
    })
    assert login_resp.status_code == 200
    token_data = login_resp.json()
    assert token_data["access_token"] is not None


def test_failed_login_and_account_lockout():
    """Verify 5 consecutive failed logins trigger automatic account lockout."""
    uid = uuid.uuid4().hex[:6]
    victim = f"lockout_{uid}"
    # Register test victim user
    client.post("/api/auth/register", json={
        "username": victim,
        "email": f"{victim}@enterprise.corp",
        "password": "CorrectPassword123!",
        "full_name": "Lockout Victim User"
    })

    # Attempt 4 failed logins (should return 401)
    for i in range(4):
        resp = client.post("/api/auth/login", json={
            "username_or_email": victim,
            "password": "WrongPassword!"
        })
        assert resp.status_code == 401

    # 5th failed attempt should trigger lockout (401 or 423)
    resp5 = client.post("/api/auth/login", json={
        "username_or_email": victim,
        "password": "WrongPassword!"
    })
    assert resp5.status_code in [401, 423]

    # Subsequent attempt even with CORRECT password should be rejected with 423 LOCKED
    locked_resp = client.post("/api/auth/login", json={
        "username_or_email": victim,
        "password": "CorrectPassword123!"
    })
    assert locked_resp.status_code == 423
    assert "locked" in locked_resp.json()["detail"].lower()


def test_rbac_permission_boundaries():
    """Verify VIEWER role cannot access admin user-creation, but SUPER_ADMIN can."""
    uid = uuid.uuid4().hex[:6]
    viewer_user = f"viewer_{uid}"
    client.post("/api/auth/register", json={
        "username": viewer_user,
        "email": f"{viewer_user}@enterprise.corp",
        "password": "SecurePassword123!",
        "full_name": "Viewer User"
    })

    # Login as VIEWER
    viewer_login = client.post("/api/auth/login", json={
        "username_or_email": viewer_user,
        "password": "SecurePassword123!"
    })
    viewer_token = viewer_login.json()["access_token"]

    # Attempt to create user with VIEWER token -> must be 403 Forbidden
    forbidden_resp = client.post("/api/users", json={
        "username": f"illegal_{uid}",
        "email": f"illegal_{uid}@enterprise.corp",
        "password": "Password123!",
        "full_name": "Illegal User",
        "role": "SUPER_ADMIN"
    }, headers={"Authorization": f"Bearer {viewer_token}"})
    assert forbidden_resp.status_code == 403

    # Login as SUPER_ADMIN
    admin_login = client.post("/api/auth/login", json={
        "username_or_email": "superadmin",
        "password": "CyberShield2026!"
    })
    admin_token = admin_login.json()["access_token"]

    # Create user with SUPER_ADMIN token -> must succeed with 201 Created
    admin_resp = client.post("/api/users", json={
        "username": f"legal_{uid}",
        "email": f"legal_{uid}@enterprise.corp",
        "password": "Password123!",
        "full_name": "Legal Security Analyst",
        "role": "SECURITY_ANALYST"
    }, headers={"Authorization": f"Bearer {admin_token}"})
    assert admin_resp.status_code == 201
    assert admin_resp.json()["role"] == "SECURITY_ANALYST"


def test_token_refresh_workflow():
    """Verify refresh token endpoint issues new access token."""
    login_resp = client.post("/api/auth/login", json={
        "username_or_email": "superadmin",
        "password": "CyberShield2026!"
    })
    refresh_token = login_resp.json()["refresh_token"]

    refresh_resp = client.post("/api/auth/refresh", json={
        "refresh_token": refresh_token
    })
    assert refresh_resp.status_code == 200
    assert "access_token" in refresh_resp.json()


def test_audit_logs_endpoint():
    """Verify audit log records can be queried by administrator."""
    admin_login = client.post("/api/auth/login", json={
        "username_or_email": "superadmin",
        "password": "CyberShield2026!"
    })
    admin_token = admin_login.json()["access_token"]

    audit_resp = client.get("/api/audit?limit=10", headers={"Authorization": f"Bearer {admin_token}"})
    assert audit_resp.status_code == 200
    data = audit_resp.json()
    assert "items" in data
    assert len(data["items"]) >= 1
    assert data["items"][0]["action"] in ["LOGIN_SUCCESS", "USER_REGISTER", "ADMIN_CREATE_USER"]
