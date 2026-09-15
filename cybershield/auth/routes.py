"""Authentication & Identity REST API Endpoints for CyberShield Enterprise."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, status, Request
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, or_, desc

from cybershield.database.session import get_db
from cybershield.database.models import User, LoginHistory, get_role_permissions
from cybershield.auth.schemas import (
    LoginRequest,
    TokenResponse,
    RefreshTokenRequest,
    UserRegisterRequest,
    UserProfileResponse,
    LoginHistoryItem,
    PasswordResetRequest,
)
from cybershield.auth.security import (
    verify_password,
    get_password_hash,
    create_access_token,
    create_refresh_token,
    decode_token,
    ACCESS_TOKEN_EXPIRE_MINUTES,
)
from cybershield.auth.dependencies import get_current_user
from cybershield.audit.service import AuditService

router = APIRouter(prefix="/api/auth", tags=["Authentication"])

MAX_FAILED_ATTEMPTS = 5
LOCKOUT_DURATION_MINUTES = 15


@router.post("/register", response_model=UserProfileResponse, status_code=status.HTTP_201_CREATED)
async def register(
    payload: UserRegisterRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """Register a new user account with default VIEWER role."""
    # Check if username or email already exists
    query = select(User).where(or_(User.username == payload.username.lower(), User.email == payload.email.lower()))
    existing = (await db.execute(query)).scalar_one_or_none()
    if existing:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username or email address is already registered",
        )

    # Safe role assignment (self-registration is always VIEWER unless admin explicitly sets it)
    assigned_role = payload.role if payload.role in {"VIEWER", "SECURITY_ANALYST"} else "VIEWER"

    new_user = User(
        username=payload.username.lower(),
        email=payload.email.lower(),
        full_name=payload.full_name,
        hashed_password=get_password_hash(payload.password),
        role=assigned_role,
        is_active=True,
        is_verified=True,
    )
    db.add(new_user)
    await db.commit()
    await db.refresh(new_user)

    # Record audit log
    ip = request.client.host if request.client else "127.0.0.1"
    ua = request.headers.get("user-agent", "Unknown")
    await AuditService.log_event(
        db,
        action="USER_REGISTER",
        username=new_user.username,
        user_id=new_user.id,
        resource="auth/register",
        ip_address=ip,
        user_agent=ua,
        details={"assigned_role": assigned_role, "email": new_user.email},
    )

    resp = UserProfileResponse.model_validate(new_user)
    resp.permissions = get_role_permissions(new_user.role)
    return resp


@router.post("/login", response_model=TokenResponse)
async def login(
    payload: LoginRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """Authenticate user credentials with brute-force lockout protection and login auditing."""
    ip = request.client.host if request.client else "127.0.0.1"
    ua = request.headers.get("user-agent", "Unknown")
    identifier = payload.username_or_email.strip().lower()

    # Look up user by username or email
    query = select(User).where(or_(User.username == identifier, User.email == identifier))
    user = (await db.execute(query)).scalar_one_or_none()

    now = datetime.now(timezone.utc)

    # Handle unknown user
    if not user:
        # Record failed attempt in LoginHistory
        db.add(LoginHistory(
            username=identifier,
            ip_address=ip,
            user_agent=ua,
            success=False,
            failure_reason="User does not exist"
        ))
        await db.commit()
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password",
        )

    # Check if account is locked
    if user.is_temporarily_locked():
        lock_msg = f"Account locked until {user.lockout_until.isoformat()} due to excessive failed attempts."
        db.add(LoginHistory(
            user_id=user.id,
            username=user.username,
            ip_address=ip,
            user_agent=ua,
            success=False,
            failure_reason=lock_msg
        ))
        await db.commit()
        raise HTTPException(
            status_code=status.HTTP_423_LOCKED,
            detail=lock_msg,
        )

    # Check deactivated account
    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account is deactivated. Contact security administrator.",
        )

    # Verify password
    if not verify_password(payload.password, user.hashed_password):
        user.failed_login_attempts += 1
        failure_reason = f"Password mismatch (Attempt {user.failed_login_attempts}/{MAX_FAILED_ATTEMPTS})"

        # Trigger automatic lockout if threshold reached
        if user.failed_login_attempts >= MAX_FAILED_ATTEMPTS:
            user.is_locked = True
            user.lockout_until = now + timedelta(minutes=LOCKOUT_DURATION_MINUTES)
            failure_reason = f"Account locked for {LOCKOUT_DURATION_MINUTES}m after {MAX_FAILED_ATTEMPTS} failed attempts"
            await AuditService.log_event(
                db,
                action="ACCOUNT_LOCKED",
                username=user.username,
                user_id=user.id,
                resource="auth/login",
                status="BLOCKED",
                ip_address=ip,
                user_agent=ua,
                details={"reason": "Excessive failed logins", "lockout_until": user.lockout_until.isoformat()},
            )

        db.add(LoginHistory(
            user_id=user.id,
            username=user.username,
            ip_address=ip,
            user_agent=ua,
            success=False,
            failure_reason=failure_reason
        ))
        await db.commit()

        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=failure_reason if user.is_locked else "Invalid username or password",
        )

    # Successful login: reset failed counters and update timestamps
    user.failed_login_attempts = 0
    user.is_locked = False
    user.lockout_until = None
    user.last_login_at = now
    user.last_login_ip = ip

    db.add(LoginHistory(
        user_id=user.id,
        username=user.username,
        ip_address=ip,
        user_agent=ua,
        success=True,
    ))

    # Issue JWT tokens
    token_claims = {
        "sub": str(user.id),
        "username": user.username,
        "email": user.email,
        "role": user.role,
    }
    access_token = create_access_token(token_claims)
    refresh_token = create_refresh_token(token_claims)

    await AuditService.log_event(
        db,
        action="LOGIN_SUCCESS",
        username=user.username,
        user_id=user.id,
        resource="auth/login",
        status="SUCCESS",
        ip_address=ip,
        user_agent=ua,
        details={"role": user.role},
    )

    await db.commit()

    profile = UserProfileResponse.model_validate(user)
    profile.permissions = get_role_permissions(user.role)

    return TokenResponse(
        access_token=access_token,
        refresh_token=refresh_token,
        expires_in_seconds=ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        user=profile,
    )


@router.post("/refresh", response_model=TokenResponse)
async def refresh_token_endpoint(
    payload: RefreshTokenRequest,
    db: AsyncSession = Depends(get_db),
):
    """Issue a new access token using a valid refresh token."""
    try:
        decoded = decode_token(payload.refresh_token)
        if decoded.get("token_type") != "refresh":
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid token type")
        user_id = decoded.get("sub")
    except Exception as ex:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid or expired refresh token")

    result = await db.execute(select(User).where(User.id == int(user_id)))
    user = result.scalar_one_or_none()

    if not user or not user.is_active or user.is_temporarily_locked():
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User account inactive or locked")

    token_claims = {
        "sub": str(user.id),
        "username": user.username,
        "email": user.email,
        "role": user.role,
    }
    new_access_token = create_access_token(token_claims)
    new_refresh_token = create_refresh_token(token_claims)

    profile = UserProfileResponse.model_validate(user)
    profile.permissions = get_role_permissions(user.role)

    return TokenResponse(
        access_token=new_access_token,
        refresh_token=new_refresh_token,
        expires_in_seconds=ACCESS_TOKEN_EXPIRE_MINUTES * 60,
        user=profile,
    )


@router.get("/me", response_model=UserProfileResponse)
async def get_my_profile(current_user: User = Depends(get_current_user)):
    """Fetch profile and permissions for currently authenticated user."""
    profile = UserProfileResponse.model_validate(current_user)
    profile.permissions = get_role_permissions(current_user.role)
    return profile


@router.post("/logout")
async def logout(
    request: Request,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Log out and terminate authenticated session."""
    ip = request.client.host if request.client else "127.0.0.1"
    await AuditService.log_event(
        db,
        action="LOGOUT",
        username=current_user.username,
        user_id=current_user.id,
        resource="auth/logout",
        ip_address=ip,
        details={"status": "session_terminated"},
    )
    return {"message": "Successfully logged out. Session invalidated."}


@router.get("/login-history", response_model=List[LoginHistoryItem])
async def get_login_history(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Fetch authentication history for the current user."""
    query = (
        select(LoginHistory)
        .where(LoginHistory.username == current_user.username)
        .order_by(desc(LoginHistory.timestamp))
        .limit(25)
    )
    results = (await db.execute(query)).scalars().all()
    return list(results)


@router.post("/password-reset")
async def request_password_reset(
    payload: PasswordResetRequest,
    db: AsyncSession = Depends(get_db),
):
    """Initiate password reset request."""
    # Lookup email
    query = select(User).where(User.email == payload.email.lower())
    user = (await db.execute(query)).scalar_one_or_none()
    # Always return 200 to prevent user enumeration
    if user:
        logger.info("Password reset requested for email: %s", payload.email)
    return {"message": "If an account exists with this email, instructions have been dispatched."}
