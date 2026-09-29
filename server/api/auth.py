"""
JOCKY Authentication API Endpoints.
Provides secure login, logout, password updates, and user profile management.
"""

from datetime import datetime, timezone, timedelta
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Header, Request, status
from sqlalchemy.orm import Session

from server.config import config
from server.database import get_db
from server.models.user import UserModel, RevokedTokenModel
from server.schemas.auth import (
    LoginRequest,
    TokenResponse,
    CurrentUserProfile,
    ChangePasswordRequest,
)
from server.security.crypto import hash_password, verify_password
from server.security.tokens import create_access_token, decode_access_token
from server.security.permissions import ROLE_PERMISSIONS
from server.security.rate_limiter import rate_limit_check
from server.security.audit_service import AuditService
from server.api.security import get_current_user, get_current_user_strict

router = APIRouter(prefix="/auth", tags=["Authentication"])


@router.post("/login", response_model=TokenResponse)
def login(
    req: LoginRequest,
    request: Request,
    db: Session = Depends(get_db),
):
    """Authenticate user with username and password, returning a signed JWT access token."""
    client_ip = request.client.host if request.client else "unknown"
    rate_limit_check(f"login:{client_ip}", limit=10, window_seconds=60, action="login")

    user = db.query(UserModel).filter(UserModel.username == req.username).first()
    now = datetime.now(timezone.utc)

    # Constant time / safe message on non-existent user
    if not user:
        AuditService.log_security_event(
            db=db,
            event_type="AUTHENTICATION_FAILURE",
            description=f"Failed login attempt for unknown user '{req.username}'.",
            severity="MEDIUM",
            source_ip=client_ip,
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials.",
        )

    # Check deactivated account
    if not user.is_active:
        AuditService.log_security_event(
            db=db,
            event_type="AUTHENTICATION_FAILURE",
            description=f"Login attempt on deactivated user '{user.username}'.",
            severity="HIGH",
            actor_id=user.user_id,
            organization_id=user.organization_id,
            source_ip=client_ip,
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Account is deactivated. Contact an administrator.",
        )

    # Check lockout
    if user.locked_until:
        locked_tz = user.locked_until.replace(tzinfo=timezone.utc) if user.locked_until.tzinfo is None else user.locked_until
        if locked_tz > now:
            AuditService.log_security_event(
                db=db,
                event_type="AUTHENTICATION_FAILURE",
                description=f"Login attempt on locked user '{user.username}'.",
                severity="HIGH",
                actor_id=user.user_id,
                organization_id=user.organization_id,
                source_ip=client_ip,
            )
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=f"Account is temporarily locked. Try again later.",
            )

    # Verify password
    if not verify_password(req.password, user.password_hash):
        user.failed_login_attempts += 1
        if user.failed_login_attempts >= config.MAX_LOGIN_ATTEMPTS:
            user.locked_until = now + timedelta(minutes=config.LOCKOUT_MINUTES)
            AuditService.log_security_event(
                db=db,
                event_type="RATE_LIMIT_TRIGGERED",
                description=f"User '{user.username}' locked for {config.LOCKOUT_MINUTES} minutes after {user.failed_login_attempts} failed attempts.",
                severity="HIGH",
                actor_id=user.user_id,
                organization_id=user.organization_id,
                source_ip=client_ip,
            )

        db.commit()

        AuditService.log(
            db=db,
            actor_type="USER",
            actor_id=user.user_id,
            action="USER_LOGIN_FAILED",
            resource_type="USER",
            resource_id=user.user_id,
            organization_id=user.organization_id,
            ip_address=client_ip,
            result="FAILURE",
            details={"failed_attempts": user.failed_login_attempts},
        )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials.",
        )

    # Successful login: reset counters
    user.failed_login_attempts = 0
    user.locked_until = None
    user.last_login = now
    db.commit()

    token = create_access_token(
        user_id=user.user_id,
        username=user.username,
        role=user.role,
        organization_id=user.organization_id,
    )

    AuditService.log(
        db=db,
        actor_type="USER",
        actor_id=user.user_id,
        action="USER_LOGIN_SUCCESS",
        resource_type="USER",
        resource_id=user.user_id,
        organization_id=user.organization_id,
        ip_address=client_ip,
        result="SUCCESS",
    )

    return TokenResponse(
        access_token=token,
        token_type="Bearer",
        expires_in_minutes=config.ACCESS_TOKEN_EXPIRE_MINUTES,
        user_id=user.user_id,
        username=user.username,
        role=user.role,
        organization_id=user.organization_id,
    )


@router.get("/me", response_model=CurrentUserProfile)
def get_me(user: UserModel = Depends(get_current_user_strict)):
    """Return currently authenticated user profile and assigned permissions."""
    perms = list(ROLE_PERMISSIONS.get(user.role.upper(), set()))
    return CurrentUserProfile(
        user_id=user.user_id,
        username=user.username,
        email=user.email,
        role=user.role,
        organization_id=user.organization_id,
        permissions=perms,
    )


@router.post("/logout")
def logout(
    request: Request,
    authorization: Optional[str] = Header(None),
    user: UserModel = Depends(get_current_user_strict),
    db: Session = Depends(get_db),
):
    """Invalidate current JWT access token server-side."""
    if authorization and authorization.startswith("Bearer "):
        token = authorization.split("Bearer ", 1)[1].strip()
        try:
            payload = decode_access_token(token)
            jti = payload.get("jti")
            exp_ts = payload.get("exp")
            if jti:
                exp_dt = datetime.fromtimestamp(exp_ts, tz=timezone.utc) if exp_ts else datetime.now(timezone.utc) + timedelta(hours=1)
                revoked = RevokedTokenModel(
                    jti=jti,
                    revoked_at=datetime.now(timezone.utc),
                    expires_at=exp_dt,
                )
                db.add(revoked)
                db.commit()
        except Exception:
            pass

    AuditService.log(
        db=db,
        actor_type="USER",
        actor_id=user.user_id,
        action="USER_LOGOUT",
        resource_type="USER",
        resource_id=user.user_id,
        organization_id=user.organization_id,
        ip_address=request.client.host if request.client else None,
        result="SUCCESS",
    )
    return {"message": "Successfully logged out."}


@router.post("/change-password")
def change_password(
    req: ChangePasswordRequest,
    user: UserModel = Depends(get_current_user_strict),
    db: Session = Depends(get_db),
):
    """Allow authenticated user to change their password."""
    if not verify_password(req.current_password, user.password_hash):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Current password verification failed.",
        )

    if len(req.new_password) < 8:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="New password must be at least 8 characters long.",
        )

    user.password_hash = hash_password(req.new_password)
    user.updated_at = datetime.now(timezone.utc)
    db.commit()

    AuditService.log(
        db=db,
        actor_type="USER",
        actor_id=user.user_id,
        action="USER_PASSWORD_CHANGED",
        resource_type="USER",
        resource_id=user.user_id,
        organization_id=user.organization_id,
        result="SUCCESS",
    )
    return {"message": "Password changed successfully."}
