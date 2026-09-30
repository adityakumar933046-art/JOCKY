"""
JOCKY Security, Authentication & RBAC Authorization Dependencies.
Enforces role separation, JWT validation, organization isolation, and agent trust state checks.
"""

from datetime import datetime, timezone
from typing import Optional, List, Callable
from fastapi import Header, HTTPException, Depends, Request, status
from sqlalchemy.orm import Session

from server.config import config
from server.database import get_db
from server.models.user import UserModel, RevokedTokenModel
from server.models.agent import AgentModel
from server.security.tokens import decode_access_token
from server.security.permissions import has_permission, Roles
from server.security.audit_service import AuditService


def get_current_user(
    request: Request,
    authorization: Optional[str] = Header(None),
    x_analyst_key: Optional[str] = Header(None, alias="X-Analyst-Key"),
    db: Session = Depends(get_db),
) -> UserModel:
    """Authenticate the current user via JWT Bearer token or backward-compatible Analyst Secret Key."""
    # 1. Check JWT Bearer token
    token = None
    if authorization and authorization.startswith("Bearer "):
        token = authorization.split("Bearer ", 1)[1].strip()

    if token:
        try:
            payload = decode_access_token(token)
            jti = payload.get("jti")

            # Check server-side revocation
            if jti:
                revoked = db.query(RevokedTokenModel).filter(RevokedTokenModel.jti == jti).first()
                if revoked:
                    raise HTTPException(
                        status_code=status.HTTP_401_UNAUTHORIZED,
                        detail="Authentication token has been revoked.",
                        headers={"WWW-Authenticate": "Bearer"},
                    )

            user_id = payload.get("sub")
            user = db.query(UserModel).filter(UserModel.user_id == user_id).first()
            if not user:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="User account no longer exists.",
                    headers={"WWW-Authenticate": "Bearer"},
                )

            if not user.is_active:
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="User account is deactivated.",
                    headers={"WWW-Authenticate": "Bearer"},
                )

            now = datetime.now(timezone.utc)
            if user.locked_until:
                locked_tz = user.locked_until.replace(tzinfo=timezone.utc) if user.locked_until.tzinfo is None else user.locked_until
                if locked_tz > now:
                    raise HTTPException(
                        status_code=status.HTTP_401_UNAUTHORIZED,
                        detail="User account is temporarily locked due to excessive failed logins.",
                        headers={"WWW-Authenticate": "Bearer"},
                    )

            return user
        except HTTPException:
            # Fall back to Analyst Key if present, otherwise re-raise 401
            if not (x_analyst_key and config.ANALYST_SECRET_KEY and x_analyst_key == config.ANALYST_SECRET_KEY):
                raise

    # 2. Check legacy Analyst Secret Key (Step 4 backward compatibility)
    if x_analyst_key and config.ANALYST_SECRET_KEY and x_analyst_key == config.ANALYST_SECRET_KEY:
        admin_user = db.query(UserModel).filter(UserModel.username == "admin").first()
        if admin_user:
            return admin_user
        # Fallback virtual super-admin
        return UserModel(
            user_id="USR-SUPERADMIN",
            username="admin",
            email="admin@jocky.local",
            role=Roles.SUPER_ADMIN,
            organization_id=config.DEFAULT_ORG_ID,
            is_active=True,
        )

    # 3. Development / testing fallback when no auth headers are provided
    if authorization is None and x_analyst_key is None and config.ENVIRONMENT != "production":
        admin_user = db.query(UserModel).filter(UserModel.username == "admin").first()
        if admin_user:
            return admin_user
        return UserModel(
            user_id="USR-SUPERADMIN",
            username="admin",
            email="admin@jocky.local",
            role=Roles.SUPER_ADMIN,
            organization_id=config.DEFAULT_ORG_ID,
            is_active=True,
        )

    # Missing or invalid credentials
    AuditService.log_security_event(
        db=db,
        event_type="AUTHENTICATION_FAILURE",
        description="Request attempted with missing or invalid authentication credentials.",
        severity="MEDIUM",
        source_ip=request.client.host if request.client else None,
    )
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Unauthorized: Authentication required.",
        headers={"WWW-Authenticate": "Bearer"},
    )


def get_current_user_strict(
    request: Request,
    authorization: Optional[str] = Header(None),
    db: Session = Depends(get_db),
) -> UserModel:
    """Strict Bearer token validation required for account operations."""
    token = None
    if authorization and authorization.startswith("Bearer "):
        token = authorization.split("Bearer ", 1)[1].strip()

    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Unauthorized: Bearer token required.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    payload = decode_access_token(token)
    jti = payload.get("jti")
    if jti:
        revoked = db.query(RevokedTokenModel).filter(RevokedTokenModel.jti == jti).first()
        if revoked:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Authentication token has been revoked.",
                headers={"WWW-Authenticate": "Bearer"},
            )

    user_id = payload.get("sub")
    user = db.query(UserModel).filter(UserModel.user_id == user_id).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User account no longer exists.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User account is deactivated.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return user


def require_permission(permission: str) -> Callable:
    """Dependency factory returning a validator that ensures the user has a specific permission."""
    def permission_checker(
        request: Request,
        user: UserModel = Depends(get_current_user),
        db: Session = Depends(get_db),
    ) -> UserModel:
        if not has_permission(user.role, permission):
            AuditService.log(
                db=db,
                actor_type="USER",
                actor_id=user.user_id,
                action="AUTHORIZATION_FAILURE",
                resource_type="PERMISSION",
                resource_id=permission,
                organization_id=user.organization_id,
                ip_address=request.client.host if request.client else None,
                result="FAILURE",
                details={"required_permission": permission, "user_role": user.role},
            )
            AuditService.log_security_event(
                db=db,
                event_type="AUTHORIZATION_FAILURE",
                description=f"User '{user.username}' ({user.role}) denied access: missing '{permission}'.",
                severity="HIGH",
                actor_id=user.user_id,
                organization_id=user.organization_id,
                source_ip=request.client.host if request.client else None,
                details={"required_permission": permission},
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Forbidden: Missing required permission '{permission}'.",
            )
        return user

    return permission_checker


def check_org_access(user: UserModel, resource_org_id: Optional[str]) -> bool:
    """Validate that the user is permitted to access resources belonging to resource_org_id."""
    if user.role == Roles.SUPER_ADMIN:
        return True
    if not resource_org_id:
        return True
    return user.organization_id == resource_org_id


def verify_agent_auth(
    request: Request,
    x_agent_key: Optional[str] = Header(None, alias="X-Agent-Key"),
    x_agent_token: Optional[str] = Header(None, alias="X-Agent-Token"),
    authorization: Optional[str] = Header(None),
    db: Session = Depends(get_db),
) -> str:
    """Validate authentication key for JOCKY Agent communications."""
    provided_key = x_agent_token or x_agent_key
    if not provided_key and authorization and authorization.startswith("Bearer "):
        provided_key = authorization.split("Bearer ", 1)[1].strip()

    expected_key = config.AGENT_SECRET_KEY
    if not provided_key or (expected_key and provided_key != expected_key):
        # Also allow if matches agent token hash in database
        from server.security.crypto import hash_agent_token
        agent = None
        if provided_key:
            token_h = hash_agent_token(provided_key)
            agent = db.query(AgentModel).filter(AgentModel.agent_token_hash == token_h).first()

        if not agent and (not expected_key or provided_key != expected_key):
            AuditService.log_security_event(
                db=db,
                event_type="AUTHENTICATION_FAILURE",
                description="Agent request rejected: Invalid or missing agent secret key.",
                severity="HIGH",
                source_ip=request.client.host if request.client else None,
            )
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Unauthorized: Invalid or missing Agent Secret Key.",
            )

    return provided_key or "authenticated_agent"


def verify_analyst_auth(user: UserModel = Depends(get_current_user)) -> UserModel:
    """Legacy analyst auth validator for Step 4 compatibility."""
    return user
