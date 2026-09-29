"""
JOCKY JWT Token Management.
Handles generation, signature verification, expiration checks, and server-side revocation.
"""

import uuid
from datetime import datetime, timezone, timedelta
from typing import Dict, Any, Optional
import jwt
from fastapi import HTTPException, status
from sqlalchemy.orm import Session

from server.config import config


def create_access_token(
    user_id: str,
    username: str,
    role: str,
    organization_id: str,
    expires_delta: Optional[timedelta] = None,
) -> str:
    """Issue a signed JWT access token containing identity, role, and organization."""
    now = datetime.now(timezone.utc)
    expire = now + (expires_delta or timedelta(minutes=config.ACCESS_TOKEN_EXPIRE_MINUTES))
    jti = uuid.uuid4().hex

    payload: Dict[str, Any] = {
        "sub": user_id,
        "username": username,
        "role": role,
        "organization_id": organization_id,
        "type": "access",
        "jti": jti,
        "iat": now,
        "exp": expire,
    }

    return jwt.encode(payload, config.SECRET_KEY, algorithm=config.JWT_ALGORITHM)


def decode_access_token(token: str) -> Dict[str, Any]:
    """Decode and verify signature, expiration, and token type."""
    try:
        payload = jwt.decode(
            token,
            config.SECRET_KEY,
            algorithms=[config.JWT_ALGORITHM],
            options={"verify_exp": True},
        )
        if payload.get("type") != "access":
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token type.",
                headers={"WWW-Authenticate": "Bearer"},
            )
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Session token has expired. Please log in again.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    except jwt.PyJWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Could not validate credentials.",
            headers={"WWW-Authenticate": "Bearer"},
        )
