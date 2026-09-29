"""
JOCKY Authentication & User Pydantic Schemas.
"""

from datetime import datetime
from typing import Optional, List
from pydantic import BaseModel, ConfigDict, EmailStr


class LoginRequest(BaseModel):
    username: str
    password: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "Bearer"
    expires_in_minutes: int
    user_id: str
    username: str
    role: str
    organization_id: str


class UserCreateRequest(BaseModel):
    username: str
    email: str
    password: str
    role: str = "VIEWER"
    organization_id: str = "org-default"


class ChangePasswordRequest(BaseModel):
    current_password: str
    new_password: str


class UserResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    user_id: str
    username: str
    email: str
    role: str
    organization_id: str
    is_active: bool
    created_at: datetime
    last_login: Optional[datetime] = None


class CurrentUserProfile(BaseModel):
    user_id: str
    username: str
    email: str
    role: str
    organization_id: str
    permissions: List[str]
