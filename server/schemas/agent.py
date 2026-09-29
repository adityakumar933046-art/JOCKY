"""
JOCKY Agent Pydantic Schemas.
"""

from datetime import datetime
from typing import Optional
from pydantic import BaseModel, ConfigDict


class AgentRegisterRequest(BaseModel):
    agent_id: str
    hostname: str
    operating_system: str
    os_version: Optional[str] = None
    architecture: Optional[str] = None
    jocky_version: str = "1.0.0"
    collector_version: str = "1.0.0"
    organization_id: Optional[str] = "org-default"
    trust_state: Optional[str] = None


class AgentRegisterResponse(BaseModel):
    registered: bool
    agent_id: str
    status: str
    trust_state: str = "PENDING"
    agent_token: Optional[str] = None


class AgentHeartbeatResponse(BaseModel):
    agent_id: str
    status: str
    trust_state: str = "AUTHORIZED"
    last_seen: datetime


class AgentResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    agent_id: str
    hostname: str
    operating_system: str
    os_version: Optional[str] = None
    architecture: Optional[str] = None
    jocky_version: str
    collector_version: str
    registered_at: datetime
    last_seen: datetime
    status: str
    organization_id: str = "org-default"
    trust_state: str = "PENDING"
