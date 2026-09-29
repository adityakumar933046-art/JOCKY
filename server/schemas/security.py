"""
JOCKY Security, Audit & Custody Pydantic Schemas.
"""

from datetime import datetime
from typing import Optional, Dict, Any, List
from pydantic import BaseModel, ConfigDict


class AuditLogResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    audit_id: str
    timestamp: datetime
    actor_type: str
    actor_id: str
    organization_id: Optional[str] = None
    action: str
    resource_type: str
    resource_id: Optional[str] = None
    ip_address: Optional[str] = None
    result: str
    details: Dict[str, Any] = {}


class SecurityEventResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    event_id: str
    timestamp: datetime
    event_type: str
    severity: str
    source_ip: Optional[str] = None
    actor_id: Optional[str] = None
    organization_id: Optional[str] = None
    description: str
    details: Dict[str, Any] = {}


class CustodyEventResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    event_id: str
    evidence_id: str
    timestamp: datetime
    actor_type: str
    actor_id: str
    action: str
    previous_hash: str
    event_hash: str
    metadata_json: str


class SecurityMetricsResponse(BaseModel):
    authorized_agents: int
    pending_agents: int
    suspended_agents: int
    revoked_agents: int
    authentication_failures: int
    authorization_failures: int
    integrity_failures: int
    open_investigations: int
    critical_findings: int
    high_findings: int
    recent_security_events: List[SecurityEventResponse]


class AgentTrustUpdateRequest(BaseModel):
    reason: Optional[str] = None
