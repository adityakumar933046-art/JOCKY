"""
JOCKY Investigation and Timeline Pydantic Schemas.
"""

from datetime import datetime
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, ConfigDict
from server.schemas.agent import AgentResponse
from server.schemas.job import JobResponse
from server.schemas.evidence import EvidenceResponse
from server.schemas.finding import FindingResponse


class InvestigationCreateRequest(BaseModel):
    title: str
    description: Optional[str] = None
    assigned_analyst: Optional[str] = "analyst"
    created_by: Optional[str] = "analyst"
    organization_id: Optional[str] = None
    agent_ids: List[str] = []
    job_ids: List[str] = []
    evidence_ids: List[str] = []
    finding_ids: List[str] = []


class InvestigationUpdateRequest(BaseModel):
    title: Optional[str] = None
    description: Optional[str] = None
    status: Optional[str] = None
    assigned_analyst: Optional[str] = None
    agent_ids: Optional[List[str]] = None
    job_ids: Optional[List[str]] = None
    evidence_ids: Optional[List[str]] = None
    finding_ids: Optional[List[str]] = None


class InvestigationResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    investigation_id: str
    title: str
    description: Optional[str] = None
    status: str
    organization_id: str = "org-default"
    created_at: datetime
    updated_at: datetime
    created_by: str
    assigned_analyst: Optional[str] = None
    agents: List[AgentResponse] = []
    jobs: List[JobResponse] = []
    evidence: List[EvidenceResponse] = []
    findings: List[FindingResponse] = []


class TimelineEvent(BaseModel):
    timestamp: datetime
    event_type: str  # e.g., "AGENT_REGISTERED", "JOB_CREATED", "EVIDENCE_COLLECTED", "FINDING_GENERATED"
    summary: str
    details: Dict[str, Any] = {}


class TimelineResponse(BaseModel):
    investigation_id: str
    title: str
    total_events: int
    events: List[TimelineEvent] = []
