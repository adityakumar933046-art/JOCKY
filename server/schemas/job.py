"""
JOCKY Job Pydantic Schemas.
"""

from datetime import datetime
from typing import Optional, List, Any, Dict
from pydantic import BaseModel, ConfigDict


class JobCreateRequest(BaseModel):
    name: str
    agent_id: str
    jocky_source: str
    detection_enabled: bool = True
    created_by: str = "analyst"
    organization_id: Optional[str] = None


class JobStatusUpdateRequest(BaseModel):
    status: str
    error: Optional[str] = None


class JobResultUploadRequest(BaseModel):
    job_id: str
    agent_id: str
    evidence_records: List[Dict[str, Any]] = []
    findings: List[Dict[str, Any]] = []
    execution_status: str = "COMPLETED"
    execution_timestamp: Optional[str] = None
    error: Optional[str] = None


class JobResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    job_id: str
    name: str
    agent_id: str
    organization_id: str = "org-default"
    created_at: datetime
    created_by: str
    status: str
    jocky_source: str
    submitted_at: Optional[datetime] = None
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    error: Optional[str] = None
    detection_enabled: bool = True
