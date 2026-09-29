"""
JOCKY Evidence Pydantic Schemas.
"""

from datetime import datetime
from typing import Optional, Any
from pydantic import BaseModel, ConfigDict


class EvidenceResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    evidence_id: str
    agent_id: str
    job_id: Optional[str] = None
    organization_id: str = "org-default"
    hostname: str
    timestamp: datetime
    operation: str
    collection_status: str
    data: Any = None
    content_hash: Optional[str] = None
    hash_algorithm: str = "SHA-256"
    integrity_verified: bool = True
    collected_by_agent: Optional[str] = None
    collected_at: Optional[datetime] = None
    received_at: Optional[datetime] = None
