"""
JOCKY Threat Finding Pydantic Schemas.
"""

from datetime import datetime
from typing import Optional, List, Dict, Any
from pydantic import BaseModel, ConfigDict


class FindingResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    finding_id: str
    agent_id: str
    job_id: Optional[str] = None
    organization_id: str = "org-default"
    rule_id: str
    title: str
    category: str
    severity: str
    confidence: float
    description: Optional[str] = None
    evidence_ids: List[str] = []
    affected_object: Optional[str] = None
    indicators: Dict[str, Any] = {}
    recommendation: Optional[str] = None
    timestamp: datetime
