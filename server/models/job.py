"""
JOCKY Job Database Model.
Supports multi-tenancy organization mapping and execution auditing.
"""

from datetime import datetime, timezone
from sqlalchemy import Column, String, DateTime, Text, Boolean, ForeignKey
from sqlalchemy.orm import relationship
from server.database import Base


class JobModel(Base):
    __tablename__ = "jobs"

    job_id = Column(String(64), primary_key=True, index=True)
    name = Column(String(255), nullable=False)
    agent_id = Column(String(64), ForeignKey("agents.agent_id"), nullable=False, index=True)
    organization_id = Column(String(64), default="org-default", nullable=False, index=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    created_by = Column(String(128), default="analyst")
    status = Column(String(32), default="PENDING", index=True)
    jocky_source = Column(Text, nullable=False)
    submitted_at = Column(DateTime, nullable=True)
    started_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)
    error = Column(Text, nullable=True)
    detection_enabled = Column(Boolean, default=True)

    # Relationships
    agent = relationship("AgentModel", back_populates="jobs")
    evidence_records = relationship("CentralEvidenceModel", back_populates="job")
    findings = relationship("CentralFindingModel", back_populates="job")
