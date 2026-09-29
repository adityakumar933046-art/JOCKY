"""
JOCKY Central Threat Finding Database Model.
Supports multi-tenancy organization mapping and indicator context.
"""

from datetime import datetime, timezone
from sqlalchemy import Column, String, DateTime, Text, Float, ForeignKey, JSON
from sqlalchemy.orm import relationship
from server.database import Base


class CentralFindingModel(Base):
    __tablename__ = "central_findings"

    finding_id = Column(String(64), primary_key=True, index=True)
    agent_id = Column(String(64), ForeignKey("agents.agent_id"), nullable=False, index=True)
    job_id = Column(String(64), ForeignKey("jobs.job_id"), nullable=True, index=True)
    organization_id = Column(String(64), default="org-default", nullable=False, index=True)
    rule_id = Column(String(64), nullable=False, index=True)
    title = Column(String(255), nullable=False)
    category = Column(String(64), nullable=False, index=True)
    severity = Column(String(32), nullable=False, index=True)
    confidence = Column(Float, default=0.85)
    description = Column(Text, nullable=True)
    evidence_ids = Column(JSON, default=list)
    affected_object = Column(String(255), nullable=True)
    indicators = Column(JSON, default=dict)
    recommendation = Column(Text, nullable=True)
    timestamp = Column(DateTime, default=lambda: datetime.now(timezone.utc), index=True)

    # Relationships
    agent = relationship("AgentModel", back_populates="findings")
    job = relationship("JobModel", back_populates="findings")
