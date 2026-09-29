"""
JOCKY Investigation Database Model and Association Tables.
Supports multi-tenancy organization mapping, chain of custody, and timeline analysis.
"""

from datetime import datetime, timezone
from sqlalchemy import Column, String, DateTime, Text, Table, ForeignKey
from sqlalchemy.orm import relationship
from server.database import Base

# Association Tables
investigation_agents = Table(
    "investigation_agents",
    Base.metadata,
    Column("investigation_id", String(64), ForeignKey("investigations.investigation_id", ondelete="CASCADE"), primary_key=True),
    Column("agent_id", String(64), ForeignKey("agents.agent_id", ondelete="CASCADE"), primary_key=True),
)

investigation_jobs = Table(
    "investigation_jobs",
    Base.metadata,
    Column("investigation_id", String(64), ForeignKey("investigations.investigation_id", ondelete="CASCADE"), primary_key=True),
    Column("job_id", String(64), ForeignKey("jobs.job_id", ondelete="CASCADE"), primary_key=True),
)

investigation_evidence = Table(
    "investigation_evidence",
    Base.metadata,
    Column("investigation_id", String(64), ForeignKey("investigations.investigation_id", ondelete="CASCADE"), primary_key=True),
    Column("evidence_id", String(64), ForeignKey("central_evidence.evidence_id", ondelete="CASCADE"), primary_key=True),
)

investigation_findings = Table(
    "investigation_findings",
    Base.metadata,
    Column("investigation_id", String(64), ForeignKey("investigations.investigation_id", ondelete="CASCADE"), primary_key=True),
    Column("finding_id", String(64), ForeignKey("central_findings.finding_id", ondelete="CASCADE"), primary_key=True),
)


class InvestigationModel(Base):
    __tablename__ = "investigations"

    investigation_id = Column(String(64), primary_key=True, index=True)
    title = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    status = Column(String(32), default="OPEN", index=True)  # OPEN, IN_PROGRESS, CLOSED
    organization_id = Column(String(64), default="org-default", nullable=False, index=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))
    created_by = Column(String(128), default="analyst")
    assigned_analyst = Column(String(128), nullable=True)

    # Relationships
    agents = relationship("AgentModel", secondary=investigation_agents, backref="investigations")
    jobs = relationship("JobModel", secondary=investigation_jobs, backref="investigations")
    evidence = relationship("CentralEvidenceModel", secondary=investigation_evidence, backref="investigations")
    findings = relationship("CentralFindingModel", secondary=investigation_findings, backref="investigations")
