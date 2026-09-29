"""
JOCKY Central Evidence Database Model.
Supports SHA-256 canonical hashing, cryptographic integrity verification, and multi-tenant isolation.
"""

from datetime import datetime, timezone
from sqlalchemy import Column, String, DateTime, ForeignKey, JSON, Boolean
from sqlalchemy.orm import relationship
from server.database import Base


class CentralEvidenceModel(Base):
    __tablename__ = "central_evidence"

    evidence_id = Column(String(64), primary_key=True, index=True)
    agent_id = Column(String(64), ForeignKey("agents.agent_id"), nullable=False, index=True)
    job_id = Column(String(64), ForeignKey("jobs.job_id"), nullable=True, index=True)
    organization_id = Column(String(64), default="org-default", nullable=False, index=True)
    hostname = Column(String(255), nullable=False)
    timestamp = Column(DateTime, default=lambda: datetime.now(timezone.utc), index=True)
    operation = Column(String(64), nullable=False, index=True)
    collection_status = Column(String(32), default="success")
    data = Column(JSON, nullable=True)

    # Step 5 Evidence Integrity Extensions
    content_hash = Column(String(64), nullable=True, index=True)
    hash_algorithm = Column(String(32), default="SHA-256", nullable=False)
    integrity_verified = Column(Boolean, default=True, nullable=False)
    collected_by_agent = Column(String(64), nullable=True)
    collected_at = Column(DateTime, nullable=True)
    received_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)

    # Relationships
    agent = relationship("AgentModel", back_populates="evidence_records")
    job = relationship("JobModel", back_populates="evidence_records")
