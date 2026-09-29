"""
JOCKY Agent Database Model.
Supports multi-tenancy organization mapping, trust lifecycle states, and per-agent token authentication.
"""

from datetime import datetime, timezone
from sqlalchemy import Column, String, DateTime
from sqlalchemy.orm import relationship
from server.database import Base


class AgentModel(Base):
    __tablename__ = "agents"

    agent_id = Column(String(64), primary_key=True, index=True)
    hostname = Column(String(255), nullable=False, index=True)
    operating_system = Column(String(64), nullable=False)
    os_version = Column(String(128), nullable=True)
    architecture = Column(String(64), nullable=True)
    jocky_version = Column(String(32), default="1.0.0")
    collector_version = Column(String(32), default="1.0.0")
    registered_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    last_seen = Column(DateTime, default=lambda: datetime.now(timezone.utc), index=True)
    status = Column(String(32), default="ONLINE", index=True)  # ONLINE, OFFLINE
    
    # Step 5 Security & Multi-Tenancy extensions
    organization_id = Column(String(64), default="org-default", nullable=False, index=True)
    trust_state = Column(String(32), default="PENDING", nullable=False, index=True)  # PENDING, AUTHORIZED, SUSPENDED, REVOKED
    agent_token_hash = Column(String(64), nullable=True)

    # Relationships
    jobs = relationship("JobModel", back_populates="agent", cascade="all, delete-orphan")
    evidence_records = relationship("CentralEvidenceModel", back_populates="agent")
    findings = relationship("CentralFindingModel", back_populates="agent")
